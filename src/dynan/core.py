"""Core validation pipeline kept intentionally small and deterministic."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml


EXIT = {
    "PASS": 0,
    "VULN_REMAINS": 10,
    "FUNC_REGRESSION": 20,
    "BUILD_OR_CONFIG_ERROR": 30,
    "INCONCLUSIVE": 40,
}

RELEASE_FLAGS = "-O2 -g -fstack-protector-strong -fPIE"
SANITIZER_FLAGS = "-O1 -g -fno-omit-frame-pointer -fstack-protector-strong -fPIE -fsanitize=address,undefined"
LINK_FLAGS = "-Wl,-z,relro,-z,now -pie"
Progress = Callable[[str, str], None]


# Configuration and content fingerprints


class ConfigError(ValueError):
    """Represent an invalid project configuration."""


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate YAML keys instead of silently replacing them."""


def _unique_mapping(loader: UniqueLoader, node: yaml.Node, deep: bool = False) -> dict[str, Any]:
    """Build a YAML mapping while checking duplicate keys."""
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ConfigError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def load_yaml(path: Path) -> dict[str, Any]:
    """Load and validate a YAML mapping."""
    try:
        value = yaml.load(path.read_text(), Loader=UniqueLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(str(exc)) from exc
    if not isinstance(value, dict):
        raise ConfigError(f"{path} must contain a mapping")
    return value


def require(mapping: dict[str, Any], dotted: str) -> Any:
    """Return a required nested configuration value."""
    value: Any = mapping
    for key in dotted.split("."):
        if not isinstance(value, dict) or key not in value:
            raise ConfigError(f"missing configuration field: {dotted}")
        value = value[key]
    return value


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hash of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path: Path) -> str:
    """Return a stable content hash for a source tree."""
    digest = hashlib.sha256()
    for file in sorted(item for item in path.rglob("*") if item.is_file() and "build" not in item.parts):
        digest.update(str(file.relative_to(path)).encode())
        digest.update(file.read_bytes())
    return digest.hexdigest()


def _limits(memory_mb: int, cpu_s: int) -> Callable[[], None]:
    """Create a child-process resource limiter."""
    def apply() -> None:
        """Apply resource limits in the child process."""
        if memory_mb:
            resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 1))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
    return apply


# Isolated process execution


def _sandboxed(command: list[str], cwd: Path, enabled: bool) -> list[str]:
    """Wrap a command in a read-only bubblewrap filesystem sandbox."""
    if not enabled:
        return command
    if not shutil.which("bwrap"):
        raise ConfigError("bubblewrap is required for isolated execution")
    return [
        "bwrap", "--ro-bind", "/", "/", "--bind", str(cwd), str(cwd),
        "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev",
        "--die-with-parent", "--new-session", "--chdir", str(cwd),
        "--", *command,
    ]


def execute(
    command: list[str], cwd: Path, *, data: bytes | None = None,
    timeout: float = 10, memory_mb: int = 1024, cpu_s: int = 10,
    env: dict[str, str] | None = None, sandbox: bool = True,
) -> dict[str, Any]:
    """Execute one isolated command and capture complete termination evidence."""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            _sandboxed(command, cwd, sandbox), cwd=cwd, input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            env=env, preexec_fn=_limits(memory_mb, cpu_s), check=False,
        )
        code = completed.returncode
        return {
            "command": command, "exit_code": code if code >= 0 else None,
            "signal": signal.Signals(-code).name if code < 0 else None,
            "timed_out": False, "stdout": completed.stdout.decode("utf-8", "replace"),
            "stderr": completed.stderr.decode("utf-8", "replace"),
            "duration_s": round(time.monotonic() - started, 4),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command, "exit_code": None, "signal": None, "timed_out": True,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace"),
            "duration_s": round(time.monotonic() - started, 4),
        }


def parse_error(run: dict[str, Any]) -> dict[str, Any] | None:
    """Classify a sanitizer, hardening, signal, or timeout failure."""
    text = run["stderr"]
    asan = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", text)
    ubsan = re.search(r"runtime error: ([^\n]+)", text)
    frame = re.search(r"#\d+\s+.*?\bin\s+([\w:~]+).*?([^\s:]+\.(?:c|cc|cpp)):(\d+)", text)
    if asan:
        error_type, mechanism = asan.group(1), "ASan"
    elif ubsan:
        message = ubsan.group(1).lower()
        error_type = "division-by-zero" if "division by zero" in message else "undefined-behavior"
        mechanism = "UBSan"
    elif "stack smashing detected" in text:
        error_type, mechanism = "stack-smashing", "stack-canary"
    elif run["timed_out"]:
        error_type, mechanism = "timeout", "resource-limit"
    elif run["signal"]:
        error_type, mechanism = "crash", "OS-signal"
    else:
        return None
    function = frame.group(1) if frame else None
    return {
        "error_type": error_type, "mechanism": mechanism,
        "function": function, "file": frame.group(2) if frame else None,
        "line": int(frame.group(3)) if frame else None,
        "termination": {key: run[key] for key in ("exit_code", "signal", "timed_out")},
        "signature": f"{error_type}:{function or run['signal'] or 'unknown'}",
    }


def _function_blocks(text: str) -> dict[str, str]:
    """Extract simple C/C++ function bodies for diff correlation."""
    header = re.compile(r"^[\w\s*]+\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", re.M)
    result: dict[str, str] = {}
    for match in header.finditer(text):
        depth, index = 0, match.end() - 1
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    result[match.group(1)] = text[match.start():index + 1]
                    break
            index += 1
    return result


def source_diff(base: Path, patched: Path) -> tuple[str, list[str]]:
    """Create a unified source diff and list changed functions."""
    output: list[str] = []
    changed: set[str] = set()
    paths = sorted({p.relative_to(base) for p in base.rglob("*") if p.is_file()} |
                   {p.relative_to(patched) for p in patched.rglob("*") if p.is_file()})
    for relative in paths:
        left, right = base / relative, patched / relative
        if left.suffix not in {".c", ".cc", ".cpp", ".h", ".hpp"}:
            continue
        a = left.read_text(errors="replace") if left.exists() else ""
        b = right.read_text(errors="replace") if right.exists() else ""
        if a == b:
            continue
        output.extend(difflib.unified_diff(a.splitlines(True), b.splitlines(True),
                                           f"a/{relative}", f"b/{relative}"))
        af, bf = _function_blocks(a), _function_blocks(b)
        changed.update(name for name in af.keys() | bf.keys() if af.get(name) != bf.get(name))
    return "".join(output), sorted(changed)


# Build, hardening, and test execution


def build_version(
    source: Path, version: str, profile: str, config: dict[str, Any], run_dir: Path,
) -> dict[str, Any]:
    """Copy and build one source version with one compiler profile."""
    destination = run_dir / "sources" / version / profile
    shutil.copytree(source, destination)
    flags = SANITIZER_FLAGS if profile == "sanitized" else RELEASE_FLAGS
    env = os.environ.copy()
    env.update({str(k): str(v) for k, v in config.get("build", {}).get("env", {}).items()})
    env.update({"CFLAGS": flags, "CXXFLAGS": flags, "LDFLAGS": f"{LINK_FLAGS} {'-fsanitize=address,undefined' if profile == 'sanitized' else ''}"})
    logs: list[dict[str, Any]] = []
    for raw in require(config, "build.commands"):
        command = [str(part) for part in raw]
        result = execute(command, destination, timeout=float(config["build"].get("timeout_s", 300)),
                         memory_mb=2048, cpu_s=120, env=env,
                         sandbox=bool(config.get("sandbox", {}).get("enabled", True)))
        logs.append(result)
        if result["exit_code"] != 0:
            return {"ok": False, "source": str(destination), "logs": logs, "profile": profile, "version": version}
    binary = destination / require(config, "build.binary")
    return {
        "ok": binary.is_file(), "source": str(destination), "binary": str(binary),
        "binary_sha256": sha256_file(binary) if binary.is_file() else None,
        "source_sha256": sha256_tree(source), "flags": flags, "logs": logs,
        "profile": profile, "version": version,
    }


def hardening(binary: Path) -> dict[str, str]:
    """Inspect NX, PIE, RELRO, and stack-canary evidence in an ELF binary."""
    headers = subprocess.run(["readelf", "-W", "-h", "-l", str(binary)], capture_output=True, text=True, check=False).stdout
    dynamic = subprocess.run(["readelf", "-W", "-d", str(binary)], capture_output=True, text=True, check=False).stdout
    symbols = subprocess.run(["readelf", "-W", "-s", str(binary)], capture_output=True, text=True, check=False).stdout
    stack = next((line for line in headers.splitlines() if "GNU_STACK" in line), "")
    return {
        "NX": "enabled" if stack and " E " not in stack else "disabled",
        "PIE": "enabled" if re.search(r"Type:\s+DYN", headers) else "disabled",
        "RELRO": "full" if "GNU_RELRO" in headers and "BIND_NOW" in dynamic else ("partial" if "GNU_RELRO" in headers else "disabled"),
        "Stack Canary": "enabled" if "__stack_chk_fail" in symbols else "disabled",
    }


def oracle_ok(run: dict[str, Any], expected: dict[str, Any], cwd: Path) -> tuple[bool, list[str]]:
    """Compare an execution with its independent expected behavior."""
    failures: list[str] = []
    if "exit_code" in expected and run["exit_code"] != expected["exit_code"]:
        failures.append(f"exit code {run['exit_code']} != {expected['exit_code']}")
    if "stdout_exact" in expected and run["stdout"] != expected["stdout_exact"]:
        failures.append("stdout differs")
    for fragment in expected.get("stderr_contains", []):
        if fragment not in run["stderr"]:
            failures.append(f"stderr lacks {fragment!r}")
    if expected.get("must_not_crash") and parse_error(run):
        failures.append("program crashed")
    output = expected.get("output_file")
    if output:
        path = cwd / output["path"]
        if not path.exists():
            failures.append(f"missing output file {output['path']}")
        elif "exact" in output and path.read_text() != output["exact"]:
            failures.append(f"output file {output['path']} differs")
    return not failures, failures


def run_case(
    build: dict[str, Any], case: dict[str, Any], manifest_dir: Path,
    config: dict[str, Any], run_dir: Path, input_override: bytes | None = None,
) -> dict[str, Any]:
    """Run one test case against one built binary."""
    work = run_dir / "work" / f"{build['version']}-{build['profile']}-{case['id']}-{time.monotonic_ns()}"
    work.mkdir(parents=True)
    data = input_override
    if data is None:
        data = (manifest_dir / case["input_file"]).read_bytes() if "input_file" in case else str(case.get("input", "")).encode()
    delivery = case.get("delivery", config.get("execution", {}).get("delivery", "stdin"))
    input_path = work / "input.bin"
    input_path.write_bytes(data)
    argv = [str(item) for item in config.get("execution", {}).get("argv", ["{binary}"])]
    argv.extend(str(item) for item in case.get("argv", []))
    replacements = {"{binary}": build["binary"], "{input}": str(input_path) if delivery == "file" else data.decode("utf-8", "replace")}
    command = [replacements.get(item, item) for item in argv]
    stdin = data if delivery == "stdin" else None
    limits = config.get("execution", {}).get("limits", {})
    env = os.environ.copy()
    if build["profile"] == "sanitized":
        # ASan reserves a large virtual address range, so RLIMIT_AS cannot be used here.
        env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:symbolize=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    result = execute(command, work, data=stdin, timeout=float(config.get("execution", {}).get("timeout_s", 10)),
                     memory_mb=0 if build["profile"] == "sanitized" else int(limits.get("memory_mb", 1024)), cpu_s=int(limits.get("cpu_s", 10)),
                     env=env, sandbox=bool(config.get("sandbox", {}).get("enabled", True)))
    ok, failures = oracle_ok(result, case.get("expect", {}), work)
    result.update({
        "id": case["id"], "category": case["category"], "version": build["version"],
        "profile": build["profile"], "oracle_passed": ok, "oracle_failures": failures,
        "input_sha256": hashlib.sha256(data).hexdigest(), "input_size": len(data),
        "finding": parse_error(result), "provenance": case.get("expect", {}).get("provenance"),
    })
    return result


def ddmin(data: bytes, predicate: Callable[[bytes], bool], limit: int = 100) -> bytes:
    """Minimize bytes while preserving a failure signature."""
    current, granularity, attempts = data, 2, 0
    while len(current) > 1 and attempts < limit:
        size = max(1, len(current) // granularity)
        reduced = False
        for start in range(0, len(current), size):
            candidate = current[:start] + current[start + size:]
            attempts += 1
            if candidate and predicate(candidate):
                current, granularity, reduced = candidate, max(2, granularity - 1), True
                break
            if attempts >= limit:
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return current


# Finding reproduction and final decision


def _write_reproducer(
    finding: dict[str, Any], original: bytes, minimized: bytes, build: dict[str, Any],
    case: dict[str, Any], config: dict[str, Any], run_dir: Path, replays: list[dict[str, Any]],
) -> str:
    """Write a self-contained reproducer bundle for a confirmed finding."""
    name = f"{build['version']}-{case['id']}"
    bundle = run_dir / "reproducers" / name
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "input-original.bin").write_bytes(original)
    (bundle / "input-minimized.bin").write_bytes(minimized)
    metadata = {
        "signature": finding["signature"], "version": build["version"],
        "source_sha256": build["source_sha256"], "binary_sha256": build["binary_sha256"],
        "build_flags": build["flags"], "build_commands": config["build"]["commands"],
        "environment": {key: os.environ.get(key) for key in ("PATH", "LANG")},
        "command": replays[0]["command"], "replays": replays,
    }
    (bundle / "metadata.json").write_text(json.dumps(metadata, indent=2))
    quoted = " ".join(json.dumps(part) for part in replays[0]["command"])
    (bundle / "reproduce.sh").write_text(f"#!/bin/sh\n{quoted} < input-minimized.bin\n")
    (bundle / "reproduce.sh").chmod(0o755)
    return str(bundle)


def _decide(build_error: bool, security: str, regression: bool, complete: bool) -> tuple[str, int]:
    """Select the required CI verdict using assignment precedence."""
    if build_error:
        return "BUILD_OR_CONFIG_ERROR", 30
    if security in {"VULN_REMAINS", "NEW_ISSUE"}:
        return security, 10
    if regression:
        return "FUNC_REGRESSION", 20
    if not complete:
        return "INCONCLUSIVE", 40
    return "PASS", 0


def validate(
    config_path: Path, *, minimize: bool = True, progress: Progress | None = None,
) -> tuple[dict[str, Any], int]:
    """Validate one patch and persist all evidence as JSON artifacts."""
    def note(stage: str, message: str) -> None:
        """Send a structured progress event when the caller requested one."""
        if progress:
            progress(stage, message)

    config_path = config_path.resolve()
    config = load_yaml(config_path)
    for field in ("target.name", "source.base_path", "source.patched_path", "build.binary", "build.commands", "tests.manifest"):
        require(config, field)
    base = (config_path.parent / config["source"]["base_path"]).resolve()
    patched = (config_path.parent / config["source"]["patched_path"]).resolve()
    manifest_path = (config_path.parent / config["tests"]["manifest"]).resolve()
    artifacts = (config_path.parent / config.get("artifacts", {}).get("root", "../.dynan")).resolve()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = artifacts / "runs" / run_id
    run_dir.mkdir(parents=True)
    results_path = run_dir / "results.json"
    report: dict[str, Any] = {
        "schema": 1, "run_id": run_id, "target": config["target"]["name"],
        "config": str(config_path), "started_at": datetime.now(timezone.utc).isoformat(),
        "run_dir": str(run_dir), "results_path": str(results_path),
        "builds": [], "tests": [], "findings": [], "reproducers": [],
    }
    note("config", f"target={report['target']} | evidence={run_dir}")
    try:
        manifest = load_yaml(manifest_path)
        cases = require(manifest, "tests")
        if not isinstance(cases, list) or not cases:
            raise ConfigError("test manifest has no tests")
        categories = {case.get("category") for case in cases}
        if not {"valid", "boundary", "invalid", "security"}.issubset(categories):
            raise ConfigError("tests must cover valid, boundary, invalid, and security inputs")
        counts = {category: sum(case.get("category") == category for case in cases) for category in sorted(categories)}
        note("tests", f"loaded {len(cases)} cases | " + ", ".join(f"{key}={value}" for key, value in counts.items()))
        diff, changed_functions = source_diff(base, patched)
        (run_dir / "diff.patch").write_text(diff)
        report["diff"] = {"path": str(run_dir / "diff.patch"), "changed_functions": changed_functions}
        changed = ", ".join(changed_functions) or "none detected"
        note("diff", f"changed functions: {changed}")
        builds: dict[tuple[str, str], dict[str, Any]] = {}
        for version, source in (("base", base), ("patched", patched)):
            for profile in ("release", "sanitized"):
                note("build", f"building {version}/{profile}")
                built = build_version(source, version, profile, config, run_dir)
                builds[(version, profile)] = built
                report["builds"].append(built)
                state = "ok" if built["ok"] else "failed"
                note("build", f"{version}/{profile}: {state}")
        build_error = not all(item["ok"] for item in builds.values())
        if build_error:
            verdict, code = _decide(True, "INCONCLUSIVE", False, False)
            report.update({"verdict": verdict, "exit_code": code, "complete": False})
            results_path.write_text(json.dumps(report, indent=2))
            note("result", f"{verdict} ({code}) | one or more builds failed")
            return report, code
        report["hardening"] = {
            version: hardening(Path(builds[(version, "release")]["binary"]))
            for version in ("base", "patched")
        }
        hardened = ", ".join(f"{key}={value}" for key, value in report["hardening"]["patched"].items())
        note("hardening", f"patched/release: {hardened}")
        for build in builds.values():
            note("run", f"running {len(cases)} cases on {build['version']}/{build['profile']}")
            first = len(report["tests"])
            for case in cases:
                report["tests"].append(run_case(build, case, manifest_path.parent, config, run_dir))
            batch = report["tests"][first:]
            passed = sum(item["oracle_passed"] for item in batch)
            findings = sum(item["finding"] is not None for item in batch)
            note("run", f"{build['version']}/{build['profile']}: oracle {passed}/{len(batch)} passed, findings={findings}")

        # Security status is derived only from sanitizer-backed security cases.
        security_runs = [run for run in report["tests"] if run["category"] == "security" and run["profile"] == "sanitized"]
        base_findings = {run["id"]: run for run in security_runs if run["version"] == "base" and run["finding"]}
        patched_findings = {run["id"]: run for run in security_runs if run["version"] == "patched" and run["finding"]}
        if not base_findings:
            security = "INCONCLUSIVE"
        elif patched_findings:
            security = "VULN_REMAINS" if any(key in base_findings for key in patched_findings) else "NEW_ISSUE"
        else:
            security = "FIXED"
        for case in (item for item in cases if item["category"] == "security"):
            before, after = base_findings.get(case["id"]), patched_findings.get(case["id"])
            if before and after:
                status, run = "Incomplete Fix", after
            elif before:
                status, run = "Fixed", before
            elif after:
                status, run = "New Issue", after
            else:
                status, run = "Inconclusive", None
            finding = run["finding"].copy() if run else {}
            function = finding.get("function")
            finding.update({
                "test": case["id"], "status": status,
                "correlation": "supported" if function and function in changed_functions else "unknown",
                "correlation_evidence": f"stack function {function!r}; changed functions: {changed_functions}",
            })
            report["findings"].append(finding)
        valid_ids = {case["id"] for case in cases if case["category"] == "valid"}
        release = {(run["version"], run["id"]): run for run in report["tests"] if run["profile"] == "release"}
        # A regression exists only when the base passes an oracle that the patch fails.
        regressions = [test_id for test_id in valid_ids if release[("base", test_id)]["oracle_passed"] and not release[("patched", test_id)]["oracle_passed"]]
        replay_count = max(3, int(config.get("analysis", {}).get("replay_count", 3)))
        note("analysis", f"security={security} | functional regressions={len(regressions)}")
        case_by_id = {case["id"]: case for case in cases}
        for version, found in (("base", base_findings), ("patched", patched_findings)):
            for test_id, original_run in found.items():
                case = case_by_id[test_id]
                build = builds[(version, "sanitized")]
                original = (manifest_path.parent / case["input_file"]).read_bytes() if "input_file" in case else str(case.get("input", "")).encode()
                signature = original_run["finding"]["signature"]
                note("replay", f"confirming {version}/{test_id} {replay_count} times ({signature})")
                replayed = [run_case(build, case, manifest_path.parent, config, run_dir, original) for _ in range(replay_count)]
                stable = all((item.get("finding") or {}).get("signature") == signature for item in replayed)
                if not stable:
                    note("replay", f"{version}/{test_id}: unstable, reproducer skipped")
                    continue
                reduced = original
                if minimize:
                    note("minimize", f"reducing {version}/{test_id} from {len(original)} bytes")
                    reduced = ddmin(original, lambda candidate: (run_case(build, case, manifest_path.parent, config, run_dir, candidate).get("finding") or {}).get("signature") == signature)
                bundle = _write_reproducer(original_run["finding"], original, reduced, build, case, config, run_dir, replayed)
                report["reproducers"].append({"test": test_id, "version": version, "stable_replays": replay_count, "original_size": len(original), "minimized_size": len(reduced), "path": bundle})
                note("reproducer", f"{version}/{test_id}: stable, {len(original)} -> {len(reduced)} bytes | {bundle}")
                generated = artifacts / "generated-tests" / config["target"]["name"]
                generated.mkdir(parents=True, exist_ok=True)
                (generated / f"{version}-{test_id}.bin").write_bytes(reduced)
                report.setdefault("generated_regressions", []).append({
                    "path": str(generated / f"{version}-{test_id}.bin"),
                    "base_signature": (run_case(builds[("base", "sanitized")], case, manifest_path.parent, config, run_dir, reduced).get("finding") or {}).get("signature"),
                    "patched_signature": (run_case(builds[("patched", "sanitized")], case, manifest_path.parent, config, run_dir, reduced).get("finding") or {}).get("signature"),
                })
        complete = bool(base_findings) and bool(diff) and bool(report["reproducers"])
        verdict, code = _decide(False, security, bool(regressions), complete)
        report.update({
            "security_status": security, "functional_regressions": sorted(regressions),
            "complete": complete, "verdict": verdict, "exit_code": code,
            "finished_at": datetime.now(timezone.utc).isoformat(),
        })
        results_path.write_text(json.dumps(report, indent=2))
        note("result", f"{verdict} ({code}) | evidence={results_path}")
        return report, code
    except (ConfigError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        report.update({"verdict": "BUILD_OR_CONFIG_ERROR", "exit_code": 30, "complete": False, "error": str(exc)})
        results_path.write_text(json.dumps(report, indent=2))
        note("result", f"BUILD_OR_CONFIG_ERROR (30) | {exc}")
        return report, 30
