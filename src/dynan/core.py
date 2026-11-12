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


def _user_task_count() -> int:
    """Count visible processes and threads owned by the current user."""
    uid, count = os.getuid(), 0
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            if process.stat().st_uid == uid:
                count += sum(1 for _ in (process / "task").iterdir())
        except (FileNotFoundError, PermissionError):
            continue
    return count


def _nproc_ceiling(additional: int) -> int:
    """Allow a bounded number of new tasks without penalizing existing user tasks."""
    _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    desired = max(128, _user_task_count() + additional)
    return desired if hard == resource.RLIM_INFINITY else min(desired, hard)


def _limits(memory_mb: int, cpu_s: int, nproc: int) -> Callable[[], None]:
    """Create a child-process resource limiter."""
    def apply() -> None:
        """Apply resource limits in the child process."""
        if memory_mb:
            resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 1))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
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


def _sandbox_unavailable(stderr: str) -> bool:
    """Recognize Bubblewrap setup failures that occur before the child starts."""
    text = stderr.lower()
    return text.startswith("bwrap:") and any(marker in text for marker in (
        "creating new namespace failed",
        "no permissions to create new namespace",
        "operation not permitted",
        "resource temporarily unavailable",
        "setting up uid map",
    ))


def execute(
    command: list[str], cwd: Path, *, data: bytes | None = None,
    timeout: float = 10, memory_mb: int = 1024, cpu_s: int = 10,
    process_budget: int = 64, env: dict[str, str] | None = None, sandbox: bool = True,
) -> dict[str, Any]:
    """Execute one isolated command and capture complete termination evidence."""
    started = time.monotonic()
    nproc = _nproc_ceiling(process_budget)
    try:
        wrapped = _sandboxed(command, cwd, sandbox)
        completed = subprocess.run(
            wrapped, cwd=cwd, input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            env=env, preexec_fn=_limits(memory_mb, cpu_s, nproc), check=False,
        )
        sandbox_used = sandbox
        fallback_reason = None
        first_stderr = completed.stderr.decode("utf-8", "replace")
        if sandbox and completed.returncode != 0 and _sandbox_unavailable(first_stderr):
            # Some CI and desktop shells disable user namespaces. Resource limits
            # still apply, and the report records that filesystem isolation degraded.
            fallback_reason = first_stderr.strip()
            completed = subprocess.run(
                command, cwd=cwd, input=data,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                env=env, preexec_fn=_limits(memory_mb, cpu_s, nproc), check=False,
            )
            sandbox_used = False
        code = completed.returncode
        return {
            "command": command, "exit_code": code if code >= 0 else None,
            "signal": signal.Signals(-code).name if code < 0 else None,
            "timed_out": False, "stdout": completed.stdout.decode("utf-8", "replace"),
            "stderr": completed.stderr.decode("utf-8", "replace"),
            "duration_s": round(time.monotonic() - started, 4),
            "sandbox_requested": sandbox, "sandbox_used": sandbox_used,
            "sandbox_fallback": fallback_reason,
            "limits": {"memory_mb": memory_mb, "cpu_s": cpu_s, "nproc": nproc},
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command, "exit_code": None, "signal": None, "timed_out": True,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace"),
            "duration_s": round(time.monotonic() - started, 4),
            "sandbox_requested": sandbox, "sandbox_used": sandbox,
            "sandbox_fallback": None,
            "limits": {"memory_mb": memory_mb, "cpu_s": cpu_s, "nproc": nproc},
        }


def parse_error(run: dict[str, Any]) -> dict[str, Any] | None:
    """Classify a sanitizer, hardening, signal, or timeout failure."""
    text = run["stderr"]
    asan = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", text)
    ubsan = re.search(r"runtime error: ([^\n]+)", text)
    frames = [
        {"function": match.group(1), "file": match.group(2), "line": int(match.group(3))}
        for match in re.finditer(
            r"#\d+\s+.*?\bin\s+([\w:~]+).*?([^\s:]+\.(?:c|cc|cpp)):(\d+)", text
        )
    ]
    frame = frames[0] if frames else None
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
    function = frame["function"] if frame else None
    file = frame["file"] if frame else None
    line = frame["line"] if frame else None
    identity = f"{error_type}:{function or run['signal'] or 'unknown'}:{file or 'unknown'}"
    return {
        "error_type": error_type, "mechanism": mechanism,
        "function": function, "file": file, "line": line, "frames": frames,
        "termination": {key: run[key] for key in ("exit_code", "signal", "timed_out")},
        "identity": identity,
        "signature": f"{identity}:{line if line is not None else 'unknown'}",
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
    commit = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=False,
    )
    dirty = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain", "--", str(source)],
        capture_output=True, text=True, check=False,
    )
    return {
        "ok": binary.is_file(), "source": str(destination), "binary": str(binary),
        "binary_sha256": sha256_file(binary) if binary.is_file() else None,
        "source_sha256": sha256_tree(source), "flags": flags, "logs": logs,
        "commit_hash": commit.stdout.strip() if commit.returncode == 0 else None,
        "source_dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None,
        "profile": profile, "version": version,
    }


def hardening(binary: Path) -> tuple[dict[str, str], dict[str, Any]]:
    """Inspect NX, PIE, RELRO, and stack-canary evidence in an ELF binary."""
    commands = {
        "headers": ["readelf", "-W", "-h", "-l", str(binary)],
        "dynamic": ["readelf", "-W", "-d", str(binary)],
        "symbols": ["readelf", "-W", "-s", str(binary)],
    }
    runs = {
        name: subprocess.run(command, capture_output=True, text=True, check=False)
        for name, command in commands.items()
    }
    failed = [name for name, run in runs.items() if run.returncode != 0]
    if failed:
        details = "; ".join(f"{name}: {runs[name].stderr.strip()}" for name in failed)
        raise ConfigError(f"hardening inspection failed ({details})")
    headers, dynamic, symbols = (runs[name].stdout for name in ("headers", "dynamic", "symbols"))
    stack = next((line for line in headers.splitlines() if "GNU_STACK" in line), "")
    statuses = {
        "NX": "enabled" if stack and " E " not in stack else "disabled",
        "PIE": "enabled" if re.search(r"Type:\s+DYN", headers) else "disabled",
        "RELRO": "full" if "GNU_RELRO" in headers and "BIND_NOW" in dynamic else ("partial" if "GNU_RELRO" in headers else "disabled"),
        "Stack Canary": "enabled" if "__stack_chk_fail" in symbols else "disabled",
    }
    evidence = {
        "binary": str(binary),
        "commands": commands,
        "elf_type": next((line.strip() for line in headers.splitlines() if "Type:" in line), ""),
        "gnu_stack": stack.strip(),
        "gnu_relro": next((line.strip() for line in headers.splitlines() if "GNU_RELRO" in line), ""),
        "bind_now": next((line.strip() for line in dynamic.splitlines() if "BIND_NOW" in line), ""),
        "stack_chk_fail": next((line.strip() for line in symbols.splitlines() if "__stack_chk_fail" in line), ""),
    }
    return statuses, evidence


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


def _case_data(case: dict[str, Any], manifest_dir: Path) -> bytes:
    """Read inline, manifest-relative, or generated absolute test input."""
    if "input_path" in case:
        return Path(case["input_path"]).read_bytes()
    if "input_file" in case:
        return (manifest_dir / case["input_file"]).read_bytes()
    return str(case.get("input", "")).encode()


def run_case(
    build: dict[str, Any], case: dict[str, Any], manifest_dir: Path,
    config: dict[str, Any], run_dir: Path, input_override: bytes | None = None,
) -> dict[str, Any]:
    """Run one test case against one built binary."""
    work = run_dir / "work" / f"{build['version']}-{build['profile']}-{case['id']}-{time.monotonic_ns()}"
    work.mkdir(parents=True)
    data = input_override
    if data is None:
        data = _case_data(case, manifest_dir)
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
    shutil.copy2(build["binary"], bundle / "target.bin")
    delivery = case.get("delivery", config.get("execution", {}).get("delivery", "stdin"))
    argv = [str(item) for item in config.get("execution", {}).get("argv", ["{binary}"])]
    argv.extend(str(item) for item in case.get("argv", []))
    effective_environment = {
        **{str(key): str(value) for key, value in config.get("build", {}).get("env", {}).items()},
        "LANG": os.environ.get("LANG"),
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
    }
    effective_environment = {key: value for key, value in effective_environment.items() if value is not None}
    metadata = {
        "signature": finding["signature"], "version": build["version"],
        "commit_hash": build.get("commit_hash"), "source_dirty": build.get("source_dirty"),
        "source_sha256": build["source_sha256"], "binary_sha256": build["binary_sha256"],
        "build_flags": build["flags"], "link_flags": LINK_FLAGS,
        "build_commands": config["build"]["commands"],
        "environment": effective_environment,
        "delivery": delivery, "command_template": argv,
        "original_command": replays[0]["command"], "replays": replays,
    }
    (bundle / "metadata.json").write_text(json.dumps(metadata, indent=2))
    runner = f'''#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent
data = (root / "input-minimized.bin").read_bytes()
delivery = {delivery!r}
template = {argv!r}
replacement = str(root / "input-minimized.bin") if delivery == "file" else data.decode("utf-8", "replace")
command = [str(root / "target.bin") if item == "{{binary}}" else replacement if item == "{{input}}" else item for item in template]
environment = os.environ.copy()
environment.update({effective_environment!r})
completed = subprocess.run(command, cwd=root, input=data if delivery == "stdin" else None, env=environment, check=False)
raise SystemExit(completed.returncode if completed.returncode >= 0 else 128 - completed.returncode)
'''
    (bundle / "reproduce.py").write_text(runner)
    (bundle / "reproduce.py").chmod(0o755)
    (bundle / "reproduce.sh").write_text(
        '#!/bin/sh\nset -eu\nDIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec python3 "$DIR/reproduce.py"\n'
    )
    (bundle / "reproduce.sh").chmod(0o755)
    return str(bundle)


def _load_generated_cases(artifacts: Path, target: str) -> list[dict[str, Any]]:
    """Load minimized regression inputs registered by earlier pipeline runs."""
    registry = artifacts / "generated-tests" / target / "regressions.json"
    if not registry.exists():
        return []
    try:
        entries = json.loads(registry.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"invalid generated regression registry: {exc}") from exc
    if not isinstance(entries, list):
        raise ConfigError("generated regression registry must contain a list")
    cases: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("input_file"):
            raise ConfigError("invalid generated regression entry")
        input_path = registry.parent / entry["input_file"]
        if not input_path.is_file():
            raise ConfigError(f"generated regression input is missing: {input_path}")
        cases.append({
            "id": entry["id"], "category": "security", "generated": True,
            "input_path": str(input_path), "delivery": entry.get("delivery", "stdin"),
            "argv": entry.get("argv", []), "expect": entry.get("expect", {}),
            "expected_base_signature": entry.get("base_signature"),
            "provenance": entry.get("provenance", "automatically minimized regression"),
        })
    return cases


def _register_generated_case(
    artifacts: Path, target: str, case: dict[str, Any], minimized: bytes,
    finding: dict[str, Any], base_signature: str | None, patched_signature: str | None,
) -> dict[str, Any]:
    """Persist a minimized input in a registry consumed by subsequent runs."""
    directory = artifacts / "generated-tests" / target
    directory.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(case["id"]))
    registry = directory / "regressions.json"
    entries = json.loads(registry.read_text()) if registry.exists() else []
    identity = finding.get("identity", finding["signature"])
    identity_key = hashlib.sha256(f"{case['id']}:{identity}".encode()).hexdigest()[:12]
    generated_id = f"generated_{stem}_{identity_key}"
    filename = f"{generated_id}.bin"
    matching = [
        item for item in entries
        if item.get("source_test") == case["id"]
        and (item.get("identity") == identity or item.get("signature") == finding["signature"])
    ]
    candidates = [minimized]
    for item in matching:
        old_input = directory / str(item.get("input_file", ""))
        if old_input.is_file():
            candidates.append(old_input.read_bytes())
    best = min(candidates, key=len)
    (directory / filename).write_bytes(best)
    entry = {
        "id": generated_id, "input_file": filename,
        "source_test": case["id"], "signature": finding["signature"], "identity": identity,
        "base_signature": base_signature, "patched_signature": patched_signature,
        "delivery": case.get("delivery", "stdin"), "argv": case.get("argv", []),
        "expect": case.get("expect", {}),
        "provenance": "automatically minimized from a confirmed dynamic finding",
    }
    matching_ids = {item.get("id") for item in matching}
    entries = [item for item in entries if item.get("id") not in matching_ids | {generated_id}]
    entries.append(entry)
    registry.write_text(json.dumps(entries, indent=2))
    return {
        "path": str(directory / filename), "registry": str(registry),
        "minimized_size": len(best), **entry,
    }


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


def _correlate_finding(finding: dict[str, Any], changed_functions: list[str]) -> tuple[str, str]:
    """Correlate dynamic stack frames with functions changed by the patch."""
    stack_functions = [
        frame.get("function") for frame in finding.get("frames", []) if frame.get("function")
    ]
    if not stack_functions and finding.get("function"):
        stack_functions = [finding["function"]]
    intersections = sorted(set(stack_functions) & set(changed_functions))
    if intersections:
        return "supported", (
            f"dynamic stack path {stack_functions}; changed functions on that path: {intersections}"
        )
    return "unknown", (
        f"dynamic stack path {stack_functions}; changed functions: {changed_functions}; "
        "no execution-path intersection was established"
    )


def _classify_security(
    base_security_findings: dict[str, dict[str, Any]],
    patched_findings: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Separate remaining baseline vulnerabilities from newly introduced issues."""
    base_identities = {
        run["finding"].get("identity", run["finding"]["signature"])
        for run in base_security_findings.values()
    }
    remaining = {
        test_id: run for test_id, run in patched_findings.items()
        if run["finding"].get("identity", run["finding"]["signature"]) in base_identities
    }
    new_issues = {
        test_id: run for test_id, run in patched_findings.items() if test_id not in remaining
    }
    if not base_security_findings:
        security = "INCONCLUSIVE"
    elif new_issues:
        security = "NEW_ISSUE"
    elif remaining:
        security = "VULN_REMAINS"
    else:
        security = "FIXED"
    return security, remaining, new_issues


def _functional_regressions(
    cases: list[dict[str, Any]], runs: list[dict[str, Any]],
) -> list[str]:
    """Find all reference-behavior regressions, including boundary and invalid cases."""
    functional_ids = {
        case["id"] for case in cases if case["category"] in {"valid", "boundary", "invalid"}
    }
    release = {
        (run["version"], run["id"]): run for run in runs if run["profile"] == "release"
    }
    return sorted(
        test_id for test_id in functional_ids
        if release[("base", test_id)]["oracle_passed"]
        and not release[("patched", test_id)]["oracle_passed"]
    )


def validate(
    config_path: Path, *, minimize: bool = True, progress: Progress | None = None,
) -> tuple[dict[str, Any], int]:
    """Validate one patch and persist all evidence as JSON artifacts."""
    def note(stage: str, message: str) -> None:
        """Send a structured progress event when the caller requested one."""
        if progress:
            progress(stage, message)

    config_path = config_path.resolve()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    results_path: Path | None = None
    report: dict[str, Any] = {
        "schema": 1, "run_id": run_id, "target": None,
        "config": str(config_path), "started_at": datetime.now(timezone.utc).isoformat(),
        "builds": [], "tests": [], "findings": [], "reproducers": [],
    }
    try:
        config = load_yaml(config_path)
        for field in ("target.name", "source.base_path", "source.patched_path", "build.binary", "build.commands", "tests.manifest"):
            require(config, field)
        base = (config_path.parent / config["source"]["base_path"]).resolve()
        patched = (config_path.parent / config["source"]["patched_path"]).resolve()
        manifest_path = (config_path.parent / config["tests"]["manifest"]).resolve()
        artifacts = (config_path.parent / config.get("artifacts", {}).get("root", "../.dynan")).resolve()
        run_dir = artifacts / "runs" / run_id
        run_dir.mkdir(parents=True)
        results_path = run_dir / "results.json"
        report.update({
            "target": config["target"]["name"], "run_dir": str(run_dir),
            "results_path": str(results_path),
        })
        note("config", f"target={report['target']} | evidence={run_dir}")
        manifest = load_yaml(manifest_path)
        configured_cases = require(manifest, "tests")
        if not isinstance(configured_cases, list) or not configured_cases:
            raise ConfigError("test manifest has no tests")
        cases = list(configured_cases)
        categories = {case.get("category") for case in cases}
        if not {"valid", "boundary", "invalid", "security"}.issubset(categories):
            raise ConfigError("tests must cover valid, boundary, invalid, and security inputs")
        generated_cases = _load_generated_cases(artifacts, config["target"]["name"])
        known_ids = {case.get("id") for case in cases}
        cases.extend(case for case in generated_cases if case["id"] not in known_ids)
        counts = {category: sum(case.get("category") == category for case in cases) for category in sorted(categories)}
        note(
            "tests",
            f"loaded {len(cases)} cases ({len(generated_cases)} generated) | "
            + ", ".join(f"{key}={value}" for key, value in counts.items()),
        )
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
                if any(log.get("sandbox_fallback") for log in built["logs"]):
                    state += " (Bubblewrap unavailable; resource-limit fallback used)"
                note("build", f"{version}/{profile}: {state}")
        build_error = not all(item["ok"] for item in builds.values())
        if build_error:
            verdict, code = _decide(True, "INCONCLUSIVE", False, False)
            report.update({"verdict": verdict, "exit_code": code, "complete": False})
            results_path.write_text(json.dumps(report, indent=2))
            note("result", f"{verdict} ({code}) | one or more builds failed")
            return report, code
        report["hardening"], report["hardening_evidence"] = {}, {}
        for version in ("base", "patched"):
            status, evidence = hardening(Path(builds[(version, "release")]["binary"]))
            report["hardening"][version] = status
            report["hardening_evidence"][version] = evidence
        protection_rank = {"disabled": 0, "partial": 1, "enabled": 2, "full": 2}
        report["hardening_warnings"] = [
            f"{name} downgraded: {report['hardening']['base'][name]} -> {report['hardening']['patched'][name]}"
            for name in report["hardening"]["base"]
            if protection_rank[report["hardening"]["patched"][name]]
            < protection_rank[report["hardening"]["base"][name]]
        ]
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
            fallbacks = sum(item.get("sandbox_fallback") is not None for item in batch)
            isolation = f", sandbox fallbacks={fallbacks}" if fallbacks else ""
            note("run", f"{build['version']}/{build['profile']}: oracle {passed}/{len(batch)} passed, findings={findings}{isolation}")

        sanitized_runs = [run for run in report["tests"] if run["profile"] == "sanitized"]
        base_security_findings = {
            run["id"]: run for run in sanitized_runs
            if run["version"] == "base" and run["category"] == "security" and run["finding"]
        }
        patched_all_findings = {
            run["id"]: run for run in sanitized_runs
            if run["version"] == "patched" and run["finding"]
        }
        sanitized_by_version = {
            (run["version"], run["id"]): run for run in sanitized_runs
        }
        generated_validation_failures: list[dict[str, Any]] = []
        for case in (item for item in cases if item.get("generated")):
            expected = case.get("expected_base_signature")
            base_run = sanitized_by_version[("base", case["id"])]
            actual = (base_run.get("finding") or {}).get("signature")
            if actual != expected:
                generated_validation_failures.append({
                    "test": case["id"], "expected_base_signature": expected,
                    "actual_base_signature": actual,
                })
        report["generated_regression_failures"] = generated_validation_failures
        security, remaining, new_issues = _classify_security(
            base_security_findings, patched_all_findings,
        )
        for case in (item for item in cases if item["category"] == "security"):
            before = base_security_findings.get(case["id"])
            after = patched_all_findings.get(case["id"])
            if before and after:
                before_identity = before["finding"].get("identity", before["finding"]["signature"])
                after_identity = after["finding"].get("identity", after["finding"]["signature"])
                status, run = ("Incomplete Fix" if before_identity == after_identity else "New Issue"), after
            elif before:
                status, run = "Fixed", before
            elif after:
                status, run = "New Issue", after
            else:
                status, run = "Inconclusive", None
            finding = run["finding"].copy() if run else {}
            correlation, evidence = _correlate_finding(finding, changed_functions) if finding else (
                "unknown", "no classified dynamic finding",
            )
            finding.update({
                "test": case["id"], "status": status,
                "correlation": correlation, "correlation_evidence": evidence,
            })
            report["findings"].append(finding)
        reported_ids = {finding["test"] for finding in report["findings"]}
        for test_id, run in new_issues.items():
            if test_id in reported_ids:
                continue
            finding = run["finding"].copy()
            correlation, evidence = _correlate_finding(finding, changed_functions)
            finding.update({
                "test": test_id, "status": "New Issue", "correlation": correlation,
                "correlation_evidence": evidence,
            })
            report["findings"].append(finding)
        regressions = _functional_regressions(cases, report["tests"])
        replay_count = max(3, int(config.get("analysis", {}).get("replay_count", 3)))
        note("analysis", f"security={security} | functional regressions={len(regressions)}")
        case_by_id = {case["id"]: case for case in cases}
        stable_findings = True
        for version, found in (("base", base_security_findings), ("patched", patched_all_findings)):
            for test_id, original_run in found.items():
                case = case_by_id[test_id]
                build = builds[(version, "sanitized")]
                original = _case_data(case, manifest_path.parent)
                signature = original_run["finding"]["signature"]
                note("replay", f"confirming {version}/{test_id} {replay_count} times ({signature})")
                replayed = [run_case(build, case, manifest_path.parent, config, run_dir, original) for _ in range(replay_count)]
                stable = all((item.get("finding") or {}).get("signature") == signature for item in replayed)
                if not stable:
                    stable_findings = False
                    note("replay", f"{version}/{test_id}: unstable, reproducer skipped")
                    continue
                reduced = original
                if minimize:
                    note("minimize", f"reducing {version}/{test_id} from {len(original)} bytes")
                    reduced = ddmin(original, lambda candidate: (run_case(build, case, manifest_path.parent, config, run_dir, candidate).get("finding") or {}).get("signature") == signature)
                bundle = _write_reproducer(original_run["finding"], original, reduced, build, case, config, run_dir, replayed)
                report["reproducers"].append({"test": test_id, "version": version, "stable_replays": replay_count, "original_size": len(original), "minimized_size": len(reduced), "path": bundle})
                note("reproducer", f"{version}/{test_id}: stable, {len(original)} -> {len(reduced)} bytes | {bundle}")
                if not case.get("generated"):
                    normalized_case = {
                        **case,
                        "delivery": case.get("delivery", config.get("execution", {}).get("delivery", "stdin")),
                    }
                    base_signature = (
                        run_case(builds[("base", "sanitized")], case, manifest_path.parent, config, run_dir, reduced).get("finding") or {}
                    ).get("signature")
                    patched_signature = (
                        run_case(builds[("patched", "sanitized")], case, manifest_path.parent, config, run_dir, reduced).get("finding") or {}
                    ).get("signature")
                    generated = _register_generated_case(
                        artifacts, config["target"]["name"], normalized_case, reduced,
                        original_run["finding"], base_signature, patched_signature,
                    )
                    report.setdefault("generated_regressions", []).append(generated)
        all_runs = [log for build in report["builds"] for log in build["logs"]] + report["tests"]
        fallback_runs = sum(run.get("sandbox_fallback") is not None for run in all_runs)
        report["isolation"] = {
            "requested": bool(config.get("sandbox", {}).get("enabled", True)),
            "status": "degraded" if fallback_runs else "isolated",
            "fallback_runs": fallback_runs,
            "resource_limits_applied": True,
        }
        patched_oracle_failures = [
            {"test": run["id"], "profile": run["profile"], "failures": run["oracle_failures"]}
            for run in report["tests"]
            if run["version"] == "patched" and not run["oracle_passed"]
        ]
        report["mandatory_check_failures"] = patched_oracle_failures
        classified_failure_ids = set(regressions) | set(patched_all_findings)
        unclassified_failures = [
            failure for failure in patched_oracle_failures
            if failure["test"] not in classified_failure_ids
        ]
        report["unclassified_check_failures"] = unclassified_failures
        complete = all((
            bool(base_security_findings), bool(diff), bool(report["reproducers"]),
            stable_findings, not unclassified_failures, fallback_runs == 0,
            not generated_validation_failures,
        ))
        verdict, code = _decide(False, security, bool(regressions), complete)
        report.update({
            "security_status": security, "functional_regressions": sorted(regressions),
            "complete": complete, "verdict": verdict, "exit_code": code,
            "finished_at": datetime.now(timezone.utc).isoformat(),
        })
        results_path.write_text(json.dumps(report, indent=2))
        note("result", f"{verdict} ({code}) | evidence={results_path}")
        return report, code
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        report.update({"verdict": "BUILD_OR_CONFIG_ERROR", "exit_code": 30, "complete": False, "error": str(exc)})
        if results_path is not None:
            results_path.write_text(json.dumps(report, indent=2))
        note("result", f"BUILD_OR_CONFIG_ERROR (30) | {exc}")
        return report, 30
