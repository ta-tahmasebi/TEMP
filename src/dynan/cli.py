"""Small command-line interface for the validator."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .core import ConfigError, load_yaml, require, validate


VERDICT_HELP = {
    "PASS": "the patch fixes the reproduced issue and valid behavior still passes",
    "VULN_REMAINS": "a security failure from the base version is still reproducible after the patch",
    "NEW_ISSUE": "the patched version introduces a new sanitizer finding",
    "FUNC_REGRESSION": "the security issue is fixed, but a previously valid case now fails",
    "BUILD_OR_CONFIG_ERROR": "a configuration, source, tool, or build step failed",
    "INCONCLUSIVE": "there is not enough reproducible evidence to decide safely",
}


def doctor(config: Path) -> int:
    """Check tools and required configuration paths."""
    problems = [f"missing executable: {name}" for name in ("gcc", "make", "readelf", "bwrap") if not shutil.which(name)]
    try:
        data = load_yaml(config.resolve())
        for field in ("source.base_path", "source.patched_path", "build.commands", "tests.manifest"):
            require(data, field)
    except (ConfigError, OSError) as exc:
        problems.append(str(exc))
    if problems:
        print("environment is not ready", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 30
    print("environment is ready")
    return 0


def _print_test_details(report: dict[str, object]) -> None:
    """Print one compact line for every executed test."""
    print("\nTest executions:")
    for run in report.get("tests", []):
        finding = run.get("finding") or {}
        if finding:
            state = f"FINDING {finding.get('error_type')} via {finding.get('mechanism')}"
        elif run.get("oracle_passed"):
            state = "PASS"
        else:
            state = "FAIL: " + "; ".join(run.get("oracle_failures", []))
        termination = "timeout" if run.get("timed_out") else (
            f"signal={run.get('signal')}" if run.get("signal") else f"exit={run.get('exit_code')}"
        )
        isolation = "fallback" if run.get("sandbox_fallback") else (
            "bwrap" if run.get("sandbox_used") else "disabled"
        )
        print(
            f"  {run['version']}/{run['profile']} {run['id']}: {state} "
            f"({termination}, {run['duration_s']}s, sandbox={isolation}, "
            f"nproc-limit={run.get('limits', {}).get('nproc', 'unknown')})"
        )


def _print_summary(report: dict[str, object], code: int, *, verbose: bool) -> None:
    """Explain the final verdict and point to the saved evidence."""
    verdict = str(report["verdict"])
    print("\n=== Validation result ===")
    print(f"Verdict     : {verdict} (exit code {code})")
    print(f"Meaning     : {VERDICT_HELP.get(verdict, 'see the JSON evidence for details')}")
    print(f"Security    : {report.get('security_status', 'unknown')}")
    regressions = report.get("functional_regressions", [])
    print(f"Regressions : {', '.join(regressions) if regressions else 'none'}")
    print(f"Analysis    : {'complete' if report.get('complete') else 'incomplete'}")

    findings = report.get("findings", [])
    if findings:
        print("Findings:")
        for finding in findings:
            signature = finding.get("signature", "no sanitizer finding")
            print(
                f"  - {finding.get('test')}: {finding.get('status')} | "
                f"{signature} | diff correlation={finding.get('correlation')}"
            )

    hardening = report.get("hardening", {}).get("patched") if report.get("hardening") else None
    if hardening:
        print("Hardening   : " + ", ".join(f"{key}={value}" for key, value in hardening.items()))
    isolation = report.get("isolation")
    if isolation:
        print(
            f"Isolation   : {isolation['status']} "
            f"(fallback runs={isolation['fallback_runs']}, resource limits=enabled)"
        )
    print(f"Evidence    : {report.get('results_path', 'not written')}")
    if verbose:
        _print_test_details(report)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point."""
    parser = argparse.ArgumentParser(prog="dynan", description="Dynamic security patch validator")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("doctor", help="check the environment")
    check.add_argument("--config", type=Path, required=True)
    run = sub.add_parser("validate", help="validate a patch")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--json-out", type=Path)
    run.add_argument("--no-minimize", action="store_true")
    detail = run.add_mutually_exclusive_group()
    detail.add_argument("--quiet", action="store_true", help="print only the final verdict")
    detail.add_argument("--verbose", action="store_true", help="also print every test execution")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return doctor(args.config)
    progress = None if args.quiet else lambda stage, message: print(f"[{stage:<10}] {message}", flush=True)
    report, code = validate(args.config, minimize=not args.no_minimize, progress=progress)
    if args.quiet:
        print(f"{report['verdict']} ({code})")
    else:
        _print_summary(report, code, verbose=args.verbose)
    if code == 30:
        if report.get("error"):
            print(f"error: {report['error']}", file=sys.stderr)
        for build in report.get("builds", []):
            for log in build.get("logs", []):
                if log.get("exit_code") != 0 and log.get("stderr"):
                    print(
                        f"{build['version']}/{build['profile']}: {log['stderr'].strip()}",
                        file=sys.stderr,
                    )
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2))
        if not args.quiet:
            print(f"JSON copy   : {args.json_out}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
