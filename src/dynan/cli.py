"""Small command-line interface for the validator."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .core import ConfigError, load_yaml, require, validate


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
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return doctor(args.config)
    report, code = validate(args.config, minimize=not args.no_minimize)
    print(f"{report['verdict']} ({code})")
    print(f"security: {report.get('security_status', 'unknown')}")
    print(f"regressions: {', '.join(report.get('functional_regressions', [])) or 'none'}")
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2))
        print(f"JSON: {args.json_out}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
