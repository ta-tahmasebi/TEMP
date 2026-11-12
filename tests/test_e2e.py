"""End-to-end checks against real compiled C fixtures."""

from pathlib import Path

import pytest

from dynan.core import validate


ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    ("config", "verdict", "code"),
    [
        ("confparse-correct.yaml", "PASS", 0),
        ("confparse-incomplete.yaml", "VULN_REMAINS", 10),
        ("confparse-regression.yaml", "FUNC_REGRESSION", 20),
        ("logparse-correct.yaml", "PASS", 0),
        ("logparse-incomplete.yaml", "VULN_REMAINS", 10),
        ("logparse-regression.yaml", "FUNC_REGRESSION", 20),
    ],
)
def test_required_patch_scenarios(config: str, verdict: str, code: int) -> None:
    """Recognize correct, incomplete, and regressing patches dynamically."""
    events: list[tuple[str, str]] = []
    report, actual = validate(
        ROOT / "configs" / config,
        minimize=False,
        progress=lambda stage, message: events.append((stage, message)),
    )
    assert actual == code
    assert report["verdict"] == verdict
    assert len(report["builds"]) == 4
    assert report["reproducers"]
    assert all(value in {"enabled", "full"} for value in report["hardening"]["patched"].values())
    assert {stage for stage, _ in events} >= {"config", "build", "run", "analysis", "result"}
