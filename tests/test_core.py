"""Focused tests for the minimal validation core."""

from pathlib import Path

import pytest

from dynan.core import ConfigError, _decide, _sandbox_unavailable, ddmin, execute, load_yaml, parse_error, source_diff


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    """Reject ambiguous configuration files."""
    path = tmp_path / "bad.yaml"
    path.write_text("value: 1\nvalue: 2\n")
    with pytest.raises(ConfigError):
        load_yaml(path)


def test_sanitizer_output_is_classified() -> None:
    """Extract error type and source function from ASan output."""
    run = {
        "stderr": "ERROR: AddressSanitizer: stack-buffer-overflow\n#0 0x123 in copy_value src/tool.c:42\n",
        "exit_code": 1, "signal": None, "timed_out": False,
    }
    finding = parse_error(run)
    assert finding is not None
    assert finding["error_type"] == "stack-buffer-overflow"
    assert finding["function"] == "copy_value"


def test_bubblewrap_namespace_failure_is_recognized() -> None:
    """Allow a controlled fallback only for sandbox setup failures."""
    assert _sandbox_unavailable("bwrap: Creating new namespace failed: Resource temporarily unavailable\n")
    assert not _sandbox_unavailable("compiler: source file not found\n")


def test_execution_retries_when_bubblewrap_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep resource-limited execution working when user namespaces are disabled."""
    calls: list[list[str]] = []

    class Result:
        """Provide the subprocess fields consumed by the executor."""

        def __init__(self, code: int, stdout: bytes, stderr: bytes) -> None:
            self.returncode, self.stdout, self.stderr = code, stdout, stderr

    def fake_run(command: list[str], **_: object) -> Result:
        """Fail Bubblewrap setup once, then emulate a successful direct command."""
        calls.append(command)
        if command[0] == "bwrap":
            return Result(1, b"", b"bwrap: Creating new namespace failed: Resource temporarily unavailable\n")
        return Result(0, b"ok\n", b"")

    monkeypatch.setattr("dynan.core.shutil.which", lambda _: "/usr/bin/bwrap")
    monkeypatch.setattr("dynan.core.subprocess.run", fake_run)
    result = execute(["demo"], tmp_path, sandbox=True)

    assert [command[0] for command in calls] == ["bwrap", "demo"]
    assert result["exit_code"] == 0
    assert result["sandbox_used"] is False
    assert "namespace failed" in result["sandbox_fallback"]


def test_minimizer_preserves_predicate() -> None:
    """Reduce an input without losing its failure marker."""
    result = ddmin(b"prefix-CRASH-suffix", lambda data: b"CRASH" in data)
    assert result == b"CRASH"


def test_diff_reports_changed_function(tmp_path: Path) -> None:
    """Associate a source change with its containing function."""
    base, patched = tmp_path / "base", tmp_path / "patched"
    base.mkdir()
    patched.mkdir()
    (base / "a.c").write_text("int work(void) { return 1; }\n")
    (patched / "a.c").write_text("int work(void) { return 2; }\n")
    diff, functions = source_diff(base, patched)
    assert "return 2" in diff
    assert functions == ["work"]


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ((True, "FIXED", False, True), 30),
        ((False, "VULN_REMAINS", True, True), 10),
        ((False, "FIXED", True, False), 20),
        ((False, "FIXED", False, False), 40),
        ((False, "FIXED", False, True), 0),
    ],
)
def test_exit_code_precedence(arguments: tuple[bool, str, bool, bool], expected: int) -> None:
    """Apply the assignment's required exit-code priority."""
    assert _decide(*arguments)[1] == expected
