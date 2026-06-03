import sys

import pytest

from pip_audit import _subprocess
from pip_audit._state import AuditState
from pip_audit._subprocess import CalledProcessError, run


def test_run_raises():
    with pytest.raises(CalledProcessError):
        run(["false"])


class _RecordingState(AuditState):
    def __init__(self):
        super().__init__()
        self.logs = []

    def update_state(self, message, logs=None):
        self.logs.append(logs)


class _FakeStream:
    """A byte stream that hands back pre-split chunks one `read()` at a time."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    def read(self, *args):
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class _FakeProcess:
    """A minimal `Popen` stand-in driven by scripted stdout chunks."""

    def __init__(self, stdout_chunks):
        # One extra poll cycle after the last chunk so EOF is observed.
        self.stdout = _FakeStream(stdout_chunks + [b""])
        self.stderr = _FakeStream([])
        self.returncode = 0
        self._polls = len(stdout_chunks)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def poll(self):
        # Stay alive while there are still scripted chunks to read, so the loop
        # processes each chunk in its own iteration (matching unbuffered reads).
        if self._polls > 0:
            self._polls -= 1
            return None
        return 0


def test_run_decodes_multibyte_utf8_split_across_reads(monkeypatch):
    # U+20AC (Euro sign) is 0xE2 0x82 0xAC in UTF-8. Split it across two reads
    # so each individual read carries an incomplete codepoint. This is the
    # exact unsound condition from https://github.com/pypa/pip-audit/issues/574.
    chunks = [b"\xe2\x82", b"\xac"]

    def fake_popen(*args, **kwargs):
        return _FakeProcess(chunks)

    monkeypatch.setattr(_subprocess, "Popen", fake_popen)

    state = _RecordingState()
    out = run(["pip"], log_stdout=True, state=state)

    # The final result must be the exact codepoint, never a replacement char.
    assert out == "€"
    assert "�" not in out

    # No live progress update may expose a replacement character: the first
    # read held an incomplete sequence, which the incremental decoder must
    # buffer rather than surface as U+FFFD.
    for logs in state.logs:
        if logs is not None:
            assert "�" not in logs
    assert any(logs == "€" for logs in state.logs)


def test_run_decodes_multibyte_utf8_end_to_end():
    # End-to-end smoke test through a real subprocess: emit a multi-byte
    # codepoint and confirm `run` returns it intact.
    program = "import sys; sys.stdout.buffer.write('€'.encode('utf-8'))\n"
    out = run([sys.executable, "-c", program])
    assert out == "€"
    assert "�" not in out
