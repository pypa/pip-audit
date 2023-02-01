from email.message import Message
from pathlib import Path
from subprocess import CalledProcessError

import pretend
import pytest
from packaging.version import Version

from pip_audit._dependency_source import RequirementHashes
from pip_audit._dependency_source.interface import InvalidRequirementSpecifier
from pip_audit._dependency_source.resolvelib import pypi_provider
from pip_audit._dependency_source.resolvelib.pypi_provider import ResolvedCandidate
from pip_audit._virtual_env import VirtualEnvError


class TestResolvedCandidate:
    def test_get_metadata_for_sdist_venv_create_fails(self, monkeypatch):
        virtualenv_obj = pretend.stub(
            create=pretend.call_recorder(
                pretend.raiser(CalledProcessError(returncode=1, cmd=["fake"]))
            )
        )
        virtualenv_cls = pretend.call_recorder(lambda args, state: virtualenv_obj)
        monkeypatch.setattr(pypi_provider, "VirtualEnv", virtualenv_cls)

        response = pretend.stub(
            raise_for_status=pretend.call_recorder(lambda: None), content=b"fake sdist content"
        )
        session = pretend.stub(get=pretend.call_recorder(lambda url, timeout: response))

        state = pretend.stub(update_state=pretend.call_recorder(lambda s: None))

        candidate = ResolvedCandidate(
            "fakepkg",
            "fakepkg",
            Path("fakepath"),
            Version("1.0.0"),
            url="hxxps://fake.url",
            extras=set(),
            is_wheel=False,
            reqs=[],
            session=session,
            timeout=None,
            state=state,
            req_hashes=RequirementHashes(),
        )

        with pytest.raises(
            VirtualEnvError, match=r"virtual environment creation failed internally"
        ):
            _ = candidate.metadata

        assert len(virtualenv_obj.create.calls) == 1
        assert state.update_state.calls[1] == pretend.call(
            "Installing source distribution in isolated environment for fakepkg (1.0.0)"
        )

    @pytest.mark.parametrize("invalid", ["pytz (>dev)", "fakedep>=3.*"])
    def test_get_dependencies_invalid_req_specifer(self, invalid, monkeypatch):
        candidate = ResolvedCandidate(
            "fakepkg",
            "fakepkg",
            Path("fakepath"),
            Version("1.0.0"),
            url="hxxps://fake.url",
            extras=set(),
            is_wheel=False,
            reqs=[],
            session=pretend.stub(),
            timeout=None,
            state=pretend.stub(),
            req_hashes=RequirementHashes(),
        )

        metadata = Message()
        metadata["Requires-Dist"] = invalid
        monkeypatch.setattr(candidate, "_metadata", metadata)

        with pytest.raises(InvalidRequirementSpecifier):
            list(candidate._get_dependencies())


def test_get_project_from_index_relative_url():
    data = """
        <a href="../../packages/packages/foo/bar/long-hash/Flask-2.0.1-py3-none-any.whl">
        Flask-2.0.1-py3-none-any.whl</a><br/>
    """
    response = pretend.stub(
        raise_for_status=lambda: None,
        content=data,
        status_code=200,
    )
    session = pretend.stub(get=pretend.call_recorder(lambda u, **kw: response))
    state = pretend.stub()

    candidates = list(
        pypi_provider.get_project_from_index(
            index_url="https://fake-index.example.com/api/pypi/pypi-all/simple/",
            session=session,
            project="Flask",
            reqs=[],
            extras=set(),
            req_hashes=RequirementHashes(),
            timeout=None,
            state=state,
        )
    )

    assert len(candidates) == 1

    candidate = candidates[0]
    assert candidate.name == "flask"
    assert candidate.filename == Path("Flask-2.0.1-py3-none-any.whl")
    assert candidate.version == Version("2.0.1")
    assert candidate.url == (
        "https://fake-index.example.com/api/pypi/pypi-all/packages/packages/foo/bar/"
        "long-hash/Flask-2.0.1-py3-none-any.whl"
    )
