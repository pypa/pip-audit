from pathlib import Path
from subprocess import CalledProcessError

import pretend
import pytest
from packaging.version import Version

from pip_audit._dependency_source.resolvelib import pypi_provider
from pip_audit._dependency_source.resolvelib.pypi_provider import Candidate
from pip_audit._virtual_env import VirtualEnvError


class TestCandidate:
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

        candidate = Candidate(
            "fakepkg",
            Path("fakepath"),
            Version("1.0.0"),
            url="hxxps://fake.url",
            extras=set(),
            is_wheel=False,
            session=session,
            timeout=None,
            state=state,
        )

        with pytest.raises(
            VirtualEnvError, match=r"virtual environment creation failed internally"
        ):
            candidate._get_metadata_for_sdist()

        assert len(virtualenv_obj.create.calls) == 1
        assert state.update_state.calls == [
            pretend.call(
                "Installing source distribution in isolated environment for fakepkg (1.0.0)"
            ),
        ]
