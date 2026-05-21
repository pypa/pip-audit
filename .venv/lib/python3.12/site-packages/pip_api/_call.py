import os
import subprocess
import sys


def call(*args, cwd=None):
    python_location = os.environ.get("PIPAPI_PYTHON_LOCATION", sys.executable)
    env = {**os.environ, **{"PIP_YES": "true", "PIP_DISABLE_PIP_VERSION_CHECK": "true"}}
    result = subprocess.check_output(
        [python_location, "-m", "pip"] + list(args), cwd=cwd, env=env
    )
    return result.decode()
