import os

from pip_api._vendor.packaging.version import Version  # type: ignore

import pip_api
from pip_api._call import call
from pip_api.exceptions import Incompatible, InvalidArguments

incompatible = pip_api.PIP_VERSION < Version("8.0.0")


def hash(filename: os.PathLike, algorithm: str = "sha256") -> str:
    """
    Hash the given filename. Unavailable in `pip<8.0.0`
    """
    if incompatible:
        raise Incompatible

    if algorithm not in ["sha256", "sha384", "sha512"]:
        raise InvalidArguments("Algorithm {} not supported".format(algorithm))

    result = call("hash", "--algorithm", algorithm, filename)

    # result is of the form:
    # <filename>:\n--hash=<algorithm>:<hash>\n
    return result.strip().split(":")[-1]
