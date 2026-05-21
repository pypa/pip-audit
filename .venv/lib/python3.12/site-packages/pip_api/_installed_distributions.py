import json
import re
import os
from typing import Dict, Optional, List

import pip_api
from pip_api._call import call
from pip_api.exceptions import PipError

from pip_api._vendor.packaging.version import parse  # type: ignore


class Distribution:
    def __init__(
        self,
        name: str,
        version: str,
        location: Optional[str] = None,
        editable_project_location: Optional[str] = None,
    ):
        self.name = name
        self.version = parse(version)
        self.location = location
        self.editable_project_location = editable_project_location

        if pip_api.PIP_VERSION >= parse("21.3"):
            self.editable = bool(self.editable_project_location)
        else:
            self.editable = bool(self.location)

    def __repr__(self):
        return "<Distribution(name='{}', version='{}'{}{})>".format(
            self.name,
            self.version,
            ", location='{}'".format(self.location) if self.location else "",
            (
                ", editable_project_location='{}'".format(
                    self.editable_project_location
                )
                if self.editable_project_location
                else ""
            ),
        )


def _old_installed_distributions(local: bool):
    list_args = ["list"]
    if local:
        list_args.append("--local")
    result = call(*list_args)

    # result is of the form:
    # <package_name> (<version>)
    #
    # or, if editable
    # <package_name> (<version>, <location>)
    #
    # or, could be a warning line

    ret = {}

    pattern = re.compile(r"(.*) \((.*)\)")

    for line in result.strip().split("\n"):
        match = re.match(pattern, line)

        if match:
            name, paren = match.groups()
            version, location = (paren.split(", ") + [None])[:2]

            ret[name] = Distribution(name, version, location)
        else:
            # This is a warning line or some other output
            pass

    return ret


def _new_installed_distributions(local: bool, paths: List[os.PathLike]):
    list_args = ["list", "-v", "--format=json"]
    if local:
        list_args.append("--local")
    for path in paths:
        list_args.extend(["--path", str(path)])
    result = call(*list_args)

    ret = {}

    # The returned JSON is an array of objects, each of which looks like this:
    # { "name": "some-package", "version": "0.0.1", "location": "/path/", ... }
    # The location key was introduced with pip 10.0.0b1, so we don't assume its
    # presence. The editable_project_location key was introduced with pip 21.3,
    # so we also don't assume its presence.
    for raw_dist in json.loads(result):
        dist = Distribution(
            raw_dist["name"],
            raw_dist["version"],
            raw_dist.get("location"),
            raw_dist.get("editable_project_location"),
        )
        ret[dist.name] = dist

    return ret


def installed_distributions(
    local: bool = False, paths: List[os.PathLike] = []
) -> Dict[str, Distribution]:
    # Check whether our version of pip supports the `--path` parameter
    if pip_api.PIP_VERSION < parse("19.2") and paths:
        raise PipError(
            f"pip {pip_api.PIP_VERSION} does not support the `paths` argument"
        )
    if pip_api.PIP_VERSION < parse("9.0.0"):
        return _old_installed_distributions(local)
    return _new_installed_distributions(local, paths)
