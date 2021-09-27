"""
A `resolvelib` provider implementation that resolves against PyPI.

Closely adapted from `resolvelib`'s examples, which are copyrighted by the `resolvelib`
authors under the ISC license.
"""

from email.message import EmailMessage
from email.parser import BytesParser
from io import BytesIO
from operator import attrgetter
from platform import python_version
from tarfile import TarFile
from typing import Tuple
from urllib.parse import urlparse
from zipfile import ZipFile

import html5lib
import requests
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from resolvelib.providers import AbstractProvider

PYTHON_VERSION = Version(python_version())


class Candidate:
    def __init__(self, name, version, url=None, extras=None, is_wheel=True):
        self.name = canonicalize_name(name)
        self.version = version
        self.url = url
        self.extras = extras
        self.is_wheel = is_wheel

        self._metadata = None
        self._dependencies = None

    def __repr__(self):  # pragma: no cover
        if not self.extras:
            return f"<{self.name}=={self.version}>"
        return f"<{self.name}[{','.join(self.extras)}]=={self.version}>"

    @property
    def metadata(self):
        if self._metadata is None:
            if self.is_wheel:
                self._metadata = get_metadata_for_wheel(self.url)
            else:
                self._metadata = get_metadata_for_sdist(self.url)
        return self._metadata

    def _get_dependencies(self):
        deps = self.metadata.get_all("Requires-Dist", [])
        extras = self.extras if self.extras else [""]

        for d in deps:
            r = Requirement(d)
            if r.marker is None:
                yield r
            else:
                for e in extras:
                    if r.marker.evaluate({"extra": e}):
                        yield r  # pragma: no cover

    @property
    def dependencies(self):
        if self._dependencies is None:
            self._dependencies = list(self._get_dependencies())
        return self._dependencies


def get_project_from_pypi(project, extras):
    """Return candidates created from the project name and extras."""
    url = "https://pypi.org/simple/{}".format(project)
    data = requests.get(url).content
    doc = html5lib.parse(data, namespaceHTMLElements=False)
    for i in doc.findall(".//a"):
        url = i.attrib["href"]
        py_req = i.attrib.get("data-requires-python")
        # Skip items that need a different Python version
        if py_req:
            spec = SpecifierSet(py_req)
            if PYTHON_VERSION not in spec:
                continue

        path = urlparse(url).path
        filename = path.rpartition("/")[-1]
        # Handle wheels and source distributions
        if not filename.endswith(".whl") and not filename.endswith(".tar.gz"):
            continue

        is_wheel: bool = filename.endswith(".whl")

        # TODO: Handle compatibility tags?

        # Very primitive wheel filename parsing
        try:
            name, version = parse_filename(filename, is_wheel)
        except InvalidVersion:
            # Ignore files with invalid versions
            continue

        yield Candidate(name, version, url=url, extras=extras, is_wheel=is_wheel)


def parse_filename(filename: str, is_wheel: bool) -> Tuple[str, Version]:
    original_filename = filename
    # Strip out the file extension
    if is_wheel:
        filename = filename[:-4]
    else:
        filename = filename[:-7]
    # Go through each segment and try to create a version with it. If it fails, we're still in the
    # package name, so we should keep appending the segments to the name.
    name = str()
    version = None
    for s in filename.split("-"):
        try:
            version = Version(s)
            break
        except InvalidVersion:
            if name:
                name += "-"
            name += s
    if version is None:
        raise InvalidVersion(f"Unable to parse filename {original_filename}")
    return name, version


def get_metadata_for_wheel(url):
    data = requests.get(url).content
    with ZipFile(BytesIO(data)) as z:
        for n in z.namelist():
            if n.endswith(".dist-info/METADATA"):
                p = BytesParser()
                return p.parse(z.open(n), headersonly=True)

    # If we didn't find the metadata, return an empty dict
    return EmailMessage()  # pragma: no cover


def get_metadata_for_sdist(url):
    data = requests.get(url).content
    with TarFile.open(fileobj=BytesIO(data), mode="r:gz") as t:
        for n in t.getnames():
            if n.endswith("PKG-INFO"):
                p = BytesParser()
                return p.parse(t.extractfile(n), headersonly=True)

    return EmailMessage()  # pragma: no cover


class PyPIProvider(AbstractProvider):
    def identify(self, requirement_or_candidate):
        return canonicalize_name(requirement_or_candidate.name)

    def get_preference(self, identifier, resolutions, candidates, information):
        return sum(1 for _ in candidates[identifier])

    def find_matches(self, identifier, requirements, incompatibilities):
        requirements = list(requirements[identifier])
        assert not any(r.extras for r in requirements), "extras not supported in this example"

        bad_versions = {c.version for c in incompatibilities[identifier]}

        # Need to pass the extras to the search, so they
        # are added to the candidate at creation - we
        # treat candidates as immutable once created.
        candidates = (
            candidate
            for candidate in get_project_from_pypi(identifier, set())
            if candidate.version not in bad_versions
            and all(candidate.version in r.specifier for r in requirements)
        )
        # We want to prefer more recent versions and prioritize wheels
        return sorted(candidates, key=attrgetter("version", "is_wheel"), reverse=True)

    def is_satisfied_by(self, requirement, candidate):
        if canonicalize_name(requirement.name) != candidate.name:
            return False
        return candidate.version in requirement.specifier

    def get_dependencies(self, candidate):
        return candidate.dependencies
