"""
A (wheel-only) `resolvelib` provider implementation that resolves against PyPI.

Closely adapted from `resolvelib`'s examples, which are copyrighted by the `resolvelib`
authors under the ISC license.
"""

from email.message import EmailMessage
from email.parser import BytesParser
from io import BytesIO
from operator import attrgetter
from platform import python_version
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
    def __init__(self, name, version, url=None, extras=None):
        self.name = canonicalize_name(name)
        self.version = version
        self.url = url
        self.extras = extras

        self._metadata = None
        self._dependencies = None

    def __repr__(self):  # pragma: no cover
        if not self.extras:
            return f"<{self.name}=={self.version}>"
        return f"<{self.name}[{','.join(self.extras)}]=={self.version}>"

    @property
    def metadata(self):
        if self._metadata is None:
            self._metadata = get_metadata_for_wheel(self.url)
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
        # We only handle wheels
        if not filename.endswith(".whl"):
            continue

        # TODO: Handle compatibility tags?

        # Very primitive wheel filename parsing
        name, version = filename[:-4].split("-")[:2]
        try:
            version = Version(version)
        except InvalidVersion:
            # Ignore files with invalid versions
            continue

        yield Candidate(name, version, url=url, extras=extras)


def get_metadata_for_wheel(url):
    data = requests.get(url).content
    with ZipFile(BytesIO(data)) as z:
        for n in z.namelist():
            if n.endswith(".dist-info/METADATA"):
                p = BytesParser()
                return p.parse(z.open(n), headersonly=True)

    # If we didn't find the metadata, return an empty dict
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
        return sorted(candidates, key=attrgetter("version"), reverse=True)

    def is_satisfied_by(self, requirement, candidate):
        if canonicalize_name(requirement.name) != candidate.name:
            return False
        return candidate.version in requirement.specifier

    def get_dependencies(self, candidate):
        return candidate.dependencies
