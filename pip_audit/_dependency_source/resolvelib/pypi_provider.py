"""
A `resolvelib` provider implementation that resolves against PyPI.

Closely adapted from `resolvelib`'s examples, which are copyrighted by the `resolvelib`
authors under the ISC license.
"""

import os
from email.message import EmailMessage
from email.parser import BytesParser
from io import BytesIO
from operator import attrgetter
from platform import python_version
from tarfile import TarFile
from tempfile import TemporaryDirectory
from typing import BinaryIO, List, Optional, Set, cast
from urllib.parse import urlparse
from zipfile import ZipFile

import html5lib
import requests
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import Version
from resolvelib.providers import AbstractProvider

from pip_audit._state import AuditState
from pip_audit._virtual_env import VirtualEnv

PYTHON_VERSION = Version(python_version())


class Candidate:
    """
    Represents a dependency candidate. A dependency being resolved may have
    multiple candidates, which go through a selection process guided by various
    weights (version, `sdist` vs. `wheel`, etc.)
    """

    def __init__(
        self,
        name: str,
        version: Version,
        url: str,
        extras: Set[str],
        is_wheel: bool = True,
        timeout: Optional[int] = None,
        state: Optional[AuditState] = None,
    ) -> None:
        """
        Create a new `Candidate`.
        """

        self.name = canonicalize_name(name)
        self.version = version
        self.url = url
        self.extras = extras
        self.is_wheel = is_wheel
        self.timeout = timeout
        self.state = state

        self._metadata: Optional[EmailMessage] = None
        self._dependencies: Optional[List[Requirement]] = None

    def __repr__(self):  # pragma: no cover
        """
        A string representation for `Candidate`.
        """
        if not self.extras:
            return f"<{self.name}=={self.version}>"
        return f"<{self.name}[{','.join(self.extras)}]=={self.version}>"

    @property
    def metadata(self) -> EmailMessage:
        """
        Return the package metadata for this candidate.
        """

        if self._metadata is None:
            if self.state is not None:  # pragma: no cover
                self.state.update_state(f"Fetching metadata for {self.name} ({self.version})")

            if self.is_wheel:
                self._metadata = self._get_metadata_for_wheel()
            else:
                self._metadata = self._get_metadata_for_sdist()
        return self._metadata

    def _get_dependencies(self):
        """
        Computes the dependency set for this candidate.
        """
        deps: List[str] = self.metadata.get_all("Requires-Dist", [])
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
    def dependencies(self) -> List[Requirement]:
        """
        Returns the list of `Requirement`s for this candidate.
        """
        if self._dependencies is None:
            self._dependencies = list(self._get_dependencies())
        return self._dependencies

    def _get_metadata_for_wheel(self):
        """
        Extracts the metadata for this candidate, if it's a wheel.
        """
        data = requests.get(self.url, timeout=self.timeout).content

        if self.state is not None:
            self.state.update_state(
                f"Extracting wheel for {self.name} ({self.version})"
            )  # pragma: no cover

        with ZipFile(BytesIO(data)) as z:
            for n in z.namelist():
                if n.endswith(".dist-info/METADATA"):
                    p = BytesParser()
                    # NOTE: MyPy bug? ZipFile.open is treated as IO[bytes], which
                    # should be unified with BinaryIO but isn't.
                    return p.parse(cast(BinaryIO, z.open(n)), headersonly=True)

        # If we didn't find the metadata, return an empty dict
        return EmailMessage()  # pragma: no cover

    def _get_metadata_for_sdist(self):
        """
        Extracts the metadata for this candidate, if it's a source distribution.
        """
        response: requests.Response = requests.get(self.url, timeout=self.timeout)
        response.raise_for_status()
        data = response.content
        metadata = EmailMessage()

        with TemporaryDirectory() as pkg_dir:
            if self.state is not None:
                self.state.update_state(
                    f"Extracting source distribution for {self.name} ({self.version})"
                )  # pragma: no cover

            # Extract archive onto the disk
            with TarFile.open(fileobj=BytesIO(data), mode="r:gz") as t:
                # The directory is the first member in a tarball
                names = t.getnames()
                pkg_name = names[0]
                t.extractall(pkg_dir)

            if self.state is not None:
                self.state.update_state(
                    f"Installing source distribution in isolated environment for {self.name} "
                    f"({self.version})"
                )  # pragma: no cover

            # Put together a full path of where the source distribution is
            pkg_path = os.path.join(pkg_dir, pkg_name)

            with TemporaryDirectory() as ve_dir:
                ve = VirtualEnv(["-e", pkg_path], self.state)
                ve.create(ve_dir)

                if self.state is not None:
                    self.state.update_state(
                        f"Querying installed packages for {self.name} ({self.version})"
                    )  # pragma: no cover

                installed_packages = ve.installed_packages
                for name, version in installed_packages:
                    metadata["Requires-Dist"] = f"{name}=={str(version)}"

        return metadata


def get_project_from_pypi(project, extras, timeout: Optional[int], state: Optional[AuditState]):
    """Return candidates created from the project name and extras."""
    url = "https://pypi.org/simple/{}".format(project)
    response: requests.Response = requests.get(url, timeout=timeout)
    if response.status_code == 404:
        raise PyPINotFoundError(f'Could not find project "{project}" on PyPI')
    response.raise_for_status()
    data = response.content
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
        try:
            if filename.endswith(".whl"):
                (name, version, _, _) = parse_wheel_filename(filename)
                is_wheel = True
            else:
                # If it doesn't look like a wheel, try to parse it as an
                # sdist. This will raise for incorrect looking filenames,
                # which we'll then skip via the exception handler.
                (name, version) = parse_sdist_filename(filename)
                is_wheel = False
        except Exception:
            continue

        # TODO: Handle compatibility tags?

        yield Candidate(
            name, version, url=url, extras=extras, is_wheel=is_wheel, timeout=timeout, state=state
        )


class PyPIProvider(AbstractProvider):
    """
    An implementation of `resolvelib`'s `AbstractProvider` that uses
    the official Python Package Index.
    """

    def __init__(self, timeout: Optional[int] = None, state: Optional[AuditState] = None):
        """
        Create a new `PyPIProvider`.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        `state` is an optional `AuditState` to use for state callbacks.
        """
        self.timeout = timeout
        self.state = state

    def identify(self, requirement_or_candidate):
        """
        See `resolvelib.providers.AbstractProvider.identify`.
        """
        return canonicalize_name(requirement_or_candidate.name)

    def get_preference(self, identifier, resolutions, candidates, information, backtrack_causes):
        """
        See `resolvelib.providers.AbstractProvider.get_preference`.
        """
        return sum(1 for _ in candidates[identifier])

    def find_matches(self, identifier, requirements, incompatibilities):
        """
        See `resolvelib.providers.AbstractProvider.find_matches`.
        """
        if self.state is not None:
            self.state.update_state(f"Resolving {identifier}")  # pragma: no cover

        requirements = list(requirements[identifier])

        bad_versions = {c.version for c in incompatibilities[identifier]}

        # Accumulate extras
        extras: Set[str] = set()
        for r in requirements:
            extras |= r.extras

        # Need to pass the extras to the search, so they
        # are added to the candidate at creation - we
        # treat candidates as immutable once created.
        candidates = (
            candidate
            for candidate in get_project_from_pypi(identifier, extras, self.timeout, self.state)
            if candidate.version not in bad_versions
            and all(candidate.version in r.specifier for r in requirements)
        )
        # We want to prefer more recent versions and prioritize wheels
        return sorted(candidates, key=attrgetter("version", "is_wheel"), reverse=True)

    def is_satisfied_by(self, requirement, candidate):
        """
        See `resolvelib.providers.AbstractProvider.is_satisfied_by`.
        """
        if canonicalize_name(requirement.name) != candidate.name:
            return False
        return candidate.version in requirement.specifier

    def get_dependencies(self, candidate):
        """
        See `resolvelib.providers.AbstractProvider.get_dependencies`.
        """
        return candidate.dependencies


class PyPINotFoundError(Exception):
    """
    An error to signify that the provider could not find the requested project on PyPI.
    """

    pass
