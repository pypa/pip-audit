import os
from pathlib import Path
from typing import List

import pretend  # type: ignore
import pytest
from packaging.requirements import Requirement
from packaging.version import Version
from pip_api import _parse_requirements

from pip_audit._dependency_source import (
    DependencyFixError,
    DependencyResolver,
    DependencyResolverError,
    DependencySourceError,
    ResolveLibResolver,
    requirement,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency


@pytest.mark.online
def test_requirement_source(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    specs = list(source.collect())
    assert ResolvedDependency("flask", Version("2.0.1")) in specs


@pytest.mark.online
def test_requirement_source_multiple_files(monkeypatch):
    file1 = "requirements1.txt"
    file2 = "requirements2.txt"
    file3 = "requirements3.txt"

    source = requirement.RequirementSource(
        [Path(file1), Path(file2), Path(file3)],
        ResolveLibResolver(),
    )

    def read_file_mock(f):
        filename = f.name
        if filename == file1:
            return ["flask==2.0.1"]
        elif filename == file2:
            return ["requests==2.8.1"]
        else:
            assert filename == file3
            return ["pip-api==0.0.22\n", "packaging==21.0"]

    monkeypatch.setattr(_parse_requirements, "_read_file", read_file_mock)

    specs = list(source.collect())
    assert ResolvedDependency("flask", Version("2.0.1")) in specs
    assert ResolvedDependency("requests", Version("2.8.1")) in specs
    assert ResolvedDependency("pip-api", Version("0.0.22")) in specs
    assert ResolvedDependency("packaging", Version("21.0")) in specs


def test_requirement_source_parse_error(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    # Duplicate dependencies aren't allowed in a requirements file so we should expect the parser to
    # raise here
    monkeypatch.setattr(
        _parse_requirements, "_read_file", lambda _: ["flask==2.0.1\n", "flask==2.0.0"]
    )

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_resolver_error(monkeypatch):
    # Pass the requirement source a resolver that automatically raises errors
    class MockResolver(DependencyResolver):
        def resolve(self, req: Requirement) -> List[Dependency]:
            raise DependencyResolverError

    source = requirement.RequirementSource([Path("requirements.txt")], MockResolver())

    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_requirement_source_duplicate_dependencies(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements1.txt"), Path("requirements2.txt")], ResolveLibResolver()
    )

    # Return the same requirements for both files
    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    specs = list(source.collect())

    # If the dependency list has duplicates, then converting to a set will reduce the length of the
    # collection
    assert len(specs) == len(set(specs))


def _check_fixes(
    input_reqs: List[str],
    expected_reqs: List[str],
    req_paths: List[Path],
    fixes: List[ResolvedFixVersion],
) -> None:
    # Populate the requirements files
    for (input_req, req_path) in zip(input_reqs, req_paths):
        with open(req_path, "w") as f:
            print(input_req, file=f)

    source = requirement.RequirementSource(req_paths, ResolveLibResolver())
    for fix in fixes:
        source.fix(fix)

    # Check the requirements files
    for (expected_req, req_path) in zip(expected_reqs, req_paths):
        with open(req_path, "r") as f:
            # NOTE: We don't make any guarantees about non-semantic whitespace
            # preservation, hence the strip.
            assert expected_req == f.read().strip()


def test_requirement_source_fix(req_file):
    _check_fixes(
        ["flask==0.5"],
        ["flask==1.0"],
        [req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_multiple_files(req_file):
    _check_fixes(
        ["flask==0.5", "requests==1.0\nflask==0.5"],
        ["flask==1.0", "requests==1.0\nflask==1.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_specifier_match(req_file):
    _check_fixes(
        ["flask<1.0", "requests==1.0\nflask<=0.6"],
        ["flask==1.0", "requests==1.0\nflask==1.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_specifier_no_match(req_file):
    # In order to make a fix, the specifier must match the current version and NOT the resolved fix
    # version. If the specifier matches both, we don't apply the fix since installing from the given
    # requirements file would already install the fixed version.
    _check_fixes(
        ["flask>=0.5", "requests==1.0\nflask<2.0"],
        ["flask>=0.5", "requests==1.0\nflask<2.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_marker(req_file):
    # `pip-api` automatically filters out requirements with markers that don't apply to the current
    # environment
    _check_fixes(
        [
            'flask<1.0; python_version > "2.7"',
            'requests==1.0\nflask<=0.6; python_version <= "2.7"',
        ],
        [
            'flask==1.0; python_version > "2.7"',
            "requests==1.0",
        ],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_comments(req_file):
    # `pip-api` automatically filters out comments
    _check_fixes(
        [
            "# comment here\nflask==0.5",
            "requests==1.0\n# another comment\nflask==0.5",
        ],
        ["flask==1.0", "requests==1.0\nflask==1.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_parse_failure(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(requirement, "logger", logger)

    # If `pip-api` encounters multiple of the same package in the requirements file, it will throw a
    # parsing error
    input_reqs = ["flask==0.5", "flask==0.5\nrequests==1.0\nflask==0.3"]
    req_paths = [req_file(), req_file()]

    # Populate the requirements files
    for (input_req, req_path) in zip(input_reqs, req_paths):
        with open(req_path, "w") as f:
            f.write(input_req)

    source = requirement.RequirementSource(req_paths, ResolveLibResolver())
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        )
    assert len(logger.warning.calls) == 1

    # Check that the requirements files remain unchanged
    # If we encounter a failure while applying a fix, the fix should be rolled back from all files
    for (expected_req, req_path) in zip(input_reqs, req_paths):
        with open(req_path, "r") as f:
            assert expected_req == f.read().strip()


def test_requirement_source_fix_rollback_failure(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(requirement, "logger", logger)

    # If `pip-api` encounters multiple of the same package in the requirements file, it will throw a
    # parsing error
    input_reqs = ["flask==0.5", "flask==0.5\nrequests==1.0\nflask==0.3"]
    req_paths = [req_file(), req_file()]

    # Populate the requirements files
    for (input_req, req_path) in zip(input_reqs, req_paths):
        with open(req_path, "w") as f:
            f.write(input_req)

    # Simulate an error being raised during file recovery
    def mock_replace(*_args, **_kwargs):
        raise OSError

    monkeypatch.setattr(os, "replace", mock_replace)

    source = requirement.RequirementSource(req_paths, ResolveLibResolver())
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        )
    # One for the parsing error and one for each file that we failed to rollback
    assert len(logger.warning.calls) == 3

    # We couldn't move the original requirements files back so we should expect a partially applied
    # fix. The first requirements file contains the fix, while the second one doesn't since we were
    # in the process of writing it out and didn't flush.
    expected_reqs = ["flask==1.0", "flask==0.5\nrequests==1.0\nflask==0.3"]
    for (expected_req, req_path) in zip(expected_reqs, req_paths):
        with open(req_path, "r") as f:
            assert expected_req == f.read().strip()


def test_requirement_source_require_hashes(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements.txt")], ResolveLibResolver(), require_hashes=True
    )

    monkeypatch.setattr(
        _parse_requirements, "_read_file", lambda _: ["flask==2.0.1 --hash=sha256:flask-hash"]
    )

    # The hash should be populated in the resolved dependency. Additionally, the source should not
    # calculate and resolve transitive dependencies since requirements files with hashes must
    # explicitly list all dependencies.
    specs = list(source.collect())
    assert specs == [
        ResolvedDependency("flask", Version("2.0.1"), hashes={"sha256": ["flask-hash"]})
    ]


def test_requirement_source_require_hashes_missing(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements.txt")], ResolveLibResolver(), require_hashes=True
    )

    monkeypatch.setattr(
        _parse_requirements,
        "_read_file",
        lambda _: ["flask==2.0.1"],
    )

    # All requirements must be hashed when collecting with `require-hashes`
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_inferred(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    monkeypatch.setattr(
        _parse_requirements,
        "_read_file",
        lambda _: ["flask==2.0.1 --hash=sha256:flask-hash\nrequests==1.0"],
    )

    # If at least one requirement is hashed, this infers `require-hashes`
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_unpinned(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements.txt")], ResolveLibResolver(), require_hashes=True
    )

    monkeypatch.setattr(
        _parse_requirements,
        "_read_file",
        lambda _: [
            "flask==2.0.1 --hash=sha256:flask-hash\nrequests>=1.0 --hash=sha256:requests-hash"
        ],
    )

    # When hashed dependencies are provided, all dependencies must be explicitly pinned to an exact
    # version number
    with pytest.raises(DependencySourceError):
        list(source.collect())
