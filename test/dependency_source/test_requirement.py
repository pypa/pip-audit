import os
from pathlib import Path
from typing import List, Optional

import pip_requirements_parser
import pretend  # type: ignore
import pytest
from packaging.requirements import Requirement
from packaging.version import Version

from pip_audit._dependency_source import (
    DependencyFixError,
    DependencyResolver,
    DependencyResolverError,
    DependencySourceError,
    ResolveLibResolver,
    requirement,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency, SkippedDependency


@pytest.mark.online
def test_requirement_source(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    monkeypatch.setattr(pip_requirements_parser, "get_file_content", lambda _: "flask==2.0.1")

    specs = list(source.collect())
    assert ResolvedDependency("flask", Version("2.0.1")) in specs


@pytest.mark.online
def test_requirement_source_multiple_files(monkeypatch):
    file1 = Path("requirements1.txt")
    file2 = Path("requirements2.txt")
    file3 = Path("requirements3.txt")

    source = requirement.RequirementSource(
        [file1, file2, file3],
        ResolveLibResolver(),
    )

    def get_file_content_mock(filename):
        if filename == file1:
            return "flask==2.0.1"
        elif filename == file2:
            return "requests==2.8.1"
        else:
            assert filename == file3
            return "pip-api==0.0.22\npackaging==21.0"

    monkeypatch.setattr(pip_requirements_parser, "get_file_content", get_file_content_mock)

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
        pip_requirements_parser, "get_file_content", lambda _: "flask==2.0.1\nflask==2.0.0"
    )

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_resolver_error(monkeypatch):
    # Pass the requirement source a resolver that automatically raises errors
    class MockResolver(DependencyResolver):
        def resolve(self, req: Requirement) -> List[Dependency]:
            raise DependencyResolverError

    source = requirement.RequirementSource([Path("requirements.txt")], MockResolver())

    monkeypatch.setattr(pip_requirements_parser, "get_file_content", lambda _: "flask==2.0.1")

    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_requirement_source_duplicate_dependencies(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements1.txt"), Path("requirements2.txt")], ResolveLibResolver()
    )

    # Return the same requirements for both files
    monkeypatch.setattr(pip_requirements_parser, "get_file_content", lambda _: "flask==2.0.1")

    specs = list(source.collect())

    # If the dependency list has duplicates, then converting to a set will reduce the length of the
    # collection
    assert len(specs) == len(set(specs))


@pytest.mark.online
def test_requirement_source_invalid_lines(monkeypatch):
    source = requirement.RequirementSource([Path("requirements1.txt")], ResolveLibResolver())

    monkeypatch.setattr(pip_requirements_parser, "get_file_content", lambda _: "a#b#c")

    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_requirement_source_editable_with_egg_fragment(monkeypatch):
    source = requirement.RequirementSource([Path("requirements1.txt")], ResolveLibResolver())

    monkeypatch.setattr(
        pip_requirements_parser, "get_file_content", lambda _: "-e file:flask.py#egg=flask==2.0.1"
    )

    specs = list(source.collect())
    assert ResolvedDependency("flask", Version("2.0.1")) in specs


def test_requirement_source_editable_without_egg_fragment(monkeypatch):
    source = requirement.RequirementSource([Path("requirements1.txt")], ResolveLibResolver())

    monkeypatch.setattr(pip_requirements_parser, "get_file_content", lambda _: "-e file:flask.py")

    specs = list(source.collect())
    assert (
        SkippedDependency(
            name="-e file:flask.py",
            skip_reason="could not deduce package/specifier pair from requirement, please specify "
            "them with #egg=your_package_name==your_package_version",
        )
        in specs
    )


def test_requirement_source_non_editable_without_egg_fragment(monkeypatch):
    source = requirement.RequirementSource([Path("requirements1.txt")], ResolveLibResolver())

    monkeypatch.setattr(
        pip_requirements_parser,
        "get_file_content",
        lambda _: "git+https://github.com/unbit/uwsgi.git@1bb9ad77c6d2d310c2d6d1d9ad62de61f725b824",
    )

    specs = list(source.collect())
    assert (
        SkippedDependency(
            name="git+https://github.com/unbit/uwsgi.git@1bb9ad77c6d2d310c2d6d1d9ad62de61f725b824",
            skip_reason="could not deduce package/specifier pair from requirement, please specify "
            "them with #egg=your_package_name==your_package_version",
        )
        in specs
    )


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
        ["flask==0.5", "requests==2.0\nflask==0.5"],
        ["flask==1.0", "requests==2.0\nflask==1.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_specifier_match(req_file):
    _check_fixes(
        ["flask<1.0", "requests==2.0\nflask<=0.6"],
        ["flask==1.0", "requests==2.0\nflask==1.0"],
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
        ["flask>=0.5", "requests==2.0\nflask<2.0"],
        ["flask>=0.5", "requests==2.0\nflask<2.0"],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_preserve_marker(req_file):
    # `pip-requirements-parser` preserves requirements with markers that don't apply to the current
    # environment.
    _check_fixes(
        [
            'flask<1.0; python_version > "2.7"',
            'requests==2.0\nflask<=0.6; python_version <= "2.7"',
        ],
        [
            'flask==1.0; python_version > "2.7"',
            'requests==2.0\nflask==1.0; python_version <= "2.7"',
        ],
        [req_file(), req_file()],
        [
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        ],
    )


def test_requirement_source_fix_comments(req_file):
    _check_fixes(
        [
            "# comment here\nflask==0.5",
            "requests==2.0\n# another comment\nflask==0.5",
        ],
        ["# comment here\nflask==1.0", "requests==2.0\n# another comment\nflask==1.0"],
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

    # If we encounter multiple of the same package in the requirements file, we will throw a parsing
    # error
    input_reqs = ["flask==0.5", "flask==0.5\nrequests==2.0\nflask==0.3"]
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

    # If we encounter multiple of the same package in the requirements file, we will throw a parsing
    # error
    input_reqs = ["flask==0.5", "flask==0.5\nrequests==2.0\nflask==0.3"]
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
    expected_reqs = ["flask==1.0", "flask==0.5\nrequests==2.0\nflask==0.3"]
    for (expected_req, req_path) in zip(expected_reqs, req_paths):
        with open(req_path, "r") as f:
            assert expected_req == f.read().strip()


def test_requirement_source_require_hashes(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements.txt")], ResolveLibResolver(), require_hashes=True
    )

    monkeypatch.setattr(
        pip_requirements_parser,
        "get_file_content",
        lambda _: "flask==2.0.1 --hash=sha256:flask-hash",
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
        pip_requirements_parser,
        "get_file_content",
        lambda _: "flask==2.0.1",
    )

    # All requirements must be hashed when collecting with `require-hashes`
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_inferred(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    monkeypatch.setattr(
        pip_requirements_parser,
        "get_file_content",
        lambda _: "flask==2.0.1 --hash=sha256:flask-hash\nrequests==2.0",
    )

    # If at least one requirement is hashed, this infers `require-hashes`
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_unpinned(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements.txt")], ResolveLibResolver(), require_hashes=True
    )

    monkeypatch.setattr(
        pip_requirements_parser,
        "get_file_content",
        lambda _: "flask==2.0.1 --hash=sha256:flask-hash\nrequests>=1.0 "
        "--hash=sha256:requests-hash",
    )

    # When hashed dependencies are provided, all dependencies must be explicitly pinned to an exact
    # version number
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_no_deps(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements.txt")], ResolveLibResolver(), no_deps=True
    )

    monkeypatch.setattr(
        pip_requirements_parser,
        "get_file_content",
        lambda _: "flask==2.0.1",
    )

    specs = list(source.collect())
    assert specs == [ResolvedDependency("flask", Version("2.0.1"), hashes={})]


def test_requirement_source_no_deps_unpinned(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements.txt")], ResolveLibResolver(), no_deps=True
    )

    monkeypatch.setattr(
        pip_requirements_parser,
        "get_file_content",
        lambda _: "flask\nrequests>=1.0",
    )

    # When dependency resolution is disabled, all requirements must be pinned.
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_dep_caching(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements.txt")], ResolveLibResolver(), no_deps=True
    )

    monkeypatch.setattr(
        pip_requirements_parser,
        "get_file_content",
        lambda _: "flask==2.0.1",
    )

    specs = list(source.collect())

    class MockResolver(DependencyResolver):
        def resolve(self, req: Requirement) -> List[Dependency]:
            raise DependencyResolverError

    # Now run collect again and check that dependency resolution doesn't get repeated
    source._resolver = MockResolver()

    cached_specs = list(source.collect())
    assert specs == cached_specs


def test_requirement_source_fix_explicit_subdep(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(requirement, "logger", logger)

    # We're going to simulate the situation where a subdependency of `flask` has a vulnerability.
    # In this case, we're choosing `jinja2`.
    flask_deps = ResolveLibResolver().resolve(Requirement("flask==2.0.1"))

    # Firstly, get a handle on the `jinja2` dependency. The version cannot be hardcoded since it
    # depends what versions are available on PyPI when dependency resolution runs.
    jinja_dep: Optional[ResolvedDependency] = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # Check that the `jinja2` dependency is explicitly added to the requirements file with an
    # associated comment.
    _check_fixes(
        ["flask==2.0.1"],
        ["flask==2.0.1\n    # pip-audit: subdependency fixed via flask==2.0.1\njinja2==4.0.0"],
        [req_file()],
        [
            ResolvedFixVersion(
                dep=jinja_dep,
                version=Version("4.0.0"),
            )
        ],
    )

    # When explicitly listing a fixed subdependency, we issue a warning.
    assert len(logger.warning.calls) == 1


def test_requirement_source_fix_explicit_subdep_multiple_reqs(monkeypatch, req_file):
    # Recreate the vulnerable subdependency case.
    flask_deps = ResolveLibResolver().resolve(Requirement("flask==2.0.1"))
    jinja_dep: Optional[ResolvedDependency] = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # This time our requirements file also lists `django-jinja`, another requirement that depends on
    # `jinja2`. We're expecting that the comment generated above the `jinja2` requirement that gets
    # added into the file will list both `flask` and `django-jinja` as sources.
    _check_fixes(
        ["flask==2.0.1\ndjango-jinja==1.0"],
        [
            "flask==2.0.1\ndjango-jinja==1.0\n"
            "    # pip-audit: subdependency fixed via django-jinja==1.0,flask==2.0.1\n"
            "jinja2==4.0.0"
        ],
        [req_file()],
        [
            ResolvedFixVersion(
                dep=jinja_dep,
                version=Version("4.0.0"),
            )
        ],
    )


def test_requirement_source_fix_explicit_subdep_resolver_error(req_file):
    # Pass the requirement source a resolver that automatically raises errors
    class MockResolver(DependencyResolver):
        def resolve(self, req: Requirement) -> List[Dependency]:
            raise DependencyResolverError

    req_file_name = req_file()
    with open(req_file_name, "w") as f:
        f.write("flask==2.0.1")

    # Recreate the vulnerable subdependency case.
    flask_deps = ResolveLibResolver().resolve(Requirement("flask==2.0.1"))
    jinja_dep: Optional[ResolvedDependency] = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # When we try to fix a vulnerable subdependency, we need to resolve dependencies if that
    # information isn't already cached.
    #
    # Test the case where we hit a resolver error.
    source = requirement.RequirementSource([req_file_name], MockResolver())
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=jinja_dep,
                version=Version("4.0.0"),
            )
        )


def test_requirement_source_fix_explicit_subdep_comment_retension(req_file):
    # This test is regression testing a weakness in the previous fix implementation.
    #
    # When fixing a subdependency and explicitly adding it to the requirements file, we add a
    # comment above the line to explain its presence since it's unusual to explicitly pin a
    # subdependency like this.
    #
    # When we "fix" dependencies, we parse the requirements file and write it back out with the
    # relevant line amended or added. When we used `pip-api` for requirements parsing, our fix logic
    # had the unfortunate side effect of stripping comments from the file. Importantly, when we
    # applied subdependency fixes, the automated comments used to be removed by any subsequent
    # fixes.
    #
    # Since we've switching `pip-requirements-parser`, we should no longer have this issue.

    # Recreate the vulnerable subdependency case.
    flask_deps = ResolveLibResolver().resolve(Requirement("flask==2.0.1"))
    jinja_dep: Optional[ResolvedDependency] = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # Now place a fix for the top-level `flask` requirement after the `jinja2` subdependency fix.
    #
    # When applying the `flask` fix, `pip-audit` reparses the requirements file, and writes it back
    # out with the fixed `flask` version with the comments preserved.
    #
    # One quirk is that comment indentation isn't preserved (the automated comment was originally
    # indented with 4 spaces).
    _check_fixes(
        ["flask==2.0.1"],
        ["flask==3.0.0\n# pip-audit: subdependency fixed via flask==2.0.1\njinja2==4.0.0"],
        [req_file()],
        [
            ResolvedFixVersion(
                dep=jinja_dep,
                version=Version("4.0.0"),
            ),
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("2.0.1")),
                version=Version("3.0.0"),
            ),
        ],
    )


def test_requirement_source_fix_invalid_lines(req_file):
    req_file_name = req_file()
    with open(req_file_name, "w") as f:
        f.write("a#b#c\nflask==0.5")

    source = requirement.RequirementSource([req_file_name], ResolveLibResolver())
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        )
