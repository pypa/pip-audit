from __future__ import annotations

import os
from email.message import EmailMessage
from pathlib import Path

import pretend  # type: ignore
import pytest
from packaging.version import Version

from pip_audit._dependency_source import (
    PYPI_URL,
    DependencyFixError,
    DependencySourceError,
    requirement,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState
from pip_audit._virtual_env import VirtualEnvError


def get_metadata_mock():
    return EmailMessage()


def _init_requirement(
    files: list[tuple[Path, str]],
    **kwargs,
) -> requirement.RequirementSource:
    paths: list[Path] = []
    for path, contents in files:
        with open(path, mode="w") as f:
            f.write(contents)
        paths.append(path)
    return requirement.RequirementSource(paths, **kwargs)


@pytest.mark.online
def test_requirement_source(req_file):
    source = _init_requirement([(req_file(), "flask==2.0.1")])
    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs


@pytest.mark.online
def test_requirement_source_multiple_files(req_file):
    source = _init_requirement(
        [
            (req_file(), "flask==2.0.1"),
            (req_file(), "requests==2.8.1"),
            (req_file(), "pip-api==0.0.22\npackaging==21.0"),
        ]
    )
    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs
    assert ResolvedDependency("requests", Version("2.8.1")) in specs
    assert ResolvedDependency("pip-api", Version("0.0.22")) in specs
    assert ResolvedDependency("packaging", Version("21.0")) in specs


def test_requirement_source_impossible_resolution(req_file):
    source = _init_requirement([(req_file(), "flask==2.0.1\nflask==2.0.0")])

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_virtualenv_error(monkeypatch, req_file):
    class MockVirtualEnv:
        def __init__(
            self, install_args: list[str], index_urls: list[str], state: AuditState
        ) -> None:
            pass

        def create(self, dir: Path) -> None:
            raise VirtualEnvError

    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1",
            )
        ]
    )
    monkeypatch.setattr(requirement, "VirtualEnv", MockVirtualEnv)

    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_requirement_source_duplicate_dependencies(req_file):
    # Return the same requirements for both files
    source = _init_requirement([(req_file(), "flask==2.0.1"), (req_file(), "flask==2.0.1")])

    specs = list(source.collect())

    # If the dependency list has duplicates, then converting to a set will reduce the length of the
    # collection
    assert len(specs) == len(set(specs))


def test_requirement_source_invalid_lines(req_file):
    source = _init_requirement([(req_file(), "a#b#c")])

    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_requirement_source_git(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "git+https://github.com/unbit/uwsgi.git@1bb9ad77c6d2d310c2d6d1d9ad62de61f725b824",
            )
        ]
    )

    specs = list(source.collect())
    assert ResolvedDependency(name="uWSGI", version=Version("2.0.20")) in specs


@pytest.mark.online
def test_requirement_source_multiple_indexes(req_file):
    source = _init_requirement(
        [(req_file(), "flask==2.0.1")], index_urls=[PYPI_URL, "https://test.pypi.org/simple/"]
    )
    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs


def _check_fixes(
    input_reqs: list[str],
    expected_reqs: list[str],
    req_paths: list[Path],
    fixes: list[ResolvedFixVersion],
) -> None:
    # Populate the requirements files
    for input_req, req_path in zip(input_reqs, req_paths):
        with open(req_path, "w") as f:
            print(input_req, file=f)

    source = requirement.RequirementSource(req_paths)
    for fix in fixes:
        source.fix(fix)

    # Check the requirements files
    for expected_req, req_path in zip(expected_reqs, req_paths):
        with open(req_path) as f:
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
                dep=ResolvedDependency(name="flask", version=Version("0.5")),
                version=Version("1.0"),
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
    for input_req, req_path in zip(input_reqs, req_paths):
        with open(req_path, "w") as f:
            f.write(input_req)

    source = requirement.RequirementSource(req_paths)
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        )
    assert len(logger.warning.calls) == 1

    # Check that the requirements files remain unchanged
    # If we encounter a failure while applying a fix, the fix should be rolled back from all files
    for expected_req, req_path in zip(input_reqs, req_paths):
        with open(req_path) as f:
            assert expected_req == f.read().strip()


def test_requirement_source_fix_rollback_failure(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(requirement, "logger", logger)

    # If we encounter multiple of the same package in the requirements file, we will throw a parsing
    # error
    input_reqs = ["flask==0.5", "flask==0.5\nrequests==2.0\nflask==0.3"]
    req_paths = [req_file(), req_file()]

    # Populate the requirements files
    for input_req, req_path in zip(input_reqs, req_paths):
        with open(req_path, "w") as f:
            f.write(input_req)

    # Simulate an error being raised during file recovery
    def mock_replace(*_args, **_kwargs):
        raise OSError

    monkeypatch.setattr(os, "replace", mock_replace)

    source = requirement.RequirementSource(req_paths)
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
    for expected_req, req_path in zip(expected_reqs, req_paths):
        with open(req_path) as f:
            assert expected_req == f.read().strip()


def test_requirement_source_require_hashes(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1 "
                "--hash=sha256:a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9",
            )
        ],
        require_hashes=True,
    )

    specs = list(source.collect())
    assert specs == [ResolvedDependency("flask", Version("2.0.1"))]


def test_requirement_source_require_hashes_missing(req_file):
    source = _init_requirement([(req_file(), "flask==2.0.1")], require_hashes=True)

    # All requirements must be hashed when collecting with `require-hashes`
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_inferred(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1 "
                "--hash=sha256:a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9\n"
                "requests==2.0",
            )
        ]
    )

    # If at least one requirement is hashed, this infers `require-hashes`
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_require_hashes_unpinned(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "flask==2.0.1 "
                "--hash=sha256:a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9\n"
                "requests>=1.0 "
                "--hash=sha256:requests-hash",
            )
        ]
    )

    # When hashed dependencies are provided, all dependencies must be explicitly pinned to an exact
    # version number
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_no_deps(req_file):
    source = _init_requirement([(req_file(), "flask==2.0.1")], no_deps=True)

    specs = list(source.collect())
    assert specs == [ResolvedDependency("flask", Version("2.0.1"))]


def test_requirement_source_no_deps_unpinned(req_file):
    source = _init_requirement([(req_file(), "flask\nrequests==1.0")], no_deps=True)

    # When dependency resolution is disabled, all requirements must be pinned.
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_no_deps_not_exact_version(req_file):
    source = _init_requirement([(req_file(), "flask==1.0\nrequests>=1.0")], no_deps=True)

    # When dependency resolution is disabled, all requirements must be pinned.
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_no_deps_unpinned_url(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "https://github.com/pallets/flask/archive/refs/tags/2.0.1.tar.gz#egg=flask\n",
            )
        ],
        no_deps=True,
    )

    assert list(source.collect()) == [
        SkippedDependency(
            name="flask",
            skip_reason="URL requirements cannot be pinned to a specific package version",
        )
    ]


def test_requirement_source_no_deps_editable_with_egg_fragment(req_file):
    source = _init_requirement([(req_file(), "-e file:flask.py#egg=flask==2.0.1")], no_deps=True)

    specs = list(source.collect())
    assert (
        SkippedDependency(
            name="flask",
            skip_reason="URL requirements cannot be pinned to a specific package version",
        )
        in specs
    )


def test_requirement_source_no_deps_editable_without_egg_fragment(req_file):
    source = _init_requirement([(req_file(), "-e file:flask.py")], no_deps=True)

    specs = list(source.collect())
    assert (
        SkippedDependency(
            name="-e file:flask.py",
            skip_reason="could not deduce package version from URL requirement",
        )
        in specs
    )


def test_requirement_source_no_deps_non_editable_without_egg_fragment(req_file):
    source = _init_requirement(
        [
            (
                req_file(),
                "git+https://github.com/unbit/uwsgi.git@1bb9ad77c6d2d310c2d6d1d9ad62de61f725b824",
            )
        ],
        no_deps=True,
    )

    specs = list(source.collect())
    assert (
        SkippedDependency(
            name="git+https://github.com/unbit/uwsgi.git@1bb9ad77c6d2d310c2d6d1d9ad62de61f725b824",
            skip_reason="could not deduce package version from URL requirement",
        )
        in specs
    )


def test_requirement_source_no_deps_editable_skip(req_file):
    source = _init_requirement(
        [(req_file(), "-e file:flask.py#egg=flask==2.0.1")], no_deps=True, skip_editable=True
    )

    specs = list(source.collect())
    assert SkippedDependency(name="flask", skip_reason="requirement marked as editable") in specs


def test_requirement_source_no_deps_duplicate_dependencies(req_file):
    source = _init_requirement([(req_file(), "flask==1.0\nflask==1.0")], no_deps=True)

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_fix_explicit_subdep(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(requirement, "logger", logger)

    source = _init_requirement([(req_file(), "flask==2.0.1")])
    flask_deps = source.collect()

    # Firstly, get a handle on the `jinja2` dependency. The version cannot be hardcoded since it
    # depends what versions are available on PyPI when dependency resolution runs.
    jinja_dep: ResolvedDependency | None = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # Check that the `jinja2` dependency is explicitly added to the requirements file with an
    # associated comment.
    _check_fixes(
        ["flask==2.0.1"],
        ["flask==2.0.1\n    # pip-audit: subdependency explicitly fixed\njinja2==4.0.0"],
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
    source = _init_requirement([(req_file(), "flask==2.0.1")])
    flask_deps = source.collect()
    jinja_dep: ResolvedDependency | None = None
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
            "    # pip-audit: subdependency explicitly fixed\n"
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
    # Recreate the vulnerable subdependency case.
    source = _init_requirement([(req_file(), "flask==2.0.1")])
    flask_deps = source.collect()
    jinja_dep: ResolvedDependency | None = None
    for dep in flask_deps:
        if isinstance(dep, ResolvedDependency) and dep.canonical_name == "jinja2":
            jinja_dep = dep
            break
    assert jinja_dep is not None

    # Dependee requirements are a attached to each dependency. We no longer resolve dependencies
    # as part of `--fix` so we shouldn't call into dependency resolution.
    mock_resolver = pretend.stub(resolve=pretend.call_recorder(lambda _reqs, _req_hashes: []))
    source.fix(
        ResolvedFixVersion(
            dep=jinja_dep,
            version=Version("4.0.0"),
        )
    )
    assert len(mock_resolver.resolve.calls) == 0


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
    source = _init_requirement([(req_file(), "flask==2.0.1")])
    flask_deps = source.collect()
    jinja_dep: ResolvedDependency | None = None
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
        ["flask==3.0.0\n# pip-audit: subdependency explicitly fixed\njinja2==4.0.0"],
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
    source = _init_requirement([(req_file(), "a#b#c\nflask==0.5")])
    with pytest.raises(DependencyFixError):
        source.fix(
            ResolvedFixVersion(
                dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
            )
        )
