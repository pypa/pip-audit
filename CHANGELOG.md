# Changelog

All notable changes to `pip-audit` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 0.0.9 are untracked.

## [Unreleased]

### Changed

* CLI: `pip-audit` now warns on the combination of `-s osv` and
  `--require-hashes`, notifying users that only the PyPI service
  can fully verify hashes
  ([#298](https://github.com/trailofbits/pip-audit/pull/298))

### Fixed

* CLI/Dependency sources: `--cache-dir=...` and other flags that affect
  dependency resolver behavior now work correctly when auditing a
  `pyproject.toml` dependency source
  ([#300](https://github.com/trailofbits/pip-audit/pull/300))

## [2.3.2] - 2022-05-14

### Changed

* CLI: `pip-audit`'s progress spinner has been refactored to make it
  faster and more responsive
  ([#283](https://github.com/trailofbits/pip-audit/pull/283))

* CLI, Vulnerability sources: the error message used to report
  connection failures to vulnerability sources was improved
  ([#287](https://github.com/trailofbits/pip-audit/pull/287))

* Vulnerability sources: the OSV service is now more resilient
  to schema changes ([#288](https://github.com/trailofbits/pip-audit/pull/288))

* Vulnerability sources: the PyPI service provides a better
  error message during some cases of service degradation
  ([#294](https://github.com/trailofbits/pip-audit/pull/294))

### Fixed

* Vulnerability sources: a bug stemming from an incorrect assumption
  about OSV's schema guarantees was fixed
  ([#284](https://github.com/trailofbits/pip-audit/pull/284))

* Caching: `pip-audit` now respects `pip`'s `PIP_NO_CACHE_DIR`
  and will not attempt to use the `pip` cache if present
  ([#290](https://github.com/trailofbits/pip-audit/pull/290))

## [2.3.1] - 2022-05-24

### Fixed

* CLI: A bug causing the terminal's cursor to disappear on some
  versions of CPython was fixed
  ([#280](https://github.com/trailofbits/pip-audit/issues/280))

## [2.3.0] - 2022-05-18

### Added

* CLI: The `--ignore-vuln` option has been added, allowing users to
  specify vulnerability IDs to ignore during the final report
  ([#275](https://github.com/trailofbits/pip-audit/pull/275))

* CLI: The `--no-deps` flag has been added, allowing users to skip dependency
  resolution entirely when `pip-audit` is used in requirements mode
  ([#255](https://github.com/trailofbits/pip-audit/pull/255))

## [2.2.1] - 2022-05-02

### Fixed

* A bug introduced with a previous fix to version parsing
  ([#263](https://github.com/trailofbits/pip-audit/pull/263)) was
  fixed ([#264](https://github.com/trailofbits/pip-audit/pull/264))

## [2.2.0] - 2022-05-02

### Added

* CLI: The `--output` option has been added, allowing users to specify
  a file to write output to. The default behavior of writing to `stdout`
  is unchanged ([#262](https://github.com/trailofbits/pip-audit/pull/262))

### Fixed

* Vulnerability sources: A bug caused by insufficient version normalization
  was fixed ([#263](https://github.com/trailofbits/pip-audit/pull/263))

## [2.1.1] - 2022-03-29

### Fixed

* Dependency sources: A bug caused by ambiguous parses of source distribution
  files was fixed ([#249](https://github.com/trailofbits/pip-audit/pull/249))

## [2.1.0] - 2022-03-11

### Added

* CLI: The `--skip-editable` flag has been added, allowing users to skip local
  packages or parsed requirements (via `-r`) that are marked as editable
  ([#244](https://github.com/trailofbits/pip-audit/pull/244))

* CLI: `pip-audit` can audit projects that list their dependencies in
  `pyproject.toml` files, via `pip-audit <dir>`
  ([#246](https://github.com/trailofbits/pip-audit/pull/246))

## [2.0.0] - 2022-02-18

### Added

* CLI: The `--fix` flag has been added, allowing users to attempt to
  automatically upgrade any vulnerable dependencies to the first safe version
  available ([#212](https://github.com/trailofbits/pip-audit/pull/212),
  [#222](https://github.com/trailofbits/pip-audit/pull/222))

* CLI: The combination of `--fix` and `--dry-run` is now supported, causing
  `pip-audit` to perform the auditing step but not any resulting fix steps
  ([#223](https://github.com/trailofbits/pip-audit/pull/223))

* CLI: The `--require-hashes` flag has been added which can be used in
  conjunction with `-r` to check that all requirements in the file have an
  associated hash ([#229](https://github.com/trailofbits/pip-audit/pull/229))

* CLI: The `--index-url` flag has been added, allowing users to use custom
  package indices when running with the `-r` flag
  ([#238](https://github.com/trailofbits/pip-audit/pull/238))

* CLI: The `--extra-index-url` flag has been added, allowing users to use
  multiple package indices when running with the `-r` flag
  ([#238](https://github.com/trailofbits/pip-audit/pull/238))

### Changed

* `pip-audit`'s minimum Python version is now 3.7.

* CLI: The default output format is now correctly pluralized
  ([#221](https://github.com/trailofbits/pip-audit/pull/221))

* Output formats: The SBOM output formats (`--format=cyclonedx-xml` and
  `--format=cyclonedx-json`) now use CycloneDX
  [Schema 1.4](https://cyclonedx.org/docs/1.4/xml/)
  ([#216](https://github.com/trailofbits/pip-audit/pull/216))

* Vulnerability sources: When using PyPI as a vulnerability service, any hashes
  provided in a requirements file are checked against those reported by PyPI
  ([#229](https://github.com/trailofbits/pip-audit/pull/229))

* Vulnerability sources: `pip-audit` now uniques each result based on its
  alias set, reducing the amount of duplicate information in the default
  columnar output format
  ([#232](https://github.com/trailofbits/pip-audit/pull/232))

* CLI: `pip-audit` now prints its output more frequently, including when
  there are no discovered vulnerabilities but packages were skipped.
  Similarly, "manifest" output formats (JSON, CycloneDX) are now emitted
  unconditionally
  ([#240](https://github.com/trailofbits/pip-audit/pull/240))

### Fixed

* CLI: A regression causing excess output during `pip audit -r`
  was fixed ([#226](https://github.com/trailofbits/pip-audit/pull/226))

### Removed

## [1.1.2] - 2022-01-13

### Fixed

* A pin on one of `pip-audit`'s dependencies was fixed
  ([#213](https://github.com/trailofbits/pip-audit/pull/213))

## [1.1.1] - 2021-12-07

### Fixed

* Dependency sources: a crash caused by unexpected logging statements in `pip`'s
  JSON output was fixed
  ([#196](https://github.com/trailofbits/pip-audit/pull/196))

## [1.1.0] - 2021-12-06

### Added

* CLI: The `--path <PATH>` flag has been added, allowing users to limit
  dependency discovery to one or more paths (specified separately)
  when `pip-audit` is invoked in environment mode
  ([#148](https://github.com/trailofbits/pip-audit/pull/148))

* CLI: The `pip-audit` CLI can now be accessed through `python -m pip_audit`.
  All functionality is identical to the functionality provided by the
  `pip-audit` entrypoint
  ([#173](https://github.com/trailofbits/pip-audit/pull/173))

* CLI: The `--verbose` flag has been added, allowing users to receive more
  more verbose output from `pip-audit`. Supplying the `--verbose` flag
  overrides the `PIP_AUDIT_LOGLEVEL` environment variable and is equivalent to
  setting it to `debug`
  ([#185](https://github.com/trailofbits/pip-audit/pull/185))

### Changed

* CLI: `pip-audit` now clears its spinner bar from the terminal upon
  completion, preventing visual confusion
  ([#174](https://github.com/trailofbits/pip-audit/pull/174))

### Fixed

* Dependency sources: a crash caused by `platform.python_version` returning
  an version string that couldn't be parsed as a PEP-440 version was fixed
  ([#175](https://github.com/trailofbits/pip-audit/pull/175))

* Dependency sources: a crash caused by incorrect assumptions about
  the structure of source distributions was fixed
  ([#166](https://github.com/trailofbits/pip-audit/pull/166))

* Vulnerability sources: a performance issue on Windows caused by cache failures
  was fixed ([#178](https://github.com/trailofbits/pip-audit/pull/178))

## [1.0.1] - 2021-12-02

### Fixed

* CLI: The `--desc` flag no longer requires a following argument. If passed
  as a bare option, `--desc` is equivalent to `--desc on`
  ([#153](https://github.com/trailofbits/pip-audit/pull/153))

* Dependency resolution: The PyPI-based dependency resolver no longer throws
  an uncaught exception on package resolution errors; instead, the package
  is marked as skipped and an appropriate warning or fatal error (in
  `--strict` mode) is produced
  ([#162](https://github.com/trailofbits/pip-audit/pull/162))

* CLI: When providing the `--cache-dir` flag, the command to read the pip cache
  directory is no longer executed. Previously this was always executed and
  could result into failure when the command fails. In CI environments, the
  default `~/.cache` directory is typically not writable by the build user and
  this meant that the `python -m pip cache dir` would fail before this fix,
  even if the `--cache-dir` flag was provided.
  ([#161](https://github.com/trailofbits/pip-audit/pull/161))

## [1.0.0] - 2021-12-01

### Added

* This is the first stable release of `pip-audit`! The CLI is considered
  stable from this point on, and all changes will comply with
  [Semantic Versioning](https://semver.org/)

## [0.0.9] - 2021-12-01

### Added

* CLI: Skipped dependencies are now listed in the output of `pip-audit`,
  for supporting output formats
  ([#145](https://github.com/trailofbits/pip-audit/pull/145))
* CLI: `pip-audit` now supports a "strict" mode (enabled with `-S` or
  `--strict`) that fails if the audit if any individual dependency cannot be
  resolved or audited. The default behavior is still to skip any individual
  dependency errors ([#146](https://github.com/trailofbits/pip-audit/pull/146))

<!-- Release URLs -->
[Unreleased]: https://github.com/trailofbits/pip-audit/compare/v2.0.0...HEAD
[2.3.1]: https://github.com/trailofbits/pip-audit/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/trailofbits/pip-audit/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/trailofbits/pip-audit/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/trailofbits/pip-audit/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/trailofbits/pip-audit/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/trailofbits/pip-audit/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/trailofbits/pip-audit/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/trailofbits/pip-audit/compare/v1.1.2...v2.0.0
[1.1.2]: https://github.com/trailofbits/pip-audit/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/trailofbits/pip-audit/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/trailofbits/pip-audit/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/trailofbits/pip-audit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/trailofbits/pip-audit/compare/v0.0.9...v1.0.0
[0.0.9]: https://github.com/trailofbits/pip-audit/compare/v0.0.8...v0.0.9
