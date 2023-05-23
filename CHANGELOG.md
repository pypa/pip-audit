# Changelog

All notable changes to `pip-audit` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 0.0.9 are untracked.

## [Unreleased]

### Fixed

* Fixed a crash caused by incompatible dependency changes
  ([#617](https://github.com/pypa/pip-audit/pull/617))

## [2.5.5]

### Fixed

* Fixed a crash caused by incompatible dependency changes
  ([#605](https://github.com/pypa/pip-audit/pull/605))

## [2.5.4]

### Changed

* Refactored `index-url` option to not override user pip config by default,
  unless specified ([#565](https://github.com/pypa/pip-audit/pull/565))

### Fixed

* Fixed bug with the `--fix` flag where new requirements were sometimes being
  appended to requirement files instead of patching the existing requirement
  ([#577](https://github.com/pypa/pip-audit/pull/577))

* Fixed a crash caused by auditing requirements files that refer to other
  requirements files ([#568](https://github.com/pypa/pip-audit/pull/568))

## [2.5.3]

### Changed

* Further simplified `pip-audit`'s dependency resolution to remove inconsistent
  behaviour when using hashed requirements or the `--no-deps` flag
  ([#540](https://github.com/pypa/pip-audit/pull/540))

### Fixed

* Fixed a crash caused by invalid UTF-8 sequences in subprocess outputs
  ([#572](https://github.com/pypa/pip-audit/pull/572))

## [2.5.2]

### Fixed

* Fixed a loose dependency constraint for CycloneDX SBOM generation
  ([#558](https://github.com/pypa/pip-audit/pull/558))

## [2.5.1]

### Fixed

* Fixed a crash on Windows caused by multiple open file handles to
  input requirements ([#551](https://github.com/pypa/pip-audit/pull/551))

## [2.5.0]

### Changed

* Improved error messaging when a requirements input or indirect dependency
  has an invalid (non-PEP 440) requirements specifier
  ([#507](https://github.com/pypa/pip-audit/pull/507))

* `pip-audit`'s handling of dependency resolution has been significantly
  refactored and simplified ([#523](https://github.com/pypa/pip-audit/pull/523))

### Fixed

* Fixed a potential crash on invalid unicode in subprocess streams
  ([#536](https://github.com/pypa/pip-audit/pull/536))

## [2.4.15]

**YANKED**

### Fixed

* Fixed an issue where hash checking would fail when using third-party indices
  ([#462](https://github.com/pypa/pip-audit/pull/462))

* Fixed the behavior of the `--skip-editable` flag, which had regressed
  with an internal API change
  ([#499](https://github.com/pypa/pip-audit/pull/499))

* Fixed a dependency resolution bug that can potentially be triggered when
  multiple packages have the same subdependency
  ([#488](https://github.com/pypa/pip-audit/pull/488))

## [2.4.14]

### Fixed

* Fixed a dependency resolution failure caused by incorrect handling of
  a PEP 440 edge case around prerelease versions
  ([#477](https://github.com/pypa/pip-audit/pull/477))

## [2.4.13]

### Fixed

* Added a lower bound on `packaging` to ensure that non-normalized versions
  are handled correctly ([#471](https://github.com/pypa/pip-audit/pull/471))

## [2.4.12]

### Fixed

* Fixed `pip-audit`'s virtual environment creation and upgrade behavior,
  preventing spurious vulnerability reports
  ([#454](https://github.com/pypa/pip-audit/pull/454))

* Users are now warned if a `pip-audit` invocation is ambiguous, e.g.
  if they've installed `pip-audit` globally but are asking for an audit
  of a loaded virtual environment
  ([#451](https://github.com/pypa/pip-audit/pull/451))

## [2.4.11]

### Fixed

* Fixed a crash triggered when a package specifies an invalid version
  specifier for its `requires-python` version
  ([#447](https://github.com/pypa/pip-audit/pull/447))

## [2.4.10]

### Fixed

* Fixed a crash triggered when no vulnerabilities are found with some
  configurations ([#437](https://github.com/pypa/pip-audit/pull/437))

## [2.4.9]

### Fixed

* The `--output` flag will no longer produce an empty file in the event
  of a failure within `pip-audit` itself, making it easier to distinguish
  between audit failures being reported by `pip-audit` and `pip-audit`'s
  own errors ([#432](https://github.com/pypa/pip-audit/pull/432))

* Removed pin on `packaging` now that our dependency pins it for us
  ([#429](https://github.com/pypa/pip-audit/pull/427))

## [2.4.8]

### Fixed

* Pin maximum version of `packaging` dependency to avoid installing the new
  22.0 version which is incompatible with `pip-requirements-parser`
  ([#427](https://github.com/pypa/pip-audit/pull/427))

## [2.4.7]

### Fixed

* Fixed a timestamp parsing bug that occurred with some vulnerability
  reports provided by the OSV service
  ([#416](https://github.com/pypa/pip-audit/issues/416))

## [2.4.6]

### Fixed

* Fixed an incorrect interaction between `--desc=auto` and `--format=json`;
  `--desc=auto` now includes the description in the generated JSON report,
  as intended ([#399](https://github.com/pypa/pip-audit/pull/399))

* Fixed a bug in dependency resolution with third-party indices where
  relative URLs were not resolved correctly
  ([#411](https://github.com/pypa/pip-audit/pull/411),
  [#412](https://github.com/pypa/pip-audit/pull/412))

## [2.4.5]

### Fixed

* Fixed an issue where audits done with the PyPI vulnerability service (the
  default) were not correctly filtered by "withdrawn" status; "withdrawn"
  vulnerabilities are now excluded
  ([#393](https://github.com/pypa/pip-audit/pull/393))

* Fixed an issue where audits done with the OSV vulnerability service (`-s osv`)
  were not correctly filtered by "withdrawn" status; "withdrawn" vulnerabilities
  are now excluded ([#386](https://github.com/pypa/pip-audit/pull/386))

* Fixed `pip-audit`'s handling of URL-style requirements in `--no-deps` mode
  (URL requirements are now treated as skipped, rather than producing
  an error due to a lack of pinning)
  ([#395](https://github.com/pypa/pip-audit/pull/395/files))

## [2.4.4]

### Changed

* `pip-audit` is now a PyPA member project, and lives under
  [`pypa/pip-audit`](https://github.com/pypa/pip-audit)!

* Improved error message for when unpinned URL requirements are found during an
  audit with the `--no-deps` flag
  ([#355](https://github.com/pypa/pip-audit/pull/355))

### Fixed

* Fixed an issue where packages on PyPI with no published versions trigger a
  dependency resolution failure instead of being skipped
  ([#357](https://github.com/pypa/pip-audit/pull/357))

* Fixed an incorrect assertion triggering for non-editable URL requirements that
  don't have an egg fragment
  ([#359](https://github.com/pypa/pip-audit/pull/359))

## [2.4.3]

### Fixed

* Fixed a regression in requirements auditing that was introduced during the
  move from `pip-api` to `pip-requirements-parser` where editable installs
  without an egg fragment would cause audits to crash
  ([#331](https://github.com/pypa/pip-audit/pull/331))

## [2.4.2]

### Fixed

* CLI: the `--format=markdown` and `--format=columns` output formats are no
  longer broken by long vulnerability descriptions from the OSV and PyPI
  vulnerability sources ([#323](https://github.com/pypa/pip-audit/pull/323))

## [2.4.1]

### Fixed

* Fixed a breakage in hash-checking mode caused by a
  [change to the PyPI JSON API](https://discuss.python.org/t/backwards-incompatible-change-to-pypi-json-api/17154)
  ([#318](https://github.com/pypa/pip-audit/pull/318))

## [2.4.0]

### Added

* Output formats: `pip-audit` now supports a Markdown format
  (`--format=markdown`) which renders results as a set of Markdown tables.
  ([#312](https://github.com/pypa/pip-audit/pull/312))

## [2.3.4]

### Fixed

* Vulnerability fixing: the `--fix` flag now works for vulnerabilities found in
  requirement subdependencies. A new line is now added to the requirement file
  to explicitly pin the offending subdependency
  ([#297](https://github.com/pypa/pip-audit/pull/297))

## [2.3.3]

### Changed

* CLI: `pip-audit` now warns on the combination of `-s osv` and
  `--require-hashes`, notifying users that only the PyPI service
  can fully verify hashes
  ([#298](https://github.com/pypa/pip-audit/pull/298))

### Fixed

* CLI/Dependency sources: `--cache-dir=...` and other flags that affect
  dependency resolver behavior now work correctly when auditing a
  `pyproject.toml` dependency source
  ([#300](https://github.com/pypa/pip-audit/pull/300))

## [2.3.2] - 2022-05-14

### Changed

* CLI: `pip-audit`'s progress spinner has been refactored to make it
  faster and more responsive
  ([#283](https://github.com/pypa/pip-audit/pull/283))

* CLI, Vulnerability sources: the error message used to report
  connection failures to vulnerability sources was improved
  ([#287](https://github.com/pypa/pip-audit/pull/287))

* Vulnerability sources: the OSV service is now more resilient
  to schema changes ([#288](https://github.com/pypa/pip-audit/pull/288))

* Vulnerability sources: the PyPI service provides a better
  error message during some cases of service degradation
  ([#294](https://github.com/pypa/pip-audit/pull/294))

### Fixed

* Vulnerability sources: a bug stemming from an incorrect assumption
  about OSV's schema guarantees was fixed
  ([#284](https://github.com/pypa/pip-audit/pull/284))

* Caching: `pip-audit` now respects `pip`'s `PIP_NO_CACHE_DIR`
  and will not attempt to use the `pip` cache if present
  ([#290](https://github.com/pypa/pip-audit/pull/290))

## [2.3.1] - 2022-05-24

### Fixed

* CLI: A bug causing the terminal's cursor to disappear on some
  versions of CPython was fixed
  ([#280](https://github.com/pypa/pip-audit/issues/280))

## [2.3.0] - 2022-05-18

### Added

* CLI: The `--ignore-vuln` option has been added, allowing users to
  specify vulnerability IDs to ignore during the final report
  ([#275](https://github.com/pypa/pip-audit/pull/275))

* CLI: The `--no-deps` flag has been added, allowing users to skip dependency
  resolution entirely when `pip-audit` is used in requirements mode
  ([#255](https://github.com/pypa/pip-audit/pull/255))

## [2.2.1] - 2022-05-02

### Fixed

* A bug introduced with a previous fix to version parsing
  ([#263](https://github.com/pypa/pip-audit/pull/263)) was
  fixed ([#264](https://github.com/pypa/pip-audit/pull/264))

## [2.2.0] - 2022-05-02

### Added

* CLI: The `--output` option has been added, allowing users to specify
  a file to write output to. The default behavior of writing to `stdout`
  is unchanged ([#262](https://github.com/pypa/pip-audit/pull/262))

### Fixed

* Vulnerability sources: A bug caused by insufficient version normalization
  was fixed ([#263](https://github.com/pypa/pip-audit/pull/263))

## [2.1.1] - 2022-03-29

### Fixed

* Dependency sources: A bug caused by ambiguous parses of source distribution
  files was fixed ([#249](https://github.com/pypa/pip-audit/pull/249))

## [2.1.0] - 2022-03-11

### Added

* CLI: The `--skip-editable` flag has been added, allowing users to skip local
  packages or parsed requirements (via `-r`) that are marked as editable
  ([#244](https://github.com/pypa/pip-audit/pull/244))

* CLI: `pip-audit` can audit projects that list their dependencies in
  `pyproject.toml` files, via `pip-audit <dir>`
  ([#246](https://github.com/pypa/pip-audit/pull/246))

## [2.0.0] - 2022-02-18

### Added

* CLI: The `--fix` flag has been added, allowing users to attempt to
  automatically upgrade any vulnerable dependencies to the first safe version
  available ([#212](https://github.com/pypa/pip-audit/pull/212),
  [#222](https://github.com/pypa/pip-audit/pull/222))

* CLI: The combination of `--fix` and `--dry-run` is now supported, causing
  `pip-audit` to perform the auditing step but not any resulting fix steps
  ([#223](https://github.com/pypa/pip-audit/pull/223))

* CLI: The `--require-hashes` flag has been added which can be used in
  conjunction with `-r` to check that all requirements in the file have an
  associated hash ([#229](https://github.com/pypa/pip-audit/pull/229))

* CLI: The `--index-url` flag has been added, allowing users to use custom
  package indices when running with the `-r` flag
  ([#238](https://github.com/pypa/pip-audit/pull/238))

* CLI: The `--extra-index-url` flag has been added, allowing users to use
  multiple package indices when running with the `-r` flag
  ([#238](https://github.com/pypa/pip-audit/pull/238))

### Changed

* `pip-audit`'s minimum Python version is now 3.7.

* CLI: The default output format is now correctly pluralized
  ([#221](https://github.com/pypa/pip-audit/pull/221))

* Output formats: The SBOM output formats (`--format=cyclonedx-xml` and
  `--format=cyclonedx-json`) now use CycloneDX
  [Schema 1.4](https://cyclonedx.org/docs/1.4/xml/)
  ([#216](https://github.com/pypa/pip-audit/pull/216))

* Vulnerability sources: When using PyPI as a vulnerability service, any hashes
  provided in a requirements file are checked against those reported by PyPI
  ([#229](https://github.com/pypa/pip-audit/pull/229))

* Vulnerability sources: `pip-audit` now uniques each result based on its
  alias set, reducing the amount of duplicate information in the default
  columnar output format
  ([#232](https://github.com/pypa/pip-audit/pull/232))

* CLI: `pip-audit` now prints its output more frequently, including when
  there are no discovered vulnerabilities but packages were skipped.
  Similarly, "manifest" output formats (JSON, CycloneDX) are now emitted
  unconditionally
  ([#240](https://github.com/pypa/pip-audit/pull/240))

### Fixed

* CLI: A regression causing excess output during `pip audit -r`
  was fixed ([#226](https://github.com/pypa/pip-audit/pull/226))

### Removed

## [1.1.2] - 2022-01-13

### Fixed

* A pin on one of `pip-audit`'s dependencies was fixed
  ([#213](https://github.com/pypa/pip-audit/pull/213))

## [1.1.1] - 2021-12-07

### Fixed

* Dependency sources: a crash caused by unexpected logging statements in `pip`'s
  JSON output was fixed
  ([#196](https://github.com/pypa/pip-audit/pull/196))

## [1.1.0] - 2021-12-06

### Added

* CLI: The `--path <PATH>` flag has been added, allowing users to limit
  dependency discovery to one or more paths (specified separately)
  when `pip-audit` is invoked in environment mode
  ([#148](https://github.com/pypa/pip-audit/pull/148))

* CLI: The `pip-audit` CLI can now be accessed through `python -m pip_audit`.
  All functionality is identical to the functionality provided by the
  `pip-audit` entrypoint
  ([#173](https://github.com/pypa/pip-audit/pull/173))

* CLI: The `--verbose` flag has been added, allowing users to receive more
  more verbose output from `pip-audit`. Supplying the `--verbose` flag
  overrides the `PIP_AUDIT_LOGLEVEL` environment variable and is equivalent to
  setting it to `debug`
  ([#185](https://github.com/pypa/pip-audit/pull/185))

### Changed

* CLI: `pip-audit` now clears its spinner bar from the terminal upon
  completion, preventing visual confusion
  ([#174](https://github.com/pypa/pip-audit/pull/174))

### Fixed

* Dependency sources: a crash caused by `platform.python_version` returning
  an version string that couldn't be parsed as a PEP-440 version was fixed
  ([#175](https://github.com/pypa/pip-audit/pull/175))

* Dependency sources: a crash caused by incorrect assumptions about
  the structure of source distributions was fixed
  ([#166](https://github.com/pypa/pip-audit/pull/166))

* Vulnerability sources: a performance issue on Windows caused by cache failures
  was fixed ([#178](https://github.com/pypa/pip-audit/pull/178))

## [1.0.1] - 2021-12-02

### Fixed

* CLI: The `--desc` flag no longer requires a following argument. If passed
  as a bare option, `--desc` is equivalent to `--desc on`
  ([#153](https://github.com/pypa/pip-audit/pull/153))

* Dependency resolution: The PyPI-based dependency resolver no longer throws
  an uncaught exception on package resolution errors; instead, the package
  is marked as skipped and an appropriate warning or fatal error (in
  `--strict` mode) is produced
  ([#162](https://github.com/pypa/pip-audit/pull/162))

* CLI: When providing the `--cache-dir` flag, the command to read the pip cache
  directory is no longer executed. Previously this was always executed and
  could result into failure when the command fails. In CI environments, the
  default `~/.cache` directory is typically not writable by the build user and
  this meant that the `python -m pip cache dir` would fail before this fix,
  even if the `--cache-dir` flag was provided.
  ([#161](https://github.com/pypa/pip-audit/pull/161))

## [1.0.0] - 2021-12-01

### Added

* This is the first stable release of `pip-audit`! The CLI is considered
  stable from this point on, and all changes will comply with
  [Semantic Versioning](https://semver.org/)

## [0.0.9] - 2021-12-01

### Added

* CLI: Skipped dependencies are now listed in the output of `pip-audit`,
  for supporting output formats
  ([#145](https://github.com/pypa/pip-audit/pull/145))
* CLI: `pip-audit` now supports a "strict" mode (enabled with `-S` or
  `--strict`) that fails if the audit if any individual dependency cannot be
  resolved or audited. The default behavior is still to skip any individual
  dependency errors ([#146](https://github.com/pypa/pip-audit/pull/146))

<!-- Release URLs -->
[Unreleased]: https://github.com/pypa/pip-audit/compare/v2.5.5...HEAD
[2.5.5]: https://github.com/pypa/pip-audit/compare/v2.5.4...v2.5.5
[2.5.4]: https://github.com/pypa/pip-audit/compare/v2.5.3...v2.5.4
[2.5.3]: https://github.com/pypa/pip-audit/compare/v2.5.2...v2.5.3
[2.5.2]: https://github.com/pypa/pip-audit/compare/v2.5.1...v2.5.2
[2.5.1]: https://github.com/pypa/pip-audit/compare/v2.5.0...v2.5.1
[2.5.0]: https://github.com/pypa/pip-audit/compare/v2.4.15...v2.5.0
[2.4.15]: https://github.com/pypa/pip-audit/compare/v2.4.14...v2.4.15
[2.4.14]: https://github.com/pypa/pip-audit/compare/v2.4.13...v2.4.14
[2.4.13]: https://github.com/pypa/pip-audit/compare/v2.4.12...v2.4.13
[2.4.12]: https://github.com/pypa/pip-audit/compare/v2.4.11...v2.4.12
[2.4.11]: https://github.com/pypa/pip-audit/compare/v2.4.10...v2.4.11
[2.4.10]: https://github.com/pypa/pip-audit/compare/v2.4.9...v2.4.10
[2.4.9]: https://github.com/pypa/pip-audit/compare/v2.4.8...v2.4.9
[2.4.8]: https://github.com/pypa/pip-audit/compare/v2.4.7...v2.4.8
[2.4.7]: https://github.com/pypa/pip-audit/compare/v2.4.6...v2.4.7
[2.4.6]: https://github.com/pypa/pip-audit/compare/v2.4.5...v2.4.6
[2.4.5]: https://github.com/pypa/pip-audit/compare/v2.4.4...v2.4.5
[2.4.4]: https://github.com/pypa/pip-audit/compare/v2.4.3...v2.4.4
[2.4.3]: https://github.com/pypa/pip-audit/compare/v2.4.2...v2.4.3
[2.4.2]: https://github.com/pypa/pip-audit/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/pypa/pip-audit/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/pypa/pip-audit/compare/v2.3.4...v2.4.0
[2.3.4]: https://github.com/pypa/pip-audit/compare/v2.3.3...v2.3.4
[2.3.3]: https://github.com/pypa/pip-audit/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/pypa/pip-audit/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/pypa/pip-audit/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/pypa/pip-audit/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/pypa/pip-audit/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/pypa/pip-audit/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/pypa/pip-audit/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/pypa/pip-audit/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/pypa/pip-audit/compare/v1.1.2...v2.0.0
[1.1.2]: https://github.com/pypa/pip-audit/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/pypa/pip-audit/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/pypa/pip-audit/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/pypa/pip-audit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/pypa/pip-audit/compare/v0.0.9...v1.0.0
[0.0.9]: https://github.com/pypa/pip-audit/compare/v0.0.8...v0.0.9
