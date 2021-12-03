# Changelog

All notable changes to `pip-audit` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 0.0.9 are untracked.

## [Unreleased] - ReleaseDate

### Added

* CLI: The `--path <PATH>` flag has been added, allowing users to limit
  dependency discovery to one or more paths (specified separately)
  when `pip-audit` is invoked in environment mode
  ([#148](https://github.com/trailofbits/pip-audit/pull/148))

* CLI: The `pip-audit` CLI can now be accessed through `python -m pip_audit`.
  All functionality is identical to the functionality provided by the
  `pip-audit` entrypoint
  ([#173](https://github.com/trailofbits/pip-audit/pull/173))

### Changed

* CLI: `pip-audit` now clears its spinner bar from the terminal upon
  completion, preventing visual confusion
  ([#174](https://github.com/trailofbits/pip-audit/pull/174))

### Fixed

### Removed

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
[Unreleased]: https://github.com/trailofbits/pip-audit/compare/v0.0.9...HEAD
[1.0.1]: https://github.com/trailofbits/pip-audit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/trailofbits/pip-audit/compare/v0.0.9...v1.0.0
[0.0.9]: https://github.com/trailofbits/pip-audit/compare/v0.0.8...v0.0.9
