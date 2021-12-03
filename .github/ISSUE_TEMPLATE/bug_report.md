---
name: Bug report
about: Create a report to help us improve
title: ''
labels: bug-candidate
assignees: ''

---

Thank you for reporting a potential bug in `pip-audit`! Please read the next parts of this template carefully:

**IMPORTANT**: Please **do not** report auditing errors (false positives or negatives) to this repository. Instead, please report them to [pypa/advisory-db](https://github.com/pypa/advisory-db/issues/new). 

**IMPORTANT:** Please fill out every section below. Bug reports with missing information will be
given a lower priority or closed outright.

Please comment out or remove this line and everything above it from your report.

## Bug description

A clear and concise description of what the bug is.

## Reproduction steps 

A step-by-step list of actions to reproduce the behavior.

## Expected behavior

A clear and concise description of what you expected to happen.

## Screenshots and logs

If applicable, add screenshots to help explain your problem.

Similarly, if applicable and possible, re-run the command with `PIP_AUDIT_LOGLEVEL=debug` exported,
and paste the logs in the code block below:

```
Paste logs here, or remove me if not applicable!
```

## Platform information

* OS name and version:
* `pip-audit` version (`pip-audit -V`): 
* Python version (`python -V` or `python3 -V`): 
* `pip` version (`pip -V` or `pip3 -V`):

## Additional context

Add any other context about the problem here.
