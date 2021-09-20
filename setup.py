#!/usr/bin/env python3

from setuptools import find_packages, setup

version = {}
with open("./pip_audit/version.py") as f:
    exec(f.read(), version)

with open("./README.md") as f:
    long_description = f.read()

setup(
    name="pip-audit",
    version=version["__version__"],
    license="Apache-2.0",
    author="William Woodruff",
    author_email="william@trailofbits.com",
    description="A tool for scanning Python environments for known vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trailofbits/pip-audit",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "pip-audit = pip_audit.cli:audit",
        ]
    },
    platforms="any",
    python_requires=">=3.6",
    install_requires=[
        "pip-api>=0.0.21",
        "packaging>=21.0.0",
        # TODO: Remove this once 3.7 is our minimally supported version.
        "dataclasses>=0.6",
        "progress>=1.6",
        "resolvelib>=0.7.1",
        "html5lib>=1.1",
    ],
    extras_require={
        "dev": [
            "bump",
            "flake8",
            "black",
            "isort",
            "pytest",
            "pytest-cov",
            "pretend",
            "coverage[toml]",
            "twine",
            # NOTE: pdoc3 does not support Python 3.6. Re-enable this once 3.7 is
            # our minimally supported version.
            # "pdoc3",
            "mypy",
            # TODO: Remove this once 3.7 is our minimally supported version.
            "types-dataclasses",
            "types-requests",
            "types-html5lib",
        ]
    },
    classifiers=[
        # TODO(ww): Upgrade this status once we're out of alpha development.
        "Development Status :: 2 - Pre-Alpha",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
)
