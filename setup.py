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
    python_requires=">=3.9",
    install_requires=[
        "pip-api==0.0.20",
    ],
    extras_require={
        "dev": [
            "flake8",
            "black",
            "isort",
            "pytest",
            "pytest-cov",
            "coverage[toml]",
            "twine",
            "pdoc3",
            "mypy",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
    ],
)
