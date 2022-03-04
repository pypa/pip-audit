#!/usr/bin/env python3

from setuptools import find_packages, setup

version = {}
with open("./pip_audit/_version.py") as f:
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
            "pip-audit = pip_audit._cli:audit",
        ]
    },
    platforms="any",
    python_requires=">=3.7",
    install_requires=[
        "pip-api>=0.0.28",
        "packaging>=21.0.0",
        "progress>=1.6",
        "resolvelib>=0.8.0",
        "html5lib>=1.1",
        "CacheControl[filecache]>=0.12.10",
        "cyclonedx-python-lib>=1.0.0,<3.0.0",
    ],
    extras_require={
        "dev": [
            "bump >= 1.3.1",
            "flake8",
            "black",
            "isort",
            "pytest",
            "pytest-cov",
            "pretend",
            "coverage[toml]",
            "interrogate",
            "pdoc3",
            "mypy",
            "types-requests",
            "types-html5lib",
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
)
