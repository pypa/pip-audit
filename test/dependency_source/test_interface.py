import pytest

from pip_audit._dependency_source import HashMismatchError, HashMissingError, RequirementHashes
from pip_audit._service.interface import Dependency


def test_dependency_source(dep_source):
    source = dep_source()

    for spec in source.collect():
        assert isinstance(spec, Dependency)


def test_requirement_hashes():
    req_hashes = RequirementHashes()

    req_name = "flask"
    hash_options = {"sha256": ["hash0", "hash1", "hash2"], "sha512": ["hash3"], "md5": ["hash4"]}
    dist_hashes = {
        "sha256": "hash1",
        "sha512": "hash5",
        "md5": "hash6",
    }

    # The requirement hasn't been added so this shouldn't work yet.
    assert not req_hashes
    assert not req_hashes.supported_algorithms(req_name)
    with pytest.raises(HashMissingError):
        req_hashes.match(req_name, dist_hashes)

    # Now add the requirement.
    req_hashes.add_req(req_name, hash_options)
    assert req_hashes
    assert req_name in req_hashes

    # We should be able to match the `sha256` hash value of `hash1`.
    req_hashes.match(req_name, dist_hashes)


def test_requirement_hashes_mismatch():
    req_hashes = RequirementHashes()

    req_name = "flask"
    hash_options = {"sha256": ["hash0", "hash1", "hash2"], "sha512": ["hash3"], "md5": ["hash4"]}
    dist_hashes = {
        "sha256": "hash5",
        "sha512": "hash6",
        "md5": "hash7",
    }

    req_hashes.add_req(req_name, hash_options)

    # None of the hashes match the calculated distribution hashes. Therefore, we should raise an
    # error.
    with pytest.raises(HashMismatchError):
        req_hashes.match(req_name, dist_hashes)
