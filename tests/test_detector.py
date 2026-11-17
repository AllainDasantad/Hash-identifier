import pytest

from hash_identifier.detector import identify_hash


@pytest.mark.parametrize(
    "hash_value, expected_algorithm, expected_confidence",
    [
        (
            "$2b$12$abcdefghijklmnopqrstuu1234567890123456789012345678901",
            "bcrypt",
            "high",
        ),
        (
            "$2a$12$abcdefghijklmnopqrstuu1234567890123456789012345678901",
            "bcrypt",
            "high",
        ),
        (
            "$2y$12$abcdefghijklmnopqrstuu1234567890123456789012345678901",
            "bcrypt",
            "high",
        ),
        (
            "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
            "Argon2",
            "high",
        ),
        (
            "5d41402abc4b2a76b9719d911017c592",
            "MD5",
            "medium",
        ),
        (
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
            "SHA-1",
            "medium",
        ),
        (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256",
            "medium",
        ),
        (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "SHA-512",
            "medium",
        ),
    ],
)
def test_identify_known_hashes(
    hash_value,
    expected_algorithm,
    expected_confidence,
):
    results = identify_hash(hash_value)

    detected_algorithms = [
        candidate.algorithm for candidate in results
    ]

    assert expected_algorithm in detected_algorithms

    expected_candidate = next(
        candidate
        for candidate in results
        if candidate.algorithm == expected_algorithm
    )

    assert expected_candidate.confidence == expected_confidence


def test_empty_input():
    assert identify_hash("") == []


def test_whitespace_input():
    assert identify_hash("   ") == []


def test_unknown_hash():
    assert identify_hash("not-a-valid-hash") == []


def test_hash_with_surrounding_whitespace():
    hash_value = "  5d41402abc4b2a76b9719d911017c592  "

    results = identify_hash(hash_value)

    detected_algorithms = [
        candidate.algorithm for candidate in results
    ]

    assert "MD4" in detected_algorithms
    assert "MD5" in detected_algorithms
    assert "NTLM" in detected_algorithms


def test_none_input():
    assert identify_hash(None) == []


def test_integer_input():
    assert identify_hash(12345) == []


def test_list_input():
    assert identify_hash(["abc123"]) == []

def test_invalid_bcrypt_structure():
    assert identify_hash("$2b$not-a-valid-hash") == []


def test_invalid_bcrypt_cost():
    invalid_hash = "$2b$99$" + "a" * 53
    assert identify_hash(invalid_hash) == []


def test_invalid_bcrypt_length():
    invalid_hash = "$2b$12$" + "a" * 52
    assert identify_hash(invalid_hash) == []

def test_invalid_argon2_version():
    invalid_hash = "$argon2id$v=18$m=65536,t=3,p=4$c2FsdA$aGFzaA"
    assert identify_hash(invalid_hash) == []


def test_invalid_argon2_memory_cost():
    invalid_hash = "$argon2id$v=19$m=0,t=3,p=4$c2FsdA$aGFzaA"
    assert identify_hash(invalid_hash) == []


def test_invalid_argon2_time_cost():
    invalid_hash = "$argon2id$v=19$m=65536,t=0,p=4$c2FsdA$aGFzaA"
    assert identify_hash(invalid_hash) == []


def test_invalid_argon2_parallelism():
    invalid_hash = "$argon2id$v=19$m=65536,t=3,p=0$c2FsdA$aGFzaA"
    assert identify_hash(invalid_hash) == []


def test_invalid_argon2_salt():
    invalid_hash = "$argon2id$v=19$m=65536,t=3,p=4$invalid!$aGFzaA"
    assert identify_hash(invalid_hash) == []


def test_invalid_argon2_digest():
    invalid_hash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$invalid!"
    assert identify_hash(invalid_hash) == []


def test_missing_argon2_digest():
    invalid_hash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA"
    assert identify_hash(invalid_hash) == []

