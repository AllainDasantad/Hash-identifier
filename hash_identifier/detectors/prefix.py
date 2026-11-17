
import base64
import re

from ..models import HashCandidate


# bcrypt: variant, cost factor, salt, and checksum structure.
BCRYPT_PATTERN = re.compile(
    r"\A\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$"
    r"[./A-Za-z0-9]{53}\Z"
)


# Argon2: variant, version, parameters, salt, and hash.
ARGON2_PATTERN = re.compile(
    r"\A\$argon2(id|i|d)"
    r"\$v=19"
    r"\$m=(\d+),t=(\d+),p=(\d+)"
    r"\$([A-Za-z0-9+/]+)"
    r"\$([A-Za-z0-9+/]+)\Z"
)


def is_valid_base64(value: str) -> bool:
    """Check whether a string contains valid unpadded Base64."""

    try:
        padded_value = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded_value, validate=True)

        return bool(decoded)

    except (ValueError, base64.binascii.Error):
        return False


def detect_prefix(hash_value: str) -> list[HashCandidate]:
    """Detect hash formats with recognizable and valid structures."""

    # Step 1: Detect bcrypt.
    if hash_value.startswith(("$2a$", "$2b$", "$2y$")):
        if BCRYPT_PATTERN.fullmatch(hash_value):
            return [
                HashCandidate(
                    algorithm="bcrypt",
                    confidence="high",
                    reason="Valid bcrypt structure recognized.",
                )
            ]

        return []

    # Step 2: Detect Argon2.
    if hash_value.startswith("$argon2"):
        match = ARGON2_PATTERN.fullmatch(hash_value)

        if not match:
            return []

        variant, memory, time_cost, parallelism, salt, digest = (
            match.groups()
        )

        # Validate Argon2 parameters.
        if min(
            int(memory),
            int(time_cost),
            int(parallelism),
        ) <= 0:
            return []

        # Validate Base64 salt and digest.
        if not is_valid_base64(salt):
            return []

        if not is_valid_base64(digest):
            return []

        return [
            HashCandidate(
                algorithm="Argon2",
                confidence="high",
                reason=f"Valid Argon2 {variant} structure recognized.",
            )
        ]

    return []

