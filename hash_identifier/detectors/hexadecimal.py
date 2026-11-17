
import re

from ..models import HashCandidate


# Algorithms grouped by hexadecimal digest length.
HEX_HASH_CANDIDATES = {
    32: ["MD4", "MD5", "NTLM"],
    40: ["SHA-1", "RIPEMD-160"],
    64: ["SHA-256", "SHA3-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512"],
}


def detect_hexadecimal(hash_value: str) -> list[HashCandidate]:
    """Detect possible algorithms using hexadecimal length."""

    if not re.fullmatch(r"[a-fA-F0-9]+", hash_value):
        return []

    hash_length = len(hash_value)
    algorithms = HEX_HASH_CANDIDATES.get(hash_length, [])

    candidates = []

    for algorithm in algorithms:
        candidates.append(
            HashCandidate(
                algorithm=algorithm,
                confidence="medium",
                reason=(
                    f"Hexadecimal string with "
                    f"{hash_length} characters."
                ),
            )
        )

    return candidates

