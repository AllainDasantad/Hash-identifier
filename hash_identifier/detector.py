
from .models import HashCandidate
from .detectors.prefix import detect_prefix
from .detectors.hexadecimal import detect_hexadecimal


def identify_hash(hash_value: str) -> list[HashCandidate]:
    """
    Identify possible hash algorithms based on hash structure.

    Returns multiple candidates when the format is ambiguous.
    """

    # Step 1: Validate input type.
    if not isinstance(hash_value, str):
        return []

    # Step 2: Normalize input.
    hash_value = hash_value.strip()

    # Step 3: Reject empty input.
    if not hash_value:
        return []

    # Step 4: Detect recognizable prefixes.
    prefix_candidates = detect_prefix(hash_value)

    if prefix_candidates:
        return prefix_candidates

    # Step 5: Detect hexadecimal formats.
    return detect_hexadecimal(hash_value)

