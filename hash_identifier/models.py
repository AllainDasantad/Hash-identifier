
from dataclasses import dataclass


@dataclass
class HashCandidate:
    algorithm: str
    confidence: str
    reason: str

