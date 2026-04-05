"""Password strength scoring and generation."""

from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass
from typing import Optional


COMMON_PATTERNS = [
    r"^[0-9]+$",                  # all digits
    r"^[a-zA-Z]+$",               # all letters
    r"(012|123|234|345|456|567|678|789|890)",
    r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk)",
    r"password|passw0rd|qwerty|letmein|admin|welcome",
]


@dataclass
class StrengthResult:
    score: int          # 0-100
    grade: str          # A-F
    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    entropy_bits: float
    warnings: list[str]

    @property
    def label(self) -> str:
        if self.score >= 80:
            return "Strong"
        if self.score >= 60:
            return "Moderate"
        if self.score >= 40:
            return "Weak"
        return "Very Weak"

    @property
    def color(self) -> str:
        if self.score >= 80:
            return "green"
        if self.score >= 60:
            return "yellow"
        if self.score >= 40:
            return "orange3"
        return "red"


def score_password(password: str) -> StrengthResult:
    """Score a password 0-100."""
    warnings: list[str] = []
    length = len(password)

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    # Charset size for entropy estimate
    charset = 0
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        charset += 32
    charset = max(charset, 1)

    entropy = length * math.log2(charset) if charset > 1 else 0.0

    # Base score from entropy
    score = min(int(entropy / 1.28), 70)  # cap at 70

    # Bonuses
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10
    if length >= 20:
        score += 10
    score = min(score, 100)

    # Penalties
    if length < 8:
        score -= 30
        warnings.append("Too short (< 8 characters)")
    elif length < 12:
        score -= 10
        warnings.append("Short password (< 12 characters recommended)")

    for pat in COMMON_PATTERNS:
        if re.search(pat, password, re.IGNORECASE):
            score -= 20
            warnings.append("Contains common pattern or weak sequence")
            break

    score = max(score, 0)

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return StrengthResult(
        score=score,
        grade=grade,
        length=length,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_symbol=has_symbol,
        entropy_bits=entropy,
        warnings=warnings,
    )


def generate_password(
    length: int = 20,
    use_symbols: bool = True,
    use_digits: bool = True,
    use_upper: bool = True,
    use_lower: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Generate a cryptographically secure random password."""
    alphabet = ""
    if use_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace("l", "").replace("o", "")
        alphabet += chars
    if use_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace("I", "").replace("O", "")
        alphabet += chars
    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace("0", "").replace("1", "")
        alphabet += chars
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if not alphabet:
        raise ValueError("At least one character class must be enabled.")

    # Guarantee at least one char from each requested class
    required: list[str] = []
    if use_lower:
        required.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        required.append(secrets.choice(string.digits))
    if use_symbols:
        required.append(secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"))

    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    combined = required + remaining
    # Shuffle to avoid predictable positions
    for i in range(len(combined) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combined[i], combined[j] = combined[j], combined[i]
    return "".join(combined)
