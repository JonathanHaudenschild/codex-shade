"""Checksum validators.

Regexes find candidates; these functions decide whether a candidate is real.
Every validator takes the raw matched text and returns True/False. They exist to
keep the false-positive rate low enough that redaction can run unattended.
"""

from __future__ import annotations

import math
import re
import string

_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn(value: str) -> bool:
    """Luhn mod-10, used by credit cards and IMEIs."""
    digits = _digits(value)
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def credit_card(value: str) -> bool:
    """Luhn plus an issuer-range check.

    Luhn alone is weak — about one long digit run in ten satisfies it — so the
    length has to match the issuer range the prefix claims. Amex starts 34/37 and
    is 15 digits; anything starting 34 with 16 digits is not a card.
    """
    digits = _digits(value)
    if not luhn(digits) or len(set(digits)) <= 1:
        return False

    length = len(digits)
    two, three, four = digits[:2], digits[:3], digits[:4]

    if digits[0] == "4":                      # Visa
        return length in (13, 16, 19)
    if two in ("34", "37"):                   # American Express
        return length == 15
    if "51" <= two <= "55":                   # Mastercard
        return length == 16
    if "2221" <= four <= "2720":              # Mastercard 2-series
        return length == 16
    if four == "6011" or two == "65" or "644" <= three <= "649":  # Discover
        return 16 <= length <= 19
    if two == "62":                           # UnionPay
        return 16 <= length <= 19
    if two == "35":                           # JCB
        return 16 <= length <= 19
    if two in ("36", "38") or "300" <= three <= "305":            # Diners
        return 14 <= length <= 19
    return False


def iban(value: str) -> bool:
    """ISO 13616 mod-97 check."""
    compact = _NON_ALNUM.sub("", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = []
    for char in rearranged:
        if char.isdigit():
            numeric.append(char)
        elif char in string.ascii_uppercase:
            numeric.append(str(ord(char) - 55))
        else:
            return False
    return int("".join(numeric)) % 97 == 1


def de_tax_id(value: str) -> bool:
    """German steuerliche Identifikationsnummer (11 digits, ISO 7064 MOD 11,10).

    Also enforces the structural rule that within the first ten digits exactly
    one digit repeats (twice or three times) and at least one digit is absent.
    """
    digits = _digits(value)
    if len(digits) != 11 or digits[0] == "0":
        return False

    body = digits[:10]
    counts: dict[str, int] = {}
    for char in body:
        counts[char] = counts.get(char, 0) + 1
    repeated = [count for count in counts.values() if count > 1]
    if len(counts) not in (9, 8):
        return False
    if len(repeated) != 1 or repeated[0] not in (2, 3):
        return False

    remainder = 10
    for char in body:
        total = (int(char) + remainder) % 10
        if total == 0:
            total = 10
        remainder = (total * 2) % 11
    check = 11 - remainder
    if check == 10:
        return False
    if check == 11:
        check = 0
    return check == int(digits[10])


_VSNR_LETTER_VALUES = {
    letter: f"{index + 1:02d}" for index, letter in enumerate(string.ascii_uppercase)
}
_VSNR_WEIGHTS = (2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1)


def de_social_security(value: str) -> bool:
    """German Versicherungsnummer: 2 digits, 6-digit birth date, letter, 2 digits, check digit."""
    compact = _NON_ALNUM.sub("", value).upper()
    if len(compact) != 12:
        return False
    if not compact[:8].isdigit() or not compact[8].isalpha() or not compact[9:].isdigit():
        return False

    day, month, year = compact[2:4], compact[4:6], compact[6:8]
    if not 1 <= int(day) <= 31 or not 1 <= int(month) <= 12:
        return False
    del year

    expanded = compact[:8] + _VSNR_LETTER_VALUES[compact[8]] + compact[9:11]
    total = 0
    for digit_char, weight in zip(expanded, _VSNR_WEIGHTS):
        product = int(digit_char) * weight
        total += product // 10 + product % 10
    return total % 10 == int(compact[11])


def us_ssn(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


_PRIVATE_V4 = (
    re.compile(r"^10\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^0\."),
    re.compile(r"^22[4-9]\.|^2[3-5]\d\."),
)


def public_ipv4(value: str) -> bool:
    """Only public IPv4 addresses are treated as personal data.

    RFC1918 / loopback / link-local addresses show up constantly in configs and
    carry no privacy risk, so redacting them would only create noise.
    """
    octets = value.split(".")
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit() or not 0 <= int(octet) <= 255:
            return False
        if len(octet) > 1 and octet[0] == "0":
            return False
    return not any(pattern.match(value) for pattern in _PRIVATE_V4)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies: dict[str, int] = {}
    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in frequencies.values()
    )


_PLACEHOLDER_TOKENS = {
    "changeme",
    "example",
    "password",
    "placeholder",
    "redacted",
    "secret",
    "todo",
    "xxxxxxxx",
    "yourkeyhere",
    "none",
    "null",
    "undefined",
    "true",
    "false",
}

_INTERPOLATION = re.compile(r"^[\$\{\<\%\#]|[\}\>\%]$|^os\.|^process\.env|^env\[")


def looks_like_real_secret(value: str) -> bool:
    """Heuristic gate for the generic `key = value` detector.

    Rejects template placeholders, env-var interpolation and low-entropy words so
    that ordinary configuration files do not get shredded.
    """
    candidate = value.strip().strip("\"'`")
    if len(candidate) < 12 or len(candidate) > 512:
        return False
    if _INTERPOLATION.search(candidate):
        return False

    lowered = candidate.lower()
    if lowered in _PLACEHOLDER_TOKENS:
        return False
    if any(token in lowered for token in ("changeme", "your-", "your_", "<your", "example.com", "xxxx")):
        return False
    if re.fullmatch(r"(.)\1+", candidate):
        return False
    # A value made only of dictionary-ish lowercase letters is probably prose.
    if re.fullmatch(r"[a-z]+", candidate):
        return False
    return shannon_entropy(candidate) >= 3.0
