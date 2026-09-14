"""Detector catalogue.

A detector is a regex plus an optional validator. `group` selects which capture
group is the sensitive part, so `Authorization: Bearer <token>` can redact only
the token and keep the surrounding text readable for the model.

Severities
----------
``secret``  credentials and keys. Leaking one is an incident.
``pii``     personal data under GDPR Art. 4.
``special`` special categories under GDPR Art. 9.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import validators

SECRET = "secret"
PII = "pii"
SPECIAL = "special"


@dataclass(frozen=True)
class Detector:
    name: str
    label: str
    severity: str
    pattern: re.Pattern
    group: int = 0
    validator: Optional[Callable[[str], bool]] = None
    # Higher wins when two detectors claim overlapping spans.
    priority: int = 50
    enabled_by_default: bool = True
    description: str = ""

    def finditer(self, text: str):
        for match in self.pattern.finditer(text):
            value = match.group(self.group)
            if not value:
                continue
            if self.validator is not None and not self.validator(value):
                continue
            yield match.start(self.group), match.end(self.group), value


def _re(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


# Numeric identifiers must stand alone. Without these guards a detector happily
# matches the tail of a geo coordinate such as `13.3885...8095`, which is how a
# coordinate column ends up reported as a wall of credit cards.
_NUM_START = r"(?<![\d.,])"
_NUM_END = r"(?![\d]|[.,]\d)"


# --------------------------------------------------------------------------
# Credentials and keys
# --------------------------------------------------------------------------

_SECRET_DETECTORS = [
    Detector(
        name="private_key",
        label="PRIVATE_KEY",
        severity=SECRET,
        priority=100,
        description="PEM/OpenSSH/PGP private key blocks",
        pattern=_re(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        ),
    ),
    Detector(
        name="aws_access_key_id",
        label="AWS_ACCESS_KEY_ID",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b"),
    ),
    Detector(
        name="aws_secret_access_key",
        label="AWS_SECRET_ACCESS_KEY",
        severity=SECRET,
        priority=95,
        group=1,
        pattern=_re(
            r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"
        ),
    ),
    Detector(
        name="github_token",
        label="GITHUB_TOKEN",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b"),
    ),
    Detector(
        name="gitlab_token",
        label="GITLAB_TOKEN",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ),
    Detector(
        name="anthropic_key",
        label="ANTHROPIC_API_KEY",
        severity=SECRET,
        priority=96,
        pattern=_re(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ),
    Detector(
        name="openai_key",
        label="OPENAI_API_KEY",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{24,}\b"),
    ),
    Detector(
        name="google_api_key",
        label="GOOGLE_API_KEY",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    Detector(
        name="slack_token",
        label="SLACK_TOKEN",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\bxox[baprse]-[A-Za-z0-9\-]{10,}\b"),
    ),
    Detector(
        name="stripe_key",
        label="STRIPE_KEY",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    Detector(
        name="huggingface_token",
        label="HUGGINGFACE_TOKEN",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\bhf_[A-Za-z0-9]{30,}\b"),
    ),
    Detector(
        name="npm_token",
        label="NPM_TOKEN",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\bnpm_[A-Za-z0-9]{36}\b"),
    ),
    Detector(
        name="sendgrid_key",
        label="SENDGRID_KEY",
        severity=SECRET,
        priority=95,
        pattern=_re(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"),
    ),
    Detector(
        name="jwt",
        label="JWT",
        severity=SECRET,
        priority=90,
        description="Signed JSON Web Token — often carries identity claims",
        pattern=_re(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
    Detector(
        name="webhook_url",
        label="WEBHOOK_URL",
        severity=SECRET,
        priority=90,
        pattern=_re(
            r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks)/[A-Za-z0-9/_\-]+"
        ),
    ),
    Detector(
        name="url_credentials",
        label="URL_PASSWORD",
        severity=SECRET,
        priority=92,
        group=1,
        description="Password embedded in a connection string",
        pattern=_re(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:([^\s/@\"']{3,})@"),
    ),
    Detector(
        name="authorization_header",
        label="AUTH_TOKEN",
        severity=SECRET,
        priority=88,
        group=1,
        pattern=_re(r"(?i)\bauthorization\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+([A-Za-z0-9_\-\.=+/]{12,})"),
    ),
    Detector(
        name="generic_secret_assignment",
        label="SECRET",
        severity=SECRET,
        priority=60,
        group=2,
        validator=validators.looks_like_real_secret,
        description="key/token/password assignment with a high-entropy value",
        pattern=_re(
            r"(?i)\b([a-z0-9_\-]*(?:api[_\-]?key|secret[_\-]?key|client[_\-]?secret|"
            r"access[_\-]?token|auth[_\-]?token|refresh[_\-]?token|private[_\-]?token|"
            r"passwd|password|passphrase|api[_\-]?secret|secret))\b"
            r"\s*[:=]\s*[\"']?([^\s\"',;}\)]{12,512})"
        ),
    ),
    Detector(
        name="url_query_secret",
        label="URL_SECRET",
        severity=SECRET,
        priority=70,
        group=2,
        pattern=_re(
            r"(?i)[?&]((?:access_)?token|api[_\-]?key|apikey|signature|sig|auth|password|"
            r"client_secret|sas|key)=([^&\s\"'<>]{8,})"
        ),
    ),
]


# --------------------------------------------------------------------------
# Personal data
# --------------------------------------------------------------------------

_PII_DETECTORS = [
    Detector(
        name="email",
        label="EMAIL",
        severity=PII,
        priority=80,
        pattern=_re(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    Detector(
        name="iban",
        label="IBAN",
        severity=PII,
        priority=85,
        validator=validators.iban,
        pattern=_re(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"),
    ),
    Detector(
        name="bic",
        label="BIC",
        severity=PII,
        priority=60,
        enabled_by_default=False,
        description="SWIFT/BIC code — noisy, opt in if you handle payments",
        pattern=_re(r"\b[A-Z]{4}(?:DE|AT|CH|FR|IT|ES|NL|BE|LU|GB|US)[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
    ),
    Detector(
        name="credit_card",
        label="CREDIT_CARD",
        severity=PII,
        priority=85,
        validator=validators.credit_card,
        # Either an unbroken 15/16-digit run, or a conventionally grouped
        # number. Allowing arbitrary separators would match any two adjacent
        # numbers in a log line.
        pattern=_re(
            _NUM_START
            + r"(?:\d{4}[ \-]\d{4}[ \-]\d{4}[ \-]\d{1,4}"
            r"|\d{4}[ \-]\d{6}[ \-]\d{5}"
            r"|\d{15,16})"
            + _NUM_END
        ),
    ),
    Detector(
        name="de_tax_id",
        label="DE_STEUER_ID",
        severity=PII,
        priority=84,
        validator=validators.de_tax_id,
        description="Steuerliche Identifikationsnummer",
        pattern=_re(_NUM_START + r"\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}" + _NUM_END),
    ),
    Detector(
        name="de_social_security",
        label="DE_SOZIALVERSICHERUNGSNUMMER",
        severity=PII,
        priority=86,
        validator=validators.de_social_security,
        pattern=_re(_NUM_START + r"\d{2}[ ]?\d{6}[ ]?[A-Z][ ]?\d{3}" + _NUM_END),
    ),
    Detector(
        name="us_ssn",
        label="US_SSN",
        severity=PII,
        priority=84,
        validator=validators.us_ssn,
        pattern=_re(_NUM_START + r"\d{3}-\d{2}-\d{4}" + _NUM_END),
    ),
    Detector(
        name="phone",
        label="PHONE",
        severity=PII,
        priority=70,
        description="International and German phone numbers",
        pattern=_re(
            r"(?<![\w.\-])(?:\+|00)\d{1,3}[ \-/]?\(?\d{1,5}\)?[ \-/]?\d{2,4}(?:[ \-/]?\d{2,6}){0,3}"
            r"(?![\w.\-])"
            r"|(?<![\w.\-])0\d{2,5}[ \-/]\d{3,9}(?![\w.\-])"
        ),
    ),
    Detector(
        name="ipv4",
        label="IP_ADDRESS",
        severity=PII,
        priority=65,
        validator=validators.public_ipv4,
        description="Public IPv4 only; RFC1918 and loopback are ignored",
        pattern=_re(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])"),
    ),
    Detector(
        name="ipv6",
        label="IP_ADDRESS",
        severity=PII,
        priority=65,
        enabled_by_default=False,
        pattern=_re(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){5,7}[0-9A-Fa-f]{1,4}(?![\w:])"),
    ),
    Detector(
        name="mac_address",
        label="MAC_ADDRESS",
        severity=PII,
        priority=65,
        pattern=_re(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
    ),
    Detector(
        name="date_of_birth",
        label="DATE_OF_BIRTH",
        severity=PII,
        priority=75,
        group=1,
        description="Date preceded by a birth-date marker (DE/EN)",
        pattern=_re(
            r"(?i)\b(?:geb\.?|geboren(?:\s+am)?|geburtsdatum|date\s+of\s+birth|dob|born(?:\s+on)?)"
            r"\s*[:\-]?\s*(\d{1,4}[./\-]\d{1,2}[./\-]\d{2,4})"
        ),
    ),
    Detector(
        name="de_postal_address",
        label="ADDRESS",
        severity=PII,
        priority=72,
        enabled_by_default=False,
        description="German street + house number. Off by default: matches code comments too",
        pattern=_re(
            r"\b[A-ZÄÖÜ][a-zäöüß]+(?:[ \-][A-ZÄÖÜ][a-zäöüß]+)*"
            r"(?:stra(?:ss|ß)e|str\.|weg|allee|platz|gasse|damm|ufer|ring)\s+\d{1,4}[a-zA-Z]?\b"
        ),
    ),
    Detector(
        name="de_plz_city",
        label="POSTAL_CODE",
        severity=PII,
        priority=55,
        enabled_by_default=False,
        pattern=_re(r"\b\d{5}\s+[A-ZÄÖÜ][a-zäöüß\-]{2,}\b"),
    ),
]


def all_detectors() -> list[Detector]:
    return list(_SECRET_DETECTORS) + list(_PII_DETECTORS)


def build_term_detector(
    name: str, label: str, severity: str, terms: list[str], priority: int = 78
) -> Optional[Detector]:
    """Build a word-boundary detector from a user-supplied term list.

    This is how names of colleagues, project code names and Art. 9 vocabulary get
    covered — no NLP model, just an explicit list the user controls.
    """
    cleaned = sorted({term.strip() for term in terms if term and term.strip()}, key=len, reverse=True)
    if not cleaned:
        return None
    alternation = "|".join(re.escape(term) for term in cleaned)
    return Detector(
        name=name,
        label=label,
        severity=severity,
        priority=priority,
        pattern=_re(rf"(?<![\w])(?:{alternation})(?![\w])", re.IGNORECASE),
    )


# Starter vocabulary for GDPR Art. 9 special categories (DE + EN).
# Matching a word here does not prove a person is identified, so the default
# policy for `special` is to warn rather than to rewrite.
DEFAULT_SPECIAL_TERMS = [
    "Schwerbehinderung", "Schwerbehindert", "Krankschreibung", "Arbeitsunfähigkeit",
    "Diagnose", "Krankheitsbild", "Therapie", "Psychotherapie", "Depression",
    "Schwangerschaft", "Gewerkschaft", "Betriebsrat", "Personalrat",
    "Religionszugehörigkeit", "Konfession", "Parteizugehörigkeit",
    "sexuelle Orientierung", "ethnische Herkunft", "Migrationshintergrund",
    "BEM-Verfahren", "Abmahnung", "Krankenkasse",
    "disability", "sick leave", "medical diagnosis", "mental health",
    "pregnancy", "trade union", "religious affiliation", "political affiliation",
    "sexual orientation", "ethnic origin", "health record",
]
