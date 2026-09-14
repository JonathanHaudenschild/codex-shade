"""Scanning and redaction."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Optional

from . import config, detectors as detector_module
from .vault import Vault, PLACEHOLDER_RE


@dataclass
class Finding:
    detector: str
    label: str
    severity: str
    start: int
    end: int
    preview: str

    def as_dict(self) -> dict:
        return asdict(self)


def mask(value: str) -> str:
    """A preview safe to print in a warning or write to the audit log."""
    stripped = value.strip()
    if len(stripped) <= 4:
        return "*" * len(stripped)
    if "@" in stripped and "." in stripped.split("@")[-1]:
        local, _, domain = stripped.partition("@")
        head = local[0] if local else ""
        tail = domain.split(".")[-1]
        return f"{head}{'*' * max(len(local) - 1, 1)}@{'*' * 3}.{tail}"
    keep = 2 if len(stripped) < 12 else 4
    return f"{stripped[:keep]}{'*' * min(len(stripped) - keep * 2, 12)}{stripped[-keep:]}"


class Engine:
    def __init__(self, settings: Optional[dict] = None, cwd: Optional[str] = None):
        self.config = settings if settings is not None else config.load(cwd)
        self.vault = Vault(self.config)
        self._detectors = self._build_detectors()
        self._allowlist = {
            term.strip().lower() for term in self.config.get("allowlist", []) if term.strip()
        }
        self._allow_domains = {
            domain.strip().lower().lstrip("@")
            for domain in self.config.get("allow_email_domains", [])
            if domain.strip()
        }

    # -- setup -------------------------------------------------------------

    def _build_detectors(self) -> list[detector_module.Detector]:
        overrides = self.config.get("detectors", {}) or {}
        active = [
            detector
            for detector in detector_module.all_detectors()
            if overrides.get(detector.name, detector.enabled_by_default)
        ]

        names = self.config.get("names") or []
        name_detector = detector_module.build_term_detector(
            "names", "PERSON", detector_module.PII, names, priority=88
        )
        if name_detector is not None:
            active.append(name_detector)

        special_terms = self.config.get("special_terms")
        if special_terms is None:
            special_terms = detector_module.DEFAULT_SPECIAL_TERMS
        special_detector = detector_module.build_term_detector(
            "special_terms",
            "SPECIAL_CATEGORY",
            detector_module.SPECIAL,
            special_terms,
            priority=40,
        )
        if special_detector is not None:
            active.append(special_detector)

        return active

    # -- scanning ----------------------------------------------------------

    def _allowed(self, detector: detector_module.Detector, value: str) -> bool:
        lowered = value.strip().lower()
        if lowered in self._allowlist:
            return True
        if detector.label == "EMAIL" and self._allow_domains:
            domain = lowered.rpartition("@")[2]
            if domain in self._allow_domains or any(
                domain.endswith("." + allowed) for allowed in self._allow_domains
            ):
                return True
        return False

    def scan(self, text: str) -> list[Finding]:
        """Return non-overlapping findings, ordered by position."""
        if not text or not self.config.get("enabled", True):
            return []

        limit = int(self.config.get("max_scan_bytes", 400_000))
        if len(text) > limit:
            text = text[:limit]

        # Spans already occupied by our own placeholders are off limits, so a
        # second pass over redacted text is a no-op instead of double-redacting.
        reserved = [(match.start(), match.end()) for match in PLACEHOLDER_RE.finditer(text)]

        candidates: list[tuple[detector_module.Detector, int, int, str]] = []
        for detector in self._detectors:
            try:
                for start, end, value in detector.finditer(text):
                    if self._allowed(detector, value):
                        continue
                    candidates.append((detector, start, end, value))
            except re.error:
                continue

        # Resolve overlaps: highest priority wins, then the longest span.
        candidates.sort(key=lambda item: (-item[0].priority, -(item[2] - item[1]), item[1]))
        taken: list[tuple[int, int]] = list(reserved)
        chosen: list[tuple[detector_module.Detector, int, int, str]] = []
        for candidate in candidates:
            _, start, end, _ = candidate
            if any(start < other_end and end > other_start for other_start, other_end in taken):
                continue
            taken.append((start, end))
            chosen.append(candidate)

        chosen.sort(key=lambda item: item[1])
        return [
            Finding(
                detector=detector.name,
                label=detector.label,
                severity=detector.severity,
                start=start,
                end=end,
                preview=mask(value),
            )
            for detector, start, end, value in chosen
        ]

    def redact(
        self, text: str, severities: Optional[Iterable[str]] = None
    ) -> tuple[str, list[Finding]]:
        """Replace findings with placeholders.

        ``severities`` limits which findings are rewritten; the rest are still
        returned so the caller can warn about them.
        """
        findings = self.scan(text)
        if not findings:
            return text, []

        allowed = set(severities) if severities is not None else {"secret", "pii", "special"}
        pieces: list[str] = []
        cursor = 0
        applied: list[Finding] = []
        for finding in findings:
            if finding.severity not in allowed:
                continue
            original = text[finding.start : finding.end]
            pieces.append(text[cursor : finding.start])
            pieces.append(self.vault.remember(finding.label, finding.severity, original))
            cursor = finding.end
            applied.append(finding)
        pieces.append(text[cursor:])
        self.vault.flush()
        return "".join(pieces), applied

    def reveal(self, text: str) -> tuple[str, int]:
        return self.vault.reveal(text)

    # -- audit -------------------------------------------------------------

    def log(self, event: str, surface: str, action: str, findings: list[Finding], extra: Optional[dict] = None) -> None:
        if not self.config.get("audit_log", True) or not findings:
            return
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "event": event,
            "surface": surface,
            "action": action,
            "findings": [
                {"label": finding.label, "severity": finding.severity, "preview": finding.preview}
                for finding in findings
            ],
        }
        if extra:
            record.update(extra)
        path = config.home() / "audit.jsonl"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass


def summarize(findings: list[Finding]) -> str:
    """A one-line, PII-free description of what was found."""
    if not findings:
        return "nothing"
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.label] = counts.get(finding.label, 0) + 1
    return ", ".join(
        f"{label}×{count}" if count > 1 else label
        for label, count in sorted(counts.items(), key=lambda item: -item[1])
    )


def highest_severity(findings: list[Finding]) -> Optional[str]:
    order = {"secret": 3, "pii": 2, "special": 1}
    if not findings:
        return None
    return max((finding.severity for finding in findings), key=lambda name: order.get(name, 0))
