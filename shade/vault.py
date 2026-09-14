"""Local pseudonym vault.

Every redacted value becomes ``<LABEL_xxxxxx>`` where the suffix is
``HMAC-SHA256(local key, label + value)`` truncated to six hex characters. Two
consequences that matter:

* the same person is the same placeholder across turns and across sessions, so
  the model can still tell two people apart and follow a thread of reasoning;
* the placeholder reveals nothing — the key never leaves this machine.

The vault maps placeholders back to originals so ``shade reveal`` can restore a
model's answer locally. It lives in ``~/.shade/vault.json`` with mode 0600 and is
never transmitted. Secrets are not stored by default (see config.vault).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

from . import config

PLACEHOLDER_RE = re.compile(r"<([A-Z][A-Z0-9_]{1,48})_([0-9a-f]{6})>")


def _ensure_home() -> Path:
    root = config.home()
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    return root


def _key_path() -> Path:
    return _ensure_home() / "key"


def local_key() -> bytes:
    """Read, or on first use create, the machine-local HMAC key."""
    path = _key_path()
    if path.is_file():
        try:
            raw = path.read_text(encoding="utf-8").strip()
            if raw:
                return bytes.fromhex(raw)
        except (OSError, ValueError):
            pass

    key = secrets.token_bytes(32)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(key.hex())
    return key


def placeholder_id(label: str, value: str) -> str:
    digest = hmac.new(
        local_key(), f"{label}\x00{value.strip()}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return digest[:6]


def make_placeholder(label: str, value: str) -> str:
    return f"<{label}_{placeholder_id(label, value)}>"


class Vault:
    def __init__(self, settings: dict):
        self.settings = settings.get("vault", {}) or {}
        self.enabled = bool(self.settings.get("enabled", True))
        self.store_severities = set(self.settings.get("store_severities", ["pii", "special"]))
        self.ttl_days = int(self.settings.get("ttl_days", 30) or 0)
        self.path = _ensure_home() / "vault.json"
        self._entries: Optional[dict] = None
        self._dirty = False
        # The proxy is threaded and the hooks are separate processes, so the
        # vault has concurrent writers. The lock covers this process; the
        # merge-and-rename in flush() covers the rest.
        self._lock = threading.RLock()

    # -- persistence -------------------------------------------------------

    def _load(self) -> dict:
        if self._entries is not None:
            return self._entries
        entries: dict = {}
        if self.path.is_file():
            try:
                with self.path.open(encoding="utf-8") as handle:
                    payload = json.load(handle)
                if isinstance(payload, dict):
                    entries = payload.get("entries", {}) or {}
            except (OSError, ValueError):
                entries = {}
        self._entries = entries
        return entries

    def _prune(self, entries: dict) -> dict:
        if not self.ttl_days:
            return entries
        cutoff = time.time() - self.ttl_days * 86400
        kept = {
            key: entry
            for key, entry in entries.items()
            if float(entry.get("last_seen", 0)) >= cutoff
        }
        if len(kept) != len(entries):
            self._dirty = True
        return kept

    def flush(self) -> None:
        """Persist, merging with whatever else has written since we loaded.

        Two failure modes are being avoided here. A shared temp filename made
        concurrent writers race for the same rename, so one of them hit
        FileNotFoundError. And a long-lived process holding stale in-memory
        entries would overwrite anything a short-lived hook added behind its
        back, silently losing placeholders and breaking `reveal`.
        """
        with self._lock:
            if not self._dirty or self._entries is None:
                return

            merged = dict(self._entries)
            on_disk = {}
            if self.path.is_file():
                try:
                    with self.path.open(encoding="utf-8") as handle:
                        payload = json.load(handle)
                    if isinstance(payload, dict):
                        on_disk = payload.get("entries", {}) or {}
                except (OSError, ValueError):
                    on_disk = {}
            for key, entry in on_disk.items():
                if key not in merged:
                    merged[key] = entry
                else:
                    merged[key]["last_seen"] = max(
                        float(merged[key].get("last_seen", 0)),
                        float(entry.get("last_seen", 0)),
                    )

            entries = self._prune(merged)
            self._entries = entries

            # A unique temp name per writer: os.replace is atomic, so the last
            # rename wins cleanly instead of two writers fighting over one path.
            temporary = self.path.with_name(
                f".vault.{os.getpid()}.{threading.get_ident():x}.tmp"
            )
            try:
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump({"version": 1, "entries": entries}, handle,
                              ensure_ascii=False, indent=1)
                os.replace(temporary, self.path)
            except OSError:
                # Losing a vault write costs reversibility, never privacy --
                # redaction already happened. Never let it break the request.
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            finally:
                self._dirty = False

    # -- api ---------------------------------------------------------------

    def remember(self, label: str, severity: str, value: str) -> str:
        token = make_placeholder(label, value)
        if not self.enabled or severity not in self.store_severities:
            return token

        with self._lock:
            return self._remember_locked(token, label, severity, value)

    def _remember_locked(self, token: str, label: str, severity: str, value: str) -> str:
        entries = self._load()
        key = token[1:-1]
        now = time.time()
        existing = entries.get(key)
        if existing is None:
            entries[key] = {
                "label": label,
                "severity": severity,
                "value": value,
                "first_seen": now,
                "last_seen": now,
            }
        else:
            existing["last_seen"] = now
        self._dirty = True
        return token

    def lookup(self, key: str) -> Optional[str]:
        entry = self._load().get(key)
        return entry.get("value") if entry else None

    def reveal(self, text: str) -> tuple[str, int]:
        """Replace placeholders with their originals. Returns (text, count)."""
        restored = 0

        def substitute(match: re.Match) -> str:
            nonlocal restored
            value = self.lookup(match.group(0)[1:-1])
            if value is None:
                return match.group(0)
            restored += 1
            return value

        return PLACEHOLDER_RE.sub(substitute, text), restored

    def stats(self) -> dict:
        entries = self._load()
        by_label: dict[str, int] = {}
        for entry in entries.values():
            by_label[entry.get("label", "?")] = by_label.get(entry.get("label", "?"), 0) + 1
        return {"count": len(entries), "by_label": by_label, "path": str(self.path)}

    def clear(self) -> int:
        count = len(self._load())
        self._entries = {}
        self._dirty = True
        self.flush()
        return count
