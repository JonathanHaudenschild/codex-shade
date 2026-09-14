"""Shared plumbing for the Codex hook scripts.

Codex's hook contract differs from Claude Code's in one way that matters a great
deal here: **`UserPromptSubmit` cannot rewrite the prompt.** It can only allow or
block. So on Codex, a prompt containing personal data is refused, and the block
message hands the user the already-redacted text to paste instead. `PreToolUse`
*can* rewrite, so tool-call redaction behaves the same on both hosts.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shade import config, policy  # noqa: E402
from shade.engine import Engine  # noqa: E402


def read_event() -> dict:
    try:
        raw = sys.stdin.read()
    except Exception:
        return {}
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def emit(
    *,
    hook_specific: dict[str, Any] | None = None,
    decision: str | None = None,
    reason: str | None = None,
    system_message: str | None = None,
    keep_going: bool | None = None,
) -> None:
    payload: dict[str, Any] = {}
    if decision:
        payload["decision"] = decision
    if reason:
        payload["reason"] = reason
    if system_message:
        payload["systemMessage"] = system_message
    if keep_going is not None:
        payload["continue"] = keep_going
    if hook_specific:
        payload["hookSpecificOutput"] = hook_specific
    if payload:
        sys.stdout.write(json.dumps(payload))
    raise SystemExit(0)


def engine_for(event: dict) -> Engine:
    return Engine(cwd=event.get("cwd") or os.getcwd())


def model_note(decision: policy.Decision) -> str:
    if decision.action == config.REDACT:
        return (
            f"[shade] Sensitive values ({decision.reason}) were replaced with placeholders "
            "of the form <LABEL_xxxxxx> before this reached you. Treat each placeholder as an "
            "opaque, stable identifier, keep it verbatim in anything you produce, and never try "
            "to reconstruct the original value or ask the user for it."
        )
    return (
        f"[shade] Sensitive values ({decision.reason}) are present here and were not removed. "
        "Do not copy them into files, commands, commit messages, or network requests."
    )


def run(entry: Callable[[dict], None]) -> None:
    event = read_event()
    try:
        entry(event)
    except SystemExit:
        raise
    except Exception:
        if os.environ.get("SHADE_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        raise SystemExit(0)
    raise SystemExit(0)
