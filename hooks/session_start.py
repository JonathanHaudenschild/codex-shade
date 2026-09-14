#!/usr/bin/env python3
"""SessionStart for Codex — tell the model how to treat placeholders."""

from __future__ import annotations

from _bootstrap import emit, engine_for, run

EVENT = "SessionStart"

NOTE = """\
[shade] A local privacy filter is active in this session.

Personal data and credentials are replaced before they reach you, with stable
placeholders of the form <LABEL_xxxxxx> — for example <EMAIL_a1b2c3>,
<PERSON_4f9c20>, <IBAN_77b105>.

How to handle them:
- Treat each placeholder as an opaque but stable identifier. The same
  placeholder always refers to the same real value.
- Never guess, reconstruct or infer the value behind a placeholder, and never
  ask the user to type the original "so you can help better".
- Keep placeholders verbatim in any code, config or text you produce. The user
  restores them locally with `shade reveal`.
- File contents and command output arrive unredacted. If you notice credentials
  or personal data there, do not echo them back or send them anywhere.
"""


def main(event: dict) -> None:
    engine = engine_for(event)
    if not engine.config.get("enabled", True):
        return
    emit(hook_specific={"hookEventName": EVENT, "additionalContext": NOTE})


if __name__ == "__main__":
    run(main)
