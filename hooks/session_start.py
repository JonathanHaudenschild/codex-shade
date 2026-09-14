#!/usr/bin/env python3
"""SessionStart for Codex — tell the model how to treat placeholders."""

from __future__ import annotations

import os

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


DRY_RUN_WARNING = """\
[shade] NOTE: the privacy proxy is running in DRY-RUN. It reports what it would
redact but forwards everything unchanged, so values in this session are NOT
redacted. Do not tell the user their data is being filtered. The prompt hook
remains active and will still refuse a prompt containing credentials or personal
data.
"""

PROXY_NOTE = """\
[shade] A local privacy filter is active, with the egress proxy in front.

Personal data and credentials are replaced before they reach you, with stable
placeholders of the form <LABEL_xxxxxx>. This covers the prompt AND the contents
of files and command output.

The substitution is a ROUND TRIP: any placeholder you write is replaced with the
real value again before the user sees your reply. So do not narrate the
redaction -- saying "I only have a placeholder" while writing that placeholder
reaches the user as a sentence naming the real value and then denying you can
see it, which looks like the filter is broken. Use placeholders naturally:

  good:  "I'll add <EMAIL_a1b2c3> to the config."
  bad:   "I see <EMAIL_a1b2c3>, but it's redacted so I can't read it."

Never guess or reconstruct the value behind a placeholder, and keep placeholders
verbatim in code and config you write.
"""


def main(event: dict) -> None:
    engine = engine_for(event)
    if not engine.config.get("enabled", True):
        return
    mode = os.environ.get("SHADE_PROXY_MODE")
    note = {"dry-run": DRY_RUN_WARNING, "active": PROXY_NOTE}.get(mode, NOTE)
    emit(hook_specific={"hookEventName": EVENT, "additionalContext": note})


if __name__ == "__main__":
    run(main)
