#!/usr/bin/env python3
"""UserPromptSubmit for Codex.

Codex cannot rewrite a prompt, so `redact` is enforced as a refusal that shows
the user the cleaned text. The block reason contains only the redacted version
and category names — never a raw value.
"""

from __future__ import annotations

import re

from _bootstrap import config, emit, engine_for, model_note, policy, run

# `/shade:allow support@example.org` must reach the CLI intact — redacting the
# argument would allowlist a placeholder instead of the value the user named.
SELF_COMMAND = re.compile(r"^\s*/shade[:\-]?", re.IGNORECASE)

EVENT = "UserPromptSubmit"


def main(event: dict) -> None:
    prompt = event.get("prompt") or ""
    if not prompt.strip() or SELF_COMMAND.match(prompt):
        return

    engine = engine_for(event)
    if not engine.config.get("enabled", True):
        return

    decision = policy.evaluate_text(engine, config.PROMPT, prompt)
    if decision.action == config.OFF or not decision.findings:
        return

    engine.log(EVENT, config.PROMPT, decision.action, decision.findings, {"host": "codex"})

    if decision.action in (config.BLOCK, config.REDACT):
        if decision.action == config.REDACT and decision.rewritten:
            reason = (
                f"shade blocked this prompt: it contains {decision.reason}.\n\n"
                "A hook cannot rewrite a prompt in place, only refuse it. "
                "Here is the same message with the sensitive parts replaced — "
                "send this instead:\n\n"
                f"{decision.updated}\n"
            )
        else:
            reason = (
                f"shade blocked this prompt: it contains {decision.reason}.\n"
                "The turn was stopped. Run `shade redact 'your text'` and send the result instead."
            )
        emit(decision="block", reason=reason)

    emit(
        hook_specific={"hookEventName": EVENT, "additionalContext": model_note(decision)},
        system_message=f"shade: {decision.reason} in your prompt was NOT removed (policy: warn)",
    )


if __name__ == "__main__":
    run(main)
