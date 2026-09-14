#!/usr/bin/env python3
"""PreToolUse for Codex — same policy engine, Codex's output schema."""

from __future__ import annotations

from _bootstrap import config, emit, engine_for, model_note, policy, run

EVENT = "PreToolUse"


def main(event: dict) -> None:
    tool_name = event.get("tool_name") or ""
    tool_input = event.get("tool_input")
    if tool_input is None:
        return

    engine = engine_for(event)
    if not engine.config.get("enabled", True):
        return

    decision = policy.evaluate_tool_input(engine, tool_name, tool_input)
    if decision.action == config.OFF:
        return

    surface = policy.classify_tool(tool_name)
    engine.log(EVENT, surface, decision.action, decision.findings, {"tool": tool_name, "host": "codex"})

    if decision.action == config.BLOCK:
        reason = decision.reason
        if decision.findings:
            reason = (
                f"shade: this {tool_name} call carries {decision.reason}. "
                f"Blocked because the policy for `{surface}` is `block`. "
                "Reference an environment variable instead of the literal value."
            )
        emit(
            hook_specific={
                "hookEventName": EVENT,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        )

    if decision.action == config.REDACT and decision.rewritten:
        # No permissionDecision is set, so Codex's normal approval flow still
        # applies — the call simply carries placeholders now.
        emit(
            hook_specific={
                "hookEventName": EVENT,
                "updatedInput": decision.updated,
                "additionalContext": model_note(decision),
            },
            system_message=f"shade: redacted {decision.reason} in {tool_name} input",
        )

    emit(
        hook_specific={"hookEventName": EVENT, "additionalContext": model_note(decision)},
        system_message=f"shade: found {decision.reason} in {tool_name} input",
    )


if __name__ == "__main__":
    run(main)
