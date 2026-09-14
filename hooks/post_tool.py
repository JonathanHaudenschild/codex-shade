#!/usr/bin/env python3
"""PostToolUse for Codex — detection and audit only.

Codex cannot rewrite tool output either. Prevention lives in `deny_paths`,
enforced by `cx_pre_tool.py` before the file is ever opened.
"""

from __future__ import annotations

from _bootstrap import config, emit, engine_for, policy, run

EVENT = "PostToolUse"


def main(event: dict) -> None:
    tool_response = event.get("tool_response")
    if tool_response is None:
        return

    engine = engine_for(event)
    if not engine.config.get("enabled", True):
        return

    tool_name = event.get("tool_name") or ""
    decision = policy.evaluate_tool_output(engine, tool_name, tool_response)
    if decision.action == config.OFF or not decision.findings:
        return

    engine.log(EVENT, config.OUTPUT, decision.action, decision.findings, {"tool": tool_name, "host": "codex"})

    paths = policy.collect_paths(event.get("tool_input") or {})
    origin = f" (from {paths[0]})" if paths else ""

    if decision.action == config.BLOCK:
        emit(
            decision="block",
            keep_going=False,
            reason=(
                f"shade: the output of {tool_name}{origin} contains {decision.reason}. "
                "It is already in context — start a fresh thread if that is not acceptable, "
                "and add the path to deny_paths so the read is refused next time."
            ),
        )

    emit(
        hook_specific={
            "hookEventName": EVENT,
            "additionalContext": (
                f"[shade] The output of {tool_name}{origin} contains {decision.reason}. "
                "This could not be redacted — tool output is not rewritable. Do not repeat these "
                "values back, do not copy them into files, commands, commit messages or network "
                "requests."
            ),
        },
        system_message=f"shade: {tool_name} output contains {decision.reason} — already in context",
    )


if __name__ == "__main__":
    run(main)
