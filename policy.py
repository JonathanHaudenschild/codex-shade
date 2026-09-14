"""Tool classification, path rules, and the decision shared by both hosts."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import config
from .engine import Engine, Finding, highest_severity, summarize

# --------------------------------------------------------------------------
# Tool classification
# --------------------------------------------------------------------------

# Matched in order; first hit wins. Both Claude Code and Codex tool names are
# listed so one table serves both hosts.
_TOOL_CLASSES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^(WebFetch|WebSearch|Artifact|SendMessage|Agent|Task|web_search|web_fetch|browser.*)$", re.I), config.EGRESS),
    (re.compile(r"^mcp__"), config.EGRESS),
    (re.compile(r"^(Bash|BashOutput|KillShell|shell|local_shell|exec_command)$", re.I), config.SHELL),
    (re.compile(r"^(Write|Edit|MultiEdit|NotebookEdit|apply_patch|write_file|edit_file)$", re.I), config.LOCAL_WRITE),
    (re.compile(r"^(Read|Grep|Glob|NotebookRead|read_file|list_dir|view_image)$", re.I), config.LOCAL_READ),
]


def classify_tool(tool_name: str) -> str:
    for pattern, surface in _TOOL_CLASSES:
        if pattern.match(tool_name or ""):
            return surface
    # Unknown tools — very often an MCP server — are treated as egress.
    return config.EGRESS


# Fields whose value is a file path rather than free text.
_PATH_FIELDS = ("file_path", "path", "notebook_path", "filePath", "file", "target_file")

# Fields that are written verbatim to disk. Rewriting these would put a
# placeholder into the user's source file, so they are never redacted.
_DISK_FIELDS = ("content", "new_string", "old_string", "new_str", "old_str", "patch", "edits")


# --------------------------------------------------------------------------
# Glob matching for deny_paths
# --------------------------------------------------------------------------


def _glob_to_regex(pattern: str) -> re.Pattern:
    index = 0
    out = ["(?s:"]
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif char == "*":
            out.append("[^/]*")
            index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        elif char == "[":
            close = pattern.find("]", index)
            if close == -1:
                out.append(re.escape(char))
                index += 1
            else:
                out.append(pattern[index : close + 1])
                index = close + 1
        else:
            out.append(re.escape(char))
            index += 1
    out.append(")\\Z")
    return re.compile("".join(out))


class PathRules:
    """Deny-list with negation: a leading ``!`` re-allows a path."""

    def __init__(self, patterns: list[str]):
        self.deny: list[re.Pattern] = []
        self.allow: list[re.Pattern] = []
        for raw in patterns or []:
            pattern = raw.strip()
            if not pattern:
                continue
            if pattern.startswith("!"):
                self.allow.append(_glob_to_regex(pattern[1:]))
            else:
                self.deny.append(_glob_to_regex(pattern))

    def denied(self, path: str) -> bool:
        if not path:
            return False
        normalized = path.replace("\\", "/")
        if any(pattern.match(normalized) for pattern in self.allow):
            return False
        return any(pattern.match(normalized) for pattern in self.deny)


# --------------------------------------------------------------------------
# Walking tool input
# --------------------------------------------------------------------------


def collect_paths(tool_input: Any) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _PATH_FIELDS and isinstance(value, str):
                    found.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(tool_input)
    return found


def _walk_strings(node: Any, path: tuple, skip_disk_fields: bool):
    """Yield (path, value) for every string in a nested structure."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            if skip_disk_fields and key in _DISK_FIELDS:
                continue
            yield from _walk_strings(value, path + (key,), skip_disk_fields)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _walk_strings(item, path + (index,), skip_disk_fields)


def _set_in(node: Any, path: tuple, value: str) -> None:
    cursor = node
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value


# --------------------------------------------------------------------------
# Decision
# --------------------------------------------------------------------------


@dataclass
class Decision:
    action: str = config.OFF
    findings: list[Finding] = field(default_factory=list)
    updated: Any = None
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == config.BLOCK

    @property
    def rewritten(self) -> bool:
        return self.updated is not None


def _resolve_action(settings: dict, surface: str, findings: list[Finding]) -> str:
    """The strongest action any finding's severity calls for on this surface."""
    ranking = {config.OFF: 0, config.WARN: 1, config.REDACT: 2, config.BLOCK: 3}
    action = config.OFF
    for finding in findings:
        candidate = config.action_for(settings, surface, finding.severity)
        if ranking[candidate] > ranking[action]:
            action = candidate
    return action


def evaluate_text(engine: Engine, surface: str, text: str) -> Decision:
    """Apply the policy for `surface` to a single string.

    On the prompt surface a `redact` policy degrades to `block`: no host can
    rewrite a submitted prompt, so the only honest options are to refuse it or
    to let it through. The cleaned text still rides along in `updated` so the
    caller can show the user what to paste instead.
    """
    findings = engine.scan(text)
    if not findings:
        return Decision()

    action = _resolve_action(engine.config, surface, findings)
    if action in (config.OFF, config.WARN):
        return Decision(action=action, findings=findings, reason=summarize(findings))

    if action == config.REDACT and surface == config.PROMPT:
        action = config.BLOCK

    if action == config.BLOCK:
        cleaned, _ = engine.redact(text)
        return Decision(
            action=action,
            findings=findings,
            updated=cleaned if cleaned != text else None,
            reason=summarize(findings),
        )

    # redact: only rewrite severities whose policy actually asks for it.
    redact_severities = {
        severity
        for severity in ("secret", "pii", "special")
        if config.action_for(engine.config, surface, severity) == config.REDACT
    }
    updated, applied = engine.redact(text, severities=redact_severities)
    if updated == text:
        return Decision(action=config.WARN, findings=findings, reason=summarize(findings))
    return Decision(
        action=config.REDACT, findings=findings, updated=updated, reason=summarize(applied)
    )


def evaluate_tool_input(engine: Engine, tool_name: str, tool_input: Any) -> Decision:
    """Apply the policy for a tool call, returning a rewritten input if needed."""
    surface = classify_tool(tool_name)
    settings = engine.config

    # 1. Path rules — refusing to open the file is stronger than redacting it.
    rules = PathRules(settings.get("deny_paths", []))
    for path in collect_paths(tool_input):
        if rules.denied(path):
            return Decision(
                action=config.BLOCK,
                reason=(
                    f"shade: reading `{path}` is blocked by deny_paths. Its contents would "
                    "enter the model's context verbatim and could not be redacted afterwards."
                ),
            )

    # 2. Content rules. For tools that write to disk, skip the payload fields so
    #    a placeholder never lands in a real file.
    skip_disk = surface == config.LOCAL_WRITE
    strings = list(_walk_strings(tool_input, (), skip_disk))
    if not strings:
        return Decision()

    all_findings: list[Finding] = []
    rewrites: list[tuple[tuple, str]] = []
    for path, value in strings:
        findings = engine.scan(value)
        if not findings:
            continue
        all_findings.extend(findings)
        rewrites.append((path, value))

    if not all_findings:
        return Decision()

    action = _resolve_action(settings, surface, all_findings)
    if action in (config.OFF, config.WARN, config.BLOCK):
        return Decision(action=action, findings=all_findings, reason=summarize(all_findings))

    redact_severities = {
        severity
        for severity in ("secret", "pii", "special")
        if config.action_for(settings, surface, severity) == config.REDACT
    }
    updated_input = copy.deepcopy(tool_input)
    applied: list[Finding] = []
    changed = False
    for path, value in rewrites:
        new_value, hits = engine.redact(value, severities=redact_severities)
        if new_value != value:
            _set_in(updated_input, path, new_value)
            applied.extend(hits)
            changed = True

    if not changed:
        return Decision(action=config.WARN, findings=all_findings, reason=summarize(all_findings))
    return Decision(
        action=config.REDACT,
        findings=all_findings,
        updated=updated_input,
        reason=summarize(applied),
    )


def evaluate_tool_output(engine: Engine, tool_name: str, tool_response: Any) -> Decision:
    """Tool output cannot be rewritten by either host — warn or block only."""
    text = tool_response if isinstance(tool_response, str) else None
    if text is None:
        parts = [value for _, value in _walk_strings(tool_response, (), False)]
        text = "\n".join(parts)
    findings = engine.scan(text)
    if not findings:
        return Decision()
    action = _resolve_action(engine.config, config.OUTPUT, findings)
    if action == config.REDACT:
        action = config.WARN  # not supported on this surface
    return Decision(action=action, findings=findings, reason=summarize(findings))


__all__ = [
    "Decision",
    "PathRules",
    "classify_tool",
    "collect_paths",
    "evaluate_text",
    "evaluate_tool_input",
    "evaluate_tool_output",
    "highest_severity",
    "summarize",
]
