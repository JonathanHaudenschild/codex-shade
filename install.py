#!/usr/bin/env python3
"""Install shade's hooks into ``~/.codex/hooks.json``.

Codex has no `${PLUGIN_ROOT}` substitution, so the absolute path to this
checkout is baked in at install time. Existing hooks in the file are preserved:
entries are merged per event, and a previous shade install is replaced rather
than duplicated.

Usage:  python3 codex/install.py [--uninstall] [--scope user|project] [--dir PATH]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
MARKER = "shade"

EVENTS = {
    "SessionStart": ("session_start.py", None, "Loading shade privacy filter", 10),
    "UserPromptSubmit": ("user_prompt.py", None, "Screening prompt for personal data", 15),
    "PreToolUse": ("pre_tool.py", "*", "Screening tool input", 15),
    "PostToolUse": ("post_tool.py", "*", None, 15),
}


def entry_for(script: str, matcher: str | None, status: str | None, timeout: int) -> dict:
    hook = {
        "type": "command",
        "command": f'python3 "{REPO_ROOT / "hooks" / script}"',
        "timeout": timeout,
        "source": MARKER,
    }
    if status:
        hook["statusMessage"] = status
    group: dict = {"hooks": [hook]}
    if matcher:
        group["matcher"] = matcher
    return group


def is_ours(group: dict) -> bool:
    return any(hook.get("source") == MARKER for hook in group.get("hooks", []))


def load(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        sys.exit(f"error: {path} is not valid JSON ({error}). Fix or move it, then re-run.")
    return data if isinstance(data, dict) else {}


def write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        backup = path.with_suffix(".json.bak")
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"  backed up existing config to {backup}")
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def install_prompts(codex_home: Path) -> None:
    """Copy the `/shade-*` custom prompts alongside the hooks."""
    source = REPO_ROOT / "prompts"
    if not source.is_dir():
        return
    destination = codex_home / "prompts"
    destination.mkdir(parents=True, exist_ok=True)
    for prompt in sorted(source.glob("*.md")):
        (destination / prompt.name).write_text(
            prompt.read_text(encoding="utf-8"), encoding="utf-8"
        )
        print(f"  prompt /{prompt.stem}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--scope", choices=["user", "project"], default="user")
    parser.add_argument("--dir", help="project directory, for --scope project")
    args = parser.parse_args()

    if args.scope == "user":
        target = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / "hooks.json"
    else:
        target = Path(args.dir or os.getcwd()) / ".codex" / "hooks.json"

    data = load(target)
    hooks = data.setdefault("hooks", {})

    # Drop any previous shade install first, so re-running is idempotent.
    for event in list(hooks):
        remaining = [group for group in hooks[event] if not is_ours(group)]
        if remaining:
            hooks[event] = remaining
        else:
            del hooks[event]

    if args.uninstall:
        if not hooks:
            data.pop("hooks", None)
        write(target, data)
        print(f"shade: removed from {target}")
        return 0

    for event, (script, matcher, status, timeout) in EVENTS.items():
        hooks.setdefault(event, []).append(entry_for(script, matcher, status, timeout))

    data.setdefault("description", "Codex lifecycle hooks")
    write(target, data)
    install_prompts(target.parent)
    print(f"shade: installed into {target}")
    print()
    print("Codex asks you to trust a hook definition the first time it runs —")
    print("review the entries above and approve them when prompted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
