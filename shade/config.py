"""Configuration loading.

Layers, later wins:

1. built-in defaults (below)
2. ``~/.shade/config.json``          user-wide
3. ``$SHADE_CONFIG``                 explicit override path
4. ``<cwd>/.shade.json``             project-local (checked into the repo if you like)
5. ``SHADE_*`` environment variables

Actions
-------
``redact``  replace the value with a stable placeholder
``block``   refuse the prompt / tool call
``warn``    let it through, tell the user (and the model) what was found
``off``     do nothing
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

REDACT = "redact"
BLOCK = "block"
WARN = "warn"
OFF = "off"
ACTIONS = (REDACT, BLOCK, WARN, OFF)

# Tool classes. Each host adapter maps its own tool names onto these.
EGRESS = "egress"
SHELL = "shell"
LOCAL_WRITE = "local_write"
LOCAL_READ = "local_read"
OUTPUT = "output"
PROMPT = "prompt"

SEVERITIES = ("secret", "pii", "special")

DEFAULTS: dict[str, Any] = {
    "enabled": True,
    # Detector name -> bool. Only needed to flip a detector away from its default.
    "detectors": {},
    # Literal terms that are always redacted (colleague names, project code names).
    "names": [],
    # GDPR Art. 9 vocabulary. Set to [] to disable, or extend with your own.
    "special_terms": None,  # None -> use the shipped starter list
    # Strings that are never redacted, even if a detector matches them.
    "allowlist": [],
    # Email addresses at these domains are left alone (e.g. shared team aliases).
    "allow_email_domains": [],
    "policies": {
        # `redact` is NOT available on the prompt surface. Neither Claude Code
        # nor Codex exposes a field that rewrites a submitted prompt — Claude
        # Code's `UserPromptSubmit` offers `decision: "block"` and
        # `additionalContext` only, and `updatedInput` is documented by the
        # binary itself as "PreToolUse only". A policy of `redact` here silently
        # degrades to `block`, which hands the user the cleaned text to paste.
        PROMPT: {"secret": BLOCK, "pii": BLOCK, "special": WARN},
        EGRESS: {"secret": BLOCK, "pii": REDACT, "special": WARN},
        SHELL: {"secret": BLOCK, "pii": WARN, "special": WARN},
        # Never `redact` here: rewriting a Write/Edit payload would write the
        # placeholder into the user's file on disk.
        LOCAL_WRITE: {"secret": WARN, "pii": WARN, "special": OFF},
        LOCAL_READ: {"secret": WARN, "pii": OFF, "special": OFF},
        # The host cannot rewrite tool output, so `redact` is not available.
        OUTPUT: {"secret": WARN, "pii": WARN, "special": OFF},
    },
    # Reads of these paths are refused outright — the surest way to keep a file
    # out of the model's context is for it never to be opened.
    "deny_paths": [
        "**/.env",
        "**/.env.*",
        "!**/.env.example",
        "!**/.env.sample",
        "!**/.env.template",
        "**/*.pem",
        "**/*.key",
        "**/*.p12",
        "**/*.pfx",
        "**/*.keystore",
        "**/id_rsa",
        "**/id_ed25519",
        "**/id_ecdsa",
        "**/.ssh/**",
        "**/.aws/credentials",
        "**/.npmrc",
        "**/.pypirc",
        "**/.netrc",
        "**/.git-credentials",
        "**/secrets.*",
        "**/*secret*.json",
        "**/*credentials*.json",
        "**/service-account*.json",
        "**/auth.json",
        "**/*.sqlite",
        "**/*.dump",
    ],
    "vault": {
        "enabled": True,
        # Secrets are deliberately absent: a leaked key should not be copied into
        # a second file on disk just so it can be un-redacted later.
        "store_severities": ["pii", "special"],
        "ttl_days": 30,
    },
    # Append-only JSONL record of what was caught. Stores categories and masked
    # previews, never raw values.
    "audit_log": True,
    # Bytes of a single tool payload to scan. Large binaries are skipped.
    "max_scan_bytes": 400_000,
}

_ENV_MAP = {
    "SHADE_ENABLED": ("enabled", "bool"),
    "SHADE_PROMPT_POLICY": (("policies", PROMPT), "policy"),
    "SHADE_EGRESS_POLICY": (("policies", EGRESS), "policy"),
    "SHADE_SHELL_POLICY": (("policies", SHELL), "policy"),
    "SHADE_OUTPUT_POLICY": (("policies", OUTPUT), "policy"),
    "SHADE_VAULT": (("vault", "enabled"), "bool"),
    "SHADE_AUDIT_LOG": ("audit_log", "bool"),
}


def home() -> Path:
    return Path(os.environ.get("SHADE_HOME") or Path.home() / ".shade")


def _as_bool(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _deep_merge(base: dict, overlay: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _read_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _apply_proxy_coordination(config: dict) -> dict:
    """When the egress proxy is in front, stand the prompt hook down.

    The two layers overlap, and the proxy is strictly better at this one job:
    it can substitute placeholders into the prompt, which no hook can do. Left
    enabled, the hook would refuse the prompt *before* the proxy ever saw it —
    so you would get a refusal where you could have had a clean substitution.

    Everything else stays: `deny_paths` still refuses to open a credentials
    file, and blocking a secret outright is still stronger than redacting it.
    An explicit SHADE_PROMPT_POLICY still wins, since it is applied after this.
    """
    if not _as_bool(os.environ.get("SHADE_PROXY", "")):
        return config
    config.setdefault("policies", {})[PROMPT] = {severity: OFF for severity in SEVERITIES}
    return config


def _apply_env(config: dict) -> dict:
    for env_name, (target, kind) in _ENV_MAP.items():
        raw = os.environ.get(env_name)
        if raw is None:
            continue
        if kind == "bool":
            value: Any = _as_bool(raw)
        else:
            if raw not in ACTIONS:
                continue
            # A bare action name sets every severity for that surface.
            value = {severity: raw for severity in SEVERITIES}

        if isinstance(target, tuple):
            cursor = config
            for key in target[:-1]:
                cursor = cursor.setdefault(key, {})
            if kind == "policy" and isinstance(cursor.get(target[-1]), dict):
                cursor[target[-1]].update(value)
            else:
                cursor[target[-1]] = value
        else:
            config[target] = value
    return config


def load(cwd: str | os.PathLike | None = None) -> dict:
    config = copy.deepcopy(DEFAULTS)

    for candidate in (
        home() / "config.json",
        Path(os.environ["SHADE_CONFIG"]) if os.environ.get("SHADE_CONFIG") else None,
        Path(cwd or os.getcwd()) / ".shade.json",
    ):
        if candidate is not None and candidate.is_file():
            config = _deep_merge(config, _read_json(candidate))

    return _apply_env(_apply_proxy_coordination(config))


def action_for(config: dict, surface: str, severity: str) -> str:
    policies = config.get("policies", {})
    surface_policy = policies.get(surface) or DEFAULTS["policies"].get(surface, {})
    if isinstance(surface_policy, str):
        return surface_policy if surface_policy in ACTIONS else OFF
    action = surface_policy.get(severity, OFF)
    return action if action in ACTIONS else OFF
