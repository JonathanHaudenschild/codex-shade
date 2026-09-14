"""Command line interface: ``shade <command>``."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from . import __version__, config
from .engine import Engine, summarize
from .policy import PathRules, classify_tool


def _read_input(args) -> str:
    if args.text:
        return " ".join(args.text)
    if args.file:
        return Path(args.file).read_text(encoding="utf-8", errors="replace")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _engine() -> Engine:
    return Engine()


def cmd_scan(args) -> int:
    text = _read_input(args)
    engine = _engine()
    findings = engine.scan(text)
    if args.json:
        print(json.dumps([finding.as_dict() for finding in findings], indent=2))
        return 1 if findings else 0
    if not findings:
        print("shade: no sensitive values found")
        return 0
    print(f"shade: {len(findings)} finding(s)")
    for finding in findings:
        line = text.count("\n", 0, finding.start) + 1
        print(f"  line {line:>4}  {finding.severity:<7} {finding.label:<28} {finding.preview}")
    return 1


def cmd_redact(args) -> int:
    text = _read_input(args)
    engine = _engine()
    severities = set(args.severity) if args.severity else None
    redacted, applied = engine.redact(text, severities=severities)
    sys.stdout.write(redacted)
    if applied and sys.stdout.isatty():
        sys.stderr.write(f"\nshade: redacted {summarize(applied)}\n")
    return 0


def cmd_reveal(args) -> int:
    """Restore placeholders from the local vault.

    Writes to a file by default. Printing restored personal data to stdout is
    exactly the thing this tool exists to prevent when the caller is an agent,
    so it takes an explicit --stdout.
    """
    text = _read_input(args)
    engine = _engine()
    restored, count = engine.reveal(text)
    if args.stdout:
        sys.stdout.write(restored)
        return 0
    destination = Path(args.out) if args.out else Path(
        tempfile.mkdtemp(prefix="shade-reveal-")
    ) / "revealed.txt"
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(restored)
    print(f"shade: restored {count} placeholder(s) -> {destination}")
    print("shade: open it yourself; the contents were not printed here on purpose.")
    return 0


def cmd_status(args) -> int:
    engine = _engine()
    settings = engine.config
    stats = engine.vault.stats()
    print(f"shade {__version__}")
    print(f"  enabled        {settings.get('enabled', True)}")
    print(f"  home           {config.home()}")
    print(f"  detectors      {len(engine._detectors)} active")
    print(f"  names          {len(settings.get('names') or [])} configured")
    print(f"  vault          {stats['count']} entries at {stats['path']}")
    print("  policies")
    for surface in (config.PROMPT, config.EGRESS, config.SHELL, config.LOCAL_WRITE, config.LOCAL_READ, config.OUTPUT):
        policy = settings.get("policies", {}).get(surface, {})
        rendered = " ".join(f"{key}={value}" for key, value in policy.items())
        print(f"    {surface:<12} {rendered}")
    if stats["by_label"]:
        print("  vault contents by label")
        for label, count in sorted(stats["by_label"].items(), key=lambda item: -item[1]):
            print(f"    {label:<28} {count}")
    return 0


def cmd_check_path(args) -> int:
    engine = _engine()
    rules = PathRules(engine.config.get("deny_paths", []))
    exit_code = 0
    for path in args.paths:
        denied = rules.denied(path)
        print(f"{'DENY ' if denied else 'allow'}  {path}")
        exit_code |= 1 if denied else 0
    return exit_code


def cmd_classify(args) -> int:
    for tool in args.tools:
        print(f"{tool:<24} {classify_tool(tool)}")
    return 0


def _user_config_path() -> Path:
    path = config.home() / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _update_user_config(key: str, values: list[str], remove: bool) -> int:
    path = _user_config_path()
    data = {}
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
    current = list(data.get(key) or [])
    for value in values:
        value = value.strip()
        if not value:
            continue
        if remove:
            current = [item for item in current if item.lower() != value.lower()]
        elif not any(item.lower() == value.lower() for item in current):
            current.append(value)
    data[key] = current
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    print(f"shade: {key} now has {len(current)} entr{'y' if len(current) == 1 else 'ies'} ({path})")
    return 0


def cmd_name(args) -> int:
    return _update_user_config("names", args.values, args.remove)


def cmd_allow(args) -> int:
    return _update_user_config("allowlist", args.values, args.remove)


def cmd_vault(args) -> int:
    engine = _engine()
    if args.clear:
        removed = engine.vault.clear()
        print(f"shade: cleared {removed} vault entries")
        return 0
    stats = engine.vault.stats()
    print(json.dumps({"count": stats["count"], "by_label": stats["by_label"], "path": stats["path"]}, indent=2))
    return 0


def cmd_log(args) -> int:
    path = config.home() / "audit.jsonl"
    if not path.is_file():
        print("shade: no audit log yet")
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines[-args.tail :]:
        print(line)
    return 0


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

# Hook capabilities are not introspectable at runtime: a host that does not
# understand a field ignores it in silence, and the hook has no way to learn
# that its rewrite was dropped. That is exactly how shade once announced
# "redacted" on a build whose UserPromptSubmit could only block. So the probe
# looks for the field names inside the host binary itself and reports what is
# really enforced.
_PROBE_FIELDS = ("updatedInput", "updatedPrompt", "permissionDecision", "additionalContext")

# This engine is vendored into two repos — claude-shade and codex-shade — which
# differ only in their hook adapter. Doctor picks the adapter by which scripts
# are present, so one file serves both.
_ADAPTERS = {
    "claude": {
        "title": "Claude Code",
        "command": "claude",
        "prompt": "hooks/cc_user_prompt.py",
        "pre_tool": "hooks/cc_pre_tool.py",
        "sibling": "codex-shade (https://github.com/JonathanHaudenschild/codex-shade)",
    },
    "codex": {
        "title": "Codex CLI",
        "command": "codex",
        "prompt": "hooks/user_prompt.py",
        "pre_tool": "hooks/pre_tool.py",
        "sibling": "claude-shade (https://github.com/JonathanHaudenschild/claude-shade)",
    },
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _local_adapter() -> tuple[Optional[str], dict]:
    root = _repo_root()
    for key, adapter in _ADAPTERS.items():
        if (root / adapter["pre_tool"]).is_file():
            return key, adapter
    return None, {}


def _binary_contains(path: Path, needles: tuple[str, ...]) -> dict[str, bool]:
    found = {needle: False for needle in needles}
    encoded = {needle: needle.encode() for needle in needles}
    longest = max(len(value) for value in encoded.values())
    try:
        with path.open("rb") as handle:
            tail = b""
            while True:
                chunk = handle.read(4 << 20)
                if not chunk:
                    break
                window = tail + chunk
                for needle, value in encoded.items():
                    if not found[needle] and value in window:
                        found[needle] = True
                if all(found.values()):
                    break
                tail = window[-longest:]
    except OSError:
        pass
    return found


def _resolve_host_binary(command: str) -> Optional[Path]:
    located = shutil.which(command)
    if not located:
        return None
    path = Path(located).resolve()
    if path.is_file() and path.stat().st_size > 1_000_000:
        return path
    for candidate in path.parent.glob("*.exe"):
        if candidate.stat().st_size > 1_000_000:
            return candidate
    return path


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        return result.stdout + result.stderr
    except (OSError, subprocess.SubprocessError):
        return ""


def _report_install_drift() -> int:
    """Compare the installed Claude Code plugin copy against this checkout.

    `claude plugin install` copies the plugin into a versioned cache directory
    and runs *that*; editing the checkout changes nothing until you update.
    `claude plugin list` reads the marketplace source, so it can report
    `enabled` while a stale copy is what actually loads.
    """
    record = Path.home() / ".claude" / "plugins" / "installed_plugins.json"
    if not record.is_file():
        return 0
    try:
        entries = json.loads(record.read_text(encoding="utf-8")).get("plugins", {})
    except ValueError:
        return 0
    installs = entries.get("shade@shade") or []
    if not installs:
        return 0

    source_root = _repo_root()
    drift = 0
    for install in installs:
        install_root = Path(install.get("installPath", ""))
        print(f"  installed copy {install_root}")
        if not install_root.is_dir():
            print("    MISSING — reinstall with: claude plugin install shade@shade")
            drift += 1
            continue
        tracked = [
            path
            for path in list((source_root / "hooks").rglob("*.py"))
            + list((source_root / "shade").rglob("*.py"))
            + [source_root / ".claude-plugin" / "plugin.json", source_root / "hooks" / "hooks.json"]
            if path.is_file()
        ]
        stale = [
            str(path.relative_to(source_root))
            for path in tracked
            if not (install_root / path.relative_to(source_root)).is_file()
            or (install_root / path.relative_to(source_root)).read_bytes() != path.read_bytes()
        ]
        if stale:
            print(f"    STALE — {len(stale)} file(s) differ from this checkout, e.g. {sorted(stale)[0]}")
            print("    the copy above is what actually runs. Refresh it with:")
            print("      bump plugin.json version, then")
            print("      claude plugin marketplace update shade && claude plugin update shade@shade")
            drift += 1
        else:
            print("    matches this checkout")
    return drift


def _check_claude(adapter: dict) -> int:
    problems = 0
    binary = _resolve_host_binary(adapter["command"])
    if binary is None:
        print("  not installed")
        return 0
    print(f"  binary         {binary}")
    found = _binary_contains(binary, _PROBE_FIELDS)
    for field_name in _PROBE_FIELDS:
        print(f"    {field_name:<20} {'yes' if found[field_name] else 'NO '}")
    if not found["updatedPrompt"]:
        print("  -> this build cannot rewrite a submitted prompt.")
        print("     A `redact` prompt policy degrades to `block`; nothing is")
        print("     silently let through, but you paste the cleaned text yourself.")
    if not found["updatedInput"]:
        print("  !! this build cannot rewrite tool input either — egress redaction")
        print("     is unavailable. Set the egress policy to `block`.")
        problems += 1

    listing = _run([adapter["command"], "plugin", "list"])
    for block in listing.split("\u276f"):
        if "shade@" in block:
            status = "enabled" if "enabled" in block else "NOT LOADED"
            print(f"  plugin         {status}")
            if status != "enabled":
                problems += 1
                for line in block.splitlines():
                    if "Error" in line:
                        print(f"    {line.strip()}")
            break
    else:
        print("  plugin         not installed")
    return problems + _report_install_drift()


def _check_codex(adapter: dict) -> int:
    problems = 0
    if not shutil.which(adapter["command"]):
        print("  not installed")
        return 0
    codex_home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    hooks_file = codex_home / "hooks.json"
    if not hooks_file.is_file():
        print(f"  hooks          not installed ({hooks_file} missing)")
        return 1
    try:
        data = json.loads(hooks_file.read_text(encoding="utf-8"))
    except ValueError:
        print(f"  hooks          {hooks_file} is not valid JSON")
        return 1
    ours = [
        (event, hook)
        for event, groups in (data.get("hooks") or {}).items()
        for group in groups
        for hook in group.get("hooks", [])
        if hook.get("source") == "shade"
    ]
    print(f"  hooks          {', '.join(sorted({e for e, _ in ours})) or 'none registered'}")
    if len({e for e, _ in ours}) < 4:
        problems += 1
    # The registered command embeds an absolute path; if this checkout moved,
    # Codex is still running whatever lives at the old location.
    root = str(_repo_root())
    elsewhere = [hook["command"] for _, hook in ours if root not in hook.get("command", "")]
    if elsewhere:
        print("    STALE — registered hooks point outside this checkout:")
        print(f"      {elsewhere[0]}")
        print("    re-register with: python3 install.py")
        problems += 1
    elif ours:
        print("    paths match this checkout")
    print("  prompt rewrite NO  (documented: UserPromptSubmit can block only)")
    return problems


def cmd_doctor(args) -> int:
    problems = 0
    print(f"shade {__version__}   python {sys.version.split()[0]}")
    print(f"  config home    {config.home()}")
    engine = _engine()
    print(f"  enabled        {engine.config.get('enabled', True)}")

    host, adapter = _local_adapter()
    if host is None:
        print("\nNo hook adapter found in this checkout.")
        return 1

    print(f"\n{adapter['title']}")
    problems += _check_claude(adapter) if host == "claude" else _check_codex(adapter)

    # -- end to end -------------------------------------------------------
    print("\nEnd-to-end")
    root = _repo_root()
    prompt_expectation = "exit2" if host == "claude" else '"decision": "block"'
    checks = [
        ("Read of .env is denied", adapter["pre_tool"],
         {"hook_event_name": "PreToolUse", "tool_name": "Read",
          "tool_input": {"file_path": "/tmp/x/.env"}}, '"permissionDecision": "deny"'),
        ("egress PII is rewritten", adapter["pre_tool"],
         {"hook_event_name": "PreToolUse", "tool_name": "WebFetch",
          "tool_input": {"prompt": "mail ada@example.com"}}, "updatedInput"),
        ("prompt with PII is blocked", adapter["prompt"],
         {"hook_event_name": "UserPromptSubmit", "prompt": "mail ada@example.com"},
         prompt_expectation),
    ]
    for label, script, payload, expected in checks:
        target = root / script
        if not target.is_file():
            print(f"  {label:<28} SKIP (missing {script})")
            continue
        try:
            result = subprocess.run(
                [sys.executable, str(target)], input=json.dumps(payload),
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            print(f"  {label:<28} FAIL (could not run)")
            problems += 1
            continue
        ok = result.returncode == 2 if expected == "exit2" else expected in result.stdout
        print(f"  {label:<28} {'ok' if ok else 'FAIL'}")
        if not ok:
            problems += 1

    print(f"\nThe other half of this pair is {adapter['sibling']}")
    print()
    print(f"shade: {problems} problem(s) found" if problems else "shade: all checks passed")
    return 1 if problems else 0


# --------------------------------------------------------------------------
# proxy
# --------------------------------------------------------------------------


def _proxy_settings(args) -> "proxy_module.ProxySettings":
    from . import proxy as proxy_module

    return proxy_module.ProxySettings(
        upstream=args.upstream,
        dry_run=args.dry_run,
        fail_open=args.fail_open,
        restore=not args.no_restore,
        verbose=getattr(args, "verbose", False),
    )


def cmd_proxy(args) -> int:
    from . import proxy as proxy_module

    engine = _engine()

    def report(event: dict) -> None:
        kind = event.get("event")
        if kind in ("redact", "scan"):
            verb = "would redact" if kind == "scan" else "redacted"
            print(f"  {verb}: {event['summary']}  ({event['path']})", flush=True)
        elif kind:
            print(f"  {kind}: {event.get('detail', '')}", flush=True)

    settings = _proxy_settings(args)
    server = proxy_module.serve(engine, args.port, settings, report)
    host, port = server.server_address
    print(f"shade proxy listening on http://{host}:{port}  ->  {settings.upstream}")
    if settings.dry_run:
        print("  DRY RUN — NOTHING IS PROTECTED IN THIS SESSION.")
        print("    traffic is forwarded unchanged, and hook policies are relaxed to")
        print("    `warn` so real prompts reach the proxy and can be reported on.")
        print("    deny_paths still blocks credential-file reads.")
        print("    Do not use dry run for work that actually needs protecting.")
    else:
        print(f"  redacting requests; {'restoring' if settings.restore else 'NOT restoring'} responses")
        print(f"  on redaction failure: {'forward anyway (--fail-open)' if settings.fail_open else 'refuse to send'}")
    print()
    print("  point an agent at it:")
    print(f"    ANTHROPIC_BASE_URL=http://{host}:{port} claude")
    print("  or let shade do it:   shade run claude")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshade proxy stopped")
    finally:
        server.server_close()
    return 0


def cmd_run(args) -> int:
    """Run an agent with its API traffic routed through the proxy."""
    from . import proxy as proxy_module
    import threading

    if not args.command:
        print("usage: shade run <command> [args...]   e.g. shade run claude", file=sys.stderr)
        return 2

    engine = _engine()
    events: list[dict] = []
    settings = _proxy_settings(args)
    server = proxy_module.serve(engine, 0, settings, events.append)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    environment = dict(os.environ)
    base = f"http://{host}:{port}"
    # ANTHROPIC_BASE_URL is verified to work with Claude Code, including with
    # subscription OAuth. OPENAI_BASE_URL is set opportunistically for other
    # clients; it is not a claim that every agent honours it.
    environment["ANTHROPIC_BASE_URL"] = base
    environment.setdefault("OPENAI_BASE_URL", base)
    # Tells the hooks to stand down on the prompt surface — see
    # config._apply_proxy_coordination.
    environment["SHADE_PROXY"] = "1"
    environment["SHADE_PROXY_MODE"] = "dry-run" if settings.dry_run else "active"

    program = os.path.basename(args.command[0])
    if program.startswith("codex"):
        print(
            "shade: Codex does not read ANTHROPIC_BASE_URL. Point it here with a\n"
            f"       [model_providers.shade] base_url = \"{base}\" entry in config.toml,\n"
            "       or use `shade proxy` standalone. Proceeding anyway.",
            file=sys.stderr,
        )

    if settings.dry_run:
        print(
            f"shade: proxy DRY RUN on port {port} — NOTHING IS PROTECTED this session.\n"
            "       Hook policies are relaxed to `warn` so real traffic reaches the proxy;\n"
            "       deny_paths still blocks credential-file reads. Observation only.",
            file=sys.stderr,
        )
    else:
        print(f"shade: proxy active on port {port}; starting {args.command[0]}", file=sys.stderr)

    try:
        completed = subprocess.run(args.command, env=environment)
        code = completed.returncode
    except FileNotFoundError:
        print(f"shade: {args.command[0]} not found on PATH", file=sys.stderr)
        code = 127
    except KeyboardInterrupt:
        code = 130
    finally:
        server.shutdown()
        server.server_close()

    # Summarise afterwards rather than during: printing mid-session would
    # scribble over an interactive agent's UI.
    redactions = [e for e in events if e.get("event") in ("redact", "scan")]
    errors = [e for e in events if e.get("event") in ("error", "upstream_error")]
    print(file=sys.stderr)
    if redactions:
        counts: dict[str, int] = {}
        for event in redactions:
            for finding in event.get("findings", []):
                counts[finding.label] = counts.get(finding.label, 0) + 1
        verb = "would have redacted" if settings.dry_run else "redacted"
        rendered = ", ".join(f"{label}x{count}" for label, count in sorted(counts.items(), key=lambda i: -i[1]))
        print(f"shade: {verb} {rendered} across {len(redactions)} request(s)", file=sys.stderr)
    else:
        print("shade: nothing sensitive found in outbound traffic", file=sys.stderr)
    for error in errors:
        print(f"shade: {error['event']} — {error.get('detail', '')}", file=sys.stderr)
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shade", description=__doc__)
    parser.add_argument("--version", action="version", version=f"shade {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_input_args(sub):
        sub.add_argument("text", nargs="*", help="text to process (or pipe on stdin)")
        sub.add_argument("-f", "--file", help="read from a file instead")

    scan = subparsers.add_parser("scan", help="report sensitive values without changing anything")
    add_input_args(scan)
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)

    redact = subparsers.add_parser("redact", help="replace sensitive values with placeholders")
    add_input_args(redact)
    redact.add_argument(
        "--severity", action="append", choices=["secret", "pii", "special"],
        help="limit redaction to these severities (repeatable)",
    )
    redact.set_defaults(func=cmd_redact)

    reveal = subparsers.add_parser("reveal", help="restore placeholders from the local vault")
    add_input_args(reveal)
    reveal.add_argument("-o", "--out", help="write here instead of a temp file")
    reveal.add_argument("--stdout", action="store_true", help="print the restored text")
    reveal.set_defaults(func=cmd_reveal)

    status = subparsers.add_parser("status", help="show the effective configuration")
    status.set_defaults(func=cmd_status)

    check_path = subparsers.add_parser("check-path", help="test paths against deny_paths")
    check_path.add_argument("paths", nargs="+")
    check_path.set_defaults(func=cmd_check_path)

    classify = subparsers.add_parser("classify", help="show which policy surface a tool falls under")
    classify.add_argument("tools", nargs="+")
    classify.set_defaults(func=cmd_classify)

    name = subparsers.add_parser("name", help="add names that must always be pseudonymised")
    name.add_argument("values", nargs="+")
    name.add_argument("--remove", action="store_true")
    name.set_defaults(func=cmd_name)

    allow = subparsers.add_parser("allow", help="add terms that must never be redacted")
    allow.add_argument("values", nargs="+")
    allow.add_argument("--remove", action="store_true")
    allow.set_defaults(func=cmd_allow)

    vault = subparsers.add_parser("vault", help="inspect or clear the placeholder vault")
    vault.add_argument("--clear", action="store_true")
    vault.set_defaults(func=cmd_vault)

    def add_proxy_args(sub):
        sub.add_argument("--upstream", default=os.environ.get("SHADE_UPSTREAM", "https://api.anthropic.com"))
        sub.add_argument("--dry-run", action="store_true",
                         help="report what would be redacted; forward traffic unchanged")
        sub.add_argument("--no-restore", action="store_true",
                         help="leave placeholders in the response instead of restoring them")
        sub.add_argument("--fail-open", action="store_true",
                         help="forward a request even if redaction failed (unsafe)")

    proxy_cmd = subparsers.add_parser(
        "proxy", help="run the egress proxy: redact requests, restore responses"
    )
    proxy_cmd.add_argument("--port", type=int, default=0, help="0 picks a free port")
    add_proxy_args(proxy_cmd)
    proxy_cmd.set_defaults(func=cmd_proxy)

    run_cmd = subparsers.add_parser(
        "run", help="run an agent with its traffic routed through the proxy"
    )
    run_cmd.add_argument("command", nargs=argparse.REMAINDER, help="e.g. claude")
    add_proxy_args(run_cmd)
    run_cmd.set_defaults(func=cmd_run)

    doctor = subparsers.add_parser(
        "doctor", help="probe what each host actually enforces and self-test the hooks"
    )
    doctor.set_defaults(func=cmd_doctor)

    log = subparsers.add_parser("log", help="show recent audit entries")
    log.add_argument("--tail", type=int, default=20)
    log.set_defaults(func=cmd_log)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
