"""Egress proxy — the interception point hooks cannot reach.

A hook can rewrite tool *input* and nothing else. This proxy sits between the
agent and the API, so it sees the complete request body on its way out: your
prompt, the system prompt, and every ``tool_result`` block — which is where file
contents and command output live. That last one is the hole hooks cannot close,
because by the time ``PostToolUse`` fires the output is already in the agent's
context and no host offers a rewrite field for it.

Direction of travel:

    request   real values  ->  placeholders     (redact, before it leaves)
    response  placeholders ->  real values      (restore, so your terminal is normal)

Restoration makes the whole thing invisible: the model reasons about
``<EMAIL_a1b2c3>``, you read the real address. Because placeholders are
``HMAC(local key, label + value)`` they are byte-stable across turns, so prompt
caching keeps working.

**This component fails CLOSED.** The hooks fail open on purpose — a bad regex
should not lock you out of your own editor. A proxy is the opposite: if it
cannot redact a request it must not forward it, because forwarding is the exact
harm it exists to prevent. ``--fail-open`` overrides that, and says so loudly.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import socketserver
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from . import config
from .engine import Engine, Finding, summarize
from .vault import PLACEHOLDER_RE

# Paths whose bodies we understand. Anything else is forwarded untouched —
# guessing at an unknown schema is how you corrupt a request.
ANTHROPIC_MESSAGES = "/v1/messages"
OPENAI_CHAT = "/v1/chat/completions"
OPENAI_RESPONSES = "/v1/responses"
REWRITABLE = (ANTHROPIC_MESSAGES, OPENAI_CHAT, OPENAI_RESPONSES)

# A placeholder is <LABEL_xxxxxx>. Nothing longer than this can be one, which
# bounds how much of a stream we hold back waiting to see if it completes.
MAX_PLACEHOLDER = 72

# Tail that might still grow into a placeholder: an unclosed '<' followed only
# by characters a placeholder may contain. The class must include lowercase --
# the six-hex-digit suffix is lowercase, so excluding it meant a chunk boundary
# inside the suffix (<EMAIL_2170a | 5>) released the text unrestored.
_PARTIAL_TAIL = re.compile(r"<[A-Za-z0-9_]{0,64}$")


# --------------------------------------------------------------------------
# Streaming restoration
# --------------------------------------------------------------------------


class Restorer:
    """Turns placeholders back into real values across a chunked stream.

    A placeholder can be split over two deltas (``<EMAIL_a1`` then ``b2c3>``),
    so text that might still grow into one is held back rather than emitted.
    """

    def __init__(self, engine: Engine, escape_json: bool = False):
        self.engine = engine
        self.escape_json = escape_json
        self.buffer = ""
        self.restored = 0

    def _substitute(self, text: str) -> str:
        def replace(match: re.Match) -> str:
            value = self.engine.vault.lookup(match.group(0)[1:-1])
            if value is None:
                return match.group(0)
            self.restored += 1
            # Inside a JSON string literal the replacement must be escaped, or
            # a value containing a quote would break the document.
            return json.dumps(value)[1:-1] if self.escape_json else value

        return PLACEHOLDER_RE.sub(replace, text)

    def feed(self, text: str) -> str:
        """Return everything safe to emit now; keep any possible partial."""
        self.buffer += text
        hold = ""
        match = _PARTIAL_TAIL.search(self.buffer)
        if match and len(self.buffer) - match.start() < MAX_PLACEHOLDER:
            hold = self.buffer[match.start() :]
            self.buffer = self.buffer[: match.start()]
        emit = self._substitute(self.buffer)
        self.buffer = hold
        return emit

    def flush(self) -> str:
        """Emit whatever is left once the stream ends."""
        remainder = self._substitute(self.buffer)
        self.buffer = ""
        return remainder


# --------------------------------------------------------------------------
# Request rewriting
# --------------------------------------------------------------------------

# Where user data lives in each wire format. Tool *schemas* are deliberately
# absent: they are declarations, not data, and rewriting them would change the
# contract the model is answering against.
def _walk_text_nodes(payload: Any, path: str = "") -> list[tuple[list, str]]:
    """Yield (container, key) pairs for every string that carries user data."""
    found: list[tuple[list, str]] = []

    def visit_content(content: Any) -> None:
        if isinstance(content, str):
            return
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                kind = block.get("type")
                if kind in ("text", "input_text", "output_text") and isinstance(block.get("text"), str):
                    found.append(([block], "text"))
                elif kind == "tool_result":
                    inner = block.get("content")
                    if isinstance(inner, str):
                        found.append(([block], "content"))
                    else:
                        visit_content(inner)
                elif kind == "tool_use" and isinstance(block.get("input"), dict):
                    for key, value in block["input"].items():
                        if isinstance(value, str):
                            found.append(([block["input"]], key))

    for message in payload.get("messages", []) or []:
        if not isinstance(message, dict):
            continue
        if isinstance(message.get("content"), str):
            found.append(([message], "content"))
        else:
            visit_content(message.get("content"))

    system = payload.get("system")
    if isinstance(system, str):
        found.append(([payload], "system"))
    else:
        visit_content(system)

    # OpenAI Responses API
    for item in payload.get("input", []) or []:
        if isinstance(item, dict):
            visit_content(item.get("content"))

    return found


@dataclass
class Rewrite:
    body: bytes
    findings: list[Finding] = field(default_factory=list)
    changed: bool = False


def redact_request(engine: Engine, body: bytes) -> Rewrite:
    """Replace real values with placeholders throughout a request body."""
    try:
        payload = json.loads(body)
    except ValueError:
        # Not JSON we understand — forward untouched rather than mangle it.
        return Rewrite(body=body)
    if not isinstance(payload, dict):
        return Rewrite(body=body)

    findings: list[Finding] = []
    changed = False
    for container, key in _walk_text_nodes(payload):
        original = container[0].get(key) if isinstance(container[0], dict) else None
        if not isinstance(original, str) or not original:
            continue
        redacted, applied = engine.redact(original)
        if redacted != original:
            container[0][key] = redacted
            findings.extend(applied)
            changed = True

    if not changed:
        return Rewrite(body=body, findings=findings)
    return Rewrite(
        body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        findings=findings,
        changed=True,
    )


def scan_request(engine: Engine, body: bytes) -> list[Finding]:
    """Report what redaction *would* do, without changing anything."""
    try:
        payload = json.loads(body)
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    findings: list[Finding] = []
    for container, key in _walk_text_nodes(payload):
        value = container[0].get(key) if isinstance(container[0], dict) else None
        if isinstance(value, str) and value:
            findings.extend(engine.scan(value))
    return findings


# --------------------------------------------------------------------------
# Response restoration
# --------------------------------------------------------------------------


def restore_sse_event(engine: Engine, raw: str, restorers: dict) -> str:
    """Restore placeholders inside one `data:` line of an SSE stream.

    Working event-by-event on parsed JSON, rather than with a regex over raw
    bytes, means a replacement value containing a quote or newline cannot break
    the framing.
    """
    if not raw.startswith("data:"):
        return raw
    payload_text = raw[5:].strip()
    if not payload_text or payload_text == "[DONE]":
        return raw
    try:
        event = json.loads(payload_text)
    except ValueError:
        return raw
    if not isinstance(event, dict):
        return raw

    index = event.get("index", 0)
    kind = event.get("type")
    delta = event.get("delta")

    if kind == "content_block_delta" and isinstance(delta, dict):
        if isinstance(delta.get("text"), str):
            restorer = restorers.setdefault(("text", index), Restorer(engine))
            delta["text"] = restorer.feed(delta["text"])
        elif isinstance(delta.get("partial_json"), str):
            restorer = restorers.setdefault(("json", index), Restorer(engine, escape_json=True))
            delta["partial_json"] = restorer.feed(delta["partial_json"])
        else:
            return raw
    elif kind == "content_block_stop":
        # Anything still held back is emitted as its own delta *before* the
        # stop event, so no characters are ever dropped. Text and JSON tails
        # go to their own field: flushing a partial_json tail into a text
        # delta would corrupt the tool call.
        catch_up = []
        for key, field_name, delta_type in (
            (("text", index), "text", "text_delta"),
            (("json", index), "partial_json", "input_json_delta"),
        ):
            restorer = restorers.pop(key, None)
            tail = restorer.flush() if restorer is not None else ""
            if tail:
                catch_up.append("data: " + json.dumps(
                    {"type": "content_block_delta", "index": index,
                     "delta": {"type": delta_type, field_name: tail}},
                    ensure_ascii=False,
                ))
        if catch_up:
            return "\n\n".join(catch_up) + f"\n\ndata: {payload_text}"
        return raw
    elif kind == "message_stop":
        restorers.clear()
        return raw
    else:
        return raw

    return "data: " + json.dumps(event, ensure_ascii=False)


def restore_json_response(engine: Engine, body: bytes) -> bytes:
    """Restore placeholders in a non-streaming response."""
    try:
        payload = json.loads(body)
    except ValueError:
        return body
    if not isinstance(payload, dict):
        return body

    restorer = Restorer(engine)

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {
                key: (restorer._substitute(value) if key in ("text", "content") and isinstance(value, str) else walk(value))
                for key, value in node.items()
            }
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return json.dumps(walk(payload), ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


@dataclass
class ProxySettings:
    upstream: str = "https://api.anthropic.com"
    dry_run: bool = False
    fail_open: bool = False
    restore: bool = True
    verbose: bool = False


def make_handler(engine: Engine, settings: ProxySettings, on_event: Callable[[dict], None]):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # silence the default stderr spam
            pass

        def do_POST(self):
            self._proxy("POST")

        def do_GET(self):
            self._proxy("GET")

        def do_DELETE(self):
            self._proxy("DELETE")

        # -- helpers -------------------------------------------------------

        def _fail(self, message: str) -> None:
            payload = json.dumps(
                {"type": "error", "error": {"type": "shade_proxy_error", "message": message}}
            ).encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _proxy(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            path = self.path.split("?")[0]

            findings: list[Finding] = []
            if body and any(path.startswith(known) for known in REWRITABLE):
                try:
                    if settings.dry_run:
                        findings = scan_request(engine, body)
                    else:
                        rewrite = redact_request(engine, body)
                        body, findings = rewrite.body, rewrite.findings
                except Exception as error:  # noqa: BLE001
                    # Fail closed: an un-redacted request must not go out just
                    # because the redactor tripped over something.
                    on_event({"event": "error", "detail": f"{type(error).__name__}: {error}"})
                    if not settings.fail_open:
                        self._fail(
                            f"shade could not redact this request ({type(error).__name__}). "
                            "Nothing was sent. Re-run with --fail-open to forward anyway."
                        )
                        return

            if findings:
                on_event({
                    "event": "scan" if settings.dry_run else "redact",
                    "path": path,
                    "summary": summarize(findings),
                    "findings": findings,
                })
                engine.log(
                    "ProxyRequest", "egress",
                    config.WARN if settings.dry_run else config.REDACT,
                    findings, {"path": path},
                )

            headers = {
                key: value for key, value in self.headers.items()
                if key.lower() not in ("host", "content-length", "accept-encoding")
            }
            if body:
                headers["Content-Length"] = str(len(body))
            headers["Accept-Encoding"] = "identity"  # so we can rewrite the stream

            request = urllib.request.Request(
                settings.upstream + self.path, data=body or None, headers=headers, method=method
            )
            try:
                response = urllib.request.urlopen(request, context=ssl.create_default_context())
            except urllib.error.HTTPError as error:
                payload = error.read()
                self.send_response(error.code)
                for key, value in error.headers.items():
                    if key.lower() not in ("transfer-encoding", "content-length", "connection", "content-encoding"):
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            except Exception as error:  # noqa: BLE001
                on_event({"event": "upstream_error", "detail": str(error)[:120]})
                self._fail(f"upstream unreachable: {type(error).__name__}")
                return

            with response:
                content_type = response.headers.get("Content-Type", "")
                streaming = "text/event-stream" in content_type
                self.send_response(response.status)
                for key, value in response.headers.items():
                    if key.lower() not in ("transfer-encoding", "content-length", "connection", "content-encoding"):
                        self.send_header(key, value)

                if not settings.restore or settings.dry_run:
                    self._passthrough(response, streaming)
                elif streaming:
                    self._stream_restored(response)
                else:
                    payload = restore_json_response(engine, response.read())
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

        def _passthrough(self, response, streaming: bool) -> None:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                self._chunk(chunk)
            self._chunk(b"")

        def _stream_restored(self, response) -> None:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            restorers: dict = {}
            pending = b""
            while True:
                chunk = response.read(4096)
                if not chunk:
                    break
                pending += chunk
                # SSE events are separated by a blank line; only process whole ones.
                while b"\n\n" in pending:
                    raw_event, pending = pending.split(b"\n\n", 1)
                    text = raw_event.decode("utf-8", "replace")
                    rebuilt = "\n".join(
                        restore_sse_event(engine, line, restorers) for line in text.split("\n")
                    )
                    self._chunk((rebuilt + "\n\n").encode("utf-8"))
            if pending:
                self._chunk(pending)
            self._chunk(b"")

        def _chunk(self, data: bytes) -> None:
            try:
                self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

    return Handler


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(
    engine: Engine,
    port: int = 0,
    settings: Optional[ProxySettings] = None,
    on_event: Optional[Callable[[dict], None]] = None,
) -> _Server:
    """Start the proxy on 127.0.0.1 and return the (already listening) server."""
    settings = settings or ProxySettings()
    handler = make_handler(engine, settings, on_event or (lambda event: None))
    server = _Server(("127.0.0.1", port), handler)
    return server
