#!/usr/bin/env python3
"""Proxy tests.

The interesting cases are the ones a naive implementation gets wrong: a
placeholder split across two stream chunks, a restored value containing a
JSON metacharacter, and tool_result blocks — which are the whole reason the
proxy exists, since hooks cannot touch them.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shade import config, proxy  # noqa: E402
from shade.engine import Engine  # noqa: E402


class ProxyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._previous = os.environ.get("SHADE_HOME")
        os.environ["SHADE_HOME"] = self._tmp.name
        self.engine = Engine(config.load(self._tmp.name))

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("SHADE_HOME", None)
        else:
            os.environ["SHADE_HOME"] = self._previous
        self._tmp.cleanup()

    def placeholder_for(self, value: str, label: str = "EMAIL") -> str:
        redacted, _ = self.engine.redact(value)
        return redacted


class TestRequestRedaction(ProxyTest):
    def test_user_text_is_redacted(self):
        body = json.dumps({
            "model": "claude-opus-5",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "mail ada@example.com about it"}]}],
        }).encode()
        result = proxy.redact_request(self.engine, body)
        self.assertTrue(result.changed)
        self.assertNotIn(b"ada@example.com", result.body)
        self.assertIn("EMAIL", json.dumps(json.loads(result.body)))

    def test_tool_result_is_redacted(self):
        """The case hooks cannot reach: file contents on their way upstream."""
        body = json.dumps({
            "messages": [{"role": "user", "content": [{
                "type": "tool_result",
                "tool_use_id": "toolu_1",
                "content": "erika@example.org\nAKIAIOSFODNN7EXAMPLE",
            }]}],
        }).encode()
        result = proxy.redact_request(self.engine, body)
        self.assertTrue(result.changed)
        self.assertNotIn(b"erika@example.org", result.body)
        self.assertNotIn(b"AKIAIOSFODNN7EXAMPLE", result.body)

    def test_system_prompt_is_redacted(self):
        body = json.dumps({
            "system": [{"type": "text", "text": "operator is ada@example.com"}],
            "messages": [],
        }).encode()
        result = proxy.redact_request(self.engine, body)
        self.assertNotIn(b"ada@example.com", result.body)

    def test_tool_schemas_are_untouched(self):
        """Tool definitions are a contract, not user data."""
        body = json.dumps({
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
            "tools": [{"name": "mailer", "description": "sends to ada@example.com",
                       "input_schema": {"type": "object"}}],
        }).encode()
        result = proxy.redact_request(self.engine, body)
        self.assertFalse(result.changed)
        self.assertIn(b"ada@example.com", result.body)

    def test_non_json_body_is_passed_through(self):
        body = b"\x00\x01binary-garbage"
        result = proxy.redact_request(self.engine, body)
        self.assertEqual(result.body, body)
        self.assertFalse(result.changed)

    def test_clean_request_is_byte_identical(self):
        """No change means no re-serialisation — prompt caching depends on it."""
        body = json.dumps({"messages": [{"role": "user", "content": [
            {"type": "text", "text": "refactor the parser"}]}]}).encode()
        result = proxy.redact_request(self.engine, body)
        self.assertEqual(result.body, body)

    def test_redaction_is_stable_across_requests(self):
        """Same value -> same bytes, so a cached prefix stays cached."""
        body = json.dumps({"messages": [{"role": "user", "content": [
            {"type": "text", "text": "ada@example.com"}]}]}).encode()
        first = proxy.redact_request(self.engine, body).body
        second = proxy.redact_request(self.engine, body).body
        self.assertEqual(first, second)

    def test_dry_run_scan_reports_without_changing(self):
        body = json.dumps({"messages": [{"role": "user", "content": [
            {"type": "text", "text": "ada@example.com"}]}]}).encode()
        findings = proxy.scan_request(self.engine, body)
        self.assertEqual([f.label for f in findings], ["EMAIL"])


class TestStreamRestoration(ProxyTest):
    def test_whole_placeholder_in_one_chunk(self):
        token = self.placeholder_for("ada@example.com")
        restorer = proxy.Restorer(self.engine)
        out = restorer.feed(f"write to {token} now") + restorer.flush()
        self.assertEqual(out, "write to ada@example.com now")

    def test_placeholder_split_across_chunks(self):
        """The case that breaks a naive per-chunk regex."""
        token = self.placeholder_for("ada@example.com")
        restorer = proxy.Restorer(self.engine)
        pieces = [token[:3], token[3:7], token[7:]]
        out = "".join(restorer.feed(piece) for piece in pieces) + restorer.flush()
        self.assertEqual(out, "ada@example.com")

    def test_split_one_character_at_a_time(self):
        token = self.placeholder_for("ada@example.com")
        restorer = proxy.Restorer(self.engine)
        out = "".join(restorer.feed(char) for char in f"a {token} b") + restorer.flush()
        self.assertEqual(out, "a ada@example.com b")

    def test_unknown_placeholder_is_left_alone(self):
        restorer = proxy.Restorer(self.engine)
        out = restorer.feed("see <EMAIL_ffffff> there") + restorer.flush()
        self.assertEqual(out, "see <EMAIL_ffffff> there")

    def test_lone_angle_bracket_is_not_held_forever(self):
        restorer = proxy.Restorer(self.engine)
        out = restorer.feed("if a < b and c > d") + restorer.flush()
        self.assertEqual(out, "if a < b and c > d")

    def test_no_characters_are_dropped(self):
        restorer = proxy.Restorer(self.engine)
        text = "generic <div> markup <NOT_A_PLACEHOLDER> end"
        out = restorer.feed(text) + restorer.flush()
        self.assertEqual(out, text)

    def test_json_escaping_when_restoring_into_partial_json(self):
        """A restored value with a quote must not break the JSON it sits in."""
        engine = self.engine
        redacted, _ = engine.redact('contact "Ada" <ada@example.com>')
        token = proxy.PLACEHOLDER_RE.search(redacted).group(0)
        restorer = proxy.Restorer(engine, escape_json=True)
        out = restorer.feed(token) + restorer.flush()
        # the emitted text must survive being embedded in a JSON string
        self.assertEqual(json.loads(f'"{out}"'), "ada@example.com")


class TestSSE(ProxyTest):
    def test_content_block_delta_is_restored(self):
        token = self.placeholder_for("ada@example.com")
        restorers: dict = {}
        line = "data: " + json.dumps({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": f"mail {token}"},
        })
        out = proxy.restore_sse_event(self.engine, line, restorers)
        # held back pending more input, flushed at block stop
        stop = "data: " + json.dumps({"type": "content_block_stop", "index": 0})
        out += proxy.restore_sse_event(self.engine, stop, restorers)
        self.assertIn("ada@example.com", out)

    def test_done_sentinel_untouched(self):
        self.assertEqual(
            proxy.restore_sse_event(self.engine, "data: [DONE]", {}), "data: [DONE]"
        )

    def test_non_data_lines_untouched(self):
        self.assertEqual(
            proxy.restore_sse_event(self.engine, "event: content_block_delta", {}),
            "event: content_block_delta",
        )

    def test_malformed_json_is_passed_through(self):
        self.assertEqual(
            proxy.restore_sse_event(self.engine, "data: {not json", {}), "data: {not json"
        )


class TestNonStreamingResponse(ProxyTest):
    def test_restores_text_blocks(self):
        token = self.placeholder_for("ada@example.com")
        body = json.dumps({"content": [{"type": "text", "text": f"mail {token}"}]}).encode()
        restored = proxy.restore_json_response(self.engine, body)
        self.assertIn(b"ada@example.com", restored)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestVaultConcurrency(ProxyTest):
    """Regression: the proxy is threaded, so the vault has concurrent writers.

    A shared temp filename made two threads race for the same rename and one
    lost with FileNotFoundError, mid-request.
    """

    def test_parallel_redaction_does_not_race(self):
        import threading

        errors: list[BaseException] = []

        def worker(n: int) -> None:
            try:
                for i in range(25):
                    self.engine.redact(f"user{n}_{i}@example.com and user{n}_{i}b@example.com")
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"vault raced: {errors[:1]}")
        self.assertGreaterEqual(self.engine.vault.stats()["count"], 400)

    def test_flush_merges_a_concurrent_writer(self):
        """A long-lived process must not clobber a hook's entries."""
        other = Engine(config.load(self._tmp.name))
        other.redact("hook_side@example.com")          # writes and flushes

        self.engine.redact("proxy_side@example.com")   # loaded before, writes after

        fresh = Engine(config.load(self._tmp.name))
        restored_hook, n1 = fresh.reveal(other.redact("hook_side@example.com")[0])
        restored_proxy, n2 = fresh.reveal(self.engine.redact("proxy_side@example.com")[0])
        self.assertEqual(restored_hook, "hook_side@example.com")
        self.assertEqual(restored_proxy, "proxy_side@example.com")


class TestProxyHookCoordination(unittest.TestCase):
    """Regression: `shade run --dry-run` used to disable the prompt hook.

    The hook stands down only when something else is actually redacting. In
    dry-run the proxy forwards unchanged, so standing the hook down left the
    prompt surface completely unguarded — worse than running no proxy at all.
    """

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ("SHADE_PROXY", "SHADE_PROXY_MODE", "SHADE_HOME")}
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["SHADE_HOME"] = self._tmp.name

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def prompt_policy(self) -> dict:
        return config.load(self._tmp.name)["policies"][config.PROMPT]

    def test_no_proxy_keeps_the_hook_armed(self):
        os.environ.pop("SHADE_PROXY", None)
        os.environ.pop("SHADE_PROXY_MODE", None)
        self.assertEqual(self.prompt_policy()["pii"], config.BLOCK)

    def test_active_proxy_stands_the_hook_down(self):
        os.environ["SHADE_PROXY"] = "1"
        os.environ["SHADE_PROXY_MODE"] = "active"
        self.assertEqual(self.prompt_policy()["pii"], config.OFF)

    def test_dry_run_keeps_the_hook_armed(self):
        os.environ["SHADE_PROXY"] = "1"
        os.environ["SHADE_PROXY_MODE"] = "dry-run"
        self.assertEqual(self.prompt_policy()["pii"], config.BLOCK)
