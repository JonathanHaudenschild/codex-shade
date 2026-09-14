#!/usr/bin/env python3
"""Test suite. Run with:  python3 -m unittest discover -s tests -v

Every test points SHADE_HOME at a throwaway directory, so the real vault and
config in ~/.shade are never touched.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shade import config, policy, validators  # noqa: E402
from shade.engine import Engine  # noqa: E402

# Published check-digit examples, used so the validators are tested against an
# external source of truth rather than against themselves.
VALID_TAX_ID = "36574261809"          # BZSt worked example
VALID_SV_NUMBER = "65170839J003"      # Deutsche Rentenversicherung worked example
VALID_IBAN = "DE89 3704 0044 0532 0130 00"


class SandboxedTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._previous = os.environ.get("SHADE_HOME")
        os.environ["SHADE_HOME"] = self._tmp.name

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("SHADE_HOME", None)
        else:
            os.environ["SHADE_HOME"] = self._previous
        self._tmp.cleanup()

    def engine(self, **overrides) -> Engine:
        settings = config.load(self._tmp.name)
        settings.update(overrides)
        return Engine(settings)

    def labels(self, engine: Engine, text: str) -> list[str]:
        return [finding.label for finding in engine.scan(text)]


class TestValidators(unittest.TestCase):
    def test_iban(self):
        self.assertTrue(validators.iban(VALID_IBAN))
        self.assertTrue(validators.iban("GB82WEST12345698765432"))
        self.assertFalse(validators.iban("DE89370400440532013001"))
        self.assertFalse(validators.iban("XX00NOTANIBAN"))

    def test_luhn_and_cards(self):
        self.assertTrue(validators.credit_card("4539578763621486"))
        self.assertTrue(validators.credit_card("5500 0000 0000 0004"))
        self.assertTrue(validators.credit_card("378282246310005"))      # Amex, 15
        self.assertFalse(validators.credit_card("4539578763621487"))     # bad Luhn
        self.assertFalse(validators.credit_card("1111111111111111"))     # padding

    def test_wrong_length_for_prefix_is_not_a_card(self):
        self.assertFalse(validators.credit_card("3782822463100050"))  # Amex, 16 not 15
        self.assertFalse(validators.credit_card("5500000000000042"))  # bad Luhn
        self.assertFalse(validators.credit_card("9999999999999995"))  # no issuer range

    def test_de_tax_id(self):
        self.assertTrue(validators.de_tax_id(VALID_TAX_ID))
        self.assertFalse(validators.de_tax_id("36574261808"))
        self.assertFalse(validators.de_tax_id("01234567890"))
        # 11 digits with no repeat at all is structurally impossible
        self.assertFalse(validators.de_tax_id("12345678901"))

    def test_de_social_security(self):
        self.assertTrue(validators.de_social_security(VALID_SV_NUMBER))
        self.assertFalse(validators.de_social_security("65170839J004"))

    def test_us_ssn(self):
        self.assertTrue(validators.us_ssn("123-45-6789"))
        self.assertFalse(validators.us_ssn("000-45-6789"))
        self.assertFalse(validators.us_ssn("123-00-6789"))

    def test_public_ipv4_only(self):
        self.assertTrue(validators.public_ipv4("93.184.216.34"))
        self.assertFalse(validators.public_ipv4("192.168.1.1"))
        self.assertFalse(validators.public_ipv4("127.0.0.1"))
        self.assertFalse(validators.public_ipv4("10.0.0.7"))
        self.assertFalse(validators.public_ipv4("999.1.1.1"))

    def test_generic_secret_gate(self):
        self.assertTrue(validators.looks_like_real_secret("hK3n8Wq2LpXz7Rv4Tb"))
        self.assertFalse(validators.looks_like_real_secret("${DATABASE_PASSWORD}"))
        self.assertFalse(validators.looks_like_real_secret("changeme123456"))
        self.assertFalse(validators.looks_like_real_secret("short"))
        self.assertFalse(validators.looks_like_real_secret("supersecretpassword"))


class TestDetection(SandboxedTest):
    def test_secrets(self):
        engine = self.engine()
        cases = {
            "AKIAIOSFODNN7EXAMPLE": "AWS_ACCESS_KEY_ID",
            "ghp_" + "a" * 36: "GITHUB_TOKEN",
            "sk-ant-api03-" + "x" * 40: "ANTHROPIC_API_KEY",
            "AIza" + "B" * 35: "GOOGLE_API_KEY",
            "xoxb-123456789012-abcdefghijkl": "SLACK_TOKEN",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk": "JWT",
        }
        for value, label in cases.items():
            with self.subTest(label=label):
                self.assertIn(label, self.labels(engine, f"here it is: {value} ok"))

    def test_private_key_block(self):
        engine = self.engine()
        blob = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA1234567890\nabcdef\n"
            "-----END RSA PRIVATE KEY-----"
        )
        redacted, findings = engine.redact(blob)
        self.assertEqual([f.label for f in findings], ["PRIVATE_KEY"])
        self.assertNotIn("MIIEowIBAAKCAQEA", redacted)

    def test_connection_string_password(self):
        engine = self.engine()
        text = "postgres://app:Hunter2Hunter2@db.example.org:5432/prod"
        redacted, _ = engine.redact(text)
        self.assertNotIn("Hunter2Hunter2", redacted)
        self.assertIn("postgres://app:", redacted)  # structure preserved

    def test_personal_data(self):
        engine = self.engine()
        text = (
            f"Kontakt: erika.mustermann@example.org, IBAN {VALID_IBAN}, "
            f"Steuer-ID {VALID_TAX_ID}, geboren am 12.03.1978, Tel. +49 30 1234567"
        )
        labels = set(self.labels(engine, text))
        self.assertEqual(
            {"EMAIL", "IBAN", "DE_STEUER_ID", "DATE_OF_BIRTH", "PHONE"} - labels, set()
        )

    def test_private_ip_is_not_pii(self):
        engine = self.engine()
        self.assertNotIn("IP_ADDRESS", self.labels(engine, "bind to 192.168.0.10"))
        self.assertIn("IP_ADDRESS", self.labels(engine, "client 93.184.216.34"))

    def test_ordinary_code_is_left_alone(self):
        engine = self.engine()
        snippet = (
            "const timeout = 30000;\n"
            "if (user.isActive && count > 12) { return buildResponse(payload); }\n"
            "// see https://docs.example.com/guide for details\n"
            "export const VERSION = '1.24.0';\n"
        )
        self.assertEqual(self.labels(engine, snippet), [])

    def test_geo_coordinates_are_not_identifiers(self):
        """Regression: decimal fractions are not credit cards or tax IDs."""
        engine = self.engine()
        rows = (
            "(52.49205375381471,13.38851234568095)\n"
            "(52.552393161665925,13.36654261803968)\n"
            "POINT(13.45412756030647 52.36574261809445)"
        )
        self.assertEqual(self.labels(engine, rows), [])

    def test_sql_dump_timestamps_are_ignored(self):
        """Regression from a real dump.

        The first card pattern allowed an optional separator between *every*
        digit, so a run of adjacent timestamps was joined into one long
        candidate whose concatenated digits happened to satisfy Luhn. 171 false
        positives in a single file. The pattern now only accepts an unbroken
        15/16-digit run or a conventionally grouped number.
        """
        engine = self.engine()
        dump = (
            "20240625211759\t2025-08-26 14:08:24\t20210710035447 20210722035447 "
            "20210730185600 20171026211738 2017102621173800"
        )
        self.assertNotIn("CREDIT_CARD", self.labels(engine, dump))

    def test_env_placeholder_is_not_a_secret(self):
        engine = self.engine()
        self.assertEqual(self.labels(engine, 'api_key = "${MY_API_KEY}"'), [])
        self.assertEqual(self.labels(engine, "password: <your-password-here>"), [])


class TestRedaction(SandboxedTest):
    def test_placeholder_is_stable_and_distinct(self):
        engine = self.engine()
        first, _ = engine.redact("write to ada@example.com")
        second, _ = engine.redact("also mail ada@example.com please")
        third, _ = engine.redact("but not bob@example.com")

        token = first.split("write to ")[1]
        self.assertIn(token, second)
        self.assertNotIn(token, third)

    def test_redaction_is_idempotent(self):
        engine = self.engine()
        once, _ = engine.redact("mail ada@example.com")
        twice, findings = engine.redact(once)
        self.assertEqual(once, twice)
        self.assertEqual(findings, [])

    def test_reveal_roundtrip(self):
        engine = self.engine()
        original = "Erika lives at erika@example.org"
        redacted, _ = engine.redact(original)
        self.assertNotIn("erika@example.org", redacted)
        restored, count = engine.reveal(redacted)
        self.assertEqual(restored, original)
        self.assertEqual(count, 1)

    def test_secrets_are_not_stored_in_the_vault(self):
        engine = self.engine()
        redacted, _ = engine.redact("key AKIAIOSFODNN7EXAMPLE")
        restored, count = engine.reveal(redacted)
        self.assertEqual(count, 0)
        self.assertEqual(restored, redacted)

    def test_allowlist(self):
        engine = self.engine(allowlist=["support@ts.berlin"])
        text = "write to support@ts.berlin or to private@example.org"
        redacted, _ = engine.redact(text)
        self.assertIn("support@ts.berlin", redacted)
        self.assertNotIn("private@example.org", redacted)

    def test_allow_email_domains(self):
        engine = self.engine(allow_email_domains=["ts.berlin"])
        redacted, _ = engine.redact("a@ts.berlin and b@gmail.com")
        self.assertIn("a@ts.berlin", redacted)
        self.assertNotIn("b@gmail.com", redacted)

    def test_configured_names(self):
        engine = self.engine(names=["Erika Mustermann", "Projekt Nordlicht"])
        redacted, findings = engine.redact(
            "Erika Mustermann arbeitet an Projekt Nordlicht."
        )
        self.assertEqual({f.label for f in findings}, {"PERSON"})
        self.assertNotIn("Erika", redacted)
        self.assertNotIn("Nordlicht", redacted)

    def test_severity_filter(self):
        engine = self.engine()
        text = "key AKIAIOSFODNN7EXAMPLE mail ada@example.com"
        redacted, _ = engine.redact(text, severities={"secret"})
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertIn("ada@example.com", redacted)


class TestPathRules(unittest.TestCase):
    def setUp(self):
        self.rules = policy.PathRules(config.DEFAULTS["deny_paths"])

    def test_denied(self):
        for path in (
            "/Users/x/project/.env",
            ".env.production",
            "/home/x/.ssh/id_rsa",
            "certs/server.pem",
            "/Users/x/.aws/credentials",
            "config/service-account-prod.json",
        ):
            with self.subTest(path=path):
                self.assertTrue(self.rules.denied(path))

    def test_negation_re_allows(self):
        self.assertFalse(self.rules.denied(".env.example"))
        self.assertFalse(self.rules.denied("apps/web/.env.sample"))

    def test_ordinary_files_pass(self):
        for path in ("src/main.py", "README.md", "package.json", "docs/env.md"):
            with self.subTest(path=path):
                self.assertFalse(self.rules.denied(path))


class TestToolPolicy(SandboxedTest):
    def test_classification(self):
        self.assertEqual(policy.classify_tool("WebFetch"), config.EGRESS)
        self.assertEqual(policy.classify_tool("mcp__notion__search"), config.EGRESS)
        self.assertEqual(policy.classify_tool("Bash"), config.SHELL)
        self.assertEqual(policy.classify_tool("shell"), config.SHELL)
        self.assertEqual(policy.classify_tool("apply_patch"), config.LOCAL_WRITE)
        self.assertEqual(policy.classify_tool("Read"), config.LOCAL_READ)
        self.assertEqual(policy.classify_tool("SomeUnknownTool"), config.EGRESS)

    def test_deny_path_blocks_a_read(self):
        engine = self.engine()
        decision = policy.evaluate_tool_input(
            engine, "Read", {"file_path": "/Users/x/project/.env"}
        )
        self.assertTrue(decision.blocked)
        self.assertIn("deny_paths", decision.reason)

    def test_example_env_is_readable(self):
        engine = self.engine()
        decision = policy.evaluate_tool_input(
            engine, "Read", {"file_path": "/Users/x/project/.env.example"}
        )
        self.assertFalse(decision.blocked)

    def test_egress_pii_is_redacted(self):
        engine = self.engine()
        decision = policy.evaluate_tool_input(
            engine, "WebFetch", {"url": "https://x.test/q", "prompt": "find ada@example.com"}
        )
        self.assertEqual(decision.action, config.REDACT)
        self.assertNotIn("ada@example.com", decision.updated["prompt"])

    def test_egress_secret_is_blocked(self):
        engine = self.engine()
        decision = policy.evaluate_tool_input(
            engine, "WebFetch", {"url": "https://x.test/?api_key=hK3n8Wq2LpXz7Rv4Tb"}
        )
        self.assertTrue(decision.blocked)

    def test_write_payload_is_never_rewritten(self):
        """A placeholder written into a real file would corrupt the user's work."""
        engine = self.engine()
        decision = policy.evaluate_tool_input(
            engine,
            "Write",
            {"file_path": "notes.md", "content": "contact ada@example.com"},
        )
        self.assertIsNone(decision.updated)
        self.assertIn(decision.action, (config.WARN, config.OFF))

    def test_shell_secret_is_blocked_not_mangled(self):
        engine = self.engine()
        decision = policy.evaluate_tool_input(
            engine,
            "Bash",
            {"command": 'curl -H "Authorization: Bearer ghp_' + "a" * 36 + '" https://api.test'},
        )
        self.assertTrue(decision.blocked)
        self.assertIsNone(decision.updated)

    def test_prompt_is_blocked_not_rewritten(self):
        """No host can rewrite a submitted prompt.

        Claude Code's own embedded hook reference states `updatedInput` is
        "PreToolUse only", and the 2.1.x binary contains no prompt-rewrite field
        at all; Codex documents the same restriction. A `redact` policy on the
        prompt surface must therefore degrade to `block` rather than report a
        rewrite that never happened.
        """
        engine = self.engine()
        decision = policy.evaluate_text(
            engine, config.PROMPT, "please email ada@example.com about the invoice"
        )
        self.assertTrue(decision.blocked)
        self.assertIsNotNone(decision.updated)
        self.assertNotIn("ada@example.com", decision.updated)

    def test_redact_policy_on_prompt_degrades_to_block(self):
        engine = self.engine(
            policies={**config.DEFAULTS["policies"],
                      config.PROMPT: {"secret": "redact", "pii": "redact", "special": "warn"}}
        )
        decision = policy.evaluate_text(engine, config.PROMPT, "mail ada@example.com")
        self.assertEqual(decision.action, config.BLOCK)

    def test_output_is_never_redacted(self):
        engine = self.engine()
        decision = policy.evaluate_tool_output(
            engine, "Read", {"content": "ada@example.com"}
        )
        self.assertNotEqual(decision.action, config.REDACT)
        self.assertTrue(decision.findings)

    def test_disabled_engine_does_nothing(self):
        engine = self.engine(enabled=False)
        self.assertEqual(engine.scan("ada@example.com AKIAIOSFODNN7EXAMPLE"), [])


class TestMasking(SandboxedTest):
    def test_preview_never_leaks_the_value(self):
        engine = self.engine()
        findings = engine.scan("mail erika.mustermann@example.org now")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("mustermann", findings[0].preview.lower())

    def test_summary_has_no_values(self):
        from shade.engine import summarize

        engine = self.engine()
        findings = engine.scan("a@b.co and c@d.co and AKIAIOSFODNN7EXAMPLE")
        summary = summarize(findings)
        self.assertNotIn("a@b.co", summary)
        self.assertIn("EMAIL", summary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
