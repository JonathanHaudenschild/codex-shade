# codex-shade

A local privacy filter for the **Codex CLI**. It finds personal data,
credentials and API tokens in what you type and in what the agent does, and
replaces them with stable placeholders — or refuses the operation — **before**
anything is sent to the model.

> The same engine ships as
> [**claude-shade**](https://github.com/JonathanHaudenschild/claude-shade),
> a Claude Code plugin. The two repos are independent; install either or both.
> They share `~/.shade/config.json` and `~/.shade/vault.json`, so your names,
> allowlists and placeholders carry across tools.

No services, no Docker, no network calls, no dependencies beyond Python 3.9+.
Everything runs on your machine, and the key used to generate placeholders never
leaves it.

```
you type:   Bitte mail an erika.mustermann@example.com, IBAN DE89 3704 0044 0532 0130 00
shade says: blocked — EMAIL, IBAN. Send this instead:
            Bitte mail an <EMAIL_97029f>, IBAN <IBAN_924945>
```

---

## 1. What it can and cannot do

A hook can only act where its host lets it act, and **a hook cannot tell whether
the host honoured its output** — an unknown field is ignored in silence. So the
table below reflects what Codex actually implements, not what a docs page
describes.

| Channel | What shade does | Guarantee |
|---|---|---|
| What you type | **blocked**, with the clean text handed back to paste | prevented |
| Tool input (`shell`, MCP, web search, …) | rewritten (`updatedInput`) or refused | prevented |
| Reading a credentials file | refused by path before it opens | prevented |
| File contents / command output | **detected, not removed** | warning only |
| What the model writes back | not touched | out of scope |

**Codex cannot rewrite a submitted prompt.** `UserPromptSubmit` supports
`decision: "block"` and `additionalContext` only; `updatedInput` is `PreToolUse`
only. So a `redact` policy on the prompt surface degrades to `block`: shade
refuses the prompt and hands you the cleaned text to paste. Nothing is let
through silently, but the substitution is yours to make, not the tool's.
(Claude Code has exactly the same limitation — this is not a Codex shortcoming.)

The fourth row is the other real limitation. Once a tool has run, its output is
in the model's context and no hook can take it back. `shade` answers that by
refusing reads of sensitive paths *before* they happen (`deny_paths`), and by
telling you what landed in context when something slips through anyway.

So: **shade substantially reduces what leaves your machine. It is not a
guarantee that nothing sensitive ever reaches the model.** Run `shade doctor`
to see what your own installation actually enforces.

It also **does not find names on its own** — no NLP model ships with it. Names
come from a list you maintain (`shade name "Erika Mustermann"`). A regex cannot
tell a person from a variable, and pretending otherwise would be worse than
being explicit.

---

## 2. Install

```bash
git clone git@github.com:JonathanHaudenschild/codex-shade.git
cd codex-shade
python3 install.py          # writes ~/.codex/hooks.json + ~/.codex/prompts/
```

Existing hooks in that file are preserved: entries are merged per event, a
previous shade install is replaced rather than duplicated, and the old file is
backed up to `hooks.json.bak`. Re-running is idempotent.

Codex asks you to **trust** a hook definition before it runs the first time —
approve it when prompted. If you have disabled hooks globally, re-enable them in
`~/.codex/config.toml`:

```toml
[features]
hooks = true
```

Project scope instead of your whole account:

```bash
python3 install.py --scope project --dir /path/to/repo
python3 install.py --uninstall
```

The registered commands embed the **absolute path** to this checkout. If you
move or rename the directory, re-run `python3 install.py`; `shade doctor` flags
the mismatch.

Optional CLI on PATH:

```bash
ln -sf "$PWD/bin/shade" ~/.local/bin/shade
```

---

### Proxy mode (shared engine, manual wiring)

The engine also ships an egress proxy that closes the tool-output hole — it sees
the full request body on its way to the API, so it can substitute placeholders
into your prompt *and* into `tool_result` blocks, then restore real values in the
streamed response. Hooks cannot do either.

```bash
shade proxy --upstream https://api.openai.com
```

Then point Codex at it with a provider entry in `~/.codex/config.toml`:

```toml
[model_providers.shade]
base_url = "http://127.0.0.1:<port>"
```

Unlike the Claude Code side, this is **not automated and not yet verified
end to end for Codex** — `shade run` sets `ANTHROPIC_BASE_URL`, which Codex does
not read. It is verified working against Claude Code; see
[claude-shade §2](https://github.com/JonathanHaudenschild/claude-shade#2-the-proxy--closing-the-tool-output-hole).
Treat Codex proxy mode as experimental.

---

## 3. Configuration

Layers, later wins:

1. built-in defaults (`shade/config.py`)
2. `~/.shade/config.json` — shared with claude-shade
3. `$SHADE_CONFIG`
4. `<project>/.shade.json`
5. `SHADE_*` environment variables

Copy `shade.example.json` to `~/.shade/config.json` and edit. `shade status`
shows what is actually in force.

### Policies

Six *surfaces*, three *severities*, four *actions*.

| Surface | Codex tools it covers |
|---|---|
| `prompt` | what you type |
| `egress` | `web_search`, MCP tools, subagents |
| `shell` | `shell` / `local_shell` |
| `local_write` | `apply_patch` |
| `local_read` | `read_file`, `list_dir` |
| `output` | tool results (detection only) |

| Severity | Meaning |
|---|---|
| `secret` | credentials, keys, tokens. Leaking one is an incident |
| `pii` | personal data under GDPR Art. 4 |
| `special` | special categories under GDPR Art. 9 |

| Action | Effect |
|---|---|
| `redact` | replace with a placeholder and continue |
| `block` | refuse the prompt or the tool call |
| `warn` | allow, but tell you and tell the model to be careful |
| `off` | ignore |

Defaults:

```
prompt        secret=block   pii=block   special=warn
egress        secret=block   pii=redact  special=warn
shell         secret=block   pii=warn    special=warn
local_write   secret=warn    pii=warn    special=off
local_read    secret=warn    pii=off     special=off
output        secret=warn    pii=warn    special=off
```

Three defaults are load-bearing:

* **`prompt` blocks rather than redacts.** Not a preference — no host exposes a
  prompt-rewrite field. `redact` there degrades to `block` automatically.
* **`local_write` never redacts.** Rewriting an `apply_patch` payload would put
  `<EMAIL_97029f>` into your actual source file. Redaction is disabled on
  disk-bound fields entirely.
* **`shell` blocks rather than redacts secrets.** Rewriting a command string
  would produce a broken command that fails confusingly. Refusing is clearer,
  and the fix — use `$GITHUB_TOKEN` instead of the literal — is right anyway.

Quick overrides:

```bash
SHADE_PROMPT_POLICY=warn   codex    # let prompts through with a warning
SHADE_EGRESS_POLICY=block  codex    # nothing sensitive goes outward, ever
SHADE_ENABLED=0            codex    # off for one session
```

### deny_paths

Globs whose contents must never be opened. A leading `!` re-allows. Enforced at
`PreToolUse`, so the file is never read — the only genuinely reliable protection
for file contents.

Defaults cover `.env*` (but not `.env.example`), `*.pem`, `*.key`, `*.p12`,
`~/.ssh/**`, `.aws/credentials`, `.npmrc`, `.netrc`, `.git-credentials`,
`service-account*.json`, `*.sqlite`, `*.dump`.

```bash
shade check-path .env .env.example src/app.py
```

---

## 4. What it detects

**Credentials** — PEM/OpenSSH/PGP private keys, AWS access key IDs and secret
keys, GitHub and GitLab tokens, Anthropic, OpenAI, Google, Slack, Stripe,
HuggingFace, npm and SendGrid keys, JWTs, Slack/Discord webhooks, passwords
inside connection strings, `Authorization:` headers, secrets in URL query
parameters, and a generic `key = value` detector gated on entropy.

**Personal data** — email addresses, IBANs (mod-97 checked), BICs, credit cards
(Luhn + issuer range), German Steuer-ID (ISO 7064 MOD 11,10), German
Sozialversicherungsnummer (check digit), US SSN, phone numbers, public IPv4/IPv6,
MAC addresses, dates of birth, German street addresses and postal codes, and any
name on your list.

**Special categories (GDPR Art. 9)** — a configurable DE/EN vocabulary covering
health, disability, union membership, religion, political affiliation, sexual
orientation and ethnic origin. Policy defaults to `warn`, because matching such a
word does not by itself mean a person has been identified.

Checksums and boundaries are what make unattended redaction tolerable: an
IBAN-shaped string that fails mod-97 is not redacted, a 16-digit number that
fails Luhn is not a card, RFC1918 addresses are ignored entirely, and numeric
detectors refuse to match inside a longer number or a decimal fraction — which
is what stops a table of geo coordinates reading as a wall of credit cards.

Off by default because they are noisy: `bic`, `ipv6`, `de_postal_address`,
`de_plz_city`. Toggle any detector by name:

```json
{ "detectors": { "de_postal_address": true, "ipv4": false } }
```

---

## 5. Placeholders and the vault

A redacted value becomes `<LABEL_xxxxxx>`, where the suffix is
`HMAC-SHA256(local key, label + value)` truncated to six hex characters.

The placeholder is **stable** — the same person is `<PERSON_4f9c20>` in every
session and in claude-shade too, so the model can follow "the same person"
through a conversation and tell two people apart. And it is **opaque** — the key
lives in `~/.shade/key` (mode 0600) and never leaves the machine.

`~/.shade/vault.json` (0600) maps placeholders back to originals:

```bash
shade reveal --file answer.md      # writes a 0600 file, prints only the path
pbpaste | shade reveal --stdout    # prints, if you ask explicitly
```

`reveal` writes to a file rather than printing by default. If an agent ever runs
it, printing would put every original value straight back into the context.

**Secrets are not stored in the vault.** A leaked API key should not be copied
into a second file on disk so it can be un-redacted later. Change that with
`vault.store_severities` if you disagree.

`~/.shade/audit.jsonl` records what was caught — categories and masked previews,
never raw values. `shade log --tail 20`.

---

## 6. Commands

Custom prompts installed into `~/.codex/prompts/`:

| Prompt | Does |
|---|---|
| `/shade-status` | effective config, active detectors, vault size |
| `/shade-scan <path>` | scan a file without changing it |

In the terminal:

```
shade scan [--file F] [--json]      report findings, exit 1 if any
shade redact [--file F] [--severity secret|pii|special]
shade reveal [--file F] [--stdout] [-o OUT]
shade status
shade doctor                        probe what Codex actually enforces, self-test
shade name NAME...   [--remove]
shade allow TERM...  [--remove]
shade check-path PATH...
shade classify TOOL...
shade vault [--clear]
shade log [--tail N]
```

`scan` and `redact` read stdin when given no text:

```bash
git diff | shade scan
cat draft.md | shade redact > draft.clean.md
```

---

## 7. Tuning it

**Add the names you work with.** The single highest-value step:

```bash
shade name "Erika Mustermann" "Projekt Nordlicht"
```

Full names only. A short entry like `Berg` matches inside ordinary German prose
and turns your transcript into noise.

**Clear false positives as they appear:**

```bash
shade allow "support@example.com" "DE89370400440532013000"
```

Allowlisted values are sent in full, every time, with no further checks — test
data belongs there, a real key does not.

**Keep your own domain readable, if you want:**

```json
{ "allow_email_domains": ["example.com"] }
```

---

## 8. Troubleshooting

**Nothing happens.** Hooks register at session start — restart Codex. Check
`~/.codex/hooks.json` exists and that you approved the trust prompt.
`shade log --tail 20` shows whether the hooks ran at all.

**`shade doctor` says hooks point outside this checkout.** You moved the
directory. Re-run `python3 install.py`.

**A hook claims something it did not do.** Run `shade doctor`. It reports which
hook fields the host actually implements, so a capability that quietly
disappears in an update shows up as a `NO` rather than as a false reassurance.

---

## 9. Failure behaviour

Hooks **fail open**. If a hook crashes, times out, or receives something it does
not understand, it exits 0 and the session continues unfiltered. The alternative
— failing closed — would mean a bad regex could lock you out of your own tools.

That is a deliberate trade and you should know which way it points. Set
`SHADE_DEBUG=1` to see tracebacks instead of silence.

---

## 10. Notes for users

This tool helps with whatever privacy rules apply to your AI use; it does not
replace them.

It reduces accidental exposure of the obvious categories — credentials and
tokens, personal data, financial data with a personal reference, GDPR Art. 9
special categories. It cannot judge whether a strategy paper is confidential,
whether a procurement is still running, or whether a research result has been
published. Those remain human decisions, and *"if in doubt, do not enter it"*
still stands.

A caught secret is still a secret that existed in a prompt. If a real credential
is blocked, rotate it — a block means it did not reach the model, not that it
was never at risk.

---

## 11. Development

```bash
python3 -m unittest discover -s tests -v
```

41 tests, no dependencies. The check-digit validators are tested against
published worked examples rather than against themselves, and two tests pin
precision regressions found by running the scanner over real repositories.

```
shade/          engine — vendored identically in claude-shade
hooks/          Codex hook scripts (_bootstrap + four events)
prompts/        /shade-* custom prompts
install.py      writes ~/.codex/hooks.json, merging with what is there
bin/shade       CLI entry point
tools/          sync-engine.sh — pull engine changes from claude-shade
```

### The shared engine

`shade/` is byte-identical to the copy in
[claude-shade](https://github.com/JonathanHaudenschild/claude-shade). Only the
`hooks/` adapter differs, because the two hosts have different output schemas.

Fix a detector or validator in whichever repo you happen to be in, then mirror
it:

```bash
tools/sync-engine.sh ../claude-shade     # from a local checkout
tools/sync-engine.sh --check ../claude-shade   # just report drift
```

`shade doctor` prints the engine version so you can spot a mismatch at a glance.

## Licence

MIT.

## See also

* [**claude-shade**](https://github.com/JonathanHaudenschild/claude-shade) — the
  same engine as a Claude Code plugin instead of Codex CLI hooks, plus the
  verified proxy mode.
* [**og-local**](https://github.com/outgate-ai/og-local) — prior art for the
  proxy approach, using an ONNX model rather than regexes. Finds unstructured
  names shade needs a list for; costs an ~840 MB download and is BSL 1.1.
