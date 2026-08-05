# Nanobot Hindsight automation

A [Nanobot](https://github.com) plugin that gives your agent governed long-term memory through [Hindsight](https://github.com) — selective Recall and Retain, not a raw memory dump — plus an automated nightly review that surfaces missing or broken skills using Hindsight Reflect. Built for a single-user Nanobot gateway, fail-closed by design, and secret-redacted at every network boundary.

This is a thin tool plugin, audited against Nanobot v0.3.0, for selective Hindsight memory and nightly skill review. Dream stays disabled. The plugin does not rewrite `MEMORY.md`, `SOUL.md`, `AGENTS.md`, `TOOLS.md`, or live skills. It reads each installed `SKILL.md` locally to derive a name, description, path, and content hash; only those metadata fields are sent to the reviewer.

It provides:

- low-budget Hindsight Recall before ordinary user turns;
- selective, deferred Retain through a deterministic safety gate;
- a read-only session watcher that checkpoints completed exchanges;
- an isolated-session 3:00 a.m. review that uses Hindsight Reflect; and
- sanitized, report-only skill and memory recommendations during calibration.

This is “hybrid” behavior assembled from Recall, selective Retain, and nightly Reflect—not a fourth Hindsight mode.

## Files

- `hindsight_core.py`: REST client, SQLite ledger, exchange parser, retention policy, and report validation.
- `nanobot_hindsight.py`: Nanobot plugin, automatic Recall, session watcher, cron installation, and nightly review.
- `NIGHTLY_REVIEW.md`: the prompt installed into the dedicated nightly cron job.
- `test_hindsight_core.py`: safety and idempotency tests that do not require running services.

## Requirements

- Nanobot's `v0.3.0` tag (pin the tag or an audited commit)
- Hindsight v0.8.6 or newer
- Python 3.11 or newer

This code targets the external tool-plugin surface published in the `v0.3.0` tag. Do not install from a moving branch unattended: pin `v0.3.0` or the exact audited commit, then rerun this test suite when upgrading.

The plugin probes Hindsight `/version` before its first write. Recall fails open when Hindsight is unavailable; both the outbound Recall query and returned memories are secret/entropy-redacted, and automatic Recall is disabled on cron/local automation turns. Retain fails closed. Retain HTTP requests complete synchronously inside a background plugin task, and success is accepted only when Hindsight confirms exactly one non-async item. The conversation is not blocked and the ledger never mistakes a merely queued operation for durable storage. User-scoped stable document IDs make retries idempotent without allowing one user tag to replace another user's document in a shared bank.

Dry-run extraction is recommended. For self-hosted Hindsight:

```text
HINDSIGHT_API_ENABLE_DRY_RUN_EXTRACT=true
```

The extractor proposes atomic facts without storing them. The local validator still decides whether a Retain call is permitted. If extraction is unavailable, heuristic candidates remain report-only; they are never automatically retained.

The unattended write path uses REST for full request control and stable document upserts. Your existing Hindsight MCP skill can remain available for explicit Recall and Reflect. Its raw `retain` tool bypasses this plugin's gate, so instruct that skill to use Retain only for an explicit “remember this” request. If the bank is shared with other agents, do not remove MCP Retain at the bank level unless you intend to change every agent; enforce a Nanobot-only restriction with a local MCP proxy or a separate bank instead.

## Plugin registration

Keep both Python modules and `NIGHTLY_REVIEW.md` in a Git-backed plugin package. Make sure the package build includes the Markdown file; the Python module has a safe fallback prompt if it is absent. Add the entry point to that package’s project metadata:

```toml
[project.entry-points."nanobot.tools"]
hindsight_automation = "nanobot_hindsight:HindsightAutomationTool"
```

Nanobot discovers the class and supplies its `SessionManager` and `CronService` through `create(ctx)`. No Nanobot source patch is required.

## Configuration

Keep credentials outside Git:

```text
HINDSIGHT_BANK_ID=your-bank-id
HINDSIGHT_API_KEY=your-key-if-required
NANOBOT_HINDSIGHT_BASE_URL=http://127.0.0.1:8888
NANOBOT_HINDSIGHT_USER_TAG=user:your-stable-id
NANOBOT_HINDSIGHT_PROJECT_TAG=project:nanobot
NANOBOT_HINDSIGHT_TAGS_MATCH=all_strict
NANOBOT_HINDSIGHT_SINGLE_USER_GATEWAY=true
NANOBOT_HINDSIGHT_MODE=observe
NANOBOT_HINDSIGHT_TIMEZONE=America/New_York
NANOBOT_HINDSIGHT_NIGHTLY_CRON=0 3 * * *
```

Remote Hindsight endpoints must use HTTPS because Recall/Retain may carry health
and other personal context. Plain HTTP is accepted by default only for
`localhost`, `127.0.0.1`, and `::1`. If an intentionally isolated Docker/LAN
deployment cannot use TLS, opt in explicitly with
`NANOBOT_HINDSIGHT_ALLOW_INSECURE_HTTP=true` and treat that network as trusted.

Omit `NANOBOT_HINDSIGHT_PROJECT_TAG` unless this gateway is dedicated to that
project; a fixed project tag on a general personal gateway would mislabel unrelated
conversations.

This first release intentionally supports a single-user Nanobot gateway. The watcher scans gateway sessions and one static tag scopes every automatic Recall, so multi-user gateways fail closed. Set the gateway declaration only when every chat/session belongs to the same person. For a bank shared by agents, the user tag must have the form `user:stable-id` and `NANOBOT_HINDSIGHT_TAGS_MATCH` must remain `all_strict`; weaker matching disables automation. Automatic Recall, Retain, and Reflect require that strict user scope or an explicit declaration that the whole bank belongs to one user:

```text
NANOBOT_HINDSIGHT_SINGLE_USER_BANK=true
```

Do not set the single-user-bank flag for a bank shared by multiple people. A bank shared by several agents for the same person should use that person's stable user tag instead. Strict tag matching intentionally excludes older untagged memories; migrate those memories instead of weakening isolation. A future multi-user deployment needs an authenticated session-to-user tag resolver; a static environment tag is not sufficient.

Useful optional settings:

```text
NANOBOT_HINDSIGHT_POLL_SECONDS=60
NANOBOT_HINDSIGHT_RECALL_MAX_TOKENS=900
NANOBOT_HINDSIGHT_RECALL_TIMEOUT=4
NANOBOT_HINDSIGHT_STATE_DIR=.nanobot-hindsight
NANOBOT_HINDSIGHT_REPORT_DIR=reports/hindsight-nightly
NANOBOT_HINDSIGHT_SKILL_ROOTS=skills
NANOBOT_HINDSIGHT_NIGHTLY_REFLECT=true
NANOBOT_HINDSIGHT_CAPTURE_LOOKBACK_DAYS=3
NANOBOT_HINDSIGHT_MAX_EXCHANGES=80
```

The state directory contains bounded, redacted evidence in SQLite. It is private runtime state and must be ignored by Git. A relative state path is confined to the workspace and rejected if any existing path component is a symlink; use an explicit absolute path only when you intentionally manage state elsewhere. The ledger is cryptographically bound to its configured Hindsight base URL, bank, user scope, and project tag; changing any of those values fails closed, so choose a new state directory or perform an explicit migration. `MAX_EXCHANGES` is a hard logical cap for new capture: old safely reviewed rows are pruned first, while pending, active, or retryable rows are protected. A compact evidence-ID tombstone survives pruning for 35 days—longer than the maximum 30-day capture window—so forced backfill cannot reinsert and re-review an old row. If protected work fills the cap, new exchanges are deferred and a later forced backfill retries them while they remain inside the lookback window. Only sanitized `*-report.md` files belong in the Git-backed report directory.

For the default path, add this to the surrounding repository's `.gitignore`:

```text
.nanobot-hindsight/
```

## First rollout

1. Install the plugin and restart the Nanobot gateway.
2. Call `hindsight_automation` with `action="status"`.
3. From any ordinary user chat, explicitly say “install the nightly Hindsight review,” then call it with `action="install_nightly"`. The whole-message intent check prevents incidental tool calls from changing cron state. The one workspace-wide job runs in a deterministic dedicated session.
4. Leave `NANOBOT_HINDSIGHT_MODE=observe` for several days.
5. Review the structural nightly reports. Explicitly ask Nanobot to “review memory candidates” for private candidate text and keys, or “review private skill findings” for the full validated skill proposals.
6. Consider automatic Retain only after those reports and private candidate views look correct.

During calibration, disable destructive idle compaction:

```json
{
  "agents": {
    "defaults": {
      "idleCompactAfterMinutes": 0
    }
  }
}
```

Token-pressure consolidation may remain enabled because it preserves the underlying session file. Disabling idle compaction keeps the final exchange of an idle chat available to the watcher and nightly backfill.

Within one gateway process, `install_nightly` is workspace-wide and idempotent across chats: rerunning it updates and re-enables the dedicated-session job and removes or disables plugin-owned legacy duplicates. A same-named job without this plugin's marker or dedicated-session prefix is left untouched. Observe mode never bulk-promotes old proposals when Retain is later enabled.

## Nightly safety boundary

The cron agent starts in a dedicated session with no copied user metadata and calls `hindsight_automation` once with `action="nightly_review"`. This plugin also suppresses automatic Hindsight Recall for the nightly marker. It does not return an evidence bundle or raw transcript to that model.

Nanobot's current cron surface cannot enforce a per-job tool allowlist or invoke a plugin callback without a model turn. The static one-tool prompt is therefore a best-effort behavioral boundary, not a sandbox. The dedicated session and absence of untrusted evidence are the hard controls available without patching Nanobot core.

Inside the plugin, the nightly action:

1. claims bounded, redacted evidence from the private SQLite ledger;
2. sends that evidence directly to Hindsight Reflect with a strict response schema and an instruction to treat evidence as data, not commands;
3. validates the structured response against observed exchanges and the installed-skill inventory; and
4. writes one sanitized Markdown report to the Git-backed report directory.

Full conversations, evidence bundles, raw tool logs, model-authored finding prose, project/person names, health details, memory keys, and candidate hashes are not written to Git or exposed to the unattended Nanobot model. The Git report contains only locally allowlisted structure such as finding kind, severity, action, and opaque evidence IDs. Full validated findings remain in the private SQLite state and are returned only by an explicit ordinary-turn request to “review private skill findings.” Keep the report repository private even with this minimization.

One run reviews the oldest bounded batch of new exchanges plus a rolling, read-only baseline from prior nights, with at most 30 exchanges total. That baseline lets a repeated uncovered task become a missing-skill proposal on its second occurrence, but only current evidence may create a new finding or memory candidate. The result reports `backlog_remains`; if that stays true, run `nightly_review` manually again or temporarily schedule more frequent reviews until the FIFO backlog is clear.

The nightly review may report directly attributable skill failures, routing gaps, dependency incidents, observation gaps, repeated uncovered tasks, and instrumented successes. A missing-skill opportunity requires repeated evidence and no reasonable match in the installed inventory. Loading a skill and later seeing an unrelated tool fail is never enough to blame that skill.

## Retention policy

The automatic selector sees the user message and final assistant answer, not research traces or raw tool output. Local tool evidence is used only to verify claims such as a resolved error.

The gate permits at most three concise candidates per exchange and rejects greetings, research-only content, logs, stack traces, speculation, historical or temporary state, credentials, financial and non-health special-category personal data, attributed/example text, unsupported personal inferences, and unverified fixes. Health facts and dated health events are intentionally permitted because this deployment is meant to remember the user's health context; they remain inside the same strict single-user bank/tag boundary, and any individual message can still opt out. An explicit message-level opt-out such as “don't retain this,” “do not add this to memory,” “forget this,” or “off the record” skips selection and is rechecked before every retry. Mutable facts require category-and-slot keys derived by local code; Reflect cannot invent them. Recognized singleton slots, named project scopes, health fact slots, issue-topic fingerprints, and locally evidenced membership entities receive separate canonical keys; unknown or ambiguous mutable relations remain report-only/rejected. Same-turn corrections use source order, cross-turn competing values use exchange time, and only the newest supported value for a single slot is written. A verified fix first replaces the matching open-issue document with a closed state, then stores the immutable resolution event. Stable user-scoped candidate or mutable-slot document IDs make retries replace instead of duplicate without collapsing distinct events from one exchange.

Health grounding remains deliberately bounded. Common medication names and
conditions, plus explicit named `disease` or `syndrome` forms, are recognized in
bare “I take …” and “I have …” statements. An unrecognized bare value remains
report-only rather than being guessed. Use an explicit form such as “my
medication is X,” “my diagnosis is Y,” or “I was diagnosed with Y” when a name
is not recognized; those forms safely establish the health slot without relying
on a medication or condition word list.

That special-category rule is an automatic Retain boundary, not a claim that a
Recall query, dry-run extraction, or Reflect review can never transmit personal
wording to the Hindsight service you configured. Credential, payment, and direct
identifier redaction is applied again at each network boundary; broader personal
context should be protected by the strict bank scope and trusted HTTPS endpoint.

Message-level opt-out is not a retrospective delete API. Wording such as “forget
my birthday” suppresses automation for that turn, but this plugin cannot promise
to remove an older Hindsight document. Use an explicit, reviewed Hindsight
delete/forget workflow for already stored data; that operation is intentionally
outside this unattended plugin.

Hindsight's dry-run and nightly Reflect may select a candidate, but neither is allowed to author the stored value. The value is copied from an exact redacted user sentence or a canonical verified-resolution sentence tied to a correlated failing and passing tool call. A successful nightly decision closes obsolete mutable candidates that never received a canonical key, so they cannot pin the evidence ledger indefinitely. Failed synchronous Retain writes remain attached to unreviewed evidence and are retried in a bounded batch; they cannot be silently marked reviewed.

Each Retain request contains one atomic candidate. Stable user and user-plus-project observation scopes avoid exponential tag combinations while keeping observations isolated.

Retain runs outside the user-facing turn but waits for Hindsight's storage confirmation before marking evidence complete. Sparsity comes from extraction, validation, and idempotency—not from background execution.

Git reports intentionally show only memory categories, statuses, and opaque evidence IDs—not candidate text, memory keys, or guessable content hashes. The interactive `review_memory` action is the private calibration surface: it returns at most 20 sanitized candidates only when the entire ordinary user message is an affirmative request such as “review memory candidates” or “show me my memory candidates.” Negated, quoted, explanatory, cron, and other automation-triggered requests are rejected. Installing cron also requires an affirmative whole-message request; running a review requires either the marked plugin cron turn or an explicit whole-message manual request. These authorization checks prevent incidental model tool selection from exposing state or causing side effects.

## Compaction and hooks

Nanobot v0.3.0 has no external before-compaction callback. A tool plugin’s `runtime_context_provider()` runs after token-pressure consolidation, idle AutoCompact emits no plugin event, and `AgentHook` has no compaction method. Therefore this plugin cannot safely run a skill immediately before compaction without patching Nanobot core.

The completed-exchange watcher is a defense-in-depth checkpoint, not an awaited lifecycle guarantee. Keep `idleCompactAfterMinutes` at `0` during calibration. If a future plugin API adds `after_run` or `before_compact`, use it only as a last-chance evidence flush; completed-exchange capture and the nightly audit remain the primary cycle.

`memory/history.jsonl` is not used because it records consolidation/archive events rather than every user, assistant, and tool exchange.

## OpenSpace and future mutation

OpenSpace is optional for selective memory, generic tool-error review, and missing-skill detection because Nanobot sessions already contain those calls and results. Directly attributing success or failure to a skill is different: that requires OpenSpace or another observer to emit a tool event that names the skill and its outcome. Without such an event, this plugin reports an `observation_gap`; it never infers that the skill succeeded or failed from nearby calls. OpenSpace silence is therefore never interpreted as an outcome.

This release stops at observation, selective memory, and sanitized reports. Git proposal branches, no-merge trials, automated skill creation, and live skill edits are future phases and are not implemented here. Any mutation controller should be separate, reviewed, tested in an isolated worktree, and unable to push or merge by itself.

## Test

```text
python -m unittest -v test_hindsight_core.py
python -m py_compile hindsight_core.py nanobot_hindsight.py
```
