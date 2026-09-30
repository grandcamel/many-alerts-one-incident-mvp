# Which model, at what effort, on a headless Run (September 2026)

Editorial cleanup, 2026-09-18: quotations shortened; historical findings and public citations retained. This is not a fresh capability or version verification. Source commit: `2f640aa4a14593fe6841058818a1659baab78006`.

Written 2026-09-15. Question: how are the model and the effort set for a Claude Code print-mode
Run, and what does a high-effort Opus 5 Run cost in time and money against a Fable 5.1 one? The
next chapter wants a high-reasoning Run that fits a thirty-minute slot in which one Run may think
for about five minutes on screen, with "Opus 5 at high effort" as the hypothesis to test first.

**Method.** The original research consulted the locally installed claude-api skill before reading
the public sources below. This edited copy removes private skill quotations and uses the existing
public model/pricing citations for its findings; it does not claim the skill was read again.
The cited Claude Code pages (CLI reference, model configuration, settings reference, environment
variables, permission modes, headless, costs, and Agent SDK references) were fetched as raw markdown
from code.claude.com. The installed binary was checked with `claude --version` and `claude --help`
(2.1.272). This repo's
`grafana_jsm_sandbox/run_command.py` and the `result` line of `fixtures/run-transcript.jsonl`
supplied what chapter one already does and what a Run reports. Everything was fetched 2026-09-15.
No live Run was started; anything only a Run could confirm is listed under "Could not verify".

## Short answer

1. **The model is a session choice, and today the Run does not make it.** `--model <alias|id>`
   overrides the `model` settings key and the `ANTHROPIC_MODEL` environment variable; the flag,
   the variable and the key all accept an alias or a full id ([cli-reference], [settings-reference]).
   `run_command.py` passes none of them, so a Run starts on whatever the host's settings resolve to.
   On this laptop that resolved to `claude-fable-5-1` ([fixture]), although the account-type default
   for Max, Team Premium, Enterprise and API accounts is Opus 5 ([model-config]); a saved `/model`
   pick in user settings explains the difference. The full ids are `claude-opus-5` and
   `claude-fable-5-1`; the `opus` alias moves with releases ([models-overview], [model-config]).
2. **Effort is settable on a headless Run, by flag or by variable.** `--effort` supports the
   documented levels and overrides saved effort settings for the session; the environment variable
   has higher precedence, subject to a configured maximum ([cli-reference], [env-vars]). The model-
   configuration page recommends passing `--effort` at launch for `-p` runs ([model-config]). `high` is the
   default on both models ([models-overview]), so "Opus 5 at high effort" is what `--model
   claude-opus-5` gives with no effort flag at all; `xhigh` is the first level that changes anything.
3. **Opus 5 costs half of Fable 5.1 per token on everything except cache reads, where it costs
   double.** $5/$25 against $10/$50 per million input/output tokens, both with a 1M context and
   128K max output ([pricing], [opus-5], [fable-5-1]). Re-priced at Opus 5 rates, the recorded
   chapter-one Run's tokens come to $0.28 against its actual $0.45 ([fixture], arithmetic below).
   What a *high-effort* Run costs is unmeasured: effort changes output and thinking tokens, and the
   fixture had none of the latter.
4. **There is no wall-clock limit on a print-mode Run; the only caps are turns and dollars.**
   `--max-turns` and print-mode `--max-budget-usd` stop a Run when their respective limits are
   reached ([cli-reference]). Both
   end the Run with a `result` line whose `subtype` is `error_max_turns` or `error_max_budget_usd`
   and which still carries `total_cost_usd`, `usage`, `modelUsage` and `permission_denials`
   ([sdk-typescript]). Nothing in the docs ties either cap to `dontAsk`; the recorded Run shows a
   denied tool call consumed a turn like any other ([fixture]).
5. **Raising effort is documented to change tool-call count, on the platform side.** The platform
   describes lower effort as using fewer and terser tool calls and higher effort as potentially using
   more ([effort]). The Claude Code page describes effort as controlling adaptive reasoning only and
   says nothing about tool calls either way ([model-config]).

## The two models

| Model | Model id | Input | Output | 5m cache write | 1h cache write | Cache read | Context | Max output | Comparative latency | Default effort |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Claude Fable 5.1 | `claude-fable-5-1` | $10 / MTok | $50 / MTok | $12.50 / MTok | $20 / MTok | $0.25 / MTok | 1M tokens | 128K tokens | Slower | `high` |
| Claude Opus 5 | `claude-opus-5` | $5 / MTok | $25 / MTok | $6.25 / MTok | $10 / MTok | $0.50 / MTok | 1M tokens | 128K tokens | Moderate | `high` |

Sources: the pricing page ([pricing]), models overview ([models-overview]), and each model page
([opus-5], [fable-5-1]). Notes that matter here:

- Fable 5.1's cache-read multiplier is 0.025x its input price, versus the standard 0.1x multiplier
  for the other models ([pricing]). That is the one line where Fable 5.1 is cheaper per token than Opus 5.
- Both models have the full 1M-token context window at standard pricing ([pricing]).
- Both support all five effort levels, `low` through `max` ([effort], [model-config]).
- Fable 5.1 has always-on adaptive thinking; Opus 5's adaptive thinking is on by default and cannot
  be disabled at `xhigh` or `max` ([models-overview], [effort]).
- Effort labels are calibrated per model and do not denote the same underlying value across models
  ([model-config]).
- The models overview recommends Opus 5 for most workloads and Fable 5.1 for demanding, long-horizon
  work or when higher-effort Opus 5 evaluations fall short ([models-overview]).

## How the model is chosen for a print-mode Run

Claude Code resolves the model in this order: `/model` in the session, `--model` at launch,
`ANTHROPIC_MODEL`, the `model` settings key, then `ANTHROPIC_DEFAULT_MODEL` when no settings file
sets `model` ([model-config], [settings]). The settings key accepts an alias or full ID and otherwise
leaves Claude Code to use the account default ([settings-reference]).

At the September 2026 snapshot, the Anthropic API aliases resolve to Opus 5, Sonnet 5, and Fable 5.1
unless the relevant default-alias variable is set ([model-config]). Aliases may move, so a full model
ID pins a selection. The same source documents account-type defaults and records that choosing a
model with `/model` saves the selection in user settings ([model-config]).

The recorded Run's `system/init` line says `"model": "claude-fable-5-1"` with `"apiKeySource":
"none"` ([fixture]). `run_command.py` sets no model, so the Run inherited the laptop's saved
selection. In the container the same command will inherit whatever `~/.claude/settings.json` the
image carries, which is nothing today, so it would start on the account default instead. The two
environments already disagree; the fix is a `--model` argument.

`--bare`, which the sandbox research recommended for a later ticket, does not change model
resolution; it skips hooks, skills, plugins, MCP servers, auto memory and CLAUDE.md and "Sets
`CLAUDE_CODE_SIMPLE`" ([cli-reference]).

## How effort is set, and whether it reaches a headless Run

Effort controls adaptive reasoning, letting the model decide how much to think at each step based on
task complexity ([model-config]). With `ultracode` off, the documented resolution order is:

1. Explicit `CLAUDE_CODE_EFFORT_LEVEL`, `--effort`, or `/effort` selection.
2. A hold on model default effort; the source says Opus 5 and Fable 5.1 have no such hold.
3. Saved settings: `modelSettings` per model or the top-level `effortLevel`
4. The model default: `high` for the relevant models ([model-config]).

Everything a headless Run can use is in the first and third steps. For non-interactive `-p` sessions,
the documentation recommends `--effort` at launch; an organization cap warns in plain text but applies
silently to JSON and stream-JSON output ([model-config]). The Agent SDK, which wraps the same `-p` entry point, exposes
`effort: 'low' | 'medium' | 'high' | 'xhigh' | 'max'` as a query option ([sdk-typescript],
[sdk-python]). `claude --help` on the installed 2.1.272 lists `--effort <level>  Effort level for
the current session` ([help]).

Three details that affect the demo:

- **`max` is session-only by design.** The documentation says it can persist only through
  `CLAUDE_CODE_EFFORT_LEVEL`, not the `effortLevel` or `modelSettings` keys ([model-config]). For a Run
  that is fine: a flag or the variable is the natural carrier anyway.
- **The Transcript will not say which effort ran.** The SDK limits the `system/init` effort field to
  Remote Control clients and omits it from application-visible init messages ([sdk-typescript]). The
  fixture's init line indeed has none ([fixture]). The observable is
  `usage.output_tokens_details.thinking_tokens` on the result line (0 in the fixture).
- **Thinking cannot be turned off on Fable, and on Opus 5 turning it off clamps effort.**
  `MAX_THINKING_TOKENS=0` does not disable Fable thinking; on Opus 5, Claude Code falls back to
  `high` when thinking-off and higher effort are incompatible ([env-vars], [model-config]). Nonzero values are ignored
  on adaptive-reasoning models ([env-vars]), so `MAX_THINKING_TOKENS` is not a lever for this demo.

## Flags, settings and variables, as documented

| Control | Summary | Source |
| --- | --- | --- |
| `--model <alias\|id>` | Session model selection; overrides `model` and `ANTHROPIC_MODEL`. | [cli-reference] |
| `ANTHROPIC_MODEL` | Shell model selection; outranks file settings. | [env-vars], [settings] |
| `model` (settings key) | Alias or full ID; otherwise account default; overridden by flag and environment. | [settings-reference] |
| `ANTHROPIC_DEFAULT_MODEL` | Default for new sessions when no other selector applies; v2.1.236+. | [env-vars], [settings-reference] |
| `ANTHROPIC_DEFAULT_OPUS_MODEL` / `_FABLE_MODEL` | Pin `opus` or `fable` aliases with full model IDs. | [model-config] |
| `--effort <level>` | Session effort selection; overrides saved effort but does not persist. | [cli-reference] |
| `CLAUDE_CODE_EFFORT_LEVEL` | Environment effort selection; outranks flag and saved settings, subject to `maxEffortLevel`. | [env-vars] |
| `effortLevel` (settings key) | Default saved effort; lower precedence than flag and environment. | [settings-reference] |
| `modelSettings` (settings key) | Per-model effort and optional maximum; outranks top-level effort. | [settings-reference] |
| `maxEffortLevel` (settings key) | Caps higher requested effort, including flag and environment selections. | [settings-reference] |
| `--max-turns <n>` | Print-mode agentic-turn cap; exits with an error at the limit. | [cli-reference] |
| `CLAUDE_CODE_MAX_TURNS` | Turn cap when the flag is absent. | [env-vars] |
| `--max-budget-usd <amount>` | Print-mode API-spend cap; subagent spend counts. | [cli-reference] |
| `--permission-mode dontAsk` | Denies calls that would prompt. | [headless] |
| `--permission-prompts none` | In headless `-p`, prevents retries of denied prompts; v2.1.259+. | [headless] |
| `--fallback-model <m,...>` | Ordered fallback models when the primary is unavailable or overloaded. | [cli-reference] |
| `CLAUDE_CODE_MAX_OUTPUT_TOKENS` | Output cap; defaults and caps vary by model; fixture reports 64,000 for Fable 5.1. | [env-vars], [fixture] |
| `MAX_THINKING_TOKENS` | Fixed budget control for non-adaptive models; nonzero values ignored on adaptive models. | [env-vars] |
| `API_TIMEOUT_MS` | Per-request timeout; default 600,000 ms. | [env-vars] |
| `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS` | Post-final-turn background-subagent idle wait; default 600,000 ms. | [env-vars] |

What `run_command.py` passes today: `--print`, `--permission-mode dontAsk`, `--allowedTools
"Bash(jira-as *)" Read`, `--output-format stream-json`, `--verbose`, `--add-dir`,
`--append-system-prompt`, and the prompt. No model, no effort, no turn or budget cap
([run_command]). `claude --help` on 2.1.272 lists `--effort`, `--model`, `--max-budget-usd`,
`--permission-mode` and `--permission-prompts`; it does not list `--max-turns`, though the CLI
reference and the `CLAUDE_CODE_MAX_TURNS` variable both document it ([help], [cli-reference],
[env-vars]).

## Limits on a print-mode Run, and what happens at each

**Turns.** A turn is "Maximum agentic turns (tool-use round trips)" in the SDK option table and
"Maximum number of agentic turns (API round-trips) before stopping" in the agent-definition table
([sdk-typescript]). The recorded Run has `num_turns: 3` for three assistant message ids: one that
ran `seq 1 40`, one whose `ls /etc` was denied by `dontAsk`, and the closing text ([fixture]). So a
denied call is a round trip and counts. At the limit, the result line's `subtype` is
`"error_max_turns"` and `terminal_reason` is `"max_turns"`; the error shape still carries
`duration_ms`, `duration_api_ms`, `num_turns`, `total_cost_usd`, `usage`, `modelUsage`,
`permission_denials` and an `errors: string[]` ([sdk-typescript]). The process exits non-zero:
"Claude Code exits with code 0 on success and a non-zero code when the run fails" ([headless]).
The Python SDK's rule of thumb applies to a Receiver reading the stream too: "when a limit you set
ends the run, such as `max_turns` or `max_budget_usd`, it reports an `error_*` subtype", whereas a
failed final request "reports `subtype` `"success"` with the cause in `terminal_reason`"
([sdk-python]).

**Dollars.** `--max-budget-usd` is "compared against the same estimate as `total_cost_usd`"
([sdk-typescript]), and that estimate is "client-side estimates, not authoritative billing data. The
SDK computes them locally from a price table bundled at build time" ([sdk-cost-tracking]). The check
is after the fact: on `error_max_budget_usd`, "`usage` leaves out the response that crossed the
budget, while `total_cost_usd` and `modelUsage` include it" ([sdk-cost-tracking]), so a Run can
overshoot by one response. The recorded Run's `modelUsage` entry says `"costBasis": "list"`
([fixture]): the figure is list price even though the Run authenticated with OAuth
(`apiKeySource: "none"`), so on a subscription it is a proxy for spend, not a bill.

**Time.** No variable or flag caps a Run's wall clock; the env-vars page has timeouts per API
request (`API_TIMEOUT_MS`, 10 minutes), per Bash command (`BASH_MAX_TIMEOUT_MS`, 10 minutes), per
WebFetch, and for the post-final-turn background wait, and nothing else ([env-vars]). For a deadline,
the headless documentation distinguishes SIGTERM (exit 143, unfinished current turn, no result) from
SIGINT (ends the turn and yields a result line) ([headless]).

**`dontAsk` and the caps together.** The docs describe them separately. `dontAsk` "auto-denies
every tool call that would otherwise prompt you ... the session never waits for input"
([permission-modes]); denials "appear as `permission_denied` system messages, and the final result
message lists them in `permission_denials`" ([headless]). Without `--permission-prompts none`,
nothing tells Claude not to retry a denied call, and each retry is another round trip against
`--max-turns`. With it, "Claude is told that nobody can approve the request and not to retry it"
([headless]). The interaction, then, is arithmetic rather than a rule: a turn cap has to leave room
for the denials the skill's guardrails are expected to produce, or the retry has to be switched off.

## Does effort change how many tool calls a Run makes?

Yes, per the platform page that defines the parameter. It applies to response text, tool calls and
arguments, and active thinking. Lower effort tends toward fewer, terser calls; higher effort may
make more calls and provide more planning and summaries. It is a behavioral signal rather than a
strict token budget ([effort]).

Two model-specific notes bear on a Run that must retrieve evidence. At `low`, Fable 5.1 is less likely
than Fable 5 to search or retrieve and more likely to answer from memory. In implied bash/editor
loops it may issue otherwise independent calls one per turn, adding tokens, a round trip and elapsed
time ([prompting-fable-5-1]). Both support `high` or above and a prompt that names the queries to run.

The Claude Code page frames effort as thinking depth: lower effort is faster and cheaper for simpler
tasks, while higher effort provides deeper reasoning for complex ones ([model-config]). It neither
confirms nor contradicts the tool-call statement.

## Cost and time: Opus 5 against Fable 5.1

**Per token.** Every line of Opus 5's price sheet is half of Fable 5.1's except cache reads, which
are $0.50 against $0.25 ([pricing]). For Fable 5.1 to come out cheaper on a Run, cache-read spend
would have to exceed everything else by a wide margin; with a 1-hour cache write of a twenty-thousand
token prompt on every Run, it does not.

**On the recorded Run.** The chapter-one fixture reports 66 input, 20,365 1h-cache-write, 131,802
cache-read and 235 output tokens, `total_cost_usd: 0.45266`, three turns, `duration_ms: 9995`,
`duration_api_ms: 6400`, `ttft_ms: 2479` and `thinking_tokens: 0` ([fixture]). At the Fable 5.1
prices above: 66 x $10 + 20,365 x $20 + 131,802 x $0.25 + 235 x $50, all per million, is $0.00066
+ $0.40730 + $0.03295 + $0.01175 = $0.45266. The harness's bundled price table and the pricing page
agree to the cent, and the 1-hour cache write of the appended prompt and skill was 90% of the
Run's cost. The same tokens at Opus 5 prices: $0.00033 + $0.20365 + $0.06590 + $0.00588 =
$0.27576, or 61% of the Fable figure. That is the price of the *same* tokens; it says nothing about
how many tokens a high-effort Run of the next chapter's skill will produce.

**What effort does to tokens and minutes, measured elsewhere.** Anthropic reports benchmark results,
not incident triage. On research and knowledge work, Fable 5 `low` traded 1--3 points for roughly
one-third to one-half lower per-task cost; `medium` matched default accuracy at 70--87% of its cost.
DeepWideSearch was 4.5 minutes at `low` and 7.9 minutes at default. A coding subset put default Opus
5 and Fable 5.1 within run-to-run noise (91.7% versus 92.1%), with Opus 5 about 15% cheaper
per solved task ($1.01 versus $1.19); low-effort Opus 5 scored 84.0% for $0.25. A research
benchmark scored default Opus 5 at 71% for $6.71 per task versus Fable 5.1 at 65% for $7.12
([cost-optimization]).
The cost page recommends starting Fable 5.1 at `low` and raising effort where it misses; the models
overview recommends starting with Opus 5 ([cost-optimization], [models-overview]).

**Per-request time.** The models overview rates Fable 5.1 slower and Opus 5 moderate, while noting
that latency depends on prompt length, output length and thinking effort ([models-overview]). At
`xhigh` and `max`, Fable 5.1 can think longer before replying ([prompting-fable-5-1]). Two
harness limits bound a single request: `API_TIMEOUT_MS` at ten minutes ([env-vars]) and the per-
request output cap, 64,000 tokens for Fable 5.1 in the recorded Run ([fixture]), which thinking
counts toward: the output cap covers thinking plus response text, and higher effort increases
the risk of exhausting that combined budget ([thinking-cost]). The platform's own default for Opus 5 at `xhigh` or `max` is
"Starting at 64k tokens and tuning from there" ([effort]).

## What this means for the map

1. **Pin the model in `run_command.py`, by full id.** Add `--model claude-opus-5` (or
   `claude-fable-5-1` for the comparison arm). Today the laptop and the container resolve the model
   differently, and the `opus` alias has moved twice this year ([model-config], [fixture]).
2. **Carry effort on the command line or in the container's environment.** `--effort xhigh` is the
   documented launch-time control for `-p`; `CLAUDE_CODE_EFFORT_LEVEL` outranks it and fits the
   Receiver's env file. Say which one the demo uses, because the Transcript will not
   ([sdk-typescript]). Note that `high` is the default: the hypothesis "Opus 5 at high effort" is
   the no-flag configuration, and the first real experiment is `xhigh` ([effort], [model-config]).
3. **The fit-to-slot guards are `--max-turns` and `--max-budget-usd`, plus SIGINT from the
   Receiver.** There is no wall-clock cap. Both caps end the Run with an `error_*` result line the
   log formatter can already render, a non-zero exit, and `permission_denials` intact
   ([sdk-typescript], [headless]). The Receiver should treat those as a finished Run with a partial
   Report, not a crash, and should send SIGINT before SIGTERM if it enforces a deadline of its own.
4. **Size the turn cap for denials, or turn retries off.** Under `dontAsk` a denied call is a turn
   ([fixture]); `--permission-prompts none` (v2.1.259+, the image has 2.1.272) tells Claude not to
   retry ([headless]). The next chapter's Eyes will widen the allow list, which is the other way to
   keep denials out of the turn count.
5. **Measure before choosing; the prices predict the ranking of tokens, not of Runs.** Ticket 11's
   prototype should record, per arm, `num_turns`, `duration_ms`, `duration_api_ms`,
   `thinking_tokens` and `total_cost_usd` from the result line, and the count of tool calls from the
   Transcript, on the same Cascade. Anthropic's own numbers show Opus 5 at default beating Fable 5.1
   at default on cost per task in two of three benchmark families ([cost-optimization]); whether that
   holds for a five-minute triage is exactly what the prototype is for.
6. **The prompt's size is the cost lever chapter one never pulled.** Ninety percent of the recorded
   Run's cost was writing the appended prompt and skill into the 1-hour cache ([fixture],
   arithmetic above). As the one Skill becomes several, that write grows; Runs within an hour that
   share a byte-identical prefix read it at 10% (Opus 5) or 2.5% (Fable 5.1) of input price
   ([pricing]).
7. **`--bare` and the Forwarder-held API key change the price basis, not the price.** A Run on an
   API key is billed at the list prices above; a Run on OAuth reports the same estimate against a
   subscription ([sdk-cost-tracking], [fixture]). Cost per demo (an open item on the map) needs the
   basis decided first.

## Could not verify

- **No live `-p` Run was started** with `--effort`, `--max-turns` or `--max-budget-usd`. The flags
  are documented and two of the three appear in `claude --help` 2.1.272; `--max-turns` is documented
  but absent from that help text. Whether the binary accepts it is a one-command test in ticket 11.
- **That every denied tool call counts as a turn** is read off one fixture (`num_turns: 3`, one
  denial), not stated in any page fetched.
- **Per-turn latency of Opus 5 against Fable 5.1 on this workload.** The docs give comparative
  labels ("Moderate", "Slower") and benchmark minutes on unrelated tasks; no page gives seconds per
  round trip. The five-minute think is a measurement, not a lookup.
- **What Claude Code does when one request exceeds `API_TIMEOUT_MS`** (retry with an `api_retry`
  event, or fail the turn) was not read; only the default was.
- **Whether `--max-budget-usd` behaves identically on OAuth and API-key runs.** It compares against
  the client-side estimate, which the fixture shows is computed on OAuth too, but no page says so.
- **Whether Claude Code sends `output_config.effort` on every request or omits it at the default.**
  The SDK says the init field is "the effort level Claude Code sends on the session's next request,
  or `null` when it sends none" ([sdk-typescript]); either way the API default is `high` ([effort]).
- **Cross-Run cache sharing.** The fixture's first request already read 30,650 cached tokens while
  writing 19,821; that looks like the Claude Code system prompt cached by an earlier session on the
  same account, but no page fetched describes cache scope across separate `claude -p` processes.
- **Pricing can drift.** The cited pricing page was the September 2026 snapshot; it recorded that a
  scheduled Sonnet 5 price change would not occur ([pricing]).

## Sources

- [pricing] https://platform.claude.com/docs/en/about-claude/pricing
- [models-overview] https://platform.claude.com/docs/en/about-claude/models/overview
- [opus-5] https://platform.claude.com/docs/en/models/opus-5/overview
- [fable-5-1] https://platform.claude.com/docs/en/models/fable-5-1/overview
- [effort] https://platform.claude.com/docs/en/build-with-claude/effort
- [thinking-cost] https://platform.claude.com/docs/en/build-with-claude/thinking-steering-and-cost
- [prompting-fable-5-1] https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompting-claude-fable-5-1
- [cost-optimization] https://platform.claude.com/docs/en/about-claude/models/optimizing-for-cost-and-intelligence
- [cli-reference] https://code.claude.com/docs/en/cli-reference
- [model-config] https://code.claude.com/docs/en/model-config
- [settings] https://code.claude.com/docs/en/settings
- [settings-reference] https://code.claude.com/docs/en/settings-reference
- [env-vars] https://code.claude.com/docs/en/env-vars
- [permission-modes] https://code.claude.com/docs/en/permission-modes
- [headless] https://code.claude.com/docs/en/headless
- [costs] https://code.claude.com/docs/en/costs
- [sdk-typescript] https://code.claude.com/docs/en/agent-sdk/typescript
- [sdk-python] https://code.claude.com/docs/en/agent-sdk/python
- [sdk-cost-tracking] https://code.claude.com/docs/en/agent-sdk/cost-tracking
- [help] `claude --version` and `claude --help` on this laptop, 2026-09-15 (2.1.272)
- [run_command] `grafana_jsm_sandbox/run_command.py` in this repo
- [fixture] `fixtures/run-transcript.jsonl` in this repo, recorded 2026-09-14 with Claude Code
  2.1.270; the `system/init` line and the `result` line
