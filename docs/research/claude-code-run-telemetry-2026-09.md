# What the harness tells us about a Run, and how it would reach the LGTM stack (September 2026)

Editorial cleanup, 2026-09-18: quotations shortened; historical findings and source citations retained. This is not a fresh capability or version verification. Source commit: `baef501a56891257757989e02b1fe3edf639796f`.

Written 2026-09-15. Question: what telemetry does Claude Code export about a headless Run, and
how would it reach the LGTM stack as a signal beside the system's own? Ticket 02 of the
many-alerts-one-incident map.

**Method.** The Claude Code monitoring, headless, CLI-reference and TypeScript Agent SDK pages
were fetched from code.claude.com as Markdown on 2026-09-15 and read in full; the two Transcript
fixtures in this repo were parsed by a script; the `grafana/otel-lgtm` image's collector,
Prometheus and Loki configuration was read from its repository and confirmed against the demo
stack that was running on this laptop. Where a page was silent, seven probes were run against
Claude Code 2.1.272 (the fixtures were recorded on 2.1.270). Six of the seven cost nothing: a
`--bare` session that fails authentication before its first model call still starts the
exporters and flushes them at exit, so its telemetry can be captured without spending a token.
One probe was a real one-turn session. Two replays posted captured payloads into the demo's
running `otel-lgtm` container. Every claim below is cited to a page, a file, or a dated probe;
what neither said is listed under "Could not verify".

## Short answer

1. **Claude Code exports three OpenTelemetry signals, opt-in.** `CLAUDE_CODE_ENABLE_TELEMETRY=1`
   plus `OTEL_METRICS_EXPORTER=otlp` and `OTEL_LOGS_EXPORTER=otlp` give eight metrics and 26
   named log events; `OTEL_TRACES_EXPORTER=otlp` with `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`
   adds spans, in beta. OTLP over `grpc`, `http/protobuf` or `http/json`; a `prometheus` scrape
   endpoint for metrics; `console` ([monitoring]).
2. **It works under `-p --permission-mode dontAsk`** (observed, probes 2 and 4): the OTLP
   payloads arrive, `session.id` is the same UUID as the Transcript's `session_id`,
   `app.entrypoint` is `sdk-cli`, and a 1.2 s session with the default 60 s metric interval
   still delivered both signals at exit. The `console` exporter is a silent no-op under `-p`
   (observed, probe 5), so debugging goes through `--debug-file` and its `[3P telemetry]` lines.
3. **Privacy by default, identity always.** Prompt text, response text, tool arguments and file
   contents are redacted or omitted unless `OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_ASSISTANT_RESPONSES`,
   `OTEL_LOG_TOOL_DETAILS`, `OTEL_LOG_TOOL_CONTENT` or `OTEL_LOG_RAW_API_BODIES` say otherwise;
   `user.email`, `organization.id`, `user.account_id` and `user.account_uuid` ride on every
   metric datapoint and event whenever the session is signed in with a Claude account
   ([monitoring]; observed in the demo Loki). The `api_error` event carries the error message
   verbatim (observed). Nothing captured carried the OAuth token or the sentinel, and no
   documented attribute would.
4. **In the `otel-lgtm` image, logs land; metrics only if the temporality is right.** Loki indexes
   `service_name` and stores everything else as structured metadata ([loki-otlp]; observed). The
   image's metrics store is Prometheus 3.9.1, not Mimir ([otel-lgtm]; observed), and Claude Code
   sends delta counters by default (`aggregationTemporality: 1`, observed), which that Prometheus
   drops (observed by replay, probes 3 and 7; [prom-flags]). Either
   `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative` on the Run ([monitoring]) or
   `PROMETHEUS_EXTRA_ARGS=--enable-feature=otlp-deltatocumulative` on the container
   ([otel-lgtm-prometheus]) fixes it. Traces are routed to Tempo by the image's collector
   ([otel-lgtm-collector]).
5. **The Transcript is a second, richer stream, and it is not OTLP.** Its Run events carry what
   the export redacts (the command, the tool output, the denial text, per-request usage) and
   things the export lacks (rate-limit windows, thinking-token progress, the final cost and turn
   count). Someone, in practice the Receiver, has to ship it. The join keys are `session_id`
   (pre-assignable with `--session-id`), `request_id` and `tool_use_id` ([monitoring],
   [cli-reference], [fixture-a]).
6. **Reference dashboards exist, all fleet-shaped.** Grafana.com 25255 is PromQL over
   `claude_code_*_total` with `session_id`, `model`, `type` and friends as labels; 25052 is the
   same idea on Azure Monitor; Anthropic's own monitoring-guide repo ships a collector, Prometheus
   and Grafana; a community repo ships a compose file for this very `otel-lgtm` image. None shows
   one Run ([dash-25255], [dash-25052], [monitoring-guide], [claude-code-otel]).

## The export, as documented

### Switching it on

Everything is an environment variable, also settable under `env` in a settings file or managed
settings ([monitoring]). The variables a Run would need, with the page's defaults:

| Variable | Values | Default | Note |
| --- | --- | --- | --- |
| `CLAUDE_CODE_ENABLE_TELEMETRY` | `1` | off | Required for any export |
| `OTEL_METRICS_EXPORTER` | `otlp`, `prometheus`, `console`, `none`, comma-separated | `none` | `prometheus` serves a scrape on `localhost:9464/metrics` |
| `OTEL_LOGS_EXPORTER` | `otlp`, `console`, `none` | `none` | Events go out as OTLP log records |
| `OTEL_TRACES_EXPORTER` | `otlp`, `console`, `none` | `none` | Beta; needs `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1` (`ENABLE_ENHANCED_TELEMETRY_BETA` also accepted) |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc`, `http/json`, `http/protobuf` | unset | Per-signal overrides `OTEL_EXPORTER_OTLP_{METRICS,LOGS,TRACES}_PROTOCOL` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | URL | unset | Per-signal `..._{METRICS,LOGS,TRACES}_ENDPOINT`; `OTEL_EXPORTER_OTLP_HEADERS` and per-signal headers for auth; mTLS via `OTEL_EXPORTER_OTLP_CLIENT_KEY`/`_CERTIFICATE` (gRPC) or `CLAUDE_CODE_CLIENT_CERT`/`_KEY` (HTTP); `NODE_EXTRA_CA_CERTS` to trust the collector's CA |
| `OTEL_METRIC_EXPORT_INTERVAL` | ms | `60000` | |
| `OTEL_LOGS_EXPORT_INTERVAL` | ms | `5000` | |
| `OTEL_TRACES_EXPORT_INTERVAL` | ms | `5000` | Beta |
| `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE` | `delta`, `cumulative` | `delta` | See Prometheus below |
| `OTEL_RESOURCE_ATTRIBUTES` | `k=v,k=v`, no spaces | unset | "attached as attributes on every metric datapoint and event record, in addition to sending them in the OTLP resource block"; cannot override `user.id`, `session.id` and the other standard attributes |
| `OTEL_METRICS_INCLUDE_SESSION_ID` | `true`/`false` | `true` | `session.id` on metrics |
| `OTEL_METRICS_INCLUDE_VERSION` | | `false` | `app.version` |
| `OTEL_METRICS_INCLUDE_ENTRYPOINT` | | `false` | `app.entrypoint` |
| `OTEL_METRICS_INCLUDE_ACCOUNT_UUID` | | `true` | `user.account_uuid`, `user.account_id` |
| `OTEL_METRICS_INCLUDE_RESOURCE_ATTRIBUTES` | | `true` | Custom keys as datapoint labels too |
| `OTEL_METRICS_INCLUDE_REPOSITORY` | | `false` | `vcs.*` from the `origin` remote; v2.1.269+ |
| `OTEL_LOG_USER_PROMPTS` | `1` | off | Prompt text on `user_prompt`; also the system prompt text when given via CLI flags |
| `OTEL_LOG_ASSISTANT_RESPONSES` | `1`/`0` | falls back to `OTEL_LOG_USER_PROMPTS` | Response text; v2.1.193+ |
| `OTEL_LOG_TOOL_DETAILS` | `1` | off | Bash commands, tool arguments, MCP and skill names, full error messages, file paths |
| `OTEL_LOG_TOOL_CONTENT` | `1` | off | Tool input and output content on span events only; v2.1.214+ |
| `OTEL_LOG_RAW_API_BODIES` | `1` or `file:<dir>` | off | Full Messages API request and response bodies as `api_request_body`/`api_response_body` events; thinking always redacted |
| `CLAUDE_CODE_OTEL_CONTENT_MAX_LENGTH` | UTF-16 units | `61440` | Truncation for the content flags |
| `CLAUDE_CODE_PROPAGATE_TRACEPARENT` | `1` | off | Send `traceparent` to a custom `ANTHROPIC_BASE_URL` proxy |

The documentation says child tools, hooks, MCP servers and language servers do not inherit
`OTEL_*` variables, so the Run's export configuration does not configure `jira-as`. Managed
settings or a launcher-specified endpoint can override developer telemetry variables
(v2.1.251+). That precedence explains the desktop telemetry environment observed here and
probe 1's lack of output ([monitoring]; observed).

### What identifies a session

Every metric datapoint and event carries the standard attributes: `session.id`, `user.id` (a
random per-installation id persisted in `~/.claude.json`), `organization.id`,
`user.account_uuid`, `user.account_id` and `user.email` when signed in, `terminal.type` when
detected, `app.version` and `app.entrypoint` when enabled, custom `OTEL_RESOURCE_ATTRIBUTES` keys,
and `vcs.*` when enabled. Events add `prompt.id` (one UUID per user prompt), `event.sequence`
(per process, starting at 0), `message.uuid`, `client_request_id`, and `workflow.*`
([monitoring]). The resource block carries `service.name: claude-code` (`claude-code-desktop`
for the desktop app's Code tab), `service.version`, `os.type`, `os.version`, `host.arch`; the
meter is `com.anthropic.claude_code` ([monitoring]). The page names three fields that match the
Transcript: `message.uuid`, `request_id` ("persisted as `requestId` on the transcript's
assistant entries") and `tool_use_id`, with the warning that the transcript format "is internal
to Claude Code and changes between versions" ([monitoring]).

### Metrics

| Metric | Unit | Attributes beyond the standard set |
| --- | --- | --- |
| `claude_code.session.count` | none | `start_type`: `fresh`, `resume`, `continue`, `agents_view` |
| `claude_code.lines_of_code.count` | none | `type`: `added`/`removed`; `model` |
| `claude_code.pull_request.count` | none | |
| `claude_code.commit.count` | none | |
| `claude_code.cost.usage` | `USD` | `model`; `query_source`: `main`/`subagent`/`auxiliary`; `speed`; `effort`; `agent.name`; `skill.name`; `plugin.name`; `marketplace.name`; `mcp_server.name`; `mcp_tool.name` |
| `claude_code.token.usage` | `tokens` | `type`: `input`/`output`/`cacheRead`/`cacheCreation`; `model`; the same attribution set as cost |
| `claude_code.code_edit_tool.decision` | none | `tool_name`: `Edit`/`Write`/`NotebookEdit`; `decision`; `source`; `language` |
| `claude_code.active_time.total` | `s` | `type`: `user`/`cli` |

All eight are from [monitoring]. There is no per-session duration, turn count or denial count
metric; those live in the Transcript's `result` event.

### Events

Twenty-six event names are documented, each an OTLP log record whose attributes carry the payload
([monitoring]). The ones a Run would emit or an audience would want:

| Event | When | Attributes beyond the standard and `event.*` set |
| --- | --- | --- |
| `claude_code.user_prompt` | The prompt is submitted | `prompt_length`; `prompt` (`<REDACTED>` unless `OTEL_LOG_USER_PROMPTS=1`); `message.uuid`; `command_name`, `command_source` |
| `claude_code.assistant_response` | Each API response with text; thinking and tool-use blocks excluded | `response_length`; `response` (redacted by default); `model`; `request_id`; `message.uuid`; `query_source` |
| `claude_code.tool_decision` | A permission decision | `tool_name`; `tool_use_id`; `decision`: `accept`/`reject`; `tool_source`; `source`: `config`, `hook`, `user_permanent`, `user_temporary`, `user_abort`, `user_reject`; `tool_parameters` with details on |
| `claude_code.tool_result` | A tool finishes; never for a rejected call | `tool_name`; `tool_use_id`; `success`; `duration_ms`; `error_type`; `decision_source`; `tool_input_size_bytes`; `tool_result_size_bytes`; `tool_parameters`, `tool_input`, `error` with details on |
| `claude_code.api_request` | Each API request | `model`; `cost_usd`; `cost_usd_micros`; `duration_ms`; `input_tokens`; `output_tokens`; `cache_read_tokens`; `cache_creation_tokens`; `request_id`; `client_request_id`; `speed`; `query_source`; `effort`; attribution set |
| `claude_code.api_error` | A request fails | `model`; `error` (verbatim, always); `status_code`; `duration_ms`; `attempt`; `request_id`; `client_request_id`; `speed`; `query_source`; `effort` |
| `claude_code.api_refusal` | `stop_reason: "refusal"` | `model`; `request_id`; `attempt`; `server_fallback_hop`; `has_category`; `has_explanation`; `category` with details on |
| `claude_code.api_retries_exhausted` | Retries run out | see page |
| `claude_code.compaction` | Context compacted | `trigger`; `success`; `duration_ms`; `pre_tokens`; `post_tokens` |
| `claude_code.subagent_completed` | A subagent returns | `agent_type`; `total_tokens`; `total_tool_uses`; `duration_ms`; `model` |
| `claude_code.permission_mode_changed` | Mode changes | `from_mode`; `to_mode`; `trigger` |

The rest are lifecycle and plumbing: `api_request_body`, `api_response_body`, `auth`,
`mcp_server_connection`, `internal_error`, `plugin_installed`, `plugin_loaded`,
`skill_activated`, `at_mention`, `hook_registered`, `hook_execution_start`,
`hook_execution_complete`, `hook_plugin_metrics`, `feedback_survey`, `retention_sweep`
([monitoring]). Two page notes matter under `-p`: in "Agent SDK or non-interactive `-p`
sessions", `tool_decision` reports a match against a personal deny rule as `user_reject` and a
personal allow rule as `user_permanent`, where the interactive CLI would say `config`; and a
denial by the permission mode itself is `config`, which "doesn't indicate which of these sources
matched" ([monitoring]). A `dontAsk` denial will therefore look like any other config denial.

### Traces (beta)

"Tracing is off by default. To enable it, set both `CLAUDE_CODE_ENABLE_TELEMETRY=1` and
`CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`, then set `OTEL_TRACES_EXPORTER`". Each prompt starts a
`claude_code.interaction` root span with `claude_code.llm_request` and `claude_code.tool`
children; a tool span has `claude_code.tool.blocked_on_user` and `claude_code.tool.execution`
children; `claude_code.hook` needs the separate detailed beta. Every span carries the standard
attributes plus `span.type`; `llm_request` carries `model`, `gen_ai.*`, token counts,
`request_id`, `duration_ms`, `ttft_ms`, `stop_reason`; `tool` carries `tool_name`,
`bash_command_class`, `bash_argv0`, `tool_use_id`, `duration_ms` ([monitoring]).

For SDK and print-mode interactions, the fetched documentation describes reading inbound
`TRACEPARENT` and `TRACESTATE`. With an inbound parent, OTLP event logs include `trace_id` and
`span_id` even without a configured traces exporter; interactive sessions ignore that parent.
Bash children receive the tool span's parent context. Model requests propagate `traceparent`
only when `ANTHROPIC_BASE_URL` is absent or first-party ([monitoring]).

### Privacy defaults

The documented defaults exclude raw files/code and leave prompt, response and tool-argument
content disabled. OAuth telemetry includes `user.email`; enabled arguments may contain sensitive
values and need filtering at the configured backend ([monitoring]). OTLP headers can carry
credentials in the Run environment, but this demo's plain-HTTP Compose collector needs none.

## What a print-mode Run actually sent

All probes ran on this laptop on 2026-09-15 (UTC 2026-09-16 00:11 to 00:18), Claude Code 2.1.272,
with `-p --permission-mode dontAsk --output-format stream-json --verbose --max-turns 1`, stdout
and stderr captured separately, and a throwaway HTTP sink on loopback as the OTLP endpoint.
Probes 2 to 7 used `env -i` so nothing from the desktop launcher could pin the destination.

- **Probe 2, `--bare`, OTLP `http/json`, intervals 1 s and 0.5 s.** The session failed
  authentication in 300 ms and still exported. `POST /v1/logs` carried three records in scope
  `com.anthropic.claude_code.events`, body equal to the event name: `claude_code.user_prompt`
  with `prompt: <REDACTED>` and `prompt_length: 47`, then two `claude_code.api_error` records
  whose `error` attribute was the verbatim "Could not resolve authentication method..." message,
  one from `query_source: generate_session_title` on `claude-haiku-4-5-20251001` and one from
  `query_source: sdk` on `claude-fable-5-1` with `effort: high`. `POST /v1/metrics` carried
  `claude_code.session.count` (`start_type: fresh`) and `claude_code.active_time.total`
  (`type: cli`), both `isMonotonic: true` with `aggregationTemporality: 1`, which is DELTA in
  OTLP. Attributes on every record and datapoint: `user.id`, `session.id`, `app.version`,
  `app.entrypoint: sdk-cli`, `terminal.type: dumb` (the probe set `TERM=dumb`; an interactive
  desktop session in the same Loki shows `non-interactive`), and the two custom keys from
  `OTEL_RESOURCE_ATTRIBUTES`, which also appeared in the resource block next to
  `service.name: claude-code`, `service.version: 2.1.272`, `os.type: darwin`, `os.version`,
  `host.arch: amd64`. The `session.id` value was byte-for-byte the `session_id` of the
  Transcript's `system/init` line. The exporter's User-Agent was
  `OTel-OTLP-Exporter-JavaScript/0.208.0`. No email or organization attribute, because the
  session had no account.
- **Probe 4, the same with default intervals.** Wall time 1.19 s; both `/v1/logs` and
  `/v1/metrics` arrived at exit, and the debug log read `getOtlpReaders: ... interval=60000`
  followed by `First logs export: SUCCESS` and `First metrics export: SUCCESS`. The page does not
  say that a session flushes at exit; this shows it does, at least for a session that ends
  cleanly. A Run killed by the Receiver's timeout (`SIGKILL` to the process group in
  [run-spawner]) would get no such flush.
- **Probe 5, `console` exporters.** stdout held only the three Transcript lines, stderr was
  empty, and the debug log read `getOtlpReaders: types=[]`, `Created 0 log exporter(s)`, then
  `[WARN] [3P telemetry] Event dropped (no event logger initialized): user_prompt`. Under `-p`,
  in this version, `console` resolves to no exporter. The page does not document this. Probe 1,
  a real non-bare session with `console` inside the desktop-pinned environment, likewise printed
  nothing beyond its five Transcript lines.
- **Probe 6, traces.** With `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`, `OTEL_TRACES_EXPORTER=otlp`
  and a `TRACEPARENT` in the environment, `POST /v1/traces` carried scope
  `com.anthropic.claude_code.tracing` with a `claude_code.interaction` span whose parent was the
  span id from `TRACEPARENT` (`parent.source: env`, `user_prompt: <REDACTED>`,
  `interaction.duration_ms`), a child `claude_code.llm_request` with `gen_ai.system: anthropic`,
  `gen_ai.request.model`, `llm_request.context: interaction`, `success: false` and OTLP status
  code 2 with the error message, and a second, standalone `llm_request` for the session-title
  request in its own trace. Every log record in the same session carried the interaction's
  `traceId` and `spanId`. Bare mode was enough; no allowlisting was needed, as the page says
  for `-p`.
- **Probe 1, a real one-turn session, not bare, on the laptop.** `system/init`, one
  `assistant` text, a `rate_limit_event`, a `system/post_turn_summary`, and a `result` with
  `total_cost_usd: 0.765` for the word "ok", because a `-p` session without `--bare` loaded the
  account's plugins, skills and MCP servers into the system prompt. The container's
  init in [fixture-b] shows `plugins: []` and `skills: []`.
- **A side finding on `--bare`.** With `CLAUDE_CODE_OAUTH_TOKEN` set and nothing else, bare mode
  answered `Not logged in · Please run /login` with `error: authentication_failed` and
  `terminal_reason: api_error`, consistent with "In bare mode, Claude Code never reads OAuth
  credentials or the system keychain. For the Anthropic API, set `ANTHROPIC_API_KEY`"
  ([headless]). The harness-sandbox research doc's fourth recommendation stands only with an API
  key behind the Forwarder, not with the OAuth token the demo holds today.

## The Transcript's Run events, from the fixtures

[fixture-a] is 12 lines from a Run in the container on 2.1.270: three turns, 9.995 s,
`total_cost_usd` 0.4527, one denial. [fixture-b] is 40 lines: ten turns, 32.186 s, 0.8569, 409
thinking tokens, no denial. Shapes seen, with the type that documents them in [sdk-ts] where one
exists:

| Kind | Fields seen | In a | In b | Documented as |
| --- | --- | --- | --- | --- |
| `system` / `init` | `session_id`, `model`, `permissionMode`, `tools`, `mcp_servers`, `apiKeySource`, `claude_code_version`, `cwd`, `output_style`, `uuid`; in b also `agents`, `skills`, `plugins`, `capabilities`, `memory_paths`, `messaging_socket_path`, `analytics_disabled`, `fast_mode_state` | 1 | 1 | `SDKSystemMessage` |
| `assistant` | `message` (a Messages API `BetaMessage`: `id`, `model`, `content` blocks of `text`, `thinking` or `tool_use`, `usage` with `input_tokens`, `output_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens`, `service_tier`), `request_id`, `timestamp`, `parent_tool_use_id`, `session_id`, `uuid`; `wire_tool_inputs` on tool-use lines; `narration_block_indexes` on some thinking lines | 4 | 17 | `SDKAssistantMessage`; the two extra keys are not in the type |
| `user` | `message.content` of `tool_result` blocks (`tool_use_id`, `content`, `is_error`), `tool_use_result` (Bash: `stdout`, `stderr`, `interrupted`, `isImage`, `noOutputExpected`; Read: `file`, `type`), `timestamp`; `tool_result_meta: [{id, non_execution_kind: "permission-rule"}]` on a denied call | 2 | 9 | `SDKUserMessage`; `tool_result_meta` is not in the type |
| `system` / `permission_denied` | `tool_name`, `tool_use_id`, `decision_reason_type: "mode"`, `message` (the paragraph handed to the model) | 1 | 0 | `SDKPermissionDeniedMessage`; "best-effort", the result's `permission_denials` is authoritative |
| `rate_limit_event` | `rate_limit_info`: `status`, `resetsAt`, `rateLimitType`, `utilization`, `unifiedWindows` per window, overage fields | 0 | 1 | `SDKRateLimitEvent` (the type lists fewer fields) |
| `system` / `thinking_tokens` | `estimated_tokens`, `estimated_tokens_delta` | 0 | 7 | `SDKThinkingTokensMessage` |
| `system` / `task_summary` | `detail` (a short phrase, or null at the end) | 2 | 3 | not in the `SDKMessage` union, not on the headless page |
| `system` / `post_turn_summary` | `status_category`, `status_detail`, `needs_action`, `summarizes_uuid` | 1 | 1 | not documented either |
| `result` / `success` | `duration_ms`, `duration_api_ms`, `num_turns`, `total_cost_usd`, `usage`, `modelUsage` per model (`inputTokens`, `outputTokens`, `cacheReadInputTokens`, `cacheCreationInputTokens`, `thinkingTokens`, `costUSD`, `contextWindow`), `permission_denials: [{tool_name, tool_use_id, tool_input}]`, `stop_reason`, `terminal_reason`, `ttft_ms`, `first_content_frame_ms`, `subagent_stats`, `result` text | 1 | 1 | `SDKResultMessage`; error arms are `error_max_turns`, `error_during_execution`, `error_max_budget_usd`, `error_max_structured_output_retries` |

Two documented kinds that neither fixture holds and a Run could emit: `system/api_retry`
(`attempt`, `max_retries`, `retry_delay_ms`, `error_status`, `error` category) ([headless]) and
`stream_event` partial messages, which need `--include-partial-messages` ([cli-reference]). The
formatter today renders `init`, `permission_denied`, assistant text and tool calls, tool results
and the result line, and deliberately drops `task_summary`, `post_turn_summary`, thinking blocks
and `rate_limit_event` ([log-formatter]).

## How each signal lands in the LGTM stack

The image's collector listens on `0.0.0.0:4317` (gRPC) and `0.0.0.0:4318` (HTTP), batches, and
exports metrics to `http://127.0.0.1:9090/api/v1/otlp` (Prometheus), logs to
`http://127.0.0.1:3100/otlp` (Loki) and traces to `http://127.0.0.1:4418` (Tempo)
([otel-lgtm-collector]). The repo's compose already publishes 4317 and 4318 and points
`rolldice` at `http://lgtm:4317` ([compose]).

### Loki

Loki turns a fixed list of resource attributes into index labels (`service.name`,
`service.namespace`, `service.instance.id`, `deployment.environment.name`, the `k8s.*` and
`cloud.*` set) and stores everything else, resource, scope and log-record attributes alike, as
structured metadata; dots become underscores; the body is `LogRecord.Body` stringified; the list
is changed with `default_resource_attributes_as_index_labels` under the distributor's
`otlp_config` ([loki-otlp]). Observed in the demo stack's Loki, where an interactive session on
this laptop had been landing all day because the desktop app pins its OTLP endpoint to
`localhost:4317`: the index label set was `service_name` (values `claude-code`,
`claude-code-desktop`, `rolldice`) plus `service_instance_id` from rolldice; a `tool_result`
entry had body `claude_code.tool_result` and structured metadata `session_id`, `event_name`,
`event_sequence`, `event_timestamp`, `prompt_id`, `tool_name`, `tool_use_id`, `success`,
`duration_ms`, `tool_input_size_bytes`, `tool_result_size_bytes`, `scope_name`, `scope_version`,
`service_version`, `os_type`, `host_arch`, `user_id`, `user_email`, `user_account_id`,
`user_account_uuid`, `organization_id`, `terminal_type`, and `detected_level: unknown`. A
per-Run query is therefore
`{service_name="claude-code"} | session_id="<id>" | event_name="tool_result"`, with the Run id
reachable the same way once it is in `OTEL_RESOURCE_ATTRIBUTES`. Loki's default caps of 128
structured-metadata entries and 64 KB per line ([loki-otlp]) are far above what the default
events carry; `OTEL_LOG_TOOL_DETAILS=1` adds a `tool_input` of up to about 4 K characters.

### Prometheus, not Mimir

The image bundles Prometheus, started with `--web.enable-otlp-receiver` and
`--enable-feature=exemplar-storage`, `otlp.promote_resource_attributes` for the `service.*`,
`k8s.*`, `cloud.*` and `host.name` set, `keep_identifying_resource_attributes: true`, and
`out_of_order_time_window: 10m`; `PROMETHEUS_EXTRA_ARGS` appends flags ([otel-lgtm-prometheus]).
The running demo container reported Prometheus 3.9.1 with exactly those flags (observed).

Naming follows Prometheus's default `UnderscoreEscapingWithSuffixes` strategy, which "fully
escapes metric names ... and includes appending type and unit suffixes" ([prom-otlp]): observed
`claude_code_session_count_total` and `claude_code_active_time_seconds_total`; the dashboard
below lists `claude_code_token_usage_tokens_total`, `claude_code_cost_usage_USD_total`,
`claude_code_lines_of_code_count_total`, `claude_code_commit_count_total`,
`claude_code_pull_request_count_total`, `claude_code_code_edit_tool_decision_total`
([dash-25255]). Datapoint attributes become labels (`session_id`, `model`, `type`,
`user_email`, and custom keys such as a run id, because Claude Code stamps them on datapoints);
unpromoted resource attributes go to `target_info` ([prom-otlp]; observed).

Temporality is the trap. "The OpenTelemetry specification says that both Delta temporality and
Cumulative temporality are supported ... cumulative temporality is the default in Prometheus";
the `otlp-deltatocumulative` flag makes Prometheus "convert OTLP metrics from delta temporality
to their cumulative equivalent, instead of dropping them", and it is experimental ([prom-otlp],
[prom-flags]). Claude Code's default is delta, on the page and on the wire. Observed in the demo
stack: after eight hours of an interactive session exporting metrics to it, Prometheus held
`claude-code-desktop` events in Loki and no `claude_code_*` metric at all. Probe 3 replayed the
captured delta payload into `localhost:4318` (HTTP 200) and a copy rewritten to cumulative under
another `session.id`; probe 7 added three more cumulative variants. Every cumulative session id
appeared in the label index and three of the four returned samples; the delta session id never
appeared. The fix on the Run side is one variable,
`OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative` ([monitoring]); on the stack
side, `PROMETHEUS_EXTRA_ARGS=--enable-feature=otlp-deltatocumulative` ([otel-lgtm-prometheus],
[prom-flags]). For a process that lives thirty seconds and owns its `session_id` label,
cumulative is simply the Run's running total, which is what a dashboard wants anyway.

### Tempo

Spans go to Tempo through the collector with no further configuration
([otel-lgtm-collector]); Claude Code's spans carry `session.id` and, under `-p` with
`TRACEPARENT`, a parent chosen by the caller (observed, probe 6). The end-to-end path into the
running Tempo was not exercised.

### Mapping each Run event onto the three stores

The Transcript is the Receiver's to ship; the harness column says what the OTel export already
provides for the same moment, so the spec can choose one or both.

| Run event | Loki | Prometheus | Tempo | Harness export for the same moment |
| --- | --- | --- | --- | --- |
| `system/init` | One line: model, permission mode, tools (the formatter's `[run]` line) | A runs-started counter by `model` | Start of a per-Run root span if the Receiver opens one | `claude_code.session.count`; `user_prompt` event; `claude_code.interaction` span |
| `assistant` text | `[claude]` lines, redacted by the formatter | none | inside the interaction span | `assistant_response` with `response_length` and redacted text |
| `assistant` thinking, `system/thinking_tokens` | drop, as the formatter does | A gauge of `estimated_tokens` per turn, if the audience should see the Run think | none | none; `api_request` carries no thinking count, `result.usage` does |
| `assistant` `tool_use` | `[tool]` line with the command verbatim | A tool-calls counter by `tool_name` | `claude_code.tool` span, beta | `tool_decision` accept (`tool_name`, `tool_use_id`; the command only with details on) |
| `assistant` `message.usage`, `request_id` | metadata on the line | Tokens per request by `type` and `model`, cost | `llm_request` span attributes | `api_request` event; `token.usage` and `cost.usage` counters, delta by default |
| `user` `tool_result` | `[out]`/`[err]` lines, trimmed and redacted | A tool-errors counter from `is_error` | `claude_code.tool.execution` span | `tool_result` (`success`, `duration_ms`, sizes; content never) |
| `system/permission_denied`, `tool_result_meta` | `[DENIED]` line with the reason | A denials counter by `tool_name` | none; no `blocked_on_user` span, nothing waited | `tool_decision` reject with `source: config` |
| `rate_limit_event` | one line, or drop | A utilization gauge per window (`five_hour`, `seven_day`) | none | none documented |
| `system/task_summary`, `post_turn_summary` | drop; undocumented and chatty | none | none | none |
| `system/api_retry` | one line | A retries counter by `error` | none | `api_error` with `attempt`; `api_retries_exhausted` |
| `result` | `[result]` line plus the denial recap | Run duration, cost, turns, denials, per-model tokens, all with the Run id | End of the root span, status from `subtype` | `cost.usage` summed by `session.id`; nothing for duration or turns |

## Reference setups and dashboards

- **Grafana.com 25255, "Claude Code Metrics (Prometheus)"** by rockdarko, for Prometheus,
  VictoriaMetrics, Mimir or Thanos, Grafana 11+: PromQL over the eight `_total` metrics with
  filter labels `organization_id`, `user_email`, `model`, `session_id`, `terminal_type`, `type`,
  `language`, `decision`, `query_source`, `effort`; its setup runs a collector with a Prometheus
  exporter scraped on 9464 ([dash-25255]). The nearest thing to a drop-in for this stack; its
  queries are per-fleet, filterable to one `session_id`.
- **Grafana.com 25052, "Claude Code"** by 1w2w3y, updated 2026-05-01: Azure Monitor and KQL over
  Application Insights, Grafana 11.6+ ([dash-25052]). Not applicable here.
- **`anthropics/claude-code-monitoring-guide`**, the "ROI measurement" repo the monitoring page
  links: a compose of `otel/opentelemetry-collector-contrib`, `prom/prometheus` and
  `grafana/grafana` with a `grafana/dashboards` directory; the collector receives OTLP on 4317
  and 4318 and exposes a `prometheus` exporter on 8889 for Prometheus to scrape; metrics only, no
  Loki in the compose ([monitoring], [monitoring-guide]).
- **`ColeMurray/claude-code-otel`**, MIT: a collector, Prometheus, Loki and Grafana compose with
  a `claude-code-dashboard.json`, and a second `docker-compose-lgtm.yml` that is one service,
  `grafana/otel-lgtm:1.4.0` on 3000, 4317 and 4318, the same image this repo runs
  ([claude-code-otel]).
- The monitoring page itself has no dashboard; it does have the SIEM recipe for events only
  (`OTEL_LOGS_EXPORTER=otlp`, `OTEL_LOG_TOOL_DETAILS=1`, a logs endpoint) and the tip to verify
  a setup by looking for `claude_code.session.count` and `claude_code.user_prompt`
  ([monitoring]).

## What this means for the map

1. **The fourth signal is two feeds with one join key.** The harness's export arrives as
   `service_name="claude-code"` logs, `claude_code_*` metrics and, in beta, spans, every one
   stamped with `session.id`; the Transcript arrives however the Receiver ships it. `session_id`
   is the same UUID in both (observed), and `--session-id <uuid>` lets the Receiver choose it
   ([cli-reference]), so the Run's directory name, its Transcript, its OTel records and its Jira
   comment can all carry one id. `request_id` and `tool_use_id` join at line level.
2. **The variables belong in `RunSpawner._environment`**, which builds a Run's environment from
   scratch ([run-spawner]): `CLAUDE_CODE_ENABLE_TELEMETRY=1`, the two exporter selectors,
   `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://lgtm:4318`,
   `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative`, an export interval short
   enough to watch, and `OTEL_RESOURCE_ATTRIBUTES` naming the Run, the Notification and the
   Fingerprint, which then label every datapoint and record. `jira-as` never inherits them
   ([monitoring]). No header, no TLS, no credential.
3. **Fix temporality on day one or see no metric.** Either variable above or the Prometheus flag;
   the demo stack as it runs today drops every Claude Code counter (observed).
4. **Telling the Run's telemetry from the system's** is free at the label level: the system is
   `rolldice` today and the OpenTelemetry Demo's services tomorrow; the Run is `claude-code`.
   Per-Run filtering is structured metadata in Loki and a label in Prometheus. If the dashboard
   needs a per-Run index label in Loki, the image accepts a mounted Loki config and collector
   config ([otel-lgtm]); the ticket that decides labelling (15) should say whether it is worth
   it.
5. **What the audience must not see is identity, not secrets.** No captured record carried the
   OAuth token or the sentinel, and none is documented to; but `user_email`, `organization_id`
   and `user_account_id` will be on every Run record and label because the Run signs in with the
   OAuth token's account ([monitoring]; observed in Loki). The formatter's `redact` does not
   touch the export. Options: accept it on a demo account, or drop the attributes in the image's
   collector (a mounted `otelcol-config.yaml` with an attributes processor), which is what the
   page recommends ("configure your telemetry backend to filter or redact"). `api_error.error`
   is verbatim; the Forwarder's URL and a `jira-as` failure text could appear there.
6. **The Transcript still has to be shipped.** The export never carries the command, the tool
   output, the denial text, the rate-limit window or the final cost and turn count; the
   formatter's lines do. The image has no log shipper and the demo container's stdout goes to
   `docker compose logs` today ([compose]). The Receiver posting one OTLP log record per Run
   event to `lgtm:4318`, body the formatter line, attributes the kind, subtype, tool name,
   session id and Run id, would keep the redaction and the join key in one place; a shipper on
   the container log is the alternative. That is a spec decision, not made here.
7. **Traces are the legible view of a Run observing itself, and they are beta.** Under `-p` the
   tracer works without allowlisting, nests under a `TRACEPARENT` the Receiver sets, and stamps
   `trace_id` on every log record even with no traces exporter (observed; [monitoring]). One
   trace per Run with a span per tool call is the waterfall an audience reads at a glance; gate it
   on the beta flag and keep the Loki view as the fallback.
8. **Two corrections to earlier assumptions.** `--bare` refuses `CLAUDE_CODE_OAUTH_TOKEN`
   (observed), so the sandbox doc's move to bare mode needs an API key. And the metrics store, which an early draft of the map called Mimir, is
   Prometheus 3.9.1 in this image (observed); nothing changes except the name and the delta
   flag's spelling.
9. **Cost of the fourth signal is nil; cost of the laptop-process form is not.** The export adds
   no tokens. A `-p` session on the laptop without `--bare` loaded the account's plugins and
   skills and cost $0.765 for one word (observed); the container's Run loads none.

## Could not verify

- Whether a Run killed by the Receiver's timeout (`SIGKILL`) loses its buffered telemetry; only
  clean exits were observed to flush, and the page says nothing about flushing.
- Whether `OTEL_RESOURCE_ATTRIBUTES` may override `service.name`; the page rules out overriding
  `user.id` and `session.id` and does not mention `service.name`.
- Traces from a successful Run: `claude_code.tool`, `tool.execution` and `blocked_on_user` spans
  were not exercised; only the interaction and failed `llm_request` spans were seen.
- End-to-end delivery of spans into the running Tempo; the routing was read from the collector
  config only.
- Why the first cumulative replay (probe 3) was indexed without a stored sample when the three
  variants of probe 7 all stored one; the delta finding does not depend on it.
- The full label set Prometheus stored for a Claude Code series; only `session_id` and the custom
  key were printed.
- Whether the `console` exporter's no-op under `-p` is deliberate; it is observed, not
  documented, on 2.1.272.
- Whether `session.id` follows `--session-id`; the flag is documented to set the conversation's
  id, and the equality was observed only for a generated id.
- Mimir's own handling of delta OTLP metrics; the image runs Prometheus.
- The `prometheus` scrape exporter on 9464 inside the container and under `-p`.
- What the export does when the collector is unreachable: whether a Run's exit waits on the
  exporter's timeout, and for how long.
- The Anthropic monitoring-guide repo's Grafana dashboard contents; the directory exists, its
  JSON was not read.

## Sources

- [monitoring] https://code.claude.com/docs/en/monitoring-usage (fetched as
  `monitoring-usage.md`, 2026-09-15)
- [headless] https://code.claude.com/docs/en/headless
- [cli-reference] https://code.claude.com/docs/en/cli-reference
- [env-vars] https://code.claude.com/docs/en/env-vars
- [sdk-ts] https://code.claude.com/docs/en/agent-sdk/typescript (the `SDKMessage` union and
  its member types)
- [fixture-a] `fixtures/run-transcript.jsonl`
- [fixture-b] `fixtures/run-transcript-repeat-firing.jsonl`
- [log-formatter] `grafana_jsm_sandbox/log_formatter.py`
- [run-command] `grafana_jsm_sandbox/run_command.py`
- [run-spawner] `grafana_jsm_sandbox/run_spawner.py`
- [compose] `docker-compose.yml`
- [otel-lgtm] https://github.com/grafana/docker-otel-lgtm
- [otel-lgtm-collector] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/otelcol-config.yaml
- [otel-lgtm-prometheus] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/run-prometheus.sh
  and `.../docker/prometheus.yaml`
- [loki-otlp] https://grafana.com/docs/loki/latest/send-data/otel/
- [prom-otlp] https://prometheus.io/docs/guides/opentelemetry/
- [prom-flags] https://prometheus.io/docs/prometheus/latest/feature_flags/
- [dash-25255] https://grafana.com/grafana/dashboards/25255-claude-code-metrics-prometheus/
- [dash-25052] https://grafana.com/grafana/dashboards/25052-claude-code/
- [monitoring-guide] https://github.com/anthropics/claude-code-monitoring-guide (README,
  `docker-compose.yml`, `otel-collector-config.yaml`)
- [claude-code-otel] https://github.com/ColeMurray/claude-code-otel (README,
  `docker-compose-lgtm.yml`)
- Probes 1 to 7: `claude` 2.1.272 on this laptop, 2026-09-15 local (2026-09-16 00:11 to 00:18
  UTC), a loopback HTTP sink as the OTLP endpoint for probes 2, 4 and 6, and the demo's running
  `grafana-jsm-sandbox_lgtm_1` container (Prometheus 3.9.1, otelcol-contrib 0.143.1) queried
  through its Grafana datasource proxy for probes 3 and 7 and for the Loki and Prometheus
  observations. Probe 1 was the only session that reached the model.
