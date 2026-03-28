# mcpnuke Changelog

All notable changes to this submodule are documented here.

## [6.0.0] - 2026-03

### Added

- **Stdio transport (`--stdio CMD`)** — Scan local MCP servers via stdin/stdout JSON-RPC.
  Launches the command as a subprocess, communicates over newline-delimited JSON-RPC.
  Eliminates the need for a proxy when scanning npm/npx/python-based MCP servers.
  E.g. `--stdio 'npx -y @modelcontextprotocol/server-everything'`

- **Fast mode (`--fast`)** — Samples top 5 security-relevant tools (ranked by danger
  keywords, URL/command params, schema size), skips heavy probes (input_sanitization,
  error_leakage, temporal_consistency, ssrf_probe), caps probe workers at 2. Cuts
  LLM-backed scan time from ~30min to ~2min.

- **Grouped findings (`--group-findings`)** — Collapses similar findings by check/severity
  into compact rows with affected-tool lists and counts. Cleaner reports for servers
  with many tools generating similar findings.

- **Parallel probe workers (`--probe-workers N`)** — Deep behavioral probes run
  concurrently via ThreadPoolExecutor with thread-safe finding accumulation.
  Default: 1 (sequential). Set higher for faster scans at the cost of more
  server load.

- **Adaptive backoff in `_call_tool`** — Per-tool latency tracking, exponential retry
  with jitter, progressive timeouts up to 30s. Reduces timeouts on slow servers
  and avoids hammering overloaded endpoints.

- **9 encoding bypass probe types** in `input_sanitization` — base64, hex, double-URL,
  homoglyph, null byte, CRLF, fullwidth, concatenation, variable expansion. Each
  technique commonly defeats blocklists that only filter raw payloads.

- **Live exfil flow verification** — `check_exfil_flow` now performs source→sink tool
  calls with canary data when a session is available, confirming reachability of
  theoretical exfiltration paths (not just static classification).

- **SSE+POST fallback fix** — Added `/message` to `POST_PATHS` and the SSE+POST
  fallback combo loop for supergateway compatibility.

## [5.0.0] - 2026-03

### Added

- **Three new static security checks (MCP-T07, MCP-T09, MCP-T14):**
  - `config_tampering` (MCP-T09) — Flags tools that can modify agent config, system prompt, or tool registry
  - `webhook_persistence` (MCP-T14) — Flags callback/webhook params enabling persistent re-injection
  - `credential_in_schema` (MCP-T07) — Detects hardcoded credentials in tool schema definitions

- **Rename: mcprowler → mcpnuke** — Full project rename across all source, tests, docs, K8s manifests, and Dockerfile.

- **Verbose mode (`-v`)** — Now emits real output throughout the scan pipeline:
  - Transport detection: shows each SSE/HTTP path probed, HTTP status codes, content types
  - Server info: prints server name, version, protocol version, capabilities
  - Enumeration: lists every discovered tool, resource, and prompt with descriptions
  - Timing: shows per-phase duration

- **OIDC client_credentials auth** — Automatic token acquisition from Keycloak or any OIDC provider:
  - `--oidc-url URL` — OIDC issuer URL (e.g. `http://keycloak:8080/realms/myapp`)
  - `--client-id ID` / `--client-secret SECRET` — OAuth2 client credentials
  - Env vars: `MCP_OIDC_URL`, `MCP_CLIENT_ID`, `MCP_CLIENT_SECRET`
  - Auto-discovers token endpoint via `.well-known/openid-configuration`
  - Falls back to standard Keycloak path if discovery fails
  - `mcpnuke/core/auth.py` — `AuthInfo`, `detect_auth_requirements`, `fetch_client_credentials_token`, `resolve_auth_token`

- **Auth-aware transport detection** — Distinguishes "server needs auth" from "no transport found":
  - Detects 401/403 during transport probing and surfaces `WWW-Authenticate` header
  - Returns a valid session for auth-required endpoints (so auth can be resolved separately)
  - In verbose mode, auto-probes first target and suggests the right `--oidc-url` to use

- **DVMCP challenge test suite** (`tests/test_dvmcp.py`) — 44 offline tests covering all 10 DVMCP challenges:
  - Ch1: Prompt injection (5 tests), Ch2: Tool poisoning (5), Ch3: Permissions (5), Ch4: Rug pull (2), Ch5: Token theft (5), Ch6: Code execution (4), Ch7: Remote access (4), Ch8: Rate limit + prompt leakage (4), Ch9: Supply chain (4), Ch10: Multi-vector (4), Full pipeline integration (2)
  - 30 optional live tests (`DVMCP_LIVE=1`) for transport, tools, and findings per port 9001-9010

- **Quickstart script** (`quickstart.sh`) — One-command setup: detects uv/pip, creates venv, installs deps, runs tests
  - `--skip-tests` and `--with-dvmcp` flags
  - `./scan` wrapper for zero-config execution without venv activation

- **Kubernetes deployment and in-cluster scanning** — Run mcpnuke as a K8s Job with full cluster posture auditing:
  - `k8s/discovery.py` — Auto-discover MCP endpoints via service annotations (`mcp.io/enabled`, `mcp.io/transport`, `mcp.io/path`), well-known port matching, and active MCP protocol probing
  - `k8s/scanner.py` — Enhanced with pod security checks (privileged containers, hostNetwork/PID, dangerous capabilities, hostPath mounts, missing resource limits), ConfigMap secret scanning, and NetworkPolicy auditing
  - `k8s/fingerprint.py` — Internal service fingerprinting: detects Spring Boot, Flask, Express, FastAPI, Django, Go, Envoy, Nginx, ASP.NET; probes for exposed actuator, debug/pprof, swagger/openapi, graphiql, and admin endpoints
  - SA blast radius mapping — Enumerates effective permissions for each ServiceAccount via SelfSubjectRulesReview impersonation, flags overprivileged accounts (secret access, pod exec, wildcard verbs)
  - Helm release version diffing — Compares decoded values across release versions (v1, v2, ...) to find credentials removed in newer releases that remain recoverable from old release secrets
  - `k8s/Dockerfile` — Multi-stage Python 3.12-slim image, runs as non-root
  - `k8s/manifests/` — Kustomize-ready manifests: Namespace, ServiceAccount, ClusterRole/Binding (read-only), Job, CronJob (6h schedule), all with pod security hardening (non-root, read-only rootfs, drop all caps, seccomp)
  - CLI: `--k8s-discover`, `--k8s-discover-namespaces NS [NS ...]`, `--k8s-no-probe`
  - K8s-only report mode: prints findings and writes JSON even when no MCP targets are discovered
  - **Many-MCP clusters:** Parallel K8s discovery and fingerprinting:
    - `discover_services()` runs MCP probes in parallel (`ThreadPoolExecutor`, default 10 workers); deduplicates by URL; optional `max_endpoints` cap.
    - `fingerprint_services()` runs per-service HTTP probes in parallel (same worker count).
    - CLI: `--k8s-discovery-workers N`, `--k8s-max-endpoints N`, `--k8s-discover-only` (list endpoints only, no MCP scan). See README "Clusters with many MCPs".

- **Custom tool-server detection (`ToolServerSession`)** — Scans non-MCP tool-execute APIs (e.g. `POST /execute` with `{"tool": "...", "query": "..."}`):
  - Auto-detects tool servers by probing `/execute`, `/tools/execute`, `/api/execute`, `/run` with tool-style payloads; recognizes servers from 200+JSON or 400 "unknown tool" responses
  - Enumerates available tools from a built-in wordlist of 84 tool names (`data/tool_names.txt`), supplemented by optional `--tool-names-file`
  - Translates MCP-style `tools/call` into tool-server POST requests so all existing static and behavioral checks run natively
  - Fallback in `detect_transport`: tried after SSE and HTTP JSON-RPC detection fail
  - Tightened JSON-RPC error detection: removed overly broad `"error" in body` match that falsely classified custom APIs as MCP
  - Added `/execute` and `/health` to K8s discovery `PROBE_PATHS`
  - Scanner labels ToolServer transport type distinctly from SSE/HTTP
  - **Tool server fingerprinting** — Detects framework (Flask, FastAPI, Express, Spring Boot, Django, Go, ASP.NET) from response headers (`Server`, `X-Powered-By`, etc.). Displayed in transport label: `ToolServer (framework=Flask, server=Werkzeug/3.0.1)`
  - **Expanded tool name enumeration** — ~90 tool names loaded from `data/tool_names.txt` (cluster ops, diagnostics, CRUD, auth, file, network, AI). Custom wordlists via `--tool-names-file FILE` (supplements built-in list)
  - **Expanded path detection** — 20+ execute/invoke paths probed (`/execute`, `/invoke`, `/api/execute`, `/v1/run`, `/command`, `/action`, etc.). Uses GET 404 pre-check to skip non-existent paths quickly
  - **Parameter inference from errors** — When a tool returns `"X is required"`, the parameter is automatically added to the inferred schema with correct `required` constraint
  - CLI: `--tool-names-file FILE` for custom tool name wordlists

- **Behavioral probe engine** — 9 new checks that actively call tools and analyze responses, moving beyond static metadata analysis:
  - `check_tool_response_injection` — Calls each tool with safe inputs, scans responses for injection payloads, hidden instructions, exfiltration URLs, invisible Unicode, and base64-encoded attacks
  - `check_input_sanitization` — Sends context-aware probes (path traversal, command injection, template injection, SQL injection) and detects unsanitized reflection. Uses a canary string (`MCP_PROBE_8f4c2a`) to confirm reflection.
  - `check_error_leakage` — Sends empty, wrong-type, and prototype-pollution inputs; checks for stack traces, internal paths, connection strings, secrets in error responses
  - `check_temporal_consistency` — Calls the same tool 3x with identical input; detects escalating injection, wildly inconsistent responses, or new threats appearing in later calls
  - `check_resource_poisoning` — Deep resource content analysis: base64-encoded injection payloads, data URIs, steganographic invisible Unicode, CSS-hidden HTML, markdown image exfiltration
  - `check_cross_tool_manipulation` — Detects when a tool's output contains instructions directing the LLM to invoke other tools (cross-tool orchestration attacks)
  - `check_deep_rug_pull` — Snapshots tools → invokes each tool multiple times → re-snapshots. Catches rug pulls that only trigger after N tool invocations (e.g. DVMCP challenge 4), including schema mutations
  - `check_state_mutation` — Snapshots resource contents before and after tool invocations; detects silent server state changes, new/disappeared resources
  - `check_notification_abuse` — Monitors SSE message queue for unsolicited `sampling/createMessage`, `roots/list`, or other server-initiated requests that abuse MCP's bidirectional protocol

- **Probe payload library** (`patterns/probes.py`)
  - Canary string system for detecting unsanitized reflection
  - Context-aware safe argument generation from tool schemas
  - Injection probe sets: path traversal (4), command injection (5), template injection (5), SQL injection (3)
  - Response analysis patterns: injection (12), exfiltration (3), cross-tool (3), hidden content (5), error leakage (9)
  - Steganographic Unicode detection (zero-width, bidi, invisible formatters)
  - CSS-hidden HTML and markdown image exfiltration detection

- **Attack chain patterns** — 10 new behavioral chain combinations:
  - `tool_response_injection → cross_tool_manipulation`
  - `tool_response_injection → token_theft`
  - `deep_rug_pull → tool_poisoning`
  - `deep_rug_pull → tool_response_injection`
  - `input_sanitization → code_execution`
  - `resource_poisoning → tool_response_injection`
  - `state_mutation → deep_rug_pull`
  - `notification_abuse → token_theft`
  - `cross_tool_manipulation → code_execution`
  - `cross_tool_manipulation → token_theft`

- **Check execution ordering** — `run_all_checks()` now runs in deliberate phases: static → behavioral → deep probes → transport → aggregate. Aggregate checks (multi_vector, attack_chains) run last so they see all prior findings.

- **Production safety controls**
  - `--no-invoke` — Static-only mode: skips all behavioral probes that call tools. Safe for production servers where tool invocation could have side effects.
  - `--safe-mode` — Skips invoking tools classified as dangerous (delete, send, exec, write, deploy, etc.) while still probing read-only tools.
  - `--probe-calls N` — Configurable invocations per tool for deep rug pull detection (default: 6). Increase for stubborn thresholds.

- **Tool danger classification** — Tools are classified as dangerous based on name keywords (delete, execute, send, write, deploy, kill, etc.) and description signals. `--safe-mode` uses this to skip dangerous invocations while still probing read-only tools.

- **Credential content detection** — `check_resource_poisoning` now scans resource text for 11 patterns of actual secrets: passwords, API keys (OpenAI `sk-`, GitHub `ghp_`, AWS `AKIA`), bearer tokens, connection strings, private keys.

- **Input reflection detection** — `check_tool_response_injection` sends a distinctive probe through each string parameter and flags tools that echo user input verbatim in responses — identifying indirect injection conduits.

- **Response-content rug pull** — `check_deep_rug_pull` now compares first vs last tool responses (not just metadata). Detects paywall/degradation rug pulls where tool output shifts but descriptions stay identical. 22 shift keywords including injection indicators.

- **DVMCP reset script** (`tests/dvmcp_reset.sh`) — Kill servers, wipe `/tmp` state, recreate test data, restart all 10 with readiness polling. `--scan` flag runs sweep immediately. `--kill-only` for cleanup.

### Changed

- `checks/__init__.py` — Reorganized check execution into clear phases with comments; all behavioral checks gated on `probe_opts`
- `checks/behavioral.py` — Refactored tool-list diffing into shared `_diff_tool_lists()` helper; deep rug pull uses configurable `probe_calls`
- `checks/tool_probes.py` — All probe checks accept `probe_opts` and respect `--no-invoke` / `--safe-mode`; `_build_safe_args()` now respects `minimum`/`maximum` constraints, schema defaults, pattern fields, and all JSON schema types
- `patterns/probes.py` — Template injection probes use `1333*7=9331` instead of `7*7=49` to avoid false positives
- `scanner.py` — `probe_opts` flows from CLI through `scan_target` and `run_parallel` into `run_all_checks`

---

## [4.1] - 2026-02

### Added

- **Bearer token auth** — `--auth-token TOKEN` for authenticated MCP endpoints (JWT, PAT, etc.). Env var `MCP_AUTH_TOKEN` supported. Enables scanning GitHub MCP (`https://api.githubcopilot.com/mcp/`), internal services, etc.

- **Differential scanning**
  - `--baseline FILE` — Compare current scan to saved baseline
  - `--save-baseline FILE` — Save current scan as baseline for future comparison
  - Reports added/removed/modified tools, resources, prompts
  - New tools flagged as MEDIUM findings for security review
  - `mcpnuke/diff.py` — `load_baseline`, `save_baseline`, `diff_against_baseline`, `print_diff_report`

- **New security checks**
  - `check_rate_limit` — Flags tools that suggest unbounded or unthrottled usage (e.g. "unlimited requests", "no rate limit")
  - `check_prompt_leakage` — Flags tools that may echo, log, or expose user prompts or internal instructions
  - `check_supply_chain` — Flags tools that install packages from user-controlled or dynamic URLs (e.g. `curl | bash`, "user-provided URL")

- **New pattern sets**
  - `RATE_LIMIT_PATTERNS` — 5 patterns for rate-limit abuse
  - `PROMPT_LEAKAGE_PATTERNS` — 8 patterns for prompt exposure
  - `SUPPLY_CHAIN_PATTERNS` — 9 patterns for supply-chain risks

- **CLI options**
  - `--targets-file FILE` — Read target URLs from file (one per line, `#` comments ignored)
  - `--public-targets` — Use built-in list in `data/public_targets.txt` (DVMCP localhost URLs)

- **Data**
  - `data/public_targets.txt` — Built-in targets for DVMCP (localhost:9001–9010) and public MCP servers

- **Test suite**
  - `tests/` — Pytest suite (38 tests) for checks, CLI, patterns, diff, and integration

### Changed

- `parse_args()` now accepts optional `args` for testability
- **Streamable HTTP support** — Scanner now handles MCP servers using Streamable HTTP (e.g. DeepWiki at `https://mcp.deepwiki.com/mcp`). Accepts `application/json` and `text/event-stream` responses; parses SSE-formatted POST responses.

---

## Planned

_Roadmap aligned with [MCP Red Team Playbook](https://github.com/babywyrm/sysadmin/tree/master/mcp/redteam) threat taxonomy (MCP-T01–T14)._

### Quick wins

- ~~**DVMCP scoreboard**~~ — ✓ Done. `tests/test_dvmcp.py` with offline + live tests
- **DVMCP scoreboard CLI** — `./scan --dvmcp-scoreboard` to auto-run all 10 challenges, report pass/fail per challenge, optional JSON
- **SARIF export** — Export findings as SARIF for IDE/CI (VS Code, GitHub Code Scanning)
- ~~**Encoding bypass probes**~~ — ✓ Done. 9 techniques (base64, hex, double-URL, homoglyph, null byte, CRLF, fullwidth, concatenation, variable expansion)

### Medium effort — new checks from playbook taxonomy + internal testing

_Gaps identified from [MCP Red Team Playbook](https://github.com/babywyrm/sysadmin/tree/master/mcp/redteam) and testing against internal MCP targets with Keycloak, K8s, and LLM integration._

- **JWT audience validation** (MCP-T04) — Decode JWT tokens, verify `aud` claim matches the target MCP endpoint, detect cross-tool token replay. Flag servers with `verify_aud: False`.
- **Cross-role token replay** (MCP-T04) — If a token is provided, attempt `tools/list` and `tools/call` for tools outside the token's role to detect role-only isolation gaps (e.g. same OIDC realm for users and agents).
- **Response credential scanning** (MCP-T07) — Scan ALL tool response content (not just errors) for credential patterns. Catches incomplete env var redaction where secrets like `CLIENT_SECRET` slip through regex filters.
- **LLM-mediated response detection** — Detect when tool responses are LLM-generated (hallucination risk, context bleed). Flag tools whose output shows LLM patterns (Ollama/OpenAI formatting, system prompt leakage through tool output).
- **AI prompt injection via tool parameters** — Detect when user-controlled tool parameters are passed into LLM prompts, creating an injection surface through tool args rather than tool descriptions.
- **Active SSRF probing** (MCP-T06) — Beyond pattern matching: probe tools with IMDS URLs (169.254.169.254), internal K8s API, RFC1918 ranges, DNS rebinding detection, IP encoding bypasses (decimal, hex, octal, IPv6-mapped).
- **Interpreter blocklist bypass** — Input sanitization probes should try multiple interpreters beyond bash/python: `perl`, `lua`, `awk`, `ruby`, `php`, `node`. Real-world blocklists often miss less common shells.
- **Actuator/debug endpoint probing** — Probe scan targets for exposed Spring Boot actuator (`/actuator/env`, `/actuator/beans`), Flask debug, pprof, Swagger, and GraphiQL. Actuator endpoints commonly leak signing keys and credentials.
- **DPoP token support** (RFC 9449) — `--dpop-key FILE` flag to sign DPoP proofs with `htm`/`htu` claims for RFC 9449-protected MCP gateways.
- **Confused deputy detection** (MCP-T03) — Check if tool calls propagate user identity vs agent SA; detect privilege gaps between caller and tool permissions.
- **Exfiltration flow analysis** (MCP-T12) — Track data flow across tools: flag when a read-tool's output feeds into a communication-tool's input (Slack, email, webhook).
- **Audit log evasion** (MCP-T13) — Verify that downstream audit logs attribute actions to the originating user, not just the agent service account.
- **AI-powered description analysis** — Use LLM to detect subtle tool poisoning, hidden instructions, misleading descriptions that bypass regex.

### Larger investments — campaign framework

- **Multi-stage campaign runner** (playbook Section 5) — Chain individual checks into named attack scenarios (CONTENT-TO-INFRA, COMMS-TO-CLUSTER, CODE-TO-PROD, etc.) with stage-gating and blast radius tracking
- **Purple team mode** — `--purple-team`: timestamp every attack, measure MTTD/MTTR, generate detection scorecard, SIEM alert correlation
- **LLM-as-proxy detection** — Detect when an LLM sits between the user and dangerous tools (e.g. chat endpoint → LLM → shell exec tool). Map the indirect execution path and flag the amplified blast radius.
- **Agent config tampering** (MCP-T09) — Detect if an agent can write its own config, system prompt, or tool registry via any connected MCP
- **Hallucination-driven destruction** (MCP-T10) — Send ambiguous instructions to tool-calling endpoints, verify confirmation gates and dry-run behavior before destructive ops
- **Cross-tenant memory leak** (MCP-T11) — Plant canary strings via one session, probe retrieval from another; test vector DB tenant isolation
- **Webhook/callback persistence** (MCP-T14) — Detect registered callbacks or webhooks that could re-inject payloads across sessions
- **Metrics endpoint** — Prometheus `/metrics` for scan counts, finding rates, tool coverage
- **Active exploitation mode** — Controlled, opt-in exploit verification (beyond safe probing)
- **MCP registry** — Curated list of public MCP servers for periodic scanning

### Done (previously planned)

- ~~**Stdio transport**~~ — ✓ `--stdio CMD` for local MCP servers via stdin/stdout
- ~~**Fast mode**~~ — ✓ `--fast` samples top 5 tools, skips heavy probes
- ~~**Grouped findings**~~ — ✓ `--group-findings` collapses similar findings
- ~~**Parallel probes**~~ — ✓ `--probe-workers N` with ThreadPoolExecutor
- ~~**Adaptive backoff**~~ — ✓ Per-tool latency tracking, exponential retry with jitter
- ~~**Encoding bypass probes**~~ — ✓ 9 encoding techniques in input_sanitization
- ~~**Live exfil verification**~~ — ✓ Source→sink canary data confirmation
- ~~**Differential MCP scanning**~~ — ✓ `--baseline` and `--save-baseline`
- ~~**Fuzzing / live probing**~~ — ✓ Behavioral probe engine with safe tool invocation
- ~~**Docker image**~~ — ✓ `k8s/Dockerfile` with multi-stage Python 3.12-slim build
- ~~**Kubernetes deployment**~~ — ✓ Job, CronJob, RBAC, Kustomize manifests
- ~~**Attack chain profiling**~~ — ✓ 17 attack chain patterns with aggregate detection
- ~~**OIDC auth**~~ — ✓ `--oidc-url` / `--client-id` / `--client-secret`
- ~~**Verbose mode**~~ — ✓ Real output in transport detection, enumeration, and checks
- ~~**DVMCP test suite**~~ — ✓ 44 offline + 30 live tests covering all 10 challenges
