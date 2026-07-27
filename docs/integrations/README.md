# Framework Integrations

Wardline is a transparent HTTP reverse proxy: it speaks the same MCP
(Model Context Protocol) JSON-RPC-over-HTTP wire format your tools
already speak. Any framework whose MCP client lets you override a base
URL and set a custom HTTP header gets policy enforcement, budget
limiting, audit logging, and OTel tracing for free — by pointing that
URL at Wardline instead of your tool server directly. No SDK to install,
no code to change in the framework itself.

Every guide below shows exactly two things: the base-URL override, and
the one required header (`X-Wardline-Identity`) that tells Wardline
which caller identity to evaluate policy against.

## Guides

- [Raw MCP client](mcp-client.md) — the reference case. Every other
  framework's MCP support is a thin wrapper around the same transport
  this guide uses directly.
- [LangChain](langchain.md)
- [LlamaIndex](llamaindex.md)
- [OpenAI Agents SDK](openai-agents-sdk.md)
- [CrewAI](crewai.md)

## What Wardline does and doesn't enforce

Policy, budget, and audit-decision enforcement apply to `tools/call`
requests only — see the main [README](../../README.md)'s "Scope note"
for the full explanation of what that means for other MCP protocol
methods (the `initialize` handshake, `notifications/initialized`,
`tools/list`, and any `resources/*`/`prompts/*` your upstream server
exposes).

## A note on error handling

Every guide below documents how a policy denial actually surfaces to
that framework's caller — and in most of these frameworks today, that's
messier than a clean, catchable exception: the underlying `mcp` SDK's
HTTP transport calls `httpx`'s `raise_for_status()` on any non-2xx
response, inside an `anyio` task group, so a 403 from Wardline commonly
surfaces wrapped in a Python `ExceptionGroup`. This isn't a Wardline
quirk — it's how these frameworks already behave for any HTTP-level
failure from any MCP server, proxy or not. Each guide shows the actual
catch pattern that works today.

The real fault line isn't which framework you're using — it's whether
that framework opens a **fresh session per call** or holds one
**long-lived session** across many calls. LangChain's
`MultiServerMCPClient.get_tools()`, LlamaIndex's `BasicMCPClient`, and
this project's own smoke test all open a new connection per tool call
(or per script run) and get a cleanly catchable
`ExceptionGroup[httpx.HTTPStatusError]` on denial. The raw `mcp` SDK
used naively (one `ClientSession` reused across calls, as in
[`mcp-client.md`](mcp-client.md#how-a-policy-denial-surfaces)) and the
OpenAI Agents SDK's `MCPServerStreamableHttp`
([`openai-agents-sdk.md`](openai-agents-sdk.md#how-a-policy-denial-surfaces))
both hold a long-lived session instead, and both were verified to raise
`asyncio.CancelledError` at the call site on denial — not a catchable
HTTP exception — and to leave that session permanently dead afterward,
including for calls to tools the policy would otherwise allow.
CrewAI's `MCPServerAdapter`
([`crewai.md`](crewai.md#how-a-policy-denial-surfaces)) also holds a
long-lived session and was verified to be the worst case of the three:
the denial crashes its background event-loop thread with an unhandled
exception that's never delivered to the caller, so a denied tool call
doesn't raise anything at all — it hangs the calling thread
indefinitely. Prefer fresh-session-per-call wherever the framework
supports it if graceful denial handling matters to your use case.

## Proving it works

[`examples/mcp_client_smoke_test.py`](examples/mcp_client_smoke_test.py)
is a real, runnable script — a real MCP client, a real MCP server, and a
real compiled `wardline` binary in between — demonstrating the exact
mechanism every guide above depends on: a successful handshake, an
allowed tool call, and a policy-denied tool call. Run it yourself:

```bash
go build -o /tmp/wardline-bin ./cmd/wardline   # from the repo root
python3 -m venv /tmp/wardline-integrations-venv
source /tmp/wardline-integrations-venv/bin/activate
pip install mcp
python3 docs/integrations/examples/mcp_client_smoke_test.py
```
