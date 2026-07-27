# CrewAI

CrewAI's MCP support (the `crewai-tools` package's `MCPServerAdapter`)
connects over the same transport documented in the
[raw MCP client guide](mcp-client.md) — this guide only covers the
CrewAI-specific wrapper around it.

Verified against `crewai-tools[mcp]` (pins `mcp>=1.28.1,<2`,
`mcpadapt>=0.1.9`) — code lives in the `crewAIInc/crewAI` monorepo; the
older standalone `crewAI-tools` repo is archived and its README examples
are stale.

## Install

```bash
pip install 'crewai-tools[mcp]'
```

## Connect through Wardline

```python
from crewai import Agent, Task, Crew
from crewai_tools import MCPServerAdapter

server_params = {
    "url": "http://<wardline-listen-addr>/mcp",
    "transport": "streamable-http",
    "headers": {"X-Wardline-Identity": "my-agent"},
}

with MCPServerAdapter(server_params, connect_timeout=60) as tools:
    print([t.name for t in tools])

    agent = Agent(
        role="Tool User",
        goal="Use the MCP-provided tools to complete the task",
        backstory="An agent wired to remote MCP tools via Wardline.",
        tools=tools,
        verbose=True,
    )
    task = Task(description="...", expected_output="...", agent=agent)
    Crew(agents=[agent], tasks=[task]).kickoff()
```

Replace `<wardline-listen-addr>` with wherever `wardline serve` is
listening. `connect_timeout` (default 30s) is the adapter's own timeout
for establishing the connection.

## How a policy denial surfaces

`MCPServerAdapter` (via `mcpadapt`) holds a long-lived session: it runs
the MCP connection in a background thread with its own event loop for
the entire `with MCPServerAdapter(...)` block, and every tool call is
dispatched onto that loop with
`asyncio.run_coroutine_threadsafe(session.call_tool(...), loop).result()`
— the same long-lived-session shape documented in the
[raw MCP client guide](mcp-client.md#how-a-policy-denial-surfaces). The
practical effect here is worse than a merely awkward exception, and was
confirmed empirically against a real Wardline denial using
`crewai-tools==1.15.7` / `mcpadapt==0.1.19`:

**A denial on an individual tool call** (connection already
established, an allowed call already having succeeded) does not raise
a catchable exception to the caller at all — it hangs the calling
thread indefinitely. The denial cancels `mcpadapt`'s background event
loop's task group the same way it does for a long-lived raw `mcp`
session; that background thread then dies with an unhandled
`ExceptionGroup[httpx.HTTPStatusError]`, printed to stderr by Python's
default thread exception hook, and **never delivered to the calling
thread**. Meanwhile `_sync_call_tool`'s `.result()` call has no
timeout, so the main thread — and any `Agent`/`Task`/`Crew` code
waiting on that tool call — blocks forever:

```python
with MCPServerAdapter(server_params) as tools:
    by_name = {t.name: t for t in tools}
    by_name["allowed_tool"]._run()   # succeeds
    by_name["denied_tool"]._run()    # HANGS — never raises, never returns
```

There is no code a caller can add around the call itself to catch
this — the failure happens on a different thread than the one running
your `try`. The only mitigation today is an external timeout (e.g. run
the call in a thread/process with its own deadline, or a `Crew`-level
execution timeout if your version supports one) — treat a denied tool
call through `MCPServerAdapter` as capable of wedging the whole crew,
not as something that fails fast.

**A failure during the initial connection** (entering the `with
MCPServerAdapter(...)` block — e.g. Wardline unreachable, or the
upstream misconfigured) is wrapped in a plain `RuntimeError`, but note
its `__cause__` is typically a generic `TimeoutError` ("Couldn't connect
to the MCP server after Ns"), not the specific underlying error — the
same background-thread-crash-isn't-propagated mechanism above means the
real exception is swallowed, and the caller only observes that
`MCPServerAdapter` never got a ready signal within `connect_timeout`:

```python
try:
    with MCPServerAdapter(server_params) as tools:
        ...
except RuntimeError as e:
    print(e)             # "Failed to initialize MCP Adapter: Couldn't connect ..."
    print(e.__cause__)    # typically TimeoutError, not the original error
```

This case is somewhat academic for Wardline specifically: policy only
gates `tools/call` (see the main [README](../../README.md)'s "Scope
note"), so Wardline's policy engine itself never denies the initial
connection — a connect-time failure here means Wardline or the upstream
is unreachable, not that a policy rule fired.

(On Python 3.10, the same caveat applies if you were catching
`except*` anywhere in adjacent code — install the `exceptiongroup`
backport package (already a dependency of `mcp`/`anyio` on that
version) and `from exceptiongroup import ExceptionGroup`, then catch
`ExceptionGroup` directly and iterate `.exceptions`. It doesn't help
with the hang above — that failure is never delivered as a raiseable
exception in the first place.)
