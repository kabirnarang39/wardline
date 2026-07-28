---
title: "Policy Cedar Reference"
weight: 50
---

Cedar policies use `permit(...)` statements matching a fixed
principal/action/resource schema: the **action is always the single
fixed value** `Wardline::Action::"call_tool"` — Wardline's action
space genuinely is just "call a tool." The tool being called is the
**resource**, not the action:

```cedar
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
);
```

Putting the tool name into `action` instead of `resource` (or leaving
`resource` unconstrained) will never match any real request, since
every request's action is always `"call_tool"` — the policy will
silently deny everything it was meant to allow.

See `policy.cedar.example` in the repo root for a complete, runnable
example.
