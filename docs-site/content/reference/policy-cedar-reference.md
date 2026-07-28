---
title: "Policy Cedar Reference"
weight: 50
---

Cedar policies use `permit(...)` statements matching a fixed
principal/action/resource schema derived from identity and tool name:

```cedar
permit(
  principal == Wardline::Identity::"agent-abc123",
  action == Wardline::Action::"read_file",
  resource
);
```

See `policy.cedar.example` in the repo root for a complete, runnable
example.
