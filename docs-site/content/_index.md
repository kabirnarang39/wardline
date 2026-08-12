---
title: "Wardline Documentation"
---

## What is this, really?

An "AI agent" is a program that can take actions on its own — read files,
call other programs, send requests — instead of just answering a chat
question. That's powerful, and also risky: if nobody's watching, an agent
can do something it shouldn't, run up a huge bill, or get tricked into
doing something harmful.

Wardline sits in the middle, between an agent and everything it's allowed
to touch. Every action the agent tries to take passes through Wardline
first. Wardline checks: *is this agent who it says it is? Is it allowed to
do this specific thing? Has it already done too much of it? And whatever
the answer, write it down.* Only after all four checks does the action get
let through — or not.

That's it. Four jobs, always in this order:

1. **Identity** — prove who's asking.
2. **Policy** — check the rule book: is this allowed?
3. **Budget** — check the meter: has this run too much already?
4. **Audit** — write down what happened, allowed or not.

Wardline is open source, free to run yourself, and doesn't send your data
anywhere.

---

Wardline is an open source control-plane proxy for AI agents: identity,
policy, budget, and audit for MCP and beyond.

- New to Wardline? Start with [Getting Started](/getting-started/).
- Want the mental model first? Read [Concepts](/concepts/).
- Looking for a specific feature? Jump to [Features](/features/).
- Deploying to Kubernetes? See [Deployment](/deployment/).
- Need exact config/CLI fields? See [Reference](/reference/).
- Extending Wardline or curious about the roadmap? See [Advanced](/advanced/).
