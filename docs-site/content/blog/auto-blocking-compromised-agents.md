---
title: "Auto-blocking a compromised AI agent, no rule and no human in the loop"
weight: 10
summary: "Why Wardline exists, how the real-time auto-block works, and — just as important — exactly what it does not catch."
---

AI agents now call tools, MCP servers, and each other on their own. That is
the whole point of an agent. It is also the problem: the moment an agent is
compromised — a prompt injection, a leaked key, a poisoned tool result — it
keeps its credentials and its network path, and nothing between it and your
systems says no.

Most of the stack around agents watches and reports. It logs the calls, maybe
scores them, and pages a human. By the time the human reads the page, the
agent has made a thousand more calls.

**Wardline is the control plane that sits inline and enforces.** Every call an
agent makes to an MCP server, a tool, or a gRPC upstream goes through Wardline
first, which applies identity, policy, budget, and anomaly detection in-process
and writes every decision to an audit trail. It is one static Go binary — no
database, no identity provider, no sidecar to start.

## The part that is actually different: auto-block

Alerting is easy and everyone does it. The claim worth making is enforcement.

Wardline keeps a per-identity behavioral baseline using Welford's algorithm —
a running mean and variance over four features per time window: call rate,
distinct-tool count, deny ratio, and mean inter-arrival time. No training data,
no external model, no history to store. Each completed window is scored as a
combined z-score against that identity's own baseline.

When the score crosses a configured threshold and `auto_block` is on, Wardline
does not just write an anomaly record. It **rejects that identity's calls** for
a bounded TTL. The compromised agent is cut off in real time, with no rule
written for the specific attack and no human in the loop. When the TTL expires,
or an operator clears the block from the dashboard, it resumes.

That is the demo in the README: a mock MCP server, an agent that starts
behaving like a compromised one, and Wardline blocking it mid-run.

## The part most projects will not tell you: what it does not catch

The auto-block catches *abrupt* deviation. It does **not** catch *low-and-slow*.

Because the baseline is self-learned and unsupervised, an attacker who ramps
activity gradually — staying within a few standard deviations of the moving
baseline each window — is never blocked. The baseline adapts upward and absorbs
the ramp. Wardline blocks the agent that suddenly does 10x its normal rate; it
does not block the agent that patiently climbs to 10x over an hour.

This is not a threshold you can simply tighten. Tighten it and you start
blocking normal agents — the false-positive rate is regression-guarded to stay
near zero on steady traffic, and that guard is the thing keeping the feature
usable. It is an inherent tradeoff of unsupervised, per-identity baselining.

Both behaviors are pinned by tests in the repo —
`TestDetector_AutoBlock_AbruptSpikeIsBlocked` and
`TestDetector_AutoBlock_LowAndSlowEvades` — so the boundary is documented, not
marketed around. See [Anomaly Detection](/features/anomaly-detection/) for the
full known-limitations list.

**Update:** the paragraph above is still true of `ml_score`/`auto_block`
alone, and stays true by design (tightening that per-window test would
cost the false-positive guarantee). It is no longer the whole picture.
`drift_detection` — a CUSUM control chart run alongside `ml_score`, the
standard statistical-process-control technique for exactly this
"per-sample test misses a sustained shift" gap — closes most of it: the
same low-and-slow ramp that evaded auto-block indefinitely above now
gets caught within 10 windows, at 1.4× baseline, in the current recall
benchmark. It isn't a full close — an attacker who reads the exact
public threshold can still hold a real, measured ~1.15× ceiling forever
— see [Anomaly Detection](/features/anomaly-detection/)'s "Recall
benchmark" and "Adversarial scenarios" sections for the actual numbers,
not a claim.

The takeaway is not "anomaly detection is weak." It is that anomaly detection
is the *last* line, not the only one. Keep explicit policy and budget limits as
the hard floor — they bound absolute behavior regardless of ramp speed — and
let auto-block catch the fast, obvious compromise that policy did not anticipate.

## Secure by default is a claim; read the defaults

Wardline fails closed on policy. It does **not** fail closed on identity or the
dashboard by default: identity is trusted from the `X-Wardline-Identity` header
(spoofable) and the dashboard's read views are unauthenticated, until you turn
on the flags that change that. The binary logs a `WARN` on startup for every
insecure default still in effect, so the posture is never silent.

For any real deployment:

```yaml
features:
  credential_issuance: true   # verify a signed bearer token instead of trusting the header
  rbac: true                  # gate the dashboard and admin actions on real permissions
```

## Where it fits

Wardline is young and unproven at scale — that is the honest status. It is not
trying to replace an LLM router like LiteLLM or a managed gateway like Portkey.
It is the enforcement-first control plane for the traffic *between* an agent and
everything it calls, in a single self-hosted binary, Apache-2.0.

If that is the layer you are missing, start here:
[Getting Started](/getting-started/). Feedback on the anomaly approach and the
threat model is exactly what the project wants right now.
