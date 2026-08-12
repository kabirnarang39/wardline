---
title: "Getting Started"
---

## Before you install anything

You're going to run one small program (`wardline`) next to the AI agents
and tools you already have. You don't need to change your agent's code —
you point it at Wardline instead of its usual destination, the same way
you'd point a web browser at a proxy. Wardline forwards the request on to
where it was really going, but only after checking it's allowed.

Two files do the configuring: one plain-language rule list (the
"policy" — who's allowed to do what) and one settings file (which
features are turned on, where things live). Both are just text files
you can open and read.

The rest of this section: install it, write a tiny policy, send one
request through, and see it get allowed or denied.

---

Zero to a working Wardline deployment: what it is, how to install it, and
how to get your first request through it.
