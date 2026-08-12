---
title: "Quickstart"
weight: 20
---

This gets one request through Wardline end to end in under five minutes.
You'll start a fake destination server, start Wardline in front of it,
send one request, and watch Wardline allow it — then send another and
watch it get denied.

## 1. Start a mock upstream

Wardline proxies to an upstream MCP server. For this quickstart, any HTTP
server that returns 200 is good enough to prove the path works:

```bash
python3 -m http.server 9000
```

## 2. Validate the example policy and config

```bash
./wardline validate-policy --file policy.yaml.example
./wardline validate-config --config wardline.yaml.example
```

## 3. Start Wardline

```bash
./wardline serve --config wardline.yaml.example
```

## 4. Make a request

Every request must carry an `X-Wardline-Identity` header — Wardline
matches this value plus the MCP tool name against your policy rules.

```bash
curl -X POST http://localhost:8080 \
  -H "X-Wardline-Identity: agent-abc123" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}'
```

This matches the `agent-abc123` / `read_file` allow rule already in
`policy.yaml.example`. You should see the request forwarded to your mock
upstream and a JSON audit line printed to Wardline's stdout with
`"decision":"allow"`.

Try changing the identity header to something not in the policy file and
re-run the same `curl` — you'll get a deny decision and a matching audit
entry, with nothing forwarded upstream.

Next: understand the model in [Concepts](/concepts/), or jump straight to
a specific capability in [Features](/features/).
