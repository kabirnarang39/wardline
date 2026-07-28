---
title: "Installation"
weight: 10
---

Wardline is a single Go binary. Three ways to get it:

## Build from source

Requires Go 1.22+.

```bash
git clone https://github.com/kabirnarang39/wardline.git
cd wardline
go build -o wardline ./cmd/wardline
```

## Docker

```bash
docker build -t wardline:local .
docker run -p 8080:8080 -v $(pwd)/wardline.yaml:/etc/wardline/wardline.yaml wardline:local \
  serve --config /etc/wardline/wardline.yaml
```

See [Docker deployment](/deployment/docker/) for the full image reference.

## Helm (Kubernetes)

```bash
helm install wardline ./charts/wardline -f my-values.yaml
```

See [Helm chart](/deployment/helm-chart/) for chart values.

Next: [Quickstart](/getting-started/quickstart/).
