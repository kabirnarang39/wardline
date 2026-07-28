---
title: "Docker"
weight: 10
---

```bash
docker build -t wardline:local .
docker run -p 8080:8080 \
  -v $(pwd)/wardline.yaml:/etc/wardline/wardline.yaml \
  -v $(pwd)/policy.yaml:/etc/wardline/policy.yaml \
  wardline:local serve --config /etc/wardline/wardline.yaml
```

No published image exists yet — build and push your own
(`docker build -t <your-registry>/wardline:<tag> . && docker push ...`)
before referencing it from the [Helm chart](/deployment/helm-chart/).
