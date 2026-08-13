# Dockerfile for Glama's automated MCP-directory check only -- NOT the
# production image (see ../../Dockerfile at the repo root for that).
#
# Wardline is a proxy, not an MCP tool server: alone, with no upstream,
# it 502s on every call, so Glama's checker would find nothing to
# introspect. This image adds a tiny spec-shaped stub (mock_mcp.go) as
# Wardline's upstream purely so the check has something real to talk to.
# A real deployment points Wardline at an actual MCP server instead --
# see wardline.yaml.example at the repo root.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/wardline ./cmd/wardline
RUN CGO_ENABLED=0 go build -trimpath -o /out/mock_mcp ./deploy/glama

FROM alpine:3.20
RUN adduser -D -H wardline
COPY --from=build /out/wardline /usr/local/bin/wardline
COPY --from=build /out/mock_mcp /usr/local/bin/mock_mcp
COPY deploy/glama/wardline.yaml /etc/wardline/wardline.yaml
COPY deploy/glama/policy.yaml /etc/wardline/policy.yaml
COPY deploy/glama/start.sh /start.sh
RUN chmod +x /start.sh
USER wardline
EXPOSE 8080
CMD ["/start.sh"]
