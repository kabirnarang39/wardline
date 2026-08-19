# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27rc3-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags "-s -w -X github.com/kabirnarang39/wardline/internal/platform/version.Version=${VERSION}" \
    -o /out/wardline ./cmd/wardline

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wardline /usr/local/bin/wardline
ENTRYPOINT ["/usr/local/bin/wardline"]
