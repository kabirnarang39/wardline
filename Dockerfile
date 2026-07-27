# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/wardline ./cmd/wardline

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wardline /usr/local/bin/wardline
ENTRYPOINT ["/usr/local/bin/wardline"]
