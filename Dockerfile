FROM docker.io/library/golang:1.25.0 as build

COPY . /build/
WORKDIR /build

RUN \
  GOPROXY=direct CGO_ENABLED=0 go build -o spire-ha-agent ./cmd/spire-ha-agent

FROM gcr.io/distroless/static-debian12
COPY --from=build /build/spire-ha-agent /usr/bin/spire-ha-agent
ENTRYPOINT ["/usr/bin/spire-ha-agent"]
