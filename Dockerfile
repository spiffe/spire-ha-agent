FROM docker.io/library/golang:1.23.2 as build

COPY . /build/
WORKDIR /build

RUN \
  GOPROXY=direct CGO_ENABLED=0 go build cmd/main.go && \
  mv main spire-ha-agent

FROM gcr.io/distroless/static-debian12
COPY --from=build /build/spire-ha-agent /usr/bin/spire-ha-agent
ENTRYPOINT ["/usr/bin/spire-ha-agent"]
