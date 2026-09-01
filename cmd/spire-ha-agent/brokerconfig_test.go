package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestBrokerConfigDefaults(t *testing.T) {
	conf, err := loadBrokerConfig("")
	if err != nil {
		t.Fatalf("loadBrokerConfig: %v", err)
	}
	if conf.single {
		t.Errorf("single: got true, want false")
	}
	if conf.socket != "/var/run/spire/agent/sockets/main/public/api.sock" {
		t.Errorf("socket default: got %q", conf.socket)
	}
	if conf.brokerA != "unix:///var/run/spire/agent/sockets/a/broker/broker.sock" {
		t.Errorf("brokerA default: got %q", conf.brokerA)
	}
	if conf.workloadB != "unix:///var/run/spire/agent/sockets/b/public/api.sock" {
		t.Errorf("workloadB default: got %q", conf.workloadB)
	}
	if conf.endpoint != nil {
		t.Errorf("endpoint: got non-nil, want nil")
	}
}

func TestBrokerConfigEnvBeatsDefault(t *testing.T) {
	t.Setenv("SPIRE_HA_AGENT_SOCK", "/env/api.sock")
	t.Setenv("SPIRE_HA_AGENT_BROKER_A", "unix:///env/broker-a.sock")
	conf, err := loadBrokerConfig("")
	if err != nil {
		t.Fatalf("loadBrokerConfig: %v", err)
	}
	if conf.socket != "/env/api.sock" {
		t.Errorf("socket: got %q, want env value", conf.socket)
	}
	if conf.brokerA != "unix:///env/broker-a.sock" {
		t.Errorf("brokerA: got %q, want env value", conf.brokerA)
	}
}

func TestBrokerConfigFileBeatsEnv(t *testing.T) {
	t.Setenv("SPIRE_HA_AGENT_SOCK", "/env/api.sock")
	t.Setenv("SPIRE_HA_AGENT_SINGLE", "enabled")
	t.Setenv("SPIRE_HA_AGENT_BROKER_A", "unix:///env/broker-a.sock")
	t.Setenv("SPIRE_HA_AGENT_WORKLOAD_SOCKET_B", "unix:///env/wl-b.sock")
	path := writeConfig(t, `
single: false
socket: /file/api.sock
upstream_a:
  broker_address: unix:///file/broker-a.sock
`)
	conf, err := loadBrokerConfig(path)
	if err != nil {
		t.Fatalf("loadBrokerConfig: %v", err)
	}
	// explicit false in the file must beat SPIRE_HA_AGENT_SINGLE=enabled
	if conf.single {
		t.Errorf("single: got true, want false (file explicitly set)")
	}
	if conf.socket != "/file/api.sock" {
		t.Errorf("socket: got %q, want file value", conf.socket)
	}
	if conf.brokerA != "unix:///file/broker-a.sock" {
		t.Errorf("brokerA: got %q, want file value", conf.brokerA)
	}
	// absent from file -> env still wins
	if conf.workloadB != "unix:///env/wl-b.sock" {
		t.Errorf("workloadB: got %q, want env value", conf.workloadB)
	}
	// absent from file and env -> default
	if conf.workloadA != "unix:///var/run/spire/agent/sockets/a/public/api.sock" {
		t.Errorf("workloadA: got %q, want default", conf.workloadA)
	}
}

func TestBrokerConfigSingleModeEnvNames(t *testing.T) {
	t.Setenv("SPIRE_HA_AGENT_BROKER", "unix:///env/single-broker.sock")
	path := writeConfig(t, "single: true\n")
	conf, err := loadBrokerConfig(path)
	if err != nil {
		t.Fatalf("loadBrokerConfig: %v", err)
	}
	if !conf.single {
		t.Fatalf("single: got false, want true")
	}
	// single mode selects the unsuffixed env var for side A
	if conf.brokerA != "unix:///env/single-broker.sock" {
		t.Errorf("brokerA: got %q, want single-mode env value", conf.brokerA)
	}
}

func TestBrokerConfigEndpoint(t *testing.T) {
	path := writeConfig(t, `
socket: /run/main/api.sock
broker_endpoint:
  socket_path: /run/broker/broker.sock
  bind_address: 127.0.0.1:8443
  brokers:
    - id: spiffe://example.org/downstream
      allowed_reference_types:
        - type_url: type.googleapis.com/spiffe.broker.WorkloadPIDReference
    - id: spiffe://other.org/remote
      allowed_reference_types:
        - type_url: "*"
          allow_over_tcp: true
`)
	conf, err := loadBrokerConfig(path)
	if err != nil {
		t.Fatalf("loadBrokerConfig: %v", err)
	}
	ep := conf.endpoint
	if ep == nil {
		t.Fatalf("endpoint: got nil")
	}
	if ep.socketPath != "/run/broker/broker.sock" || ep.bindAddress != "127.0.0.1:8443" {
		t.Errorf("listeners: got %q %q", ep.socketPath, ep.bindAddress)
	}
	if len(ep.ids) != 2 {
		t.Fatalf("ids: got %d, want 2", len(ep.ids))
	}
	pol := ep.policies[ep.ids[0]]
	rp, ok := pol["type.googleapis.com/spiffe.broker.WorkloadPIDReference"]
	if !ok || rp.allowOverTCP {
		t.Errorf("downstream PID policy: ok=%t allowOverTCP=%t", ok, rp.allowOverTCP)
	}
	pol = ep.policies[ep.ids[1]]
	rp, ok = pol[wildcardTypeURL]
	if !ok || !rp.allowOverTCP {
		t.Errorf("remote wildcard policy: ok=%t allowOverTCP=%t", ok, rp.allowOverTCP)
	}
}

func TestBrokerConfigMetricsAndKeepalive(t *testing.T) {
	// defaults when both blocks are absent
	conf, err := loadBrokerConfig(writeConfig(t, "single: false\n"))
	if err != nil {
		t.Fatalf("loadBrokerConfig: %v", err)
	}
	if conf.metrics != nil {
		t.Errorf("metrics: got %+v, want nil when the block is absent", conf.metrics)
	}
	if conf.keepaliveTime != safeKeepaliveTime || conf.keepaliveTimeout != defaultKeepaliveTimeout {
		t.Errorf("keepalive defaults: got %s/%s, want %s/%s", conf.keepaliveTime, conf.keepaliveTimeout, safeKeepaliveTime, defaultKeepaliveTimeout)
	}

	conf, err = loadBrokerConfig(writeConfig(t, `
metrics:
  bind_address: 127.0.0.1:9988
upstream_keepalive:
  time: 30s
  timeout: 5s
`))
	if err != nil {
		t.Fatalf("loadBrokerConfig: %v", err)
	}
	if conf.metrics == nil || conf.metrics.bindAddress != "127.0.0.1:9988" {
		t.Errorf("metrics bind_address: got %+v", conf.metrics)
	}
	if conf.keepaliveTime != 30*time.Second || conf.keepaliveTimeout != 5*time.Second {
		t.Errorf("keepalive: got %s/%s", conf.keepaliveTime, conf.keepaliveTimeout)
	}

	// time: 0 disables keepalive, and must not trip the timeout < time check
	conf, err = loadBrokerConfig(writeConfig(t, "upstream_keepalive:\n  time: 0s\n"))
	if err != nil {
		t.Fatalf("loadBrokerConfig with keepalive disabled: %v", err)
	}
	if conf.keepaliveTime != 0 {
		t.Errorf("keepalive time: got %s, want 0", conf.keepaliveTime)
	}
}

func TestBrokerConfigValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "no listeners",
			yaml: `
broker_endpoint:
  brokers:
    - id: spiffe://example.org/x
      allowed_reference_types: [{type_url: "*"}]
`,
			wantErr: "at least one of socket_path or bind_address",
		},
		{
			name: "bad bind address",
			yaml: `
broker_endpoint:
  bind_address: "no-port"
  brokers:
    - id: spiffe://example.org/x
      allowed_reference_types: [{type_url: "*"}]
`,
			wantErr: "invalid bind_address",
		},
		{
			name: "no brokers",
			yaml: `
broker_endpoint:
  socket_path: /run/broker/broker.sock
`,
			wantErr: "at least one broker",
		},
		{
			name: "bad id",
			yaml: `
broker_endpoint:
  socket_path: /run/broker/broker.sock
  brokers:
    - id: not-a-spiffe-id
      allowed_reference_types: [{type_url: "*"}]
`,
			wantErr: "invalid broker id",
		},
		{
			name: "duplicate id",
			yaml: `
broker_endpoint:
  socket_path: /run/broker/broker.sock
  brokers:
    - id: spiffe://example.org/x
      allowed_reference_types: [{type_url: "*"}]
    - id: spiffe://example.org/x
      allowed_reference_types: [{type_url: "*"}]
`,
			wantErr: "duplicate broker id",
		},
		{
			name: "no reference types",
			yaml: `
broker_endpoint:
  socket_path: /run/broker/broker.sock
  brokers:
    - id: spiffe://example.org/x
`,
			wantErr: "at least one allowed_reference_types",
		},
		{
			name: "empty type_url",
			yaml: `
broker_endpoint:
  socket_path: /run/broker/broker.sock
  brokers:
    - id: spiffe://example.org/x
      allowed_reference_types: [{type_url: ""}]
`,
			wantErr: "empty type_url",
		},
		{
			name: "duplicate type_url",
			yaml: `
broker_endpoint:
  socket_path: /run/broker/broker.sock
  brokers:
    - id: spiffe://example.org/x
      allowed_reference_types: [{type_url: "*"}, {type_url: "*"}]
`,
			wantErr: "duplicate type_url",
		},
		{
			name: "socket collision",
			yaml: `
socket: /run/main/api.sock
broker_endpoint:
  socket_path: /run/main/broker.sock
  brokers:
    - id: spiffe://example.org/x
      allowed_reference_types: [{type_url: "*"}]
`,
			wantErr: "must not share a directory",
		},
		{
			name:    "metrics without bind_address",
			yaml:    "metrics: {}\n",
			wantErr: "bind_address is required",
		},
		{
			name:    "metrics bad bind_address",
			yaml:    "metrics:\n  bind_address: no-port\n",
			wantErr: "invalid bind_address",
		},
		{
			name:    "keepalive bad duration",
			yaml:    "upstream_keepalive:\n  time: soon\n",
			wantErr: "invalid time",
		},
		{
			name:    "keepalive timeout not less than time",
			yaml:    "upstream_keepalive:\n  time: 10s\n  timeout: 10s\n",
			wantErr: "must be less than time",
		},
		{
			name:    "unknown key",
			yaml:    "sockte: /oops\n",
			wantErr: "field sockte not found",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.yaml)
			_, err := loadBrokerConfig(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
