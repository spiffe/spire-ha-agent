package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	yaml "gopkg.in/yaml.v3"
)

const wildcardTypeURL = "*"

// gRPC servers that set no keepalive enforcement policy reject client pings
// more frequent than this, so it is the floor for a safe default. See the
// comment on the dial option in broker.go for the full reasoning.
const safeKeepaliveTime = 5 * time.Minute

const defaultKeepaliveTimeout = 20 * time.Second

// YAML file schema. Pointer fields distinguish "set in the file" from
// "absent": an option present in the config file wins over its environment
// variable; when absent, the environment variable wins over the default.
type brokerFileConfig struct {
	Single         *bool               `yaml:"single"`
	Socket         *string             `yaml:"socket"`
	VSock          *vsockFileConfig    `yaml:"vsock"`
	UpstreamA      *upstreamFileConfig `yaml:"upstream_a"`
	UpstreamB      *upstreamFileConfig `yaml:"upstream_b"`
	BrokerEndpoint *endpointFileConfig `yaml:"broker_endpoint"`
	Metrics        *metricsFileConfig  `yaml:"metrics"`
	// Keepalive on the upstream broker connections. Absent means the safe
	// default; time: 0 disables keepalive entirely.
	UpstreamKeepalive *keepaliveFileConfig `yaml:"upstream_keepalive"`
}

type metricsFileConfig struct {
	BindAddress *string `yaml:"bind_address"`
}

type keepaliveFileConfig struct {
	Time    *string `yaml:"time"`
	Timeout *string `yaml:"timeout"`
}

type vsockFileConfig struct {
	Enabled *bool   `yaml:"enabled"`
	Port    *uint32 `yaml:"port"`
}

type upstreamFileConfig struct {
	BrokerAddress  *string `yaml:"broker_address"`
	WorkloadSocket *string `yaml:"workload_socket"`
}

type endpointFileConfig struct {
	SocketPath  *string                `yaml:"socket_path"`
	BindAddress *string                `yaml:"bind_address"`
	Brokers     []endpointBrokerConfig `yaml:"brokers"`
}

type endpointBrokerConfig struct {
	ID                    string                `yaml:"id"`
	AllowedReferenceTypes []referenceTypeConfig `yaml:"allowed_reference_types"`
}

type referenceTypeConfig struct {
	TypeURL      string `yaml:"type_url"`
	AllowOverTCP bool   `yaml:"allow_over_tcp"`
}

// Fully resolved configuration.
type brokerConfig struct {
	single       bool
	socket       string
	vsockEnabled bool
	vsockPort    uint32
	brokerA      string
	workloadA    string
	brokerB      string
	workloadB    string
	endpoint     *endpointConfig // nil => downstream broker endpoint disabled
	metrics      *metricsConfig  // nil => metrics endpoint disabled
	// Keepalive on the upstream broker connections; keepaliveTime 0 disables.
	keepaliveTime    time.Duration
	keepaliveTimeout time.Duration
}

type metricsConfig struct {
	bindAddress string
}

type endpointConfig struct {
	socketPath  string
	bindAddress string
	ids         []spiffeid.ID
	policies    map[spiffeid.ID]map[string]refPolicy // type_url (or "*") -> policy
}

type refPolicy struct {
	allowOverTCP bool
}

func resolveString(filePtr *string, envName, def string) string {
	if filePtr != nil {
		return *filePtr
	}
	if v := os.Getenv(envName); v != "" {
		return v
	}
	return def
}

func resolveEnabled(filePtr *bool, envName string) bool {
	if filePtr != nil {
		return *filePtr
	}
	return os.Getenv(envName) == "enabled"
}

func loadBrokerConfig(path string) (*brokerConfig, error) {
	fc := &brokerFileConfig{}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open config file: %w", err)
		}
		defer f.Close()
		dec := yaml.NewDecoder(f)
		dec.KnownFields(true)
		if err := dec.Decode(fc); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
	}

	conf := &brokerConfig{}
	// single must resolve first: it selects which env var names back upstream_a.
	conf.single = resolveEnabled(fc.Single, "SPIRE_HA_AGENT_SINGLE")
	conf.socket = resolveString(fc.Socket, "SPIRE_HA_AGENT_SOCK", "/var/run/spire/agent/sockets/main/public/api.sock")

	var vsEnabled *bool
	var vsPort *uint32
	if fc.VSock != nil {
		vsEnabled = fc.VSock.Enabled
		vsPort = fc.VSock.Port
	}
	conf.vsockEnabled = resolveEnabled(vsEnabled, "SPIRE_HA_AGENT_VSOCK")
	if conf.vsockEnabled {
		if vsPort != nil {
			conf.vsockPort = *vsPort
		} else {
			port := os.Getenv("SPIRE_HA_AGENT_PORT")
			if port == "" {
				port = "997"
			}
			iport, err := strconv.Atoi(port)
			if err != nil {
				return nil, fmt.Errorf("failed to parse port: %w", err)
			}
			conf.vsockPort = uint32(iport)
		}
	}

	abrokerEnv := "SPIRE_HA_AGENT_BROKER"
	aworkloadEnv := "SPIRE_HA_AGENT_WORKLOAD_SOCKET"
	if !conf.single {
		abrokerEnv = "SPIRE_HA_AGENT_BROKER_A"
		aworkloadEnv = "SPIRE_HA_AGENT_WORKLOAD_SOCKET_A"
	}
	var aBroker, aWorkload, bBroker, bWorkload *string
	if fc.UpstreamA != nil {
		aBroker = fc.UpstreamA.BrokerAddress
		aWorkload = fc.UpstreamA.WorkloadSocket
	}
	if fc.UpstreamB != nil {
		bBroker = fc.UpstreamB.BrokerAddress
		bWorkload = fc.UpstreamB.WorkloadSocket
	}
	conf.brokerA = resolveString(aBroker, abrokerEnv, "unix:///var/run/spire/agent/sockets/a/broker/broker.sock")
	conf.workloadA = resolveString(aWorkload, aworkloadEnv, "unix:///var/run/spire/agent/sockets/a/public/api.sock")
	conf.brokerB = resolveString(bBroker, "SPIRE_HA_AGENT_BROKER_B", "unix:///var/run/spire/agent/sockets/b/broker/broker.sock")
	conf.workloadB = resolveString(bWorkload, "SPIRE_HA_AGENT_WORKLOAD_SOCKET_B", "unix:///var/run/spire/agent/sockets/b/public/api.sock")

	if fc.Metrics != nil {
		if fc.Metrics.BindAddress == nil || *fc.Metrics.BindAddress == "" {
			return nil, fmt.Errorf("metrics: bind_address is required")
		}
		if _, port, err := net.SplitHostPort(*fc.Metrics.BindAddress); err != nil || port == "" {
			return nil, fmt.Errorf("metrics: invalid bind_address %q", *fc.Metrics.BindAddress)
		}
		conf.metrics = &metricsConfig{bindAddress: *fc.Metrics.BindAddress}
	}

	conf.keepaliveTime = safeKeepaliveTime
	conf.keepaliveTimeout = defaultKeepaliveTimeout
	if ka := fc.UpstreamKeepalive; ka != nil {
		if ka.Time != nil {
			d, err := time.ParseDuration(*ka.Time)
			if err != nil {
				return nil, fmt.Errorf("upstream_keepalive: invalid time %q: %w", *ka.Time, err)
			}
			if d < 0 {
				return nil, fmt.Errorf("upstream_keepalive: time must not be negative")
			}
			conf.keepaliveTime = d
		}
		if ka.Timeout != nil {
			d, err := time.ParseDuration(*ka.Timeout)
			if err != nil {
				return nil, fmt.Errorf("upstream_keepalive: invalid timeout %q: %w", *ka.Timeout, err)
			}
			if d <= 0 {
				return nil, fmt.Errorf("upstream_keepalive: timeout must be positive")
			}
			conf.keepaliveTimeout = d
		}
		if conf.keepaliveTime != 0 && conf.keepaliveTimeout >= conf.keepaliveTime {
			return nil, fmt.Errorf("upstream_keepalive: timeout (%s) must be less than time (%s)", conf.keepaliveTimeout, conf.keepaliveTime)
		}
	}

	if fc.BrokerEndpoint != nil {
		ep, err := resolveEndpointConfig(fc.BrokerEndpoint, conf)
		if err != nil {
			return nil, err
		}
		conf.endpoint = ep
	}
	return conf, nil
}

func resolveEndpointConfig(fc *endpointFileConfig, conf *brokerConfig) (*endpointConfig, error) {
	ep := &endpointConfig{policies: make(map[spiffeid.ID]map[string]refPolicy)}
	if fc.SocketPath != nil {
		ep.socketPath = *fc.SocketPath
	}
	if fc.BindAddress != nil {
		ep.bindAddress = *fc.BindAddress
	}
	if ep.socketPath == "" && ep.bindAddress == "" {
		return nil, fmt.Errorf("broker_endpoint: at least one of socket_path or bind_address is required")
	}
	if ep.bindAddress != "" {
		if _, port, err := net.SplitHostPort(ep.bindAddress); err != nil || port == "" {
			return nil, fmt.Errorf("broker_endpoint: invalid bind_address %q", ep.bindAddress)
		}
	}
	// The workload API socket directory gets removed/re-permissioned at
	// startup; the broker endpoint socket must live elsewhere (mirrors the
	// SPIRE agent's rule).
	if ep.socketPath != "" && !conf.vsockEnabled {
		sp := filepath.Clean(ep.socketPath)
		ws := filepath.Clean(conf.socket)
		if sp == ws || filepath.Dir(sp) == filepath.Dir(ws) {
			return nil, fmt.Errorf("broker_endpoint: socket_path %q must not share a directory with the workload API socket %q", ep.socketPath, conf.socket)
		}
	}
	if len(fc.Brokers) < 1 {
		return nil, fmt.Errorf("broker_endpoint: at least one broker is required")
	}
	for _, b := range fc.Brokers {
		id, err := spiffeid.FromString(b.ID)
		if err != nil {
			return nil, fmt.Errorf("broker_endpoint: invalid broker id %q: %w", b.ID, err)
		}
		if _, ok := ep.policies[id]; ok {
			return nil, fmt.Errorf("broker_endpoint: duplicate broker id %q", b.ID)
		}
		if len(b.AllowedReferenceTypes) < 1 {
			return nil, fmt.Errorf("broker_endpoint: broker %q needs at least one allowed_reference_types entry", b.ID)
		}
		pol := make(map[string]refPolicy)
		for _, rt := range b.AllowedReferenceTypes {
			if rt.TypeURL == "" {
				return nil, fmt.Errorf("broker_endpoint: broker %q has an empty type_url", b.ID)
			}
			if _, ok := pol[rt.TypeURL]; ok {
				return nil, fmt.Errorf("broker_endpoint: broker %q has duplicate type_url %q", b.ID, rt.TypeURL)
			}
			pol[rt.TypeURL] = refPolicy{allowOverTCP: rt.AllowOverTCP}
		}
		ep.ids = append(ep.ids, id)
		ep.policies[id] = pol
	}
	return ep, nil
}
