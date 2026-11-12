package main

// Tests for the Envoy SDS API (sds.go).
//
// Three layers:
//   - the handler against a fake snapshot source: resource name resolution,
//     validation context flavours, and the StreamSecrets state machine
//     (mirrors the SPIRE agent's sdsv3 handler tests)
//   - the pieces in isolation: config resolution, the snapshot built from an
//     upstream broker response, small helpers
//   - end to end through brokerMain with the fake upstream sides, as an
//     Envoy would see it on the workload API socket

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	sdsTestTD       = "spiffe://domain.test"
	sdsTestFedTD    = "spiffe://otherdomain.test"
	sdsTestWorkload = "spiffe://domain.test/workload"
)

// ---- fixtures ----

type sdsFixture struct {
	td, fedTD    spiffeid.TrustDomain
	tdCA, fedCA  *testCA
	leaf1, leaf2 *testLeaf
}

func newSDSFixture(t *testing.T) *sdsFixture {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	tdCA := newTestCA(t, "TD-CA")
	id := spiffeid.RequireFromString(sdsTestWorkload)
	return &sdsFixture{
		td:    td,
		fedTD: spiffeid.RequireTrustDomainFromString("otherdomain.test"),
		tdCA:  tdCA,
		fedCA: newTestCA(t, "FED-CA"),
		leaf1: tdCA.issue(t, id),
		leaf2: tdCA.issue(t, id),
	}
}

func (f *sdsFixture) update(t *testing.T, leaf *testLeaf) *sdsUpdate {
	t.Helper()
	return &sdsUpdate{
		identities: []sdsIdentity{{spiffeID: sdsTestWorkload, chain: leaf.cert.Raw, key: pkcs8(t, leaf.key)}},
		localTD:    f.td,
		bundle:     f.tdCA.cert.Raw,
		federated:  map[spiffeid.TrustDomain][]byte{f.fedTD: f.fedCA.cert.Raw},
	}
}

// Expected secrets are built here independently of the code under test.

func testPEMCerts(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

func testInline(b []byte) *core_v3.DataSource {
	return &core_v3.DataSource{Specifier: &core_v3.DataSource_InlineBytes{InlineBytes: b}}
}

func wantRootCA(name string, cas ...*x509.Certificate) *tls_v3.Secret {
	return &tls_v3.Secret{
		Name: name,
		Type: &tls_v3.Secret_ValidationContext{ValidationContext: &tls_v3.CertificateValidationContext{
			TrustedCa: testInline(testPEMCerts(cas...)),
		}},
	}
}

type wantTD struct {
	name string
	cas  []*x509.Certificate
}

func wantSPIFFE(t *testing.T, name string, tds ...wantTD) *tls_v3.Secret {
	t.Helper()
	conf := &tls_v3.SPIFFECertValidatorConfig{}
	for _, td := range tds {
		conf.TrustDomains = append(conf.TrustDomains, &tls_v3.SPIFFECertValidatorConfig_TrustDomain{
			Name:        td.name,
			TrustBundle: testInline(testPEMCerts(td.cas...)),
		})
	}
	typed, err := anypb.New(conf)
	if err != nil {
		t.Fatalf("anypb: %v", err)
	}
	return &tls_v3.Secret{
		Name: name,
		Type: &tls_v3.Secret_ValidationContext{ValidationContext: &tls_v3.CertificateValidationContext{
			CustomValidatorConfig: &core_v3.TypedExtensionConfig{
				Name:        "envoy.tls.cert_validator.spiffe",
				TypedConfig: typed,
			},
		}},
	}
}

func wantTLS(t *testing.T, name string, leaf *testLeaf) *tls_v3.Secret {
	t.Helper()
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(t, leaf.key)})
	return &tls_v3.Secret{
		Name: name,
		Type: &tls_v3.Secret_TlsCertificate{TlsCertificate: &tls_v3.TlsCertificate{
			CertificateChain: testInline(testPEMCerts(leaf.cert)),
			PrivateKey:       testInline(keyPEM),
		}},
	}
}

func sdsNode(major, minor uint32, md map[string]any) *core_v3.Node {
	node := &core_v3.Node{
		UserAgentVersionType: &core_v3.Node_UserAgentBuildVersion{
			UserAgentBuildVersion: &core_v3.BuildVersion{
				Version: &envoy_type_v3.SemanticVersion{MajorNumber: major, MinorNumber: minor},
			},
		},
	}
	if md != nil {
		s, err := structpb.NewStruct(md)
		if err != nil {
			panic(err)
		}
		node.Metadata = s
	}
	return node
}

func sdsNodeNoVersion() *core_v3.Node {
	return &core_v3.Node{
		UserAgentVersionType: &core_v3.Node_UserAgentBuildVersion{
			UserAgentBuildVersion: &core_v3.BuildVersion{},
		},
	}
}

// ---- fake source ----

type fakeSDSSource struct {
	mu   sync.Mutex
	upd  *sdsUpdate
	next int
	subs map[int]chan *sdsUpdate
	err  error
}

func (f *fakeSDSSource) subscribe(ctx context.Context) (<-chan *sdsUpdate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	ch := make(chan *sdsUpdate, 1)
	if f.upd != nil {
		ch <- f.upd
	}
	if f.subs == nil {
		f.subs = make(map[int]chan *sdsUpdate)
	}
	key := f.next
	f.next++
	f.subs[key] = ch
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.subs, key)
	}()
	return ch, nil
}

func (f *fakeSDSSource) fetch(context.Context) (*sdsUpdate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.upd, f.err
}

func (f *fakeSDSSource) set(upd *sdsUpdate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upd = upd
	for _, ch := range f.subs {
		select {
		case <-ch:
		default:
		}
		ch <- upd
	}
}

func (f *fakeSDSSource) subscribers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

// ---- handler harness ----

type sdsTest struct {
	t        *testing.T
	fx       *sdsFixture
	source   *fakeSDSSource
	client   secret_v3.SecretDiscoveryServiceClient
	received chan struct{}
}

func defaultSDSConfig() sdsConfig {
	return *resolveSDSConfig(nil, nil)
}

func setupSDSTest(t *testing.T, conf sdsConfig) *sdsTest {
	t.Helper()
	fx := newSDSFixture(t)
	source := &fakeSDSSource{}
	source.set(fx.update(t, fx.leaf1))

	handler := newSDSHandler(conf, source)
	received := make(chan struct{})
	handler.hooks.received = received

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	secret_v3.RegisterSecretDiscoveryServiceServer(server, handler)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &sdsTest{t: t, fx: fx, source: source, client: secret_v3.NewSecretDiscoveryServiceClient(conn), received: received}
}

func (st *sdsTest) stream() secret_v3.SecretDiscoveryService_StreamSecretsClient {
	st.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	st.t.Cleanup(cancel)
	stream, err := st.client.StreamSecrets(ctx)
	if err != nil {
		st.t.Fatalf("StreamSecrets: %v", err)
	}
	return stream
}

// Sends a request and waits for the handler to have picked it up, so the
// test knows the request was processed before it does anything else.
func (st *sdsTest) sendAndWait(stream secret_v3.SecretDiscoveryService_StreamSecretsClient, req *discovery_v3.DiscoveryRequest) {
	st.t.Helper()
	if err := stream.Send(req); err != nil {
		st.t.Fatalf("send: %v", err)
	}
	select {
	case <-st.received:
	case <-time.After(10 * time.Second):
		st.t.Fatal("handler never received the request")
	}
}

func (st *sdsTest) recv(stream secret_v3.SecretDiscoveryService_StreamSecretsClient) *discovery_v3.DiscoveryResponse {
	st.t.Helper()
	resp, err := stream.Recv()
	if err != nil {
		st.t.Fatalf("recv: %v", err)
	}
	return resp
}

func sdsSecrets(t *testing.T, resp *discovery_v3.DiscoveryResponse) []*tls_v3.Secret {
	t.Helper()
	var out []*tls_v3.Secret
	for _, res := range resp.GetResources() {
		if res.GetTypeUrl() != "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret" {
			t.Fatalf("unexpected resource type url %q", res.GetTypeUrl())
		}
		secret := new(tls_v3.Secret)
		if err := res.UnmarshalTo(secret); err != nil {
			t.Fatalf("unmarshal secret: %v", err)
		}
		out = append(out, secret)
	}
	return out
}

func requireSDSSecrets(t *testing.T, resp *discovery_v3.DiscoveryResponse, want ...*tls_v3.Secret) {
	t.Helper()
	got := sdsSecrets(t, resp)
	if len(got) != len(want) {
		var names []string
		for _, s := range got {
			names = append(names, s.Name)
		}
		t.Fatalf("got %d secrets %q, want %d", len(got), names, len(want))
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			t.Fatalf("secret %d mismatch:\n got: %v\nwant: %v", i, got[i], want[i])
		}
	}
}

func requireStatus(t *testing.T, err error, code codes.Code, msg string) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("got error %v, want code %s", err, code)
	}
	if msg != "" && !strings.Contains(status.Convert(err).Message(), msg) {
		t.Fatalf("got message %q, want it to contain %q", status.Convert(err).Message(), msg)
	}
}

// ---- resource resolution: StreamSecrets and FetchSecrets ----

type sdsCase struct {
	name   string
	names  []string
	node   *core_v3.Node
	config func(*sdsConfig)
	want   func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret
	code   codes.Code
	msg    string
}

func sdsCases() []sdsCase {
	tdRoot := func(name string) func(*testing.T, *sdsFixture) []*tls_v3.Secret {
		return func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
			return []*tls_v3.Secret{wantRootCA(name, fx.tdCA.cert)}
		}
	}
	tdSPIFFE := func(name string) func(*testing.T, *sdsFixture) []*tls_v3.Secret {
		return func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
			return []*tls_v3.Secret{wantSPIFFE(t, name, wantTD{"domain.test", []*x509.Certificate{fx.tdCA.cert}})}
		}
	}
	allRoot := func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
		return []*tls_v3.Secret{
			wantRootCA(sdsTestTD, fx.tdCA.cert),
			wantRootCA(sdsTestFedTD, fx.fedCA.cert),
			wantTLS(t, sdsTestWorkload, fx.leaf1),
		}
	}
	allSPIFFE := func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
		return []*tls_v3.Secret{
			wantSPIFFE(t, sdsTestTD, wantTD{"domain.test", []*x509.Certificate{fx.tdCA.cert}}),
			wantSPIFFE(t, sdsTestFedTD, wantTD{"otherdomain.test", []*x509.Certificate{fx.fedCA.cert}}),
			wantTLS(t, sdsTestWorkload, fx.leaf1),
		}
	}
	disable := func(c *sdsConfig) { c.disableSPIFFECertValidation = true }
	md := func(v any) map[string]any { return map[string]any{"disable_spiffe_cert_validation": v} }

	return []sdsCase{
		{name: "all secrets: root CA (envoy 1.17)", node: sdsNode(1, 17, nil), want: allRoot},
		{name: "all secrets: build version without version", node: sdsNodeNoVersion(), want: allSPIFFE},
		{name: "all secrets: SPIFFE (envoy 1.18)", node: sdsNode(1, 18, nil), want: allSPIFFE},
		{name: "all secrets: SPIFFE (envoy 2.0)", node: sdsNode(2, 0, nil), want: allSPIFFE},
		{name: "all secrets: no node", want: allSPIFFE},
		{name: "all secrets: empty names are ignored", names: []string{"", ""}, want: allSPIFFE},

		{name: "trust domain bundle: root CA", names: []string{sdsTestTD}, node: sdsNode(1, 17, nil), want: tdRoot(sdsTestTD)},
		{name: "trust domain bundle: SPIFFE", names: []string{sdsTestTD}, node: sdsNode(1, 18, nil), want: tdSPIFFE(sdsTestTD)},
		{name: "default bundle: root CA", names: []string{"ROOTCA"}, node: sdsNode(1, 17, nil), want: tdRoot("ROOTCA")},
		{name: "default bundle: SPIFFE", names: []string{"ROOTCA"}, node: sdsNode(1, 18, nil), want: tdSPIFFE("ROOTCA")},
		{name: "default bundle: SPIFFE, empty node", names: []string{"ROOTCA"}, node: &core_v3.Node{}, want: tdSPIFFE("ROOTCA")},
		{
			name: "federated bundle: root CA", names: []string{sdsTestFedTD}, node: sdsNode(1, 17, nil),
			want: func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
				return []*tls_v3.Secret{wantRootCA(sdsTestFedTD, fx.fedCA.cert)}
			},
		},
		{
			name: "federated bundle: SPIFFE", names: []string{sdsTestFedTD}, node: sdsNode(1, 18, nil),
			want: func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
				return []*tls_v3.Secret{wantSPIFFE(t, sdsTestFedTD, wantTD{"otherdomain.test", []*x509.Certificate{fx.fedCA.cert}})}
			},
		},
		{
			name: "all bundles: root CA is unsupported", names: []string{"ALL"}, node: sdsNode(1, 17, nil),
			code: codes.Internal, msg: `unable to use "SPIFFE validator" on Envoy below 1.17`,
		},
		{
			name: "all bundles: SPIFFE", names: []string{"ALL"}, node: sdsNode(1, 18, nil),
			want: func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
				return []*tls_v3.Secret{wantSPIFFE(t, "ALL",
					wantTD{"domain.test", []*x509.Certificate{fx.tdCA.cert}},
					wantTD{"otherdomain.test", []*x509.Certificate{fx.fedCA.cert}},
				)}
			},
		},

		{
			name: "TLS certificate by SPIFFE ID", names: []string{sdsTestWorkload}, node: sdsNode(1, 18, nil),
			want: func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
				return []*tls_v3.Secret{wantTLS(t, sdsTestWorkload, fx.leaf1)}
			},
		},
		{
			name: "default TLS certificate", names: []string{"default"},
			want: func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
				return []*tls_v3.Secret{wantTLS(t, "default", fx.leaf1)}
			},
		},
		{
			name: "certificate, bundle and federated bundle together", names: []string{"default", sdsTestFedTD, "ROOTCA"},
			want: func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
				return []*tls_v3.Secret{
					wantSPIFFE(t, "ROOTCA", wantTD{"domain.test", []*x509.Certificate{fx.tdCA.cert}}),
					wantSPIFFE(t, sdsTestFedTD, wantTD{"otherdomain.test", []*x509.Certificate{fx.fedCA.cert}}),
					wantTLS(t, "default", fx.leaf1),
				}
			},
		},
		{
			name: "custom resource names", names: []string{"mysvid", "mybundle"},
			config: func(c *sdsConfig) {
				c.defaultSVIDName, c.defaultBundleName, c.defaultAllBundlesName = "mysvid", "mybundle", "everything"
			},
			want: func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
				return []*tls_v3.Secret{
					wantSPIFFE(t, "mybundle", wantTD{"domain.test", []*x509.Certificate{fx.tdCA.cert}}),
					wantTLS(t, "mysvid", fx.leaf1),
				}
			},
		},
		{
			name: "custom all bundles name", names: []string{"everything"},
			config: func(c *sdsConfig) { c.defaultAllBundlesName = "everything" },
			want: func(t *testing.T, fx *sdsFixture) []*tls_v3.Secret {
				return []*tls_v3.Secret{wantSPIFFE(t, "everything",
					wantTD{"domain.test", []*x509.Certificate{fx.tdCA.cert}},
					wantTD{"otherdomain.test", []*x509.Certificate{fx.fedCA.cert}},
				)}
			},
		},
		{
			name: "custom names replace the defaults", names: []string{"default"},
			config: func(c *sdsConfig) { c.defaultSVIDName = "mysvid" },
			code:   codes.InvalidArgument, msg: `workload is not authorized for the requested identities ["default"]`,
		},

		{
			name: "unknown resource", names: []string{"spiffe://domain.test/other", "spiffe://domain.test/another"},
			code: codes.InvalidArgument,
			msg:  `workload is not authorized for the requested identities ["spiffe://domain.test/another" "spiffe://domain.test/other"]`,
		},
		{
			// Only one local bundle resource is served per request, as in SPIRE.
			name: "trust domain bundle and default bundle together", names: []string{sdsTestTD, "ROOTCA"},
			code: codes.InvalidArgument, msg: `["ROOTCA"]`,
		},
		{
			name: "default bundle and all bundles together", names: []string{"ROOTCA", "ALL"},
			code: codes.InvalidArgument, msg: `["ALL"]`,
		},
		{
			// The default name is only an alias when the ID was not asked for.
			name: "SPIFFE ID and default certificate together", names: []string{sdsTestWorkload, "default"},
			code: codes.InvalidArgument, msg: `["default"]`,
		},

		{name: "validation disabled in config", names: []string{"ROOTCA"}, node: sdsNode(1, 18, nil), config: disable, want: tdRoot("ROOTCA")},
		{
			name: "validation disabled, bundle name equal to all bundles name", names: []string{"ALL"}, node: sdsNode(1, 18, nil),
			config: func(c *sdsConfig) { c.disableSPIFFECertValidation = true; c.defaultBundleName = "ALL" },
			want:   tdRoot("ALL"),
		},
		{name: "validation disabled per instance (bool)", names: []string{sdsTestTD}, node: sdsNode(1, 18, md(true)), want: tdRoot(sdsTestTD)},
		{name: "validation disabled per instance (string)", names: []string{sdsTestTD}, node: sdsNode(1, 18, md("true")), want: tdRoot(sdsTestTD)},
		{name: "validation enabled per instance (bool false)", names: []string{sdsTestTD}, node: sdsNode(1, 18, md(false)), want: tdSPIFFE(sdsTestTD)},
		{name: "per instance unknown string keeps config", names: []string{sdsTestTD}, node: sdsNode(1, 18, md("test")), want: tdSPIFFE(sdsTestTD)},
		{name: "disabled in config and per instance", names: []string{sdsTestTD}, node: sdsNode(1, 18, md(true)), config: disable, want: tdRoot(sdsTestTD)},
		{name: "disabled in config, enabled per instance (string)", names: []string{sdsTestTD}, node: sdsNode(1, 18, md("false")), config: disable, want: tdSPIFFE(sdsTestTD)},
		{name: "disabled in config, enabled per instance (bool)", names: []string{sdsTestTD}, node: sdsNode(1, 18, md(false)), config: disable, want: tdSPIFFE(sdsTestTD)},
		{name: "disabled in config, per instance unknown string", names: []string{sdsTestTD}, node: sdsNode(1, 18, md("test")), config: disable, want: tdRoot(sdsTestTD)},
		{name: "disabled in config, per instance unexpected type", names: []string{sdsTestTD}, node: sdsNode(1, 18, md(5)), config: disable, want: tdRoot(sdsTestTD)},
		{name: "enabled per instance cannot help an old envoy", names: []string{sdsTestTD}, node: sdsNode(1, 17, md(false)), want: tdRoot(sdsTestTD)},
	}
}

func TestSDSStreamSecrets(t *testing.T) {
	for _, tc := range sdsCases() {
		t.Run(tc.name, func(t *testing.T) {
			conf := defaultSDSConfig()
			if tc.config != nil {
				tc.config(&conf)
			}
			st := setupSDSTest(t, conf)
			stream := st.stream()
			st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: tc.names, Node: tc.node, TypeUrl: "TYPEURL"})

			resp, err := stream.Recv()
			if tc.code != codes.OK {
				requireStatus(t, err, tc.code, tc.msg)
				return
			}
			if err != nil {
				t.Fatalf("recv: %v", err)
			}
			if resp.VersionInfo != "1" {
				t.Errorf("version_info: got %q, want %q", resp.VersionInfo, "1")
			}
			if len(resp.Nonce) != 8 {
				t.Errorf("nonce: got %q, want 8 hex characters", resp.Nonce)
			}
			if resp.TypeUrl != "TYPEURL" {
				t.Errorf("type_url: got %q, want it echoed", resp.TypeUrl)
			}
			requireSDSSecrets(t, resp, tc.want(t, st.fx)...)
		})
	}
}

func TestSDSFetchSecrets(t *testing.T) {
	for _, tc := range sdsCases() {
		t.Run(tc.name, func(t *testing.T) {
			conf := defaultSDSConfig()
			if tc.config != nil {
				tc.config(&conf)
			}
			st := setupSDSTest(t, conf)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			resp, err := st.client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{ResourceNames: tc.names, Node: tc.node, TypeUrl: "TYPEURL"})
			if tc.code != codes.OK {
				requireStatus(t, err, tc.code, tc.msg)
				return
			}
			if err != nil {
				t.Fatalf("FetchSecrets: %v", err)
			}
			if resp.VersionInfo != "" || resp.Nonce != "" {
				t.Errorf("fetch responses carry no version or nonce: got %q / %q", resp.VersionInfo, resp.Nonce)
			}
			if resp.TypeUrl != "TYPEURL" {
				t.Errorf("type_url: got %q, want it echoed", resp.TypeUrl)
			}
			requireSDSSecrets(t, resp, tc.want(t, st.fx)...)
		})
	}
}

func TestSDSMultipleIdentities(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	second := st.fx.tdCA.issue(t, spiffeid.RequireFromString("spiffe://domain.test/second"))
	upd := st.fx.update(t, st.fx.leaf1)
	upd.identities = append(upd.identities, sdsIdentity{
		spiffeID: "spiffe://domain.test/second", chain: second.cert.Raw, key: pkcs8(t, second.key),
	})
	st.source.set(upd)
	ctx := context.Background()

	// the default name is the first identity only
	resp, err := st.client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{ResourceNames: []string{"default"}})
	if err != nil {
		t.Fatalf("FetchSecrets: %v", err)
	}
	requireSDSSecrets(t, resp, wantTLS(t, "default", st.fx.leaf1))

	// any identity can be asked for by SPIFFE ID, alongside the default
	resp, err = st.client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{ResourceNames: []string{"spiffe://domain.test/second", "default"}})
	if err != nil {
		t.Fatalf("FetchSecrets: %v", err)
	}
	requireSDSSecrets(t, resp, wantTLS(t, "default", st.fx.leaf1), wantTLS(t, "spiffe://domain.test/second", second))

	// no names: every identity by SPIFFE ID
	resp, err = st.client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
	if err != nil {
		t.Fatalf("FetchSecrets: %v", err)
	}
	requireSDSSecrets(t, resp,
		wantSPIFFE(t, sdsTestTD, wantTD{"domain.test", []*x509.Certificate{st.fx.tdCA.cert}}),
		wantSPIFFE(t, sdsTestFedTD, wantTD{"otherdomain.test", []*x509.Certificate{st.fx.fedCA.cert}}),
		wantTLS(t, sdsTestWorkload, st.fx.leaf1),
		wantTLS(t, "spiffe://domain.test/second", second),
	)
}

func TestSDSChainAndMultiCABundle(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	otherCA := newTestCA(t, "TD-CA-2")
	upd := st.fx.update(t, st.fx.leaf1)
	// leaf followed by an intermediate, and a two-authority local bundle
	upd.identities[0].chain = append(append([]byte{}, st.fx.leaf1.cert.Raw...), otherCA.cert.Raw...)
	upd.bundle = append(append([]byte{}, st.fx.tdCA.cert.Raw...), otherCA.cert.Raw...)
	st.source.set(upd)

	resp, err := st.client.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"default", "ROOTCA"}, Node: sdsNode(1, 17, nil),
	})
	if err != nil {
		t.Fatalf("FetchSecrets: %v", err)
	}
	wantCert := wantTLS(t, "default", st.fx.leaf1)
	wantCert.GetTlsCertificate().CertificateChain = testInline(testPEMCerts(st.fx.leaf1.cert, otherCA.cert))
	requireSDSSecrets(t, resp, wantRootCA("ROOTCA", st.fx.tdCA.cert, otherCA.cert), wantCert)
}

func TestSDSNoLocalBundle(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	upd := st.fx.update(t, st.fx.leaf1)
	upd.bundle = nil
	st.source.set(upd)
	ctx := context.Background()

	for _, name := range []string{"ROOTCA", "ALL", sdsTestTD} {
		_, err := st.client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{ResourceNames: []string{name}})
		requireStatus(t, err, codes.InvalidArgument, fmt.Sprintf("[%q]", name))
	}
	// the rest is still served
	resp, err := st.client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
	if err != nil {
		t.Fatalf("FetchSecrets: %v", err)
	}
	requireSDSSecrets(t, resp,
		wantSPIFFE(t, sdsTestFedTD, wantTD{"otherdomain.test", []*x509.Certificate{st.fx.fedCA.cert}}),
		wantTLS(t, sdsTestWorkload, st.fx.leaf1),
	)
}

func TestSDSNoIdentities(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	upd := st.fx.update(t, st.fx.leaf1)
	upd.identities = nil
	st.source.set(upd)

	_, err := st.client.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{ResourceNames: []string{"default"}})
	requireStatus(t, err, codes.InvalidArgument, `["default"]`)
}

func TestSDSBadMaterial(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(*sdsUpdate)
		names  []string
	}{
		{"bad chain", func(u *sdsUpdate) { u.identities[0].chain = []byte("nope") }, []string{"default"}},
		{"bad key", func(u *sdsUpdate) { u.identities[0].key = []byte("nope") }, []string{"default"}},
		{"bad local bundle", func(u *sdsUpdate) { u.bundle = []byte("nope") }, []string{"ROOTCA"}},
		{"bad federated bundle", func(u *sdsUpdate) {
			for td := range u.federated {
				u.federated[td] = []byte("nope")
			}
		}, []string{sdsTestFedTD}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := setupSDSTest(t, defaultSDSConfig())
			upd := st.fx.update(t, st.fx.leaf1)
			tc.mutate(upd)
			st.source.set(upd)
			_, err := st.client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{ResourceNames: tc.names})
			requireStatus(t, err, codes.Internal, "")
		})
	}
}

// ---- StreamSecrets state machine ----

func TestSDSStreamUpdatePushesNewResponse(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{sdsTestWorkload}})

	first := st.recv(stream)
	requireSDSSecrets(t, first, wantTLS(t, sdsTestWorkload, st.fx.leaf1))

	st.source.set(st.fx.update(t, st.fx.leaf2))
	second := st.recv(stream)
	requireSDSSecrets(t, second, wantTLS(t, sdsTestWorkload, st.fx.leaf2))

	if first.VersionInfo != "1" || second.VersionInfo != "2" {
		t.Errorf("versions: got %q then %q, want 1 then 2", first.VersionInfo, second.VersionInfo)
	}
	if first.Nonce == second.Nonce {
		t.Errorf("nonce was reused: %q", first.Nonce)
	}
}

func TestSDSStreamKeepsNodeInformation(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{"ROOTCA"}, Node: sdsNode(1, 17, nil)})
	resp := st.recv(stream)
	requireSDSSecrets(t, resp, wantRootCA("ROOTCA", st.fx.tdCA.cert))

	// Envoy only sends the node on the first request of a stream. The
	// follow-up must still be answered for a 1.17 Envoy.
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{sdsTestTD},
		VersionInfo:   resp.VersionInfo,
		ResponseNonce: resp.Nonce,
	})
	resp = st.recv(stream)
	requireSDSSecrets(t, resp, wantRootCA(sdsTestTD, st.fx.tdCA.cert))
}

func TestSDSStreamNACKDoesNotSpin(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{sdsTestWorkload}})
	resp := st.recv(stream)
	requireSDSSecrets(t, resp, wantTLS(t, sdsTestWorkload, st.fx.leaf1))

	// Reject the update. The handler must not resend the same thing.
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{sdsTestWorkload},
		ResponseNonce: resp.Nonce,
		VersionInfo:   "OHNO",
		ErrorDetail:   &rpcstatus.Status{Message: "OHNO!"},
	})

	// The next thing on the stream is the next snapshot, not a resend.
	st.source.set(st.fx.update(t, st.fx.leaf2))
	resp = st.recv(stream)
	if resp.VersionInfo != "2" {
		t.Fatalf("version_info: got %q, want 2 (a resend of version 1 means the NACK span)", resp.VersionInfo)
	}
	requireSDSSecrets(t, resp, wantTLS(t, sdsTestWorkload, st.fx.leaf2))
}

func TestSDSStreamNACKWithNewNamesIsApplied(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{sdsTestWorkload}})
	resp := st.recv(stream)

	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"default"},
		ResponseNonce: resp.Nonce,
		VersionInfo:   "",
		ErrorDetail:   &rpcstatus.Status{Message: "OHNO!"},
	})
	resp = st.recv(stream)
	if resp.VersionInfo != "1" {
		t.Errorf("version_info: got %q, want 1 (no new snapshot)", resp.VersionInfo)
	}
	requireSDSSecrets(t, resp, wantTLS(t, "default", st.fx.leaf1))
}

func TestSDSStreamRequestBeforeFirstUpdate(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	st.source.mu.Lock()
	st.source.upd = nil
	st.source.mu.Unlock()

	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{sdsTestWorkload}})

	// nothing can be sent until the workload's identities are known
	st.source.set(st.fx.update(t, st.fx.leaf2))
	resp := st.recv(stream)
	if resp.VersionInfo != "1" {
		t.Errorf("version_info: got %q, want 1", resp.VersionInfo)
	}
	requireSDSSecrets(t, resp, wantTLS(t, sdsTestWorkload, st.fx.leaf2))
}

func TestSDSStreamSubscriptionChange(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{"default"}})
	resp := st.recv(stream)
	requireSDSSecrets(t, resp, wantTLS(t, "default", st.fx.leaf1))

	// An ACK for the same names gets no response...
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"default"},
		VersionInfo:   resp.VersionInfo,
		ResponseNonce: resp.Nonce,
	})
	// ...so the next message answers the changed subscription.
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"ROOTCA"},
		VersionInfo:   resp.VersionInfo,
		ResponseNonce: resp.Nonce,
	})
	resp = st.recv(stream)
	if resp.VersionInfo != "1" {
		t.Errorf("version_info: got %q, want 1 (a request alone never bumps the version)", resp.VersionInfo)
	}
	requireSDSSecrets(t, resp, wantSPIFFE(t, "ROOTCA", wantTD{"domain.test", []*x509.Certificate{st.fx.tdCA.cert}}))
}

func TestSDSStreamBadNonce(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{sdsTestWorkload}})
	resp := st.recv(stream)
	requireSDSSecrets(t, resp, wantTLS(t, sdsTestWorkload, st.fx.leaf1))

	// A request carrying a stale nonce is ignored entirely, including its
	// changed resource names.
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"ROOTCA"},
		VersionInfo:   resp.VersionInfo,
		ResponseNonce: "FOO",
	})
	st.source.set(st.fx.update(t, st.fx.leaf2))
	resp = st.recv(stream)
	requireSDSSecrets(t, resp, wantTLS(t, sdsTestWorkload, st.fx.leaf2))

	// The right nonce is processed.
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"default"},
		VersionInfo:   resp.VersionInfo,
		ResponseNonce: resp.Nonce,
	})
	resp = st.recv(stream)
	requireSDSSecrets(t, resp, wantTLS(t, "default", st.fx.leaf2))
}

func TestSDSStreamUnknownResourceEndsStream(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{"default"}})
	resp := st.recv(stream)

	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"nope"},
		VersionInfo:   resp.VersionInfo,
		ResponseNonce: resp.Nonce,
	})
	_, err := stream.Recv()
	requireStatus(t, err, codes.InvalidArgument, `["nope"]`)
}

func TestSDSStreamCloseAndUnsubscribe(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	stream := st.stream()
	st.sendAndWait(stream, &discovery_v3.DiscoveryRequest{ResourceNames: []string{"default"}})
	st.recv(stream)
	if n := st.source.subscribers(); n != 1 {
		t.Fatalf("subscribers: got %d, want 1", n)
	}

	// A clean close from the client ends the stream without an error.
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("recv after close: got %v, want EOF", err)
	}

	// ...and releases the source subscription.
	deadline := time.Now().Add(10 * time.Second)
	for st.source.subscribers() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscription was never released")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSDSSourceErrors(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	st.source.mu.Lock()
	st.source.err = status.Error(codes.Unavailable, "no upstream")
	st.source.mu.Unlock()

	stream := st.stream()
	_, err := stream.Recv()
	requireStatus(t, err, codes.Unavailable, "no upstream")

	_, err = st.client.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{})
	requireStatus(t, err, codes.Unavailable, "no upstream")
}

func TestSDSFetchWithoutSnapshot(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	st.source.mu.Lock()
	st.source.upd = nil
	st.source.mu.Unlock()

	_, err := st.client.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{})
	requireStatus(t, err, codes.Unavailable, "")
}

func TestSDSDeltaSecretsUnimplemented(t *testing.T) {
	st := setupSDSTest(t, defaultSDSConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := st.client.DeltaSecrets(ctx)
	if err != nil {
		t.Fatalf("DeltaSecrets: %v", err)
	}
	_, err = stream.Recv()
	requireStatus(t, err, codes.Unimplemented, "")
}

// ---- helpers in isolation ----

func TestSDSSubListChanged(t *testing.T) {
	for _, tc := range []struct {
		a, b []string
		want bool
	}{
		{nil, nil, false},
		{[]string{"a"}, []string{"a"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
		{[]string{"a"}, []string{"b"}, true},
		{[]string{"a"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"a"}, true},
		{nil, []string{"a"}, true},
	} {
		if got := subListChanged(tc.a, tc.b); got != tc.want {
			t.Errorf("subListChanged(%q, %q): got %t, want %t", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestSDSSupportsSPIFFEAuthExtension(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *core_v3.Node
		want bool
	}{
		{"no node", nil, true},
		{"no version", sdsNodeNoVersion(), true},
		{"1.16", sdsNode(1, 16, nil), false},
		{"1.17", sdsNode(1, 17, nil), false},
		{"1.18", sdsNode(1, 18, nil), true},
		{"1.30", sdsNode(1, 30, nil), true},
		{"2.0", sdsNode(2, 0, nil), true},
		{"0.9", sdsNode(0, 99, nil), false},
	} {
		if got := supportsSPIFFEAuthExtension(&discovery_v3.DiscoveryRequest{Node: tc.node}); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestSDSUpdateEqual(t *testing.T) {
	fx := newSDSFixture(t)
	base := fx.update(t, fx.leaf1)
	same := fx.update(t, fx.leaf1)
	// the key is re-marshalled, the content is the same
	if !base.equal(same) {
		t.Fatal("identical snapshots compare different")
	}
	var none *sdsUpdate
	if !none.equal(nil) || base.equal(nil) || none.equal(base) {
		t.Fatal("nil handling is wrong")
	}

	for name, mutate := range map[string]func(*sdsUpdate){
		"rotated svid":      func(u *sdsUpdate) { u.identities[0].chain = fx.leaf2.cert.Raw },
		"rotated key":       func(u *sdsUpdate) { u.identities[0].key = pkcs8(t, fx.leaf2.key) },
		"renamed identity":  func(u *sdsUpdate) { u.identities[0].spiffeID = "spiffe://domain.test/other" },
		"extra identity":    func(u *sdsUpdate) { u.identities = append(u.identities, u.identities[0]) },
		"no identities":     func(u *sdsUpdate) { u.identities = nil },
		"bundle changed":    func(u *sdsUpdate) { u.bundle = fx.fedCA.cert.Raw },
		"bundle gone":       func(u *sdsUpdate) { u.bundle = nil },
		"trust domain":      func(u *sdsUpdate) { u.localTD = fx.fedTD },
		"federated changed": func(u *sdsUpdate) { u.federated[fx.fedTD] = fx.tdCA.cert.Raw },
		"federated gone":    func(u *sdsUpdate) { delete(u.federated, fx.fedTD) },
		"federated renamed": func(u *sdsUpdate) {
			u.federated = map[spiffeid.TrustDomain][]byte{spiffeid.RequireTrustDomainFromString("third.test"): fx.fedCA.cert.Raw}
		},
	} {
		other := fx.update(t, fx.leaf1)
		mutate(other)
		if base.equal(other) || other.equal(base) {
			t.Errorf("%s: snapshots compare equal", name)
		}
	}
}

// ---- config ----

func TestSDSConfigDefaults(t *testing.T) {
	conf, err := loadBrokerConfig("")
	if err != nil {
		t.Fatalf("loadBrokerConfig: %v", err)
	}
	if conf.sds == nil {
		t.Fatal("SDS must be enabled by default")
	}
	want := sdsConfig{defaultSVIDName: "default", defaultBundleName: "ROOTCA", defaultAllBundlesName: "ALL"}
	if *conf.sds != want {
		t.Errorf("defaults: got %+v, want %+v", *conf.sds, want)
	}
}

func TestSDSConfigFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want *sdsConfig
	}{
		{
			name: "all options",
			yaml: `
sds:
  default_svid_name: mysvid
  default_bundle_name: mybundle
  default_all_bundles_name: everything
  disable_spiffe_cert_validation: true
`,
			want: &sdsConfig{"mysvid", "mybundle", "everything", true},
		},
		{
			name: "partial block keeps the other defaults",
			yaml: "sds:\n  default_svid_name: mysvid\n",
			want: &sdsConfig{"mysvid", "ROOTCA", "ALL", false},
		},
		{
			name: "empty block",
			yaml: "sds: {}\n",
			want: &sdsConfig{"default", "ROOTCA", "ALL", false},
		},
		{
			name: "explicitly enabled",
			yaml: "disable_sds_api: false\n",
			want: &sdsConfig{"default", "ROOTCA", "ALL", false},
		},
		{
			name: "disabled",
			yaml: "disable_sds_api: true\n",
			want: nil,
		},
		{
			name: "disabled wins over an sds block",
			yaml: "disable_sds_api: true\nsds:\n  default_svid_name: mysvid\n",
			want: nil,
		},
		{
			// accepted with a warning, as in SPIRE
			name: "bundle name equal to all bundles name",
			yaml: "sds:\n  default_bundle_name: ALL\n",
			want: &sdsConfig{"default", "ALL", "ALL", false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := loadBrokerConfig(writeConfig(t, tc.yaml))
			if err != nil {
				t.Fatalf("loadBrokerConfig: %v", err)
			}
			switch {
			case tc.want == nil && conf.sds != nil:
				t.Fatalf("got %+v, want SDS disabled", *conf.sds)
			case tc.want != nil && conf.sds == nil:
				t.Fatal("got SDS disabled, want it enabled")
			case tc.want != nil && *conf.sds != *tc.want:
				t.Fatalf("got %+v, want %+v", *conf.sds, *tc.want)
			}
		})
	}
}

func TestSDSConfigErrors(t *testing.T) {
	for name, yaml := range map[string]string{
		"unknown key":     "sds:\n  default_svid: mysvid\n",
		"wrong bool type": "sds:\n  disable_spiffe_cert_validation: sometimes\n",
		"wrong block":     "sds: nope\n",
	} {
		if _, err := loadBrokerConfig(writeConfig(t, yaml)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSDSRegister(t *testing.T) {
	bs := &brokerServer{}

	s := grpc.NewServer()
	registerSDS(s, bs, nil)
	if _, ok := s.GetServiceInfo()["envoy.service.secret.v3.SecretDiscoveryService"]; ok {
		t.Error("SDS registered although disabled")
	}

	s = grpc.NewServer()
	conf := defaultSDSConfig()
	registerSDS(s, bs, &conf)
	if _, ok := s.GetServiceInfo()["envoy.service.secret.v3.SecretDiscoveryService"]; !ok {
		t.Error("SDS not registered although enabled")
	}
}

// ---- snapshot from an upstream broker response ----

func TestSDSSnapshot(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	caA, caB, haCA := newTestCA(t, "A-CA"), newTestCA(t, "B-CA"), newTestCA(t, "HA-CA")
	otherCA := newTestCA(t, "OTHER-CA")
	merged := ConcatRawCertsFromCerts([]*x509.Certificate{caA.cert, caB.cert, haCA.cert})
	leaf := caA.issue(t, spiffeid.RequireFromPath(td, "/myworkload"))
	second := caA.issue(t, spiffeid.RequireFromPath(td, "/second"))

	bs := &brokerServer{
		localTD:    td,
		rawBundles: map[string][]byte{"example.org": merged},
	}
	resp := &broker.SubscribeToX509SVIDResponse{
		Svids: []*broker.X509SVID{
			{SpiffeId: "spiffe://example.org/myworkload", X509Svid: leaf.cert.Raw, X509SvidKey: pkcs8(t, leaf.key), Bundle: caA.cert.Raw},
			{SpiffeId: "spiffe://example.org/second", X509Svid: second.cert.Raw, X509SvidKey: pkcs8(t, second.key), Bundle: caA.cert.Raw},
		},
		FederatedBundles: map[string][]byte{
			"spiffe://other.org":   otherCA.cert.Raw,
			"spiffe://spire-ha":    haCA.cert.Raw,
			"spiffe://example.org": caA.cert.Raw,
			"not a trust domain":   otherCA.cert.Raw,
		},
	}

	upd := bs.sdsSnapshot(resp)
	if upd.localTD != td {
		t.Errorf("localTD: got %s", upd.localTD)
	}
	// the merged A+B+spire-ha view, not the single side's bundle
	if !bytes.Equal(upd.bundle, merged) {
		t.Errorf("bundle: got CNs %v, want the merged bundle", certCNs(t, upd.bundle))
	}
	// upstream order is kept: the first identity backs the default name
	if len(upd.identities) != 2 ||
		upd.identities[0].spiffeID != "spiffe://example.org/myworkload" ||
		upd.identities[1].spiffeID != "spiffe://example.org/second" {
		t.Fatalf("identities: got %+v", upd.identities)
	}
	if !bytes.Equal(upd.identities[0].chain, leaf.cert.Raw) || !bytes.Equal(upd.identities[0].key, pkcs8(t, leaf.key)) {
		t.Error("identity material was not carried over")
	}
	// spire-ha, the local trust domain and garbage are not federated domains
	other := spiffeid.RequireTrustDomainFromString("other.org")
	if len(upd.federated) != 1 || !bytes.Equal(upd.federated[other], otherCA.cert.Raw) {
		var tds []string
		for td := range upd.federated {
			tds = append(tds, td.Name())
		}
		sort.Strings(tds)
		t.Errorf("federated: got %v, want only other.org passed through", tds)
	}

	// a merged view that has not settled yet leaves the local bundle out
	bs.rawBundles = map[string][]byte{}
	if upd := bs.sdsSnapshot(resp); upd.bundle != nil {
		t.Errorf("bundle: got %d bytes, want none", len(upd.bundle))
	}

	// the snapshot feeds the handler: one consistent view end to end
	bs.rawBundles = map[string][]byte{"example.org": merged}
	h := newSDSHandler(defaultSDSConfig(), nil)
	out, err := h.buildResponse("7", &discovery_v3.DiscoveryRequest{ResourceNames: []string{"default", "ALL"}}, bs.sdsSnapshot(resp))
	if err != nil {
		t.Fatalf("buildResponse: %v", err)
	}
	requireSDSSecrets(t, out,
		wantSPIFFE(t, "ALL",
			wantTD{"example.org", []*x509.Certificate{caA.cert, caB.cert, haCA.cert}},
			wantTD{"other.org", []*x509.Certificate{otherCA.cert}},
		),
		wantTLS(t, "default", leaf),
	)
}

func TestSDSBrokerSourceNeedsCallerPID(t *testing.T) {
	src := &brokerSDSSource{bs: &brokerServer{}}
	_, err := src.subscribe(context.Background())
	requireStatus(t, err, codes.Internal, "peer tracker")
	_, err = src.fetch(context.Background())
	requireStatus(t, err, codes.Internal, "peer tracker")
}

// ---- end to end through brokerMain ----

func dialSDS(t *testing.T, haSock string) secret_v3.SecretDiscoveryServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+haSock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial sds: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return secret_v3.NewSecretDiscoveryServiceClient(conn)
}

func sdsByName(t *testing.T, resp *discovery_v3.DiscoveryResponse) map[string]*tls_v3.Secret {
	t.Helper()
	out := make(map[string]*tls_v3.Secret)
	for _, s := range sdsSecrets(t, resp) {
		out[s.Name] = s
	}
	return out
}

func pemCNs(t *testing.T, pemBytes []byte) []string {
	t.Helper()
	var cns []string
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse PEM cert: %v", err)
		}
		cns = append(cns, cert.Subject.CommonName)
	}
	sort.Strings(cns)
	return cns
}

// Trust domain name -> CA CNs of a SPIFFE validator validation context.
func spiffeValidatorCNs(t *testing.T, s *tls_v3.Secret) map[string][]string {
	t.Helper()
	custom := s.GetValidationContext().GetCustomValidatorConfig()
	if custom.GetName() != "envoy.tls.cert_validator.spiffe" {
		t.Fatalf("secret %q: not a SPIFFE validator context: %v", s.GetName(), s)
	}
	conf := new(tls_v3.SPIFFECertValidatorConfig)
	if err := custom.GetTypedConfig().UnmarshalTo(conf); err != nil {
		t.Fatalf("unmarshal validator config: %v", err)
	}
	out := make(map[string][]string)
	for _, td := range conf.GetTrustDomains() {
		out[td.GetName()] = pemCNs(t, td.GetTrustBundle().GetInlineBytes())
	}
	return out
}

func leafPEMIssuer(t *testing.T, s *tls_v3.Secret) string {
	t.Helper()
	block, _ := pem.Decode(s.GetTlsCertificate().GetCertificateChain().GetInlineBytes())
	if block == nil {
		t.Fatalf("secret %q has no certificate chain", s.GetName())
	}
	return leafIssuer(t, block.Bytes)
}

func TestBrokerSDS(t *testing.T) {
	dir := failoverDir(t)
	sideA, sideB := failoverSides(t, dir)
	startFakeSide(t, sideA)
	startFakeSide(t, sideB)
	haSock := dir + "/main/api.sock"
	bootBroker(t, writeFailoverConfig(t, dir, sideA, sideB, ""), haSock)

	client := dialSDS(t, haSock)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	localCAs := []string{"A-CA", "B-CA", "HA-CA-A", "HA-CA-B"}

	// What an Envoy sidecar asks for: its certificate and the trust bundle.
	stream, err := client.StreamSecrets(ctx)
	if err != nil {
		t.Fatalf("StreamSecrets: %v", err)
	}
	if err := stream.Send(&discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"default", "ROOTCA"},
		Node:          sdsNode(1, 30, nil),
		TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.VersionInfo == "" || resp.Nonce == "" {
		t.Errorf("stream response without version/nonce: %q / %q", resp.VersionInfo, resp.Nonce)
	}
	secrets := sdsByName(t, resp)
	if len(secrets) != 2 {
		t.Fatalf("got %d secrets, want default and ROOTCA", len(secrets))
	}
	if issuer := leafPEMIssuer(t, secrets["default"]); issuer != "A-CA" && issuer != "B-CA" {
		t.Errorf("default certificate issued by %q", issuer)
	}
	if block, _ := pem.Decode(secrets["default"].GetTlsCertificate().GetPrivateKey().GetInlineBytes()); block == nil || block.Type != "PRIVATE KEY" {
		t.Error("default certificate has no PKCS#8 PEM key")
	} else if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("default certificate key: %v", err)
	}
	// The local trust domain is the HA union of both sides.
	root := spiffeValidatorCNs(t, secrets["ROOTCA"])
	if len(root) != 1 {
		t.Errorf("ROOTCA trust domains: got %v", root)
	}
	checkEqual(t, "ROOTCA example.org", root["example.org"], localCAs)

	// Rotation on both sides reaches the open stream.
	td := spiffeid.RequireTrustDomainFromString("example.org")
	id := spiffeid.RequireFromPath(td, "/myworkload")
	var rotated [][]byte
	for _, side := range []*fakeSide{sideA, sideB} {
		leaf := side.ca.issue(t, id)
		rotated = append(rotated, leaf.cert.Raw)
		side.fb.setSVIDResp(&broker.SubscribeToX509SVIDResponse{
			Svids: []*broker.X509SVID{{
				SpiffeId: id.String(), X509Svid: leaf.cert.Raw, X509SvidKey: pkcs8(t, leaf.key), Bundle: side.ca.cert.Raw,
			}},
			FederatedBundles: map[string][]byte{
				"spiffe://other.org": side.otherSVIDCA.cert.Raw,
				"spiffe://spire-ha":  side.haCA.cert.Raw,
			},
		})
	}
	firstVersion := resp.VersionInfo
	resp = recvUntil(t, "rotated certificate", stream.Recv, func(r *discovery_v3.DiscoveryResponse) bool {
		block, _ := pem.Decode(sdsByName(t, r)["default"].GetTlsCertificate().GetCertificateChain().GetInlineBytes())
		return block != nil && slices.ContainsFunc(rotated, func(der []byte) bool { return bytes.Equal(der, block.Bytes) })
	})
	if resp.VersionInfo == firstVersion {
		t.Errorf("version_info did not change across a rotation: %q", resp.VersionInfo)
	}
	checkEqual(t, "ROOTCA after rotation", spiffeValidatorCNs(t, sdsByName(t, resp)["ROOTCA"])["example.org"], localCAs)

	// Everything the workload may have, by canonical name.
	resp, err = client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
	if err != nil {
		t.Fatalf("FetchSecrets all: %v", err)
	}
	if resp.VersionInfo != "" || resp.Nonce != "" {
		t.Errorf("fetch response with version/nonce: %q / %q", resp.VersionInfo, resp.Nonce)
	}
	var names []string
	for _, s := range sdsSecrets(t, resp) {
		names = append(names, s.Name)
	}
	checkEqual(t, "all secrets", names, []string{"spiffe://example.org", "spiffe://other.org", "spiffe://example.org/myworkload"})

	// All bundles: local union plus the federated domain passed through from
	// the answering side; spire-ha is never exposed.
	resp, err = client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{ResourceNames: []string{"ALL"}})
	if err != nil {
		t.Fatalf("FetchSecrets ALL: %v", err)
	}
	all := spiffeValidatorCNs(t, sdsByName(t, resp)["ALL"])
	if len(all) != 2 {
		t.Errorf("ALL trust domains: got %v", all)
	}
	checkEqual(t, "ALL example.org", all["example.org"], localCAs)
	if got := all["other.org"]; len(got) != 1 || (got[0] != "OTHER-SVID-CA-A" && got[0] != "OTHER-SVID-CA-B") {
		t.Errorf("ALL other.org: got %v, want one side's federated authority", got)
	}

	// An Envoy without the SPIFFE validator gets plain trusted CAs.
	resp, err = client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://example.org"}, Node: sdsNode(1, 17, nil),
	})
	if err != nil {
		t.Fatalf("FetchSecrets root CA: %v", err)
	}
	vc := sdsByName(t, resp)["spiffe://example.org"].GetValidationContext()
	if vc.GetCustomValidatorConfig() != nil {
		t.Error("envoy 1.17 was handed the SPIFFE validator")
	}
	checkEqual(t, "trusted_ca", pemCNs(t, vc.GetTrustedCa().GetInlineBytes()), localCAs)

	// Identities the workload does not have are refused.
	_, err = client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{ResourceNames: []string{"spiffe://example.org/admin"}})
	requireStatus(t, err, codes.InvalidArgument, "not authorized")
}

func TestBrokerSDSDisabled(t *testing.T) {
	dir := failoverDir(t)
	sideA, sideB := failoverSides(t, dir)
	startFakeSide(t, sideA)
	startFakeSide(t, sideB)
	haSock := dir + "/main/api.sock"
	cfgPath := writeFailoverConfig(t, dir, sideA, sideB, "")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := f.WriteString("disable_sds_api: true\n"); err != nil {
		t.Fatalf("append config: %v", err)
	}
	f.Close()
	bootBroker(t, cfgPath, haSock)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = dialSDS(t, haSock).FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{})
	requireStatus(t, err, codes.Unimplemented, "")

	// the workload API is unaffected
	stream, err := dialWorkload(t, haSock).FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("FetchX509SVID recv: %v", err)
	}
}
