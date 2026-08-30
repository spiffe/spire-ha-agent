package main

// End-to-end test for the downstream Broker API endpoint in -mode=broker.
// Reuses the fake upstream sides from broker_test.go and drives the real
// brokerMain with a config file that enables broker_endpoint on both a unix
// socket and a TCP listener.

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func dialEndpoint(t *testing.T, target string, id spiffeid.ID, ca *testCA, serverCAs []*x509.Certificate) broker.APIClient {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString("example.org")
	leaf := ca.issue(t, id)
	svidSrc := &staticSVID{svid: &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{leaf.cert}, PrivateKey: leaf.key}}
	bundleSrc := x509bundle.FromX509Authorities(td, serverCAs)
	creds := grpccredentials.MTLSClientCredentials(svidSrc, bundleSrc, tlsconfig.AuthorizeAny())
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	t.Cleanup(func() { conn.Close() })
	return broker.NewAPIClient(conn)
}

func recvX509SVID(ctx context.Context, client broker.APIClient, ref *broker.WorkloadReference) (*broker.SubscribeToX509SVIDResponse, error) {
	stream, err := client.SubscribeToX509SVID(ctx, &broker.SubscribeToX509SVIDRequest{Reference: ref})
	if err != nil {
		return nil, err
	}
	return stream.Recv()
}

func TestBrokerEndpoint(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sha")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// socket_path must not share a directory with the workload API socket
	for _, sub := range []string{"main", "ep"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	sideA := &fakeSide{
		name: "brokerA", ca: newTestCA(t, "A-CA"), haCA: newTestCA(t, "HA-CA-A"), otherCA: newTestCA(t, "OTHER-CA-A"),
		wlSock: dir + "/wla.sock", brokerSock: dir + "/bra.sock",
		jwtToken: "canned.jwt.a", localKid: "a1", haKid: "ha-a", otherKid: "o-a",
	}
	sideB := &fakeSide{
		name: "brokerB", ca: newTestCA(t, "B-CA"), haCA: newTestCA(t, "HA-CA-B"), otherCA: newTestCA(t, "OTHER-CA-B"),
		wlSock: dir + "/wlb.sock", brokerSock: dir + "/brb.sock",
		jwtToken: "canned.jwt.b", localKid: "b1", haKid: "ha-b", otherKid: "o-b",
	}
	startFakeSide(t, sideA)
	startFakeSide(t, sideB)

	// pre-pick a free TCP port for the endpoint's bind_address
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	tcpAddr := probe.Addr().String()
	probe.Close()

	epSock := dir + "/ep/broker.sock"
	cfg := fmt.Sprintf(`
socket: %s/main/api.sock
upstream_a:
  broker_address: unix://%s
  workload_socket: unix://%s
upstream_b:
  broker_address: unix://%s
  workload_socket: unix://%s
broker_endpoint:
  socket_path: %s
  bind_address: %s
  brokers:
    - id: spiffe://example.org/downstream
      allowed_reference_types:
        - type_url: type.googleapis.com/spiffe.broker.WorkloadPIDReference
    - id: spiffe://example.org/tcp-client
      allowed_reference_types:
        - type_url: "*"
          allow_over_tcp: true
    - id: spiffe://example.org/k8s-only
      allowed_reference_types:
        - type_url: type.googleapis.com/spiffe.broker.KubernetesObjectReference
`, dir, sideA.brokerSock, sideA.wlSock, sideB.brokerSock, sideB.wlSock, epSock, tcpAddr)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// brokerMain never returns; its goroutines die with the test process.
	go brokerMain(cfgPath)

	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.Dial("unix", epSock)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker endpoint never came up: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// the endpoint's server cert may chain to either side's CA
	serverCAs := []*x509.Certificate{sideA.ca.cert, sideB.ca.cert}
	td := spiffeid.RequireTrustDomainFromString("example.org")
	pidRef := pidWorkloadReference(os.Getpid())

	downstream := dialEndpoint(t, "unix://"+epSock, spiffeid.RequireFromPath(td, "/downstream"), sideA.ca, serverCAs)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	mdCtx := brokerMD(ctx)

	// --- positive: SubscribeToX509SVID over UDS ---
	svidResp, err := recvX509SVID(mdCtx, downstream, pidRef)
	if err != nil {
		t.Fatalf("SubscribeToX509SVID: %v", err)
	}
	if len(svidResp.Svids) != 1 {
		t.Fatalf("expected 1 svid, got %d", len(svidResp.Svids))
	}
	checkEqual(t, "ep.x509svid.id", []string{svidResp.Svids[0].SpiffeId}, []string{"spiffe://example.org/myworkload"})
	checkEqual(t, "ep.x509svid.hint", []string{svidResp.Svids[0].Hint}, []string{"internal"})
	checkEqual(t, "ep.x509svid.bundle", certCNs(t, svidResp.Svids[0].Bundle), []string{"A-CA", "B-CA", "HA-CA-A", "HA-CA-B"})
	checkEqual(t, "ep.x509svid.federated-tds", sortedKeys(svidResp.FederatedBundles), []string{"spiffe://other.org"})
	checkFederatedPassthrough(t, "ep.x509svid.federated.other.org", svidResp.FederatedBundles["spiffe://other.org"], sideA, sideB)

	// --- positive: SubscribeToX509Bundles ---
	bundleStream, err := downstream.SubscribeToX509Bundles(mdCtx, &broker.SubscribeToX509BundlesRequest{Reference: pidRef})
	if err != nil {
		t.Fatalf("SubscribeToX509Bundles: %v", err)
	}
	// Converges to both sides' federated view; see TestBrokerMode.
	bundleResp := recvUntil(t, "ep x509bundles both sides", bundleStream.Recv, func(r *broker.SubscribeToX509BundlesResponse) bool {
		return len(certCNs(t, r.Bundles["spiffe://other.org"])) == 2
	})
	checkEqual(t, "ep.x509bundles.tds", sortedKeys(bundleResp.Bundles), []string{"spiffe://example.org", "spiffe://other.org"})
	checkEqual(t, "ep.x509bundles.example.org", certCNs(t, bundleResp.Bundles["spiffe://example.org"]), []string{"A-CA", "B-CA", "HA-CA-A", "HA-CA-B"})
	checkEqual(t, "ep.x509bundles.other.org", certCNs(t, bundleResp.Bundles["spiffe://other.org"]), []string{"OTHER-CA-A", "OTHER-CA-B"})

	// --- positive: SubscribeToJWTBundles ---
	jwtStream, err := downstream.SubscribeToJWTBundles(mdCtx, &broker.SubscribeToJWTBundlesRequest{Reference: pidRef})
	if err != nil {
		t.Fatalf("SubscribeToJWTBundles: %v", err)
	}
	jwtBundleResp := recvUntil(t, "ep jwtbundles both sides", jwtStream.Recv, func(r *broker.SubscribeToJWTBundlesResponse) bool {
		return len(kidsOf(t, r.Bundles["spiffe://other.org"])) == 2
	})
	checkEqual(t, "ep.jwtbundles.tds", sortedKeys(jwtBundleResp.Bundles), []string{"spiffe://example.org", "spiffe://other.org"})
	checkEqual(t, "ep.jwtbundles.example.org.kids", kidsOf(t, jwtBundleResp.Bundles["spiffe://example.org"]), []string{"a1", "b1", "ha-a", "ha-b"})
	checkEqual(t, "ep.jwtbundles.other.org.kids", kidsOf(t, jwtBundleResp.Bundles["spiffe://other.org"]), []string{"o-a", "o-b"})

	// --- positive: FetchJWTSVID passthrough ---
	jwtResp, err := downstream.FetchJWTSVID(mdCtx, &broker.FetchJWTSVIDRequest{Reference: pidRef, Audience: []string{"aud1"}})
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if len(jwtResp.Svids) != 1 {
		t.Fatalf("expected 1 jwt svid, got %d", len(jwtResp.Svids))
	}
	if tok := jwtResp.Svids[0].Svid; tok != "canned.jwt.a" && tok != "canned.jwt.b" {
		t.Errorf("ep.jwtsvid.token: got %q", tok)
	}
	checkEqual(t, "ep.jwtsvid.hint", []string{jwtResp.Svids[0].Hint}, []string{"internal"})

	// --- positive: wildcard reference type over TCP ---
	tcpClient := dialEndpoint(t, tcpAddr, spiffeid.RequireFromPath(td, "/tcp-client"), sideA.ca, serverCAs)
	tcpResp, err := recvX509SVID(brokerMD(ctx), tcpClient, pidRef)
	if err != nil {
		t.Fatalf("SubscribeToX509SVID over TCP: %v", err)
	}
	checkEqual(t, "ep.tcp.x509svid.bundle", certCNs(t, tcpResp.Svids[0].Bundle), []string{"A-CA", "B-CA", "HA-CA-A", "HA-CA-B"})

	// --- negative: non-allowlisted client is rejected at the handshake ---
	random := dialEndpoint(t, "unix://"+epSock, spiffeid.RequireFromPath(td, "/random"), sideA.ca, serverCAs)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shortCancel()
	if _, err := recvX509SVID(brokerMD(shortCtx), random, pidRef); err == nil {
		t.Errorf("non-allowlisted client: expected error, got nil")
	}

	// --- negative: missing security header ---
	if _, err := recvX509SVID(ctx, downstream, pidRef); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing header: got %v, want InvalidArgument", err)
	}

	// --- negative: missing reference ---
	if _, err := recvX509SVID(mdCtx, downstream, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing reference: got %v, want InvalidArgument", err)
	}

	// --- negative: reference type not in the caller's allowlist ---
	k8sOnly := dialEndpoint(t, "unix://"+epSock, spiffeid.RequireFromPath(td, "/k8s-only"), sideA.ca, serverCAs)
	if _, err := recvX509SVID(brokerMD(ctx), k8sOnly, pidRef); status.Code(err) != codes.PermissionDenied {
		t.Errorf("disallowed type_url: got %v, want PermissionDenied", err)
	}

	// --- negative: PID reference over TCP without allow_over_tcp ---
	downstreamTCP := dialEndpoint(t, tcpAddr, spiffeid.RequireFromPath(td, "/downstream"), sideA.ca, serverCAs)
	if _, err := recvX509SVID(brokerMD(ctx), downstreamTCP, pidRef); status.Code(err) != codes.PermissionDenied {
		t.Errorf("PID over TCP: got %v, want PermissionDenied", err)
	}
}
