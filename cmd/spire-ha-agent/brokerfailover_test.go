package main

// Failover tests for broker mode: every downstream method of both served
// APIs (Workload API and the downstream Broker API endpoint) must keep
// working when one upstream side is absent, unreachable, erroring, or dies
// mid-stream while the other side works.

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func failoverDir(t *testing.T) string {
	t.Helper()
	// unix socket paths are limited to ~104 bytes on darwin, so t.TempDir()
	// is not usable here.
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
	return dir
}

func failoverSides(t *testing.T, dir string) (*fakeSide, *fakeSide) {
	t.Helper()
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
	return sideA, sideB
}

// Every option is explicit so the resolution never falls back to
// SPIRE_HA_AGENT_* environment variables.
// metricsAddr enables the metrics endpoint when non-empty.
func writeFailoverConfig(t *testing.T, dir string, sideA, sideB *fakeSide, metricsAddr string) string {
	t.Helper()
	cfg := fmt.Sprintf(`
single: false
vsock:
  enabled: false
socket: %s/main/api.sock
upstream_a:
  broker_address: unix://%s
  workload_socket: unix://%s
upstream_b:
  broker_address: unix://%s
  workload_socket: unix://%s
broker_endpoint:
  socket_path: %s/ep/broker.sock
  brokers:
    - id: spiffe://example.org/downstream
      allowed_reference_types:
        - type_url: type.googleapis.com/spiffe.broker.WorkloadPIDReference
`, dir, sideA.brokerSock, sideA.wlSock, sideB.brokerSock, sideB.wlSock, dir)
	if metricsAddr != "" {
		cfg += fmt.Sprintf("metrics:\n  bind_address: %s\n", metricsAddr)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func bootBroker(t *testing.T, cfgPath string, socks ...string) {
	t.Helper()
	// brokerMain never returns; its goroutines die with the test process.
	go brokerMain(cfgPath)
	deadline := time.Now().Add(30 * time.Second)
	for _, sock := range socks {
		for {
			c, err := net.Dial("unix", sock)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("socket %s never came up: %v", sock, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func dialWorkload(t *testing.T, haSock string) workload.SpiffeWorkloadAPIClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+haSock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial workload api: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return workload.NewSpiffeWorkloadAPIClient(conn)
}

func cnsContain(t *testing.T, der []byte, want string) bool {
	t.Helper()
	return slices.Contains(certCNs(t, der), want)
}

func kidsContain(t *testing.T, jwks []byte, want string) bool {
	t.Helper()
	return slices.Contains(kidsOf(t, jwks), want)
}

// Asserts all 8 downstream methods (4 workload API + 4 broker endpoint)
// serve exactly the healthy side's data. serverCAs must contain both sides'
// CAs: the endpoint's server SVID comes from whichever upstream source is
// ready/freshest, which can be the degraded side's when only its broker
// (not its workload API) is down.
func checkDegradedServing(t *testing.T, dir string, healthy *fakeSide, serverCAs []*x509.Certificate) {
	t.Helper()
	haSock := dir + "/main/api.sock"
	epSock := dir + "/ep/broker.sock"
	td := spiffeid.RequireTrustDomainFromString("example.org")
	pidRef := pidWorkloadReference(os.Getpid())

	caCN := healthy.ca.cert.Subject.CommonName
	haCN := healthy.haCA.cert.Subject.CommonName
	otherCN := healthy.otherCA.cert.Subject.CommonName
	localCNs := []string{caCN, haCN}
	slices.Sort(localCNs)
	otherCNs := []string{otherCN}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	// --- workload API ---
	wc := dialWorkload(t, haSock)

	svidStream, err := wc.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	svidResp, err := svidStream.Recv()
	if err != nil {
		t.Fatalf("FetchX509SVID recv: %v", err)
	}
	if len(svidResp.Svids) != 1 {
		t.Fatalf("expected 1 svid, got %d", len(svidResp.Svids))
	}
	checkEqual(t, "wl.x509svid.id", []string{svidResp.Svids[0].SpiffeId}, []string{"spiffe://example.org/myworkload"})
	checkEqual(t, "wl.x509svid.hint", []string{svidResp.Svids[0].Hint}, []string{"internal"})
	checkEqual(t, "wl.x509svid.bundle", certCNs(t, svidResp.Svids[0].Bundle), localCNs)
	checkEqual(t, "wl.x509svid.federated-tds", sortedKeys(svidResp.FederatedBundles), []string{"other.org"})
	checkFederatedPassthrough(t, "wl.x509svid.federated", svidResp.FederatedBundles["other.org"], healthy)

	bundleStream, err := wc.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatalf("FetchX509Bundles: %v", err)
	}
	bundleResp, err := bundleStream.Recv()
	if err != nil {
		t.Fatalf("FetchX509Bundles recv: %v", err)
	}
	checkEqual(t, "wl.x509bundles.tds", sortedKeys(bundleResp.Bundles), []string{"example.org", "other.org"})
	checkEqual(t, "wl.x509bundles.example.org", certCNs(t, bundleResp.Bundles["example.org"]), localCNs)
	checkEqual(t, "wl.x509bundles.other.org", certCNs(t, bundleResp.Bundles["other.org"]), otherCNs)

	jwtResp, err := wc.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}})
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if len(jwtResp.Svids) != 1 {
		t.Fatalf("expected 1 jwt svid, got %d", len(jwtResp.Svids))
	}
	checkEqual(t, "wl.jwtsvid.token", []string{jwtResp.Svids[0].Svid}, []string{healthy.jwtToken})
	checkEqual(t, "wl.jwtsvid.hint", []string{jwtResp.Svids[0].Hint}, []string{"internal"})

	jwtBundleStream, err := wc.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		t.Fatalf("FetchJWTBundles: %v", err)
	}
	jwtBundleResp, err := jwtBundleStream.Recv()
	if err != nil {
		t.Fatalf("FetchJWTBundles recv: %v", err)
	}
	localKids := []string{healthy.localKid, healthy.haKid}
	slices.Sort(localKids)
	checkEqual(t, "wl.jwtbundles.tds", sortedKeys(jwtBundleResp.Bundles), []string{"example.org", "other.org"})
	checkEqual(t, "wl.jwtbundles.example.org", kidsOf(t, jwtBundleResp.Bundles["example.org"]), localKids)
	checkEqual(t, "wl.jwtbundles.other.org", kidsOf(t, jwtBundleResp.Bundles["other.org"]), []string{healthy.otherKid})

	// --- broker endpoint ---
	// The client SVID must be minted by the healthy side's CA: the endpoint
	// verifies clients against the merged bundle state, which only contains
	// bundles a side actually pushed.
	ec := dialEndpoint(t, "unix://"+epSock, spiffeid.RequireFromPath(td, "/downstream"), healthy.ca, serverCAs)
	mdCtx := brokerMD(ctx)

	epSVID, err := recvX509SVID(mdCtx, ec, pidRef)
	if err != nil {
		t.Fatalf("ep SubscribeToX509SVID: %v", err)
	}
	checkEqual(t, "ep.x509svid.hint", []string{epSVID.Svids[0].Hint}, []string{"internal"})
	checkEqual(t, "ep.x509svid.bundle", certCNs(t, epSVID.Svids[0].Bundle), localCNs)
	checkEqual(t, "ep.x509svid.federated-tds", sortedKeys(epSVID.FederatedBundles), []string{"spiffe://other.org"})
	checkFederatedPassthrough(t, "ep.x509svid.federated", epSVID.FederatedBundles["spiffe://other.org"], healthy)

	epBundleStream, err := ec.SubscribeToX509Bundles(mdCtx, &broker.SubscribeToX509BundlesRequest{Reference: pidRef})
	if err != nil {
		t.Fatalf("ep SubscribeToX509Bundles: %v", err)
	}
	epBundleResp, err := epBundleStream.Recv()
	if err != nil {
		t.Fatalf("ep SubscribeToX509Bundles recv: %v", err)
	}
	checkEqual(t, "ep.x509bundles.tds", sortedKeys(epBundleResp.Bundles), []string{"spiffe://example.org", "spiffe://other.org"})
	checkEqual(t, "ep.x509bundles.example.org", certCNs(t, epBundleResp.Bundles["spiffe://example.org"]), localCNs)

	epJWT, err := ec.FetchJWTSVID(mdCtx, &broker.FetchJWTSVIDRequest{Reference: pidRef, Audience: []string{"aud1"}})
	if err != nil {
		t.Fatalf("ep FetchJWTSVID: %v", err)
	}
	checkEqual(t, "ep.jwtsvid.token", []string{epJWT.Svids[0].Svid}, []string{healthy.jwtToken})

	epJWTBundleStream, err := ec.SubscribeToJWTBundles(mdCtx, &broker.SubscribeToJWTBundlesRequest{Reference: pidRef})
	if err != nil {
		t.Fatalf("ep SubscribeToJWTBundles: %v", err)
	}
	epJWTBundleResp, err := epJWTBundleStream.Recv()
	if err != nil {
		t.Fatalf("ep SubscribeToJWTBundles recv: %v", err)
	}
	checkEqual(t, "ep.jwtbundles.tds", sortedKeys(epJWTBundleResp.Bundles), []string{"spiffe://example.org", "spiffe://other.org"})
	checkEqual(t, "ep.jwtbundles.example.org", kidsOf(t, epJWTBundleResp.Bundles["spiffe://example.org"]), localKids)
}

// One upstream side is degraded from the start; every downstream method of
// both APIs must serve the healthy side's data.
func TestBrokerFailoverStartupDegraded(t *testing.T) {
	cases := []struct {
		name   string
		victim rune // 'a' or 'b'
		mode   string
	}{
		// absent: neither the victim's workload API nor its broker listens;
		// the ha-agent's client for that side is never created (nil-client
		// guards in the pumps).
		{"side-a-absent", 'a', "absent"},
		{"side-b-absent", 'b', "absent"},
		// brokerDead: the victim's workload API is up (client SVID obtained,
		// broker client created) but its broker socket refuses connections
		// (pump connect-error/retry path).
		{"side-a-broker-dead", 'a', "brokerDead"},
		{"side-b-broker-dead", 'b', "brokerDead"},
		// rpcError: the victim's broker accepts mTLS connections but every
		// RPC returns Unavailable (pump Recv-error/retry path).
		{"side-a-rpc-error", 'a', "rpcError"},
		{"side-b-rpc-error", 'b', "rpcError"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := failoverDir(t)
			sideA, sideB := failoverSides(t, dir)
			victim, healthy := sideA, sideB
			if tc.victim == 'b' {
				victim, healthy = sideB, sideA
			}
			switch tc.mode {
			case "absent":
				victim.skipBroker = true
				victim.skipWorkloadAPI = true
			case "brokerDead":
				victim.skipBroker = true
			}
			startFakeSide(t, sideA)
			startFakeSide(t, sideB)
			if tc.mode == "rpcError" {
				victim.fb.setFail(true)
			}

			cfgPath := writeFailoverConfig(t, dir, sideA, sideB, "")
			bootBroker(t, cfgPath, dir+"/main/api.sock", dir+"/ep/broker.sock")
			checkDegradedServing(t, dir, healthy, []*x509.Certificate{sideA.ca.cert, sideB.ca.cert})
		})
	}
}

// Startup must settle only on a bundle state that covers both sides'
// authorities: a lone side delivering its local bundle plus its spire-ha
// bundle (each side's spire-ha bundle carries the other side's trust
// material), or both sides delivering their local bundles (no spire-ha
// needed). Anything less is split brain and must NOT settle. The workload
// socket is only created once startup settles, so a blocked gate means no
// socket.
func TestBrokerFailoverSettleGate(t *testing.T) {
	local := "spiffe://example.org"
	ha := "spiffe://spire-ha"
	cases := []struct {
		name     string
		bothUp   bool // side A serving too (same bundle TDs as side B)
		x509TDs  []string
		jwtTDs   []string
		expectUp bool
	}{
		{"lone-side-with-spire-ha-serves", false, []string{local, ha}, []string{local, ha}, true},
		{"both-sides-main-only-serves", true, []string{local}, []string{local}, true},
		{"lone-side-x509-missing-spire-ha-blocks", false, []string{local}, []string{local, ha}, false},
		{"lone-side-jwt-missing-spire-ha-blocks", false, []string{local, ha}, []string{local}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := failoverDir(t)
			sideA, sideB := failoverSides(t, dir)
			if !tc.bothUp {
				sideA.skipBroker = true
				sideA.skipWorkloadAPI = true
			}
			startFakeSide(t, sideA)
			startFakeSide(t, sideB)

			for _, side := range []*fakeSide{sideA, sideB} {
				if side.fb == nil {
					continue
				}
				x509Bundles := make(map[string][]byte)
				for _, td := range tc.x509TDs {
					x509Bundles[td] = side.ca.cert.Raw
				}
				jwtBundles := make(map[string][]byte)
				for _, td := range tc.jwtTDs {
					jwtBundles[td] = testJWKS(t, side.localKid)
				}
				side.fb.setBundleResp(&broker.SubscribeToX509BundlesResponse{Bundles: x509Bundles})
				side.fb.setJWTBundles(&broker.SubscribeToJWTBundlesResponse{Bundles: jwtBundles})
			}

			cfgPath := writeFailoverConfig(t, dir, sideA, sideB, "")
			haSock := dir + "/main/api.sock"

			if tc.expectUp {
				// only wait on the workload socket: the endpoint socket
				// comes up moments later, after the settle gate
				bootBroker(t, cfgPath, haSock)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				t.Cleanup(cancel)
				wc := dialWorkload(t, haSock)
				if _, err := wc.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}}); err != nil {
					t.Fatalf("FetchJWTSVID against sole survivor: %v", err)
				}
				return
			}

			go brokerMain(cfgPath)
			// the fakes deliver instantly, so a broken gate settles well
			// within this window
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if c, err := net.Dial("unix", haSock); err == nil {
					c.Close()
					t.Fatalf("workload socket came up despite incomplete survivor bundles")
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
}

// Both upstream brokers erroring: the unary JWT fetch must fail promptly
// with Unavailable on both APIs, not hang until the request deadline.
func TestBrokerFailoverBothSidesError(t *testing.T) {
	dir := failoverDir(t)
	sideA, sideB := failoverSides(t, dir)
	startFakeSide(t, sideA)
	startFakeSide(t, sideB)
	cfgPath := writeFailoverConfig(t, dir, sideA, sideB, "")
	bootBroker(t, cfgPath, dir+"/main/api.sock", dir+"/ep/broker.sock")

	td := spiffeid.RequireTrustDomainFromString("example.org")
	pidRef := pidWorkloadReference(os.Getpid())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	wc := dialWorkload(t, dir+"/main/api.sock")
	ec := dialEndpoint(t, "unix://"+dir+"/ep/broker.sock", spiffeid.RequireFromPath(td, "/downstream"), sideA.ca, []*x509.Certificate{sideA.ca.cert, sideB.ca.cert})

	// sanity: healthy first
	if _, err := wc.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}}); err != nil {
		t.Fatalf("healthy FetchJWTSVID: %v", err)
	}

	sideA.fb.setFail(true)
	sideB.fb.setFail(true)

	shortCtx, shortCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shortCancel()
	if _, err := wc.FetchJWTSVID(shortCtx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}}); status.Code(err) != codes.Unavailable {
		t.Errorf("wl FetchJWTSVID with both sides failing: got %v, want Unavailable", err)
	}
	if _, err := ec.FetchJWTSVID(brokerMD(shortCtx), &broker.FetchJWTSVIDRequest{Reference: pidRef, Audience: []string{"aud1"}}); status.Code(err) != codes.Unavailable {
		t.Errorf("ep FetchJWTSVID with both sides failing: got %v, want Unavailable", err)
	}
}

// One side dies while clients hold open streams on both APIs: the streams
// must keep delivering updates sourced from the survivor, and fresh requests
// must succeed.
func TestBrokerFailoverMidStreamDisconnect(t *testing.T) {
	cases := []struct {
		name   string
		victim rune
	}{
		{"victim-a", 'a'},
		{"victim-b", 'b'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := failoverDir(t)
			sideA, sideB := failoverSides(t, dir)
			victim, survivor := sideA, sideB
			if tc.victim == 'b' {
				victim, survivor = sideB, sideA
			}
			startFakeSide(t, sideA)
			startFakeSide(t, sideB)
			cfgPath := writeFailoverConfig(t, dir, sideA, sideB, "")
			bootBroker(t, cfgPath, dir+"/main/api.sock", dir+"/ep/broker.sock")

			td := spiffeid.RequireTrustDomainFromString("example.org")
			pidRef := pidWorkloadReference(os.Getpid())
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			t.Cleanup(cancel)
			mdCtx := brokerMD(ctx)

			wc := dialWorkload(t, dir+"/main/api.sock")
			// client SVID from the survivor's CA so mTLS keeps validating
			// after the kill; the server cert may chain to either CA.
			ec := dialEndpoint(t, "unix://"+dir+"/ep/broker.sock", spiffeid.RequireFromPath(td, "/downstream"), survivor.ca, []*x509.Certificate{sideA.ca.cert, sideB.ca.cert})

			// open all six streams and take one baseline message each
			wlSVID, err := wc.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
			if err != nil {
				t.Fatalf("wl FetchX509SVID: %v", err)
			}
			if _, err := wlSVID.Recv(); err != nil {
				t.Fatalf("wl FetchX509SVID baseline: %v", err)
			}
			wlBundles, err := wc.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
			if err != nil {
				t.Fatalf("wl FetchX509Bundles: %v", err)
			}
			if _, err := wlBundles.Recv(); err != nil {
				t.Fatalf("wl FetchX509Bundles baseline: %v", err)
			}
			wlJWT, err := wc.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
			if err != nil {
				t.Fatalf("wl FetchJWTBundles: %v", err)
			}
			if _, err := wlJWT.Recv(); err != nil {
				t.Fatalf("wl FetchJWTBundles baseline: %v", err)
			}
			epSVID, err := ec.SubscribeToX509SVID(mdCtx, &broker.SubscribeToX509SVIDRequest{Reference: pidRef})
			if err != nil {
				t.Fatalf("ep SubscribeToX509SVID: %v", err)
			}
			if _, err := epSVID.Recv(); err != nil {
				t.Fatalf("ep SubscribeToX509SVID baseline: %v", err)
			}
			epBundles, err := ec.SubscribeToX509Bundles(mdCtx, &broker.SubscribeToX509BundlesRequest{Reference: pidRef})
			if err != nil {
				t.Fatalf("ep SubscribeToX509Bundles: %v", err)
			}
			if _, err := epBundles.Recv(); err != nil {
				t.Fatalf("ep SubscribeToX509Bundles baseline: %v", err)
			}
			epJWT, err := ec.SubscribeToJWTBundles(mdCtx, &broker.SubscribeToJWTBundlesRequest{Reference: pidRef})
			if err != nil {
				t.Fatalf("ep SubscribeToJWTBundles: %v", err)
			}
			if _, err := epJWT.Recv(); err != nil {
				t.Fatalf("ep SubscribeToJWTBundles baseline: %v", err)
			}

			// kill the victim entirely
			victim.brokerServer.Stop()
			victim.wlServer.Stop()

			// push rotated material on the survivor
			extraCA := newTestCA(t, "EXTRA-CA")
			newSVID := proto.Clone(survivor.fb.svidResp).(*broker.SubscribeToX509SVIDResponse)
			newSVID.Svids[0].Hint = "rotated"
			survivor.fb.setSVIDResp(newSVID)
			newBundles := proto.Clone(survivor.fb.bundleResp).(*broker.SubscribeToX509BundlesResponse)
			newBundles.Bundles["spiffe://example.org"] = append(append([]byte{}, survivor.ca.cert.Raw...), extraCA.cert.Raw...)
			survivor.fb.setBundleResp(newBundles)
			newJWT := proto.Clone(survivor.fb.jwtBundles).(*broker.SubscribeToJWTBundlesResponse)
			newJWT.Bundles["spiffe://example.org"] = testJWKS(t, survivor.localKid, "extra-kid")
			survivor.fb.setJWTBundles(newJWT)

			// every open stream must deliver the survivor's update; the dead
			// side's stale CAs/kids remain merged in by design
			recvUntil(t, "wl x509svid update", wlSVID.Recv, func(r *workload.X509SVIDResponse) bool {
				return r.Svids[0].Hint == "rotated" && cnsContain(t, r.Svids[0].Bundle, "EXTRA-CA")
			})
			recvUntil(t, "wl x509bundles update", wlBundles.Recv, func(r *workload.X509BundlesResponse) bool {
				return cnsContain(t, r.Bundles["example.org"], "EXTRA-CA")
			})
			recvUntil(t, "wl jwtbundles update", wlJWT.Recv, func(r *workload.JWTBundlesResponse) bool {
				return kidsContain(t, r.Bundles["example.org"], "extra-kid")
			})
			recvUntil(t, "ep x509svid update", epSVID.Recv, func(r *broker.SubscribeToX509SVIDResponse) bool {
				return r.Svids[0].Hint == "rotated" && cnsContain(t, r.Svids[0].Bundle, "EXTRA-CA")
			})
			recvUntil(t, "ep x509bundles update", epBundles.Recv, func(r *broker.SubscribeToX509BundlesResponse) bool {
				return cnsContain(t, r.Bundles["spiffe://example.org"], "EXTRA-CA")
			})
			recvUntil(t, "ep jwtbundles update", epJWT.Recv, func(r *broker.SubscribeToJWTBundlesResponse) bool {
				return kidsContain(t, r.Bundles["spiffe://example.org"], "extra-kid")
			})

			// fresh requests after the kill must succeed via the survivor
			freshSVID, err := wc.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
			if err != nil {
				t.Fatalf("fresh wl FetchX509SVID: %v", err)
			}
			recvUntil(t, "fresh wl x509svid", freshSVID.Recv, func(r *workload.X509SVIDResponse) bool {
				return r.Svids[0].Hint == "rotated"
			})
			jwtResp, err := wc.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}})
			if err != nil {
				t.Fatalf("fresh wl FetchJWTSVID: %v", err)
			}
			checkEqual(t, "fresh wl jwt token", []string{jwtResp.Svids[0].Svid}, []string{survivor.jwtToken})
			epJWTResp, err := ec.FetchJWTSVID(mdCtx, &broker.FetchJWTSVIDRequest{Reference: pidRef, Audience: []string{"aud1"}})
			if err != nil {
				t.Fatalf("fresh ep FetchJWTSVID: %v", err)
			}
			checkEqual(t, "fresh ep jwt token", []string{epJWTResp.Svids[0].Svid}, []string{survivor.jwtToken})
			freshEpSVID, err := ec.SubscribeToX509SVID(mdCtx, &broker.SubscribeToX509SVIDRequest{Reference: pidRef})
			if err != nil {
				t.Fatalf("fresh ep SubscribeToX509SVID: %v", err)
			}
			recvUntil(t, "fresh ep x509svid", freshEpSVID.Recv, func(r *broker.SubscribeToX509SVIDResponse) bool {
				return r.Svids[0].Hint == "rotated"
			})
		})
	}
}

// The downstream broker endpoint must pick up a side that finishes setup
// after a stream was opened, exactly as the workload API does
// (TestBrokerLateJoiningSide). Without the clientsChan re-arm in the
// endpoint handlers the stream stays pinned to whoever was up at open time,
// so a workload only the late side knows about never gets an answer.
func TestBrokerEndpointLateJoiningSide(t *testing.T) {
	dir := failoverDir(t)
	sideA, sideB := failoverSides(t, dir)
	// Side B is deliberately left down until the streams are open.
	startFakeSide(t, sideA)

	cfgPath := writeFailoverConfig(t, dir, sideA, sideB, "")
	bootBroker(t, cfgPath, dir+"/main/api.sock", dir+"/ep/broker.sock")

	td := spiffeid.RequireTrustDomainFromString("example.org")
	pidRef := pidWorkloadReference(os.Getpid())
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	// Client SVID from side A's CA: only A's bundles are merged so far, and
	// that is what the endpoint verifies clients against. The server cert
	// may chain to either side once B joins.
	ec := dialEndpoint(t, "unix://"+dir+"/ep/broker.sock", spiffeid.RequireFromPath(td, "/downstream"),
		sideA.ca, []*x509.Certificate{sideA.ca.cert, sideB.ca.cert})
	mdCtx := brokerMD(ctx)

	// Open every endpoint stream while side B is still down.
	svidStream, err := ec.SubscribeToX509SVID(mdCtx, &broker.SubscribeToX509SVIDRequest{Reference: pidRef})
	if err != nil {
		t.Fatalf("ep SubscribeToX509SVID: %v", err)
	}
	svidResp, err := svidStream.Recv()
	if err != nil {
		t.Fatalf("ep SubscribeToX509SVID recv: %v", err)
	}
	checkEqual(t, "ep.x509svid.issuer.before", []string{leafIssuer(t, svidResp.Svids[0].X509Svid)}, []string{"A-CA"})
	checkEqual(t, "ep.x509svid.bundle.before", certCNs(t, svidResp.Svids[0].Bundle), []string{"A-CA", "HA-CA-A"})

	bundleStream, err := ec.SubscribeToX509Bundles(mdCtx, &broker.SubscribeToX509BundlesRequest{Reference: pidRef})
	if err != nil {
		t.Fatalf("ep SubscribeToX509Bundles: %v", err)
	}
	bundleResp, err := bundleStream.Recv()
	if err != nil {
		t.Fatalf("ep SubscribeToX509Bundles recv: %v", err)
	}
	checkEqual(t, "ep.x509bundles.before", certCNs(t, bundleResp.Bundles["spiffe://example.org"]), []string{"A-CA", "HA-CA-A"})

	jwtBundleStream, err := ec.SubscribeToJWTBundles(mdCtx, &broker.SubscribeToJWTBundlesRequest{Reference: pidRef})
	if err != nil {
		t.Fatalf("ep SubscribeToJWTBundles: %v", err)
	}
	jwtBundleResp, err := jwtBundleStream.Recv()
	if err != nil {
		t.Fatalf("ep SubscribeToJWTBundles recv: %v", err)
	}
	checkEqual(t, "ep.jwtbundles.kids.before", kidsOf(t, jwtBundleResp.Bundles["spiffe://example.org"]), []string{"a1", "ha-a"})

	// Side B comes up with the streams already open.
	startFakeSide(t, sideB)

	// The discriminating assertion: the SVID leaf can only come from a
	// per-stream pump, so it changes hands only if side B's pump was started
	// on the already-open stream.
	recvUntil(t, "ep x509svid after late join", svidStream.Recv, func(r *broker.SubscribeToX509SVIDResponse) bool {
		return len(r.Svids) == 1 && leafIssuer(t, r.Svids[0].X509Svid) == "B-CA"
	})

	// Weaker evidence on their own (the merged global map is populated by
	// side B's own subscription), but they must converge too.
	recvUntil(t, "ep x509bundles after late join", bundleStream.Recv, func(r *broker.SubscribeToX509BundlesResponse) bool {
		return len(certCNs(t, r.Bundles["spiffe://example.org"])) == 4
	})
	recvUntil(t, "ep jwtbundles after late join", jwtBundleStream.Recv, func(r *broker.SubscribeToJWTBundlesResponse) bool {
		return len(kidsOf(t, r.Bundles["spiffe://example.org"])) == 4
	})

	// Unary calls were never pinned, but confirm both sides are reachable.
	if _, err := ec.FetchJWTSVID(mdCtx, &broker.FetchJWTSVIDRequest{Reference: pidRef, Audience: []string{"aud1"}}); err != nil {
		t.Fatalf("ep FetchJWTSVID after late join: %v", err)
	}
}

// A side that died comes back with new material: open streams must pick it
// up once the pumps reconnect (~5s retry cycles, hence the -short gate).
func TestBrokerFailoverRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping recovery test in -short mode (depends on 5s pump reconnect cycles)")
	}
	dir := failoverDir(t)
	sideA, sideB := failoverSides(t, dir)
	startFakeSide(t, sideA)
	startFakeSide(t, sideB)
	cfgPath := writeFailoverConfig(t, dir, sideA, sideB, "")
	bootBroker(t, cfgPath, dir+"/main/api.sock", dir+"/ep/broker.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	wc := dialWorkload(t, dir+"/main/api.sock")

	stream, err := wc.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatalf("FetchX509Bundles: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("baseline recv: %v", err)
	}

	sideA.brokerServer.Stop()
	recoveredCA := newTestCA(t, "A-CA-2")
	newBundles := proto.Clone(sideA.fb.bundleResp).(*broker.SubscribeToX509BundlesResponse)
	newBundles.Bundles["spiffe://example.org"] = append(append([]byte{}, sideA.ca.cert.Raw...), recoveredCA.cert.Raw...)
	sideA.fb.setBundleResp(newBundles)
	sideA.restartBroker(t)

	recvUntil(t, "post-recovery bundle update", stream.Recv, func(r *workload.X509BundlesResponse) bool {
		return cnsContain(t, r.Bundles["example.org"], "A-CA-2")
	})

	if _, err := wc.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}}); err != nil {
		t.Fatalf("post-recovery FetchJWTSVID: %v", err)
	}
}

// Scrapes the metrics endpoint until match passes.
func pollMetrics(t *testing.T, addr, what string, match func(string) bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last string
	for {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			body, rerr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if rerr == nil {
				last = string(body)
				if match(last) {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: never observed; last scrape:\n%s", what, last)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func sideUpLine(side string, up bool) string {
	v := "0"
	if up {
		v = "1"
	}
	return fmt.Sprintf("spire_ha_agent_upstream_side_up{side=\"%s\"} %s", side, v)
}

// An upstream side going offline must be visible per-side, and recover.
func TestBrokerUpstreamHealth(t *testing.T) {
	dir := failoverDir(t)
	sideA, sideB := failoverSides(t, dir)
	startFakeSide(t, sideA)
	startFakeSide(t, sideB)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	metricsAddr := probe.Addr().String()
	probe.Close()

	cfgPath := writeFailoverConfig(t, dir, sideA, sideB, metricsAddr)
	bootBroker(t, cfgPath, dir+"/main/api.sock", dir+"/ep/broker.sock")

	pollMetrics(t, metricsAddr, "both sides up", func(body string) bool {
		return strings.Contains(body, sideUpLine("a", true)) && strings.Contains(body, sideUpLine("b", true))
	})

	// Side b fails: it must read down while side a stays up. The pairing is
	// the discriminating part -- it proves per-side attribution rather than
	// just that something went down.
	sideB.fb.setFail(true)
	pollMetrics(t, metricsAddr, "side b down, side a still up", func(body string) bool {
		return strings.Contains(body, sideUpLine("b", false)) && strings.Contains(body, sideUpLine("a", true))
	})

	// And recovers once the side starts answering again.
	sideB.fb.setFail(false)
	pollMetrics(t, metricsAddr, "side b back up", func(body string) bool {
		return strings.Contains(body, sideUpLine("b", true)) && strings.Contains(body, sideUpLine("a", true))
	})
}
