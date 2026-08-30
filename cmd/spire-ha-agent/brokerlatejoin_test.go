package main

// A side that is absent when a workload opens its stream must still join
// that stream once it finishes setup. Without this the stream stays pinned
// to whoever was up at open time, which has two consequences: a workload
// only the late side knows about never gets an answer at all, and a stream
// opened during an outage never fails back to the side that recovers.

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// CN of the CA that signed the leaf, i.e. which side served this SVID.
func leafIssuer(t *testing.T, der []byte) string {
	t.Helper()
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		t.Fatalf("parse leaf DER: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("no certs in leaf DER")
	}
	return certs[0].Issuer.CommonName
}

// Recv until match passes. Streams legitimately deliver several messages
// while the two sides' responses race, so a non-matching message is not a
// failure; running out of time is.
func recvUntil[T any](t *testing.T, what string, recv func() (T, error), match func(T) bool) T {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		v, err := recv()
		if err != nil {
			t.Fatalf("%s: recv: %v", what, err)
		}
		if match(v) {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: never saw the expected update", what)
		}
	}
}

func TestBrokerLateJoiningSide(t *testing.T) {
	// unix socket paths are limited to ~104 bytes on darwin, so t.TempDir()
	// (under deep test temp paths) is not usable here.
	dir, err := os.MkdirTemp("/tmp", "sha")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

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
	// Side B is deliberately left down: the agent must settle and serve on
	// side A alone, which bundlesSettled allows because side A carries the
	// other side's authorities in its spire-ha bundle.
	startFakeSide(t, sideA)

	haSock := dir + "/ha.sock"
	t.Setenv("SPIRE_HA_AGENT_SOCK", haSock)
	t.Setenv("SPIRE_HA_AGENT_BROKER_A", "unix://"+sideA.brokerSock)
	t.Setenv("SPIRE_HA_AGENT_BROKER_B", "unix://"+sideB.brokerSock)
	t.Setenv("SPIRE_HA_AGENT_WORKLOAD_SOCKET_A", "unix://"+sideA.wlSock)
	t.Setenv("SPIRE_HA_AGENT_WORKLOAD_SOCKET_B", "unix://"+sideB.wlSock)
	t.Setenv("SPIRE_HA_AGENT_SINGLE", "")
	t.Setenv("SPIRE_HA_AGENT_VSOCK", "")

	// brokerMain never returns; its goroutines die with the test process.
	go brokerMain("")

	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.Dial("unix", haSock)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent never came up: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	conn, err := grpc.NewClient("unix://"+haSock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial downstream: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	wc := workload.NewSpiffeWorkloadAPIClient(conn)
	// Side B's first setupBrokerClient attempt burns its own 30s bound
	// against the not-yet-listening socket, so it joins at roughly t+35s.
	// When the fix is absent the stream simply never delivers, and this
	// context is what ends the test.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	// Open every stream while side B is still down.
	svidStream, err := wc.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	svidResp, err := svidStream.Recv()
	if err != nil {
		t.Fatalf("FetchX509SVID recv: %v", err)
	}
	checkEqual(t, "x509svid.issuer.before", []string{leafIssuer(t, svidResp.Svids[0].X509Svid)}, []string{"A-CA"})
	checkEqual(t, "x509svid.bundle.before", certCNs(t, svidResp.Svids[0].Bundle), []string{"A-CA", "HA-CA-A"})

	bundleStream, err := wc.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatalf("FetchX509Bundles: %v", err)
	}
	bundleResp, err := bundleStream.Recv()
	if err != nil {
		t.Fatalf("FetchX509Bundles recv: %v", err)
	}
	checkEqual(t, "x509bundles.example.org.before", certCNs(t, bundleResp.Bundles["example.org"]), []string{"A-CA", "HA-CA-A"})

	jwtBundleStream, err := wc.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		t.Fatalf("FetchJWTBundles: %v", err)
	}
	jwtBundleResp, err := jwtBundleStream.Recv()
	if err != nil {
		t.Fatalf("FetchJWTBundles recv: %v", err)
	}
	checkEqual(t, "jwtbundles.example.org.kids.before", kidsOf(t, jwtBundleResp.Bundles["example.org"]), []string{"a1", "ha-a"})

	// Side B comes up with the streams already open.
	startFakeSide(t, sideB)

	// The discriminating assertion. The SVID leaf can only come from a
	// per-stream pump, so it changes hands only if side B's pump was
	// started on the already-open stream. The fake sends one response then
	// blocks, so once B joins its response is the last one in.
	recvUntil(t, "x509svid after late join", svidStream.Recv, func(r *workload.X509SVIDResponse) bool {
		return len(r.Svids) == 1 && leafIssuer(t, r.Svids[0].X509Svid) == "B-CA"
	})

	// The bundle streams converge as well. These are weaker evidence of the
	// fix on their own: bundle content is overridden from the merged global
	// map, which side B's own subscription populates independently of this
	// stream's pumps.
	recvUntil(t, "x509bundles after late join", bundleStream.Recv, func(r *workload.X509BundlesResponse) bool {
		return len(certCNs(t, r.Bundles["example.org"])) == 4
	})
	recvUntil(t, "jwtbundles after late join", jwtBundleStream.Recv, func(r *workload.JWTBundlesResponse) bool {
		return len(kidsOf(t, r.Bundles["example.org"])) == 4
	})

	// Unary calls were never pinned, but confirm both sides are reachable
	// now that B has joined.
	if _, err := wc.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}}); err != nil {
		t.Fatalf("FetchJWTSVID after late join: %v", err)
	}
}

// Single mode has only side A: side B is never set up, so the pump for it
// must never be started and nothing may block waiting on it. This path is
// otherwise unexercised, and it is the branch the late-join rework moved,
// so cover it explicitly. Note the env var names are the unsuffixed ones.
func TestBrokerSingleMode(t *testing.T) {
	// unix socket paths are limited to ~104 bytes on darwin, so t.TempDir()
	// (under deep test temp paths) is not usable here.
	dir, err := os.MkdirTemp("/tmp", "sha")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	sideA := &fakeSide{
		name: "brokerA", ca: newTestCA(t, "A-CA"), haCA: newTestCA(t, "HA-CA-A"), otherCA: newTestCA(t, "OTHER-CA-A"),
		wlSock: dir + "/wla.sock", brokerSock: dir + "/bra.sock",
		jwtToken: "canned.jwt.a", localKid: "a1", haKid: "ha-a", otherKid: "o-a",
	}
	startFakeSide(t, sideA)

	haSock := dir + "/ha.sock"
	t.Setenv("SPIRE_HA_AGENT_SOCK", haSock)
	t.Setenv("SPIRE_HA_AGENT_SINGLE", "enabled")
	// Unsuffixed names: brokerMain only reads the _A/_B pair when multi.
	t.Setenv("SPIRE_HA_AGENT_BROKER", "unix://"+sideA.brokerSock)
	t.Setenv("SPIRE_HA_AGENT_WORKLOAD_SOCKET", "unix://"+sideA.wlSock)
	t.Setenv("SPIRE_HA_AGENT_VSOCK", "")

	// brokerMain never returns; its goroutines die with the test process.
	go brokerMain("")

	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.Dial("unix", haSock)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent never came up: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	conn, err := grpc.NewClient("unix://"+haSock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial downstream: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	wc := workload.NewSpiffeWorkloadAPIClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

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
	checkEqual(t, "single.x509svid.issuer", []string{leafIssuer(t, svidResp.Svids[0].X509Svid)}, []string{"A-CA"})
	checkEqual(t, "single.x509svid.bundle", certCNs(t, svidResp.Svids[0].Bundle), []string{"A-CA", "HA-CA-A"})

	bundleStream, err := wc.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatalf("FetchX509Bundles: %v", err)
	}
	bundleResp, err := bundleStream.Recv()
	if err != nil {
		t.Fatalf("FetchX509Bundles recv: %v", err)
	}
	checkEqual(t, "single.x509bundles.example.org", certCNs(t, bundleResp.Bundles["example.org"]), []string{"A-CA", "HA-CA-A"})
	checkEqual(t, "single.x509bundles.other.org", certCNs(t, bundleResp.Bundles["other.org"]), []string{"OTHER-CA-A"})

	// failLimit must stay 1 here: if single mode ever counted two sides,
	// this would block until the context expired rather than answering.
	jwtResp, err := wc.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}})
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if len(jwtResp.Svids) != 1 {
		t.Fatalf("expected 1 jwt svid, got %d", len(jwtResp.Svids))
	}
	checkEqual(t, "single.jwtsvid.token", []string{jwtResp.Svids[0].Svid}, []string{"canned.jwt.a"})

	jwtBundleStream, err := wc.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		t.Fatalf("FetchJWTBundles: %v", err)
	}
	jwtBundleResp, err := jwtBundleStream.Recv()
	if err != nil {
		t.Fatalf("FetchJWTBundles recv: %v", err)
	}
	checkEqual(t, "single.jwtbundles.example.org.kids", kidsOf(t, jwtBundleResp.Bundles["example.org"]), []string{"a1", "ha-a"})
	checkEqual(t, "single.jwtbundles.other.org.kids", kidsOf(t, jwtBundleResp.Bundles["other.org"]), []string{"o-a"})
}
