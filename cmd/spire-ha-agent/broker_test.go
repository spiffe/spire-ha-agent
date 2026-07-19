package main

// End-to-end test for -mode=broker.
//
// Starts, per side (A and B):
//   - a fake SPIFFE Workload API on a unix socket serving the ha-agent its
//     own client SVID (signed by that side's CA)
//   - a fake SPIFFE Broker API on a unix socket behind mTLS with server ID
//     spiffe://example.org/spire-ha-agent, enforcing the broker.spiffe.io
//     metadata, serving canned SVIDs/bundles including a spire-ha bundle and
//     a federated other.org bundle (different certs/kids per side)
//
// Then runs brokerMain in-process pointed at the fakes and verifies, via the
// raw workload API on the downstream socket:
//   - FetchX509SVID: bundle = union of A-CA, B-CA, HA-CA-A, HA-CA-B,
//     federated bundle for other.org = both sides' CAs, spire-ha not exposed
//   - FetchX509Bundles: example.org -> 4 certs, other.org -> 2 certs
//   - FetchJWTBundles: example.org kids = {a1,b1,ha-a,ha-b}, other.org = {o-a,o-b}
//   - FetchJWTSVID: passthrough of a canned token and hint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"sort"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA %s: %v", cn, err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key}
}

type testLeaf struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (c *testCA) issue(t *testing.T, id spiffeid.ID) *testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "spiffe", Host: id.TrustDomain().Name(), Path: id.Path()}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("issue %s: %v", id, err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testLeaf{cert: cert, key: key}
}

func pkcs8(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("pkcs8: %v", err)
	}
	return b
}

func testJWKS(t *testing.T, kids ...string) []byte {
	t.Helper()
	var set jose.JSONWebKeySet
	for _, kid := range kids {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate jwks key: %v", err)
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"})
	}
	out, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return out
}

// ---- fake workload API ----

type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	resp *workload.X509SVIDResponse
}

func (f *fakeWorkloadAPI) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := stream.Send(f.resp); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

// ---- fake broker ----

type fakeBroker struct {
	broker.UnimplementedAPIServer
	svidResp   *broker.SubscribeToX509SVIDResponse
	bundleResp *broker.SubscribeToX509BundlesResponse
	jwtBundles *broker.SubscribeToJWTBundlesResponse
	jwtToken   string
}

func checkBrokerMD(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md.Get("broker.spiffe.io")) == 0 || md.Get("broker.spiffe.io")[0] != "true" {
		return status.Error(codes.InvalidArgument, "missing broker.spiffe.io metadata")
	}
	return nil
}

func (f *fakeBroker) SubscribeToX509SVID(req *broker.SubscribeToX509SVIDRequest, stream broker.API_SubscribeToX509SVIDServer) error {
	if err := checkBrokerMD(stream.Context()); err != nil {
		return err
	}
	if err := stream.Send(f.svidResp); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

func (f *fakeBroker) SubscribeToX509Bundles(req *broker.SubscribeToX509BundlesRequest, stream broker.API_SubscribeToX509BundlesServer) error {
	if err := checkBrokerMD(stream.Context()); err != nil {
		return err
	}
	if err := stream.Send(f.bundleResp); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

func (f *fakeBroker) SubscribeToJWTBundles(req *broker.SubscribeToJWTBundlesRequest, stream broker.API_SubscribeToJWTBundlesServer) error {
	if err := checkBrokerMD(stream.Context()); err != nil {
		return err
	}
	if err := stream.Send(f.jwtBundles); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

func (f *fakeBroker) FetchJWTSVID(ctx context.Context, req *broker.FetchJWTSVIDRequest) (*broker.FetchJWTSVIDResponse, error) {
	if err := checkBrokerMD(ctx); err != nil {
		return nil, err
	}
	return &broker.FetchJWTSVIDResponse{Svids: []*broker.JWTSVID{{
		SpiffeId: "spiffe://example.org/myworkload",
		Svid:     f.jwtToken,
		Hint:     "internal",
	}}}, nil
}

// static x509svid source for the fake broker's server creds
type staticSVID struct{ svid *x509svid.SVID }

func (s *staticSVID) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

func testListen(t *testing.T, path string) net.Listener {
	t.Helper()
	lis, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	return lis
}

type fakeSide struct {
	name       string
	ca         *testCA
	haCA       *testCA
	otherCA    *testCA
	wlSock     string
	brokerSock string
	jwtToken   string
	localKid   string
	haKid      string
	otherKid   string

	// optional overrides for the canned bundle responses (nil => defaults)
	x509Bundles map[string][]byte
	jwtBundles  map[string][]byte
}

func startFakeSide(t *testing.T, s *fakeSide) {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString("example.org")

	// ha-agent's own client SVID, served by the fake workload API
	clientID := spiffeid.RequireFromPath(td, "/ha-agent")
	client := s.ca.issue(t, clientID)
	wl := &fakeWorkloadAPI{resp: &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{{
			SpiffeId:    clientID.String(),
			X509Svid:    client.cert.Raw,
			X509SvidKey: pkcs8(t, client.key),
			Bundle:      s.ca.cert.Raw,
		}},
	}}
	wlServer := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(wlServer, wl)
	go wlServer.Serve(testListen(t, s.wlSock))
	t.Cleanup(wlServer.Stop)

	// canned workload SVID handed out by the broker
	workloadID := spiffeid.RequireFromPath(td, "/myworkload")
	wlLeaf := s.ca.issue(t, workloadID)

	fb := &fakeBroker{
		svidResp: &broker.SubscribeToX509SVIDResponse{
			Svids: []*broker.X509SVID{{
				SpiffeId:    workloadID.String(),
				X509Svid:    wlLeaf.cert.Raw,
				X509SvidKey: pkcs8(t, wlLeaf.key),
				Bundle:      s.ca.cert.Raw,
				Hint:        "internal",
			}},
			FederatedBundles: map[string][]byte{
				"spiffe://other.org": s.otherCA.cert.Raw,
				"spiffe://spire-ha":  s.haCA.cert.Raw,
			},
		},
		bundleResp: &broker.SubscribeToX509BundlesResponse{
			Bundles: map[string][]byte{
				"spiffe://example.org": s.ca.cert.Raw,
				"spiffe://spire-ha":    s.haCA.cert.Raw,
				"spiffe://other.org":   s.otherCA.cert.Raw,
			},
		},
		jwtBundles: &broker.SubscribeToJWTBundlesResponse{
			Bundles: map[string][]byte{
				"spiffe://example.org": testJWKS(t, s.localKid),
				"spiffe://spire-ha":    testJWKS(t, s.haKid),
				"spiffe://other.org":   testJWKS(t, s.otherKid),
			},
		},
		jwtToken: s.jwtToken,
	}
	if s.x509Bundles != nil {
		fb.bundleResp = &broker.SubscribeToX509BundlesResponse{Bundles: s.x509Bundles}
	}
	if s.jwtBundles != nil {
		fb.jwtBundles = &broker.SubscribeToJWTBundlesResponse{Bundles: s.jwtBundles}
	}

	// broker server identity: spiffe://example.org/spire-ha-agent
	serverID := spiffeid.RequireFromPath(td, "/spire-ha-agent")
	serverLeaf := s.ca.issue(t, serverID)
	svidSrc := &staticSVID{svid: &x509svid.SVID{ID: serverID, Certificates: []*x509.Certificate{serverLeaf.cert}, PrivateKey: serverLeaf.key}}
	bundleSrc := x509bundle.FromX509Authorities(td, []*x509.Certificate{s.ca.cert})
	creds := grpccredentials.MTLSServerCredentials(svidSrc, bundleSrc, tlsconfig.AuthorizeAny())
	brokerServer := grpc.NewServer(grpc.Creds(creds))
	broker.RegisterAPIServer(brokerServer, fb)
	go brokerServer.Serve(testListen(t, s.brokerSock))
	t.Cleanup(brokerServer.Stop)
}

func certCNs(t *testing.T, der []byte) []string {
	t.Helper()
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		t.Fatalf("parse bundle DER: %v", err)
	}
	var cns []string
	for _, c := range certs {
		cns = append(cns, c.Subject.CommonName)
	}
	sort.Strings(cns)
	return cns
}

func kidsOf(t *testing.T, raw []byte) []string {
	t.Helper()
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KeyID)
	}
	sort.Strings(kids)
	return kids
}

func checkEqual(t *testing.T, what string, got, want []string) {
	t.Helper()
	if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
		t.Errorf("%s: got %v want %v", what, got, want)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestBrokerMode(t *testing.T) {
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
	startFakeSide(t, sideA)
	startFakeSide(t, sideB)

	haSock := dir + "/ha.sock"
	t.Setenv("SPIRE_HA_AGENT_SOCK", haSock)
	t.Setenv("SPIRE_HA_AGENT_BROKER_A", "unix://"+sideA.brokerSock)
	t.Setenv("SPIRE_HA_AGENT_BROKER_B", "unix://"+sideB.brokerSock)
	t.Setenv("SPIRE_HA_AGENT_WORKLOAD_SOCKET_A", "unix://"+sideA.wlSock)
	t.Setenv("SPIRE_HA_AGENT_WORKLOAD_SOCKET_B", "unix://"+sideB.wlSock)
	t.Setenv("SPIRE_HA_AGENT_SINGLE", "")
	t.Setenv("SPIRE_HA_AGENT_VSOCK", "")

	// brokerMain never returns; its goroutines die with the test process.
	go brokerMain()

	// wait for the downstream socket to accept
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	// --- FetchX509SVID ---
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
	checkEqual(t, "x509svid.id", []string{svidResp.Svids[0].SpiffeId}, []string{"spiffe://example.org/myworkload"})
	checkEqual(t, "x509svid.hint", []string{svidResp.Svids[0].Hint}, []string{"internal"})
	checkEqual(t, "x509svid.bundle", certCNs(t, svidResp.Svids[0].Bundle), []string{"A-CA", "B-CA", "HA-CA-A", "HA-CA-B"})
	checkEqual(t, "x509svid.federated-tds", sortedKeys(svidResp.FederatedBundles), []string{"other.org"})
	checkEqual(t, "x509svid.federated.other.org", certCNs(t, svidResp.FederatedBundles["other.org"]), []string{"OTHER-CA-A", "OTHER-CA-B"})

	// --- FetchX509Bundles ---
	bundleStream, err := wc.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatalf("FetchX509Bundles: %v", err)
	}
	bundleResp, err := bundleStream.Recv()
	if err != nil {
		t.Fatalf("FetchX509Bundles recv: %v", err)
	}
	checkEqual(t, "x509bundles.tds", sortedKeys(bundleResp.Bundles), []string{"example.org", "other.org"})
	checkEqual(t, "x509bundles.example.org", certCNs(t, bundleResp.Bundles["example.org"]), []string{"A-CA", "B-CA", "HA-CA-A", "HA-CA-B"})
	checkEqual(t, "x509bundles.other.org", certCNs(t, bundleResp.Bundles["other.org"]), []string{"OTHER-CA-A", "OTHER-CA-B"})

	// --- FetchJWTSVID ---
	jwtResp, err := wc.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"aud1"}})
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if len(jwtResp.Svids) != 1 {
		t.Fatalf("expected 1 jwt svid, got %d", len(jwtResp.Svids))
	}
	if tok := jwtResp.Svids[0].Svid; tok != "canned.jwt.a" && tok != "canned.jwt.b" {
		t.Errorf("jwtsvid.token: got %q", tok)
	}
	checkEqual(t, "jwtsvid.hint", []string{jwtResp.Svids[0].Hint}, []string{"internal"})

	// --- FetchJWTBundles ---
	jwtBundleStream, err := wc.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		t.Fatalf("FetchJWTBundles: %v", err)
	}
	jwtBundleResp, err := jwtBundleStream.Recv()
	if err != nil {
		t.Fatalf("FetchJWTBundles recv: %v", err)
	}
	checkEqual(t, "jwtbundles.tds", sortedKeys(jwtBundleResp.Bundles), []string{"example.org", "other.org"})
	checkEqual(t, "jwtbundles.example.org.kids", kidsOf(t, jwtBundleResp.Bundles["example.org"]), []string{"a1", "b1", "ha-a", "ha-b"})
	checkEqual(t, "jwtbundles.other.org.kids", kidsOf(t, jwtBundleResp.Bundles["other.org"]), []string{"o-a", "o-b"})
}
