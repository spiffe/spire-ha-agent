package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	metadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Picks the server SVID for the downstream broker endpoint: the SVID with
// the longest remaining validity (latest leaf NotAfter) among the ready
// upstream sources. Called once per side at setup and again whenever a side
// delivers a new SVID; the result is cached in bs.serverSVID so handshakes
// never re-evaluate the sources.
func (bs *brokerServer) recomputeServerSVID() {
	bs.bundleLock.RLock()
	sources := []*workloadapi.X509Source{bs.clients[0].source, bs.clients[1].source}
	bs.bundleLock.RUnlock()

	var best *x509svid.SVID
	for _, src := range sources {
		if src == nil {
			continue
		}
		svid, err := src.GetX509SVID()
		if err != nil || len(svid.Certificates) == 0 {
			continue
		}
		if best == nil || svid.Certificates[0].NotAfter.After(best.Certificates[0].NotAfter) {
			best = svid
		}
	}
	if best == nil {
		return
	}
	bs.bundleLock.Lock()
	if bs.serverSVID != best {
		log.Printf("broker endpoint: server SVID %s not after %s", best.ID, best.Certificates[0].NotAfter)
	}
	bs.serverSVID = best
	bs.bundleLock.Unlock()
}

type serverSVIDSource struct {
	bs *brokerServer
}

func (s *serverSVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	s.bs.bundleLock.RLock()
	defer s.bs.bundleLock.RUnlock()
	if s.bs.serverSVID == nil {
		return nil, errors.New("broker endpoint: no upstream SVID available yet")
	}
	return s.bs.serverSVID, nil
}

// Client certificates are verified against the merged bundle state, so a
// client may present an SVID minted by either SPIRE server (spire-ha fold)
// or by a federated trust domain the spire-ha-agent entry federates with.
type mergedBundleSource struct {
	bs *brokerServer
}

func (m *mergedBundleSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	m.bs.bundleLock.RLock()
	defer m.bs.bundleLock.RUnlock()
	if b, ok := m.bs.mergedX509[td.Name()]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("no merged bundle for trust domain %q", td)
}

func endpointCallerID(ctx context.Context) (spiffeid.ID, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return spiffeid.ID{}, errors.New("no peer auth info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || tlsInfo.SPIFFEID == nil {
		return spiffeid.ID{}, errors.New("no peer SPIFFE ID")
	}
	return spiffeid.FromURI(tlsInfo.SPIFFEID)
}

type brokerEndpointServer struct {
	broker.UnimplementedAPIServer
	bs   *brokerServer
	conf *endpointConfig
}

// Authorizes a downstream broker call, mirroring the SPIRE agent's broker
// endpoint: mandatory security header, a non-empty workload reference, a
// caller identity from the mTLS handshake, and that caller's configured
// reference-type allowlist (with the TCP restriction unless the type is
// allowed over TCP).
func (e *brokerEndpointServer) authorize(ctx context.Context, ref *broker.WorkloadReference) (spiffeid.ID, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return spiffeid.ID{}, status.Error(codes.InvalidArgument, "security header missing from request")
	}
	vals := md.Get("broker.spiffe.io")
	if len(vals) != 1 || vals[0] != "true" {
		return spiffeid.ID{}, status.Error(codes.InvalidArgument, "security header missing from request")
	}
	if ref.GetReference() == nil || ref.GetReference().GetTypeUrl() == "" {
		return spiffeid.ID{}, status.Error(codes.InvalidArgument, "workload reference is required")
	}
	callerID, err := endpointCallerID(ctx)
	if err != nil {
		return spiffeid.ID{}, status.Error(codes.PermissionDenied, "caller identity unavailable")
	}
	pol, ok := e.conf.policies[callerID]
	if !ok {
		return spiffeid.ID{}, status.Errorf(codes.PermissionDenied, "broker %q is not authorized", callerID)
	}
	typeURL := ref.GetReference().GetTypeUrl()
	rp, ok := pol[typeURL]
	if !ok {
		rp, ok = pol[wildcardTypeURL]
	}
	if !ok {
		return spiffeid.ID{}, status.Errorf(codes.PermissionDenied, "reference type %q not allowed for broker %q", typeURL, callerID)
	}
	if p, ok := peer.FromContext(ctx); ok {
		if _, isTCP := p.Addr.(*net.TCPAddr); isTCP && !rp.allowOverTCP {
			return spiffeid.ID{}, status.Errorf(codes.PermissionDenied, "reference type %q not allowed over TCP", typeURL)
		}
	}
	return callerID, nil
}

// Broker-out converters: same merged view as the workload API converters,
// but broker API bundle maps are keyed by the trust domain SPIFFE ID
// (spiffe://example.org) rather than the bare name.

func (bs *brokerServer) mergeBrokerSVIDResponse(resp *broker.SubscribeToX509SVIDResponse) *broker.SubscribeToX509SVIDResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	svidBundles, federated := bs.mergeSVIDParts(resp)
	res := &broker.SubscribeToX509SVIDResponse{
		Crl:              resp.GetCrl(),
		FederatedBundles: make(map[string][]byte),
	}
	for i, svid := range resp.GetSvids() {
		res.Svids = append(res.Svids, &broker.X509SVID{
			SpiffeId:    svid.GetSpiffeId(),
			X509Svid:    svid.GetX509Svid(),
			X509SvidKey: svid.GetX509SvidKey(),
			Bundle:      svidBundles[i],
			Hint:        svid.GetHint(),
		})
	}
	for name, raw := range federated {
		res.FederatedBundles[trustDomainIDString(name)] = raw
	}
	return res
}

func (bs *brokerServer) mergeBrokerX509BundlesResponse(resps ...*broker.SubscribeToX509BundlesResponse) *broker.SubscribeToX509BundlesResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	bundles, crls := bs.mergeX509BundleMaps(resps...)
	res := &broker.SubscribeToX509BundlesResponse{Crl: crls, Bundles: make(map[string][]byte)}
	for name, raw := range bundles {
		res.Bundles[trustDomainIDString(name)] = raw
	}
	return res
}

func (bs *brokerServer) mergeBrokerJWTBundlesResponse(resps ...*broker.SubscribeToJWTBundlesResponse) *broker.SubscribeToJWTBundlesResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	res := &broker.SubscribeToJWTBundlesResponse{Bundles: make(map[string][]byte)}
	for name, raw := range bs.mergeJWTBundleMaps(resps...) {
		res.Bundles[trustDomainIDString(name)] = raw
	}
	return res
}

func trustDomainIDString(name string) string {
	if td, err := spiffeid.TrustDomainFromString(name); err == nil {
		return td.IDString()
	}
	return name
}

// Fetch X.509-SVIDs for all SPIFFE identities the referenced workload is
// entitled to, as well as related information like trust bundles. As this
// information changes, subsequent messages will be streamed from the server.
func (e *brokerEndpointServer) SubscribeToX509SVID(req *broker.SubscribeToX509SVIDRequest, stream broker.API_SubscribeToX509SVIDServer) error {
	dctx := stream.Context()
	callerID, err := e.authorize(dctx, req.GetReference())
	if err != nil {
		return err
	}
	tag := callerID.String()
	log.Printf("broker endpoint x509svid subscription from %s", tag)

	chan1 := make(chan *broker.SubscribeToX509SVIDResponse)
	chan2 := make(chan *broker.SubscribeToX509SVIDResponse)
	var started [2]bool
	startPump := func(id int, client broker.APIClient) {
		if id == 0 {
			go getBrokerX509SVIDs(dctx, req.GetReference(), tag, client, chan1)
		} else {
			go getBrokerX509SVIDs(dctx, req.GetReference(), tag, client, chan2)
		}
	}
	clientsChan := e.bs.currentClientsChan()
	e.bs.startPumps(&started, startPump)
	log.Printf("broker endpoint x509svid %s: upstream sides available: %s", tag, e.bs.sidesAvailable())

	var resp *broker.SubscribeToX509SVIDResponse
	for resp == nil {
		select {
		case <-dctx.Done():
			return nil
		case resp = <-chan1:
		case resp = <-chan2:
		case <-clientsChan:
			// A side finished setup after we opened; join it to this stream
			// rather than staying pinned to whoever was up at open time.
			clientsChan = e.bs.currentClientsChan()
			if e.bs.startPumps(&started, startPump) {
				log.Printf("broker endpoint x509svid %s: upstream side joined, starting pump (now %s)", tag, e.bs.sidesAvailable())
			}
		}
	}

	bundleChan := e.bs.currentX509BundleChan()
	pb := e.bs.mergeBrokerSVIDResponse(resp)

	for {
		if err := stream.Send(pb); err != nil {
			return err
		}
		for {
			diff := false

			select {
			case <-dctx.Done():
				return nil
			case resp = <-chan1:
				pb = e.bs.mergeBrokerSVIDResponse(resp)
				diff = true
			case resp = <-chan2:
				pb = e.bs.mergeBrokerSVIDResponse(resp)
				diff = true
			case <-bundleChan:
				bundleChan = e.bs.currentX509BundleChan()
				npb := e.bs.mergeBrokerSVIDResponse(resp)
				if !proto.Equal(pb, npb) {
					pb = npb
					diff = true
				}
			case <-clientsChan:
				clientsChan = e.bs.currentClientsChan()
				if e.bs.startPumps(&started, startPump) {
					log.Printf("broker endpoint x509svid %s: upstream side joined, starting pump (now %s)", tag, e.bs.sidesAvailable())
				}
			}
			if diff {
				break
			}
		}
	}
}

// Fetch trust bundles of the referenced workload. Useful in situations that
// only need to validate SVIDs without obtaining an SVID for themself. As
// this information changes, subsequent messages will be streamed from the
// server.
func (e *brokerEndpointServer) SubscribeToX509Bundles(req *broker.SubscribeToX509BundlesRequest, stream broker.API_SubscribeToX509BundlesServer) error {
	dctx := stream.Context()
	callerID, err := e.authorize(dctx, req.GetReference())
	if err != nil {
		return err
	}
	tag := callerID.String()
	log.Printf("broker endpoint x509bundles subscription from %s", tag)

	chan1 := make(chan *broker.SubscribeToX509BundlesResponse)
	chan2 := make(chan *broker.SubscribeToX509BundlesResponse)
	var started [2]bool
	startPump := func(id int, client broker.APIClient) {
		if id == 0 {
			go getBrokerX509Bundles(dctx, req.GetReference(), tag, client, chan1)
		} else {
			go getBrokerX509Bundles(dctx, req.GetReference(), tag, client, chan2)
		}
	}
	clientsChan := e.bs.currentClientsChan()
	e.bs.startPumps(&started, startPump)
	log.Printf("broker endpoint x509bundles %s: upstream sides available: %s", tag, e.bs.sidesAvailable())

	var resp1, resp2 *broker.SubscribeToX509BundlesResponse
	for resp1 == nil && resp2 == nil {
		select {
		case <-dctx.Done():
			return nil
		case resp1 = <-chan1:
		case resp2 = <-chan2:
		case <-clientsChan:
			clientsChan = e.bs.currentClientsChan()
			if e.bs.startPumps(&started, startPump) {
				log.Printf("broker endpoint x509bundles %s: upstream side joined, starting pump (now %s)", tag, e.bs.sidesAvailable())
			}
		}
	}

	bundleChan := e.bs.currentX509BundleChan()
	pb := e.bs.mergeBrokerX509BundlesResponse(resp1, resp2)

	for {
		if err := stream.Send(pb); err != nil {
			return err
		}
		for {
			diff := false

			select {
			case <-dctx.Done():
				return nil
			case resp1 = <-chan1:
			case resp2 = <-chan2:
			case <-bundleChan:
				bundleChan = e.bs.currentX509BundleChan()
			case <-clientsChan:
				clientsChan = e.bs.currentClientsChan()
				if e.bs.startPumps(&started, startPump) {
					log.Printf("broker endpoint x509bundles %s: upstream side joined, starting pump (now %s)", tag, e.bs.sidesAvailable())
				}
			}
			npb := e.bs.mergeBrokerX509BundlesResponse(resp1, resp2)
			if !proto.Equal(pb, npb) {
				pb = npb
				diff = true
			}
			if diff {
				break
			}
		}
	}
}

// Fetch JWT-SVIDs for all SPIFFE identities the referenced workload is
// entitled to, for the requested audience.
func (e *brokerEndpointServer) FetchJWTSVID(ctx context.Context, req *broker.FetchJWTSVIDRequest) (*broker.FetchJWTSVIDResponse, error) {
	callerID, err := e.authorize(ctx, req.GetReference())
	if err != nil {
		return nil, err
	}
	tag := callerID.String()
	log.Printf("broker endpoint jwt fetch from %s", tag)

	failLimit := 1
	chan1 := make(chan *broker.FetchJWTSVIDResponse)
	c0, c1 := e.bs.upstreamClients()
	go getBrokerJWT(ctx, req.GetReference(), tag, req.Audience, req.SpiffeId, c0, chan1)
	if e.bs.multi {
		failLimit = 2
		go getBrokerJWT(ctx, req.GetReference(), tag, req.Audience, req.SpiffeId, c1, chan1)
	}

	var count int
	var resp *broker.FetchJWTSVIDResponse
	for {
		select {
		case <-ctx.Done():
			return nil, status.Error(codes.Canceled, "client disconnected")
		case resp = <-chan1:
			count++
		}
		if resp != nil {
			break
		}
		if count >= failLimit {
			return nil, status.Errorf(codes.Unavailable, "failed to talk to either agent")
		}
	}
	return resp, nil
}

// Fetches the JWT bundles, formatted as JWKS documents, keyed by the SPIFFE
// ID of the trust domain. As this information changes, subsequent messages
// will be streamed from the server.
func (e *brokerEndpointServer) SubscribeToJWTBundles(req *broker.SubscribeToJWTBundlesRequest, stream broker.API_SubscribeToJWTBundlesServer) error {
	dctx := stream.Context()
	callerID, err := e.authorize(dctx, req.GetReference())
	if err != nil {
		return err
	}
	tag := callerID.String()
	log.Printf("broker endpoint jwtbundles subscription from %s", tag)

	chan1 := make(chan *broker.SubscribeToJWTBundlesResponse)
	chan2 := make(chan *broker.SubscribeToJWTBundlesResponse)
	var started [2]bool
	startPump := func(id int, client broker.APIClient) {
		if id == 0 {
			go getBrokerJWTBundles(dctx, req.GetReference(), tag, client, chan1)
		} else {
			go getBrokerJWTBundles(dctx, req.GetReference(), tag, client, chan2)
		}
	}
	clientsChan := e.bs.currentClientsChan()
	e.bs.startPumps(&started, startPump)
	log.Printf("broker endpoint jwtbundles %s: upstream sides available: %s", tag, e.bs.sidesAvailable())

	var resp1, resp2 *broker.SubscribeToJWTBundlesResponse
	for resp1 == nil && resp2 == nil {
		select {
		case <-dctx.Done():
			return nil
		case resp1 = <-chan1:
		case resp2 = <-chan2:
		case <-clientsChan:
			clientsChan = e.bs.currentClientsChan()
			if e.bs.startPumps(&started, startPump) {
				log.Printf("broker endpoint jwtbundles %s: upstream side joined, starting pump (now %s)", tag, e.bs.sidesAvailable())
			}
		}
	}

	bundleChan := e.bs.currentJWTBundleChan()
	pb := e.bs.mergeBrokerJWTBundlesResponse(resp1, resp2)

	for {
		if err := stream.Send(pb); err != nil {
			return err
		}
		for {
			diff := false

			select {
			case <-dctx.Done():
				return nil
			case resp1 = <-chan1:
			case resp2 = <-chan2:
			case <-bundleChan:
				bundleChan = e.bs.currentJWTBundleChan()
			case <-clientsChan:
				clientsChan = e.bs.currentClientsChan()
				if e.bs.startPumps(&started, startPump) {
					log.Printf("broker endpoint jwtbundles %s: upstream side joined, starting pump (now %s)", tag, e.bs.sidesAvailable())
				}
			}
			npb := e.bs.mergeBrokerJWTBundlesResponse(resp1, resp2)
			if !proto.Equal(pb, npb) {
				pb = npb
				diff = true
			}
			if diff {
				break
			}
		}
	}
}

func startBrokerEndpoint(bs *brokerServer, conf *endpointConfig) {
	tlsConf := tlsconfig.MTLSServerConfig(&serverSVIDSource{bs: bs}, &mergedBundleSource{bs: bs}, tlsconfig.AuthorizeOneOf(conf.ids...))
	// Force full verification of the client chain (against possibly updated
	// bundles) on every connection; matches the SPIRE agent's endpoint.
	tlsConf.SessionTicketsDisabled = true

	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
	broker.RegisterAPIServer(g, &brokerEndpointServer{bs: bs, conf: conf})

	if conf.socketPath != "" {
		_ = os.Remove(conf.socketPath)
		ulis, err := net.Listen("unix", conf.socketPath)
		if err != nil {
			log.Fatalf("broker endpoint: failed to listen on %s: %v", conf.socketPath, err)
		}
		if err := os.Chmod(conf.socketPath, 0777); err != nil {
			log.Fatalf("broker endpoint: failed to permission the socket: %v", err)
		}
		log.Printf("broker endpoint listening on %s", conf.socketPath)
		go func() {
			log.Fatalf("broker endpoint serve error: %v", g.Serve(ulis))
		}()
	}
	if conf.bindAddress != "" {
		tlis, err := net.Listen("tcp", conf.bindAddress)
		if err != nil {
			log.Fatalf("broker endpoint: failed to listen on tcp %s: %v", conf.bindAddress, err)
		}
		log.Printf("broker endpoint listening on tcp %s", conf.bindAddress)
		go func() {
			log.Fatalf("broker endpoint serve error: %v", g.Serve(tlis))
		}()
	}
}
