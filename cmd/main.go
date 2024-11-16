package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"net"
	"time"
	"errors"
        "encoding/json"
	"fmt"
	"crypto/x509"
	"reflect"
	"sync"
	"strconv"
	"os"

	//FIXME Local tweaked copy for now. Need to break this out on its own.
	"github.com/spiffe/spire-ha-agent/pkg/peertracker"
        jose "github.com/go-jose/go-jose/v4"

	"google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
        status "google.golang.org/grpc/status"
        metadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/credentials/insecure"
	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	agentdelegated "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	agentdebug "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	types "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	//"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type callerPIDKey struct{}

type x509BundleUpdated struct{
	id int
	bundle *x509bundle.Set
}

type jwtBundleUpdated struct{
	id int
	bundle map[string]jose.JSONWebKeySet
}

type server struct {
	x509BundleUpdate chan x509BundleUpdated
	jwtBundleUpdate chan jwtBundleUpdated
	rawBundles map[string][]byte
	rawJwtBundles map[string][]byte
	bundleChan chan struct{}
	jwtBundleChan chan struct{}
	bundleLock sync.RWMutex
	clients [2]clientSet
	workload.UnimplementedSpiffeWorkloadAPIServer
        multi bool
}

type clientSet struct {
	clientOK bool
	debugClient agentdebug.DebugClient
	delegatedClient agentdelegated.DelegatedIdentityClient
	bundle *x509bundle.Set
	jwtBundles map[string]jose.JSONWebKeySet
}

func ConcatRawCertsFromCerts(certs []*x509.Certificate) []byte {
	var rawCerts []byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw...)
	}
	return rawCerts
}

func get_x509cert(dctx context.Context, pid int, delegatedClient agentdelegated.DelegatedIdentityClient, notify *chan*agentdelegated.SubscribeToX509SVIDsResponse) {
	for {
	//	uctx, cancel := context.WithCancel(metadata.NewOutgoingContext(dctx, metadata.Pairs("workload.spiffe.io", "true")))
		uctx := metadata.NewOutgoingContext(dctx, metadata.Pairs("workload.spiffe.io", "true"))
		//defer cancel()
		upstream, err := delegatedClient.SubscribeToX509SVIDs(uctx, &agentdelegated.SubscribeToX509SVIDsRequest{Pid: int32(pid)})
		if err != nil {
			log.Printf("x509cert %d upstream error: %v", pid, err)
			time.Sleep(5 * time.Second)
			continue
		}
		for {
			resp, err := upstream.Recv()
			if err != nil {
				if errors.Is(dctx.Err(), context.Canceled) {
					log.Printf("x509cert %d canceled", pid)
					return
				}
				log.Printf("x509cert %d upstream error2: %v", pid, err)
				time.Sleep(5 * time.Second)
				break
			}
			log.Printf("x509cert %d upstream got cert", pid)
			//FIXME Can squash duplicates that happen during reconnect...
			*notify <- resp
		}
	}
}

func delegatedResponseToWorkloadResponse (resp *agentdelegated.SubscribeToX509SVIDsResponse, rawBundles *map[string][]byte) *workload.X509SVIDResponse {
	res := &workload.X509SVIDResponse{
		FederatedBundles: make(map[string][]byte),
		//FIXME Crl?
	}

	for _, svid := range resp.GetX509Svids() {
		var x509Svid *types.X509SVID = svid.GetX509Svid()
		var key []byte = svid.GetX509SvidKey()
		log.Printf("Got %s\n", x509Svid)
		id := x509Svid.GetId()
		res.Svids = append(res.Svids, &workload.X509SVID{
			SpiffeId:    fmt.Sprintf("spiffe://%s%s", id.GetTrustDomain(), id.GetPath()),
			X509Svid:    bytes.Join(x509Svid.GetCertChain(), []byte("")),
			X509SvidKey: key,
			Bundle:      (*rawBundles)[id.GetTrustDomain()],
			Hint:        x509Svid.GetHint(),
		})
		//FIXME dont forget Federated bundles
	}
	return res
}

// Fetch X.509-SVIDs for all SPIFFE identities the workload is entitled to,
// as well as related information like trust bundles and CRLs. As this
// information changes, subsequent messages will be streamed from the
// server.
func (s *server) FetchX509SVID(req *workload.X509SVIDRequest, downstream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	var bundleChan chan struct{}
	dctx := downstream.Context()
	pid := dctx.Value(callerPIDKey{}).(int)
	log.Printf("x509fetch calling pid: %d", pid)

	var chan1 chan*agentdelegated.SubscribeToX509SVIDsResponse = make(chan*agentdelegated.SubscribeToX509SVIDsResponse)
	var chan2 chan*agentdelegated.SubscribeToX509SVIDsResponse = make(chan*agentdelegated.SubscribeToX509SVIDsResponse)
	go get_x509cert(dctx, pid, s.clients[0].delegatedClient, &chan1)
        if s.multi {
		go get_x509cert(dctx, pid, s.clients[1].delegatedClient, &chan2)
	}

	var resp *agentdelegated.SubscribeToX509SVIDsResponse
	select {
		case <-dctx.Done():
			log.Printf("x509fetch client disconncted\n")
			return nil
		case resp = <-chan1:
			log.Printf("x509fetch got new certs\n")
		case resp = <-chan2:
			log.Printf("x509fetch got new certs2\n")
	}

	s.bundleLock.RLock()
	pb := delegatedResponseToWorkloadResponse(resp, &s.rawBundles)
	bundleChan = s.bundleChan
	s.bundleLock.RUnlock()
	log.Printf("Got %s\n", resp.GetFederatesWith())

	for {
		log.Printf("Sending back cert/bundle update\n")
		if err := downstream.Send(pb); err != nil {
			return err
		}
		for {
			diff := false

			select {
				case <-dctx.Done():
					log.Printf("x509fetch client disconncted\n")
					return nil
				case resp = <-chan1:
					log.Printf("x509fetch got new certs\n")
					pb = delegatedResponseToWorkloadResponse(resp, &s.rawBundles)
					diff = true
					break
				case resp = <-chan2:
					log.Printf("x509fetch got new certs2\n")
					pb = delegatedResponseToWorkloadResponse(resp, &s.rawBundles)
					diff = true
					break
				case <-bundleChan:
					log.Printf("x509fetch ca refreshed\n")
					s.bundleLock.RLock()
					for _, svid := range pb.Svids {
						td, err := spiffeid.TrustDomainFromString(svid.GetSpiffeId())
						if err != nil {
							log.Fatal("Aaahhhh")
						}
						if !bytes.Equal(svid.GetBundle(), s.rawBundles[td.Name()]) {
							diff = true
							svid.Bundle = s.rawBundles[td.Name()]
						}
					}
					//FIXME also check on federated bundles
					log.Printf("diff: %t", diff)
					log.Printf("tds total: %d", len(s.rawBundles))
					bundleChan = s.bundleChan
					s.bundleLock.RUnlock()
			}
			if diff {
				break
			}
		}
	}

	log.Printf("FetchX509SVID")
	return status.Errorf(codes.Unimplemented, "method FetchX509SVID not implemented")
}


func delegatedResponseToWorkloadBundleResponse (resp *agentdelegated.SubscribeToX509SVIDsResponse, rawBundles *map[string][]byte) *workload.X509BundlesResponse {
	var res *workload.X509BundlesResponse = &workload.X509BundlesResponse{};
	//FIXME crl?
	res.Bundles = make(map[string][]byte, 0)
	for _, trustDomain := range resp.GetFederatesWith() {
		res.Bundles[trustDomain] = (*rawBundles)[trustDomain]
	}
	for _, svid := range resp.GetX509Svids() {
                var x509Svid *types.X509SVID = svid.GetX509Svid()
		id := x509Svid.GetId()
		trustDomain := id.GetTrustDomain()
		res.Bundles[trustDomain] = (*rawBundles)[trustDomain]
	}
	return res
}

// Fetch trust bundles and CRLs. Useful for clients that only need to
// validate SVIDs without obtaining an SVID for themself. As this
// information changes, subsequent messages will be streamed from the
// server.
func (s *server) FetchX509Bundles(req *workload.X509BundlesRequest, downstream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	var bundleChan chan struct{}
	dctx := downstream.Context()
	pid := dctx.Value(callerPIDKey{}).(int)
	log.Printf("Calling pid: %d", pid)

	var chan1 chan*agentdelegated.SubscribeToX509SVIDsResponse = make(chan*agentdelegated.SubscribeToX509SVIDsResponse)
	var chan2 chan*agentdelegated.SubscribeToX509SVIDsResponse = make(chan*agentdelegated.SubscribeToX509SVIDsResponse)
	go get_x509cert(dctx, pid, s.clients[0].delegatedClient, &chan1)
        if s.multi {
		go get_x509cert(dctx, pid, s.clients[1].delegatedClient, &chan2)
	}

	var resp *agentdelegated.SubscribeToX509SVIDsResponse
	select {
		case <-dctx.Done():
			log.Printf("x509fetch client disconncted\n")
			return nil
		case resp = <-chan1:
			log.Printf("x509fetch got new certs\n")
		case resp = <-chan2:
			log.Printf("x509fetch got new certs2\n")
	}

	s.bundleLock.RLock()
	bundles := delegatedResponseToWorkloadBundleResponse(resp, &s.rawBundles)
	bundleChan = s.bundleChan
	s.bundleLock.RUnlock()
	log.Printf("Got %s\n", resp.GetFederatesWith())

	for {
		log.Printf("Sending back cert/bundle update\n")
		if err := downstream.Send(bundles); err != nil {
			return err
		}
		for {
			diff := false

			select {
				//FIXME squash duplicate sends.
				case <-dctx.Done():
					log.Printf("x509fetch client disconncted\n")
					return nil
				case resp = <-chan1:
					log.Printf("x509fetch got new certs\n")
					s.bundleLock.RLock()
					bundles = delegatedResponseToWorkloadBundleResponse(resp, &s.rawBundles)
					s.bundleLock.RUnlock()
					diff = true
					break
				case resp = <-chan2:
					log.Printf("x509fetch got new certs2\n")
					s.bundleLock.RLock()
					bundles = delegatedResponseToWorkloadBundleResponse(resp, &s.rawBundles)
					s.bundleLock.RUnlock()
					diff = true
					break
				case <-bundleChan:
					log.Printf("x509fetch ca refreshed\n")
					s.bundleLock.RLock()
					bundles = delegatedResponseToWorkloadBundleResponse(resp, &s.rawBundles)
					bundleChan = s.bundleChan
					s.bundleLock.RUnlock()
					diff = true
					break
			}
			if diff {
				break
			}
		}
	}

	log.Printf("FetchX509Bundles")
	return status.Errorf(codes.Unimplemented, "method FetchX509Bundles not implemented")
}

func get_jwt(dctx context.Context, pid int, audience []string, delegatedClient agentdelegated.DelegatedIdentityClient, notify *chan*agentdelegated.FetchJWTSVIDsResponse) {
	uctx := metadata.NewOutgoingContext(dctx, metadata.Pairs("workload.spiffe.io", "true"))
	resp, err := delegatedClient.FetchJWTSVIDs(uctx, &agentdelegated.FetchJWTSVIDsRequest{Audience: audience, Pid: int32(pid)})
	if err != nil {
		log.Printf("jwt %d upstream error: %v", pid, err)
	}
	*notify <- resp
}

// Fetch JWT-SVIDs for all SPIFFE identities the workload is entitled to,
// for the requested audience. If an optional SPIFFE ID is requested, only
// the JWT-SVID for that SPIFFE ID is returned.
func (s *server) FetchJWTSVID(dctx context.Context, downstream *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	log.Printf("FetchJWTSVID")
	pid := dctx.Value(callerPIDKey{}).(int)

	var count int = 0
	var resp *agentdelegated.FetchJWTSVIDsResponse
	var chan1 chan*agentdelegated.FetchJWTSVIDsResponse = make(chan*agentdelegated.FetchJWTSVIDsResponse)
//FIXME lots of different ways of doing this. Just do the simple thing for now.
        go get_jwt(dctx, pid, downstream.Audience, s.clients[0].delegatedClient, &chan1)
        if s.multi {
		go get_jwt(dctx, pid, downstream.Audience, s.clients[1].delegatedClient, &chan1)
	}

//FIXME  in the request,  string spiffe_id = 2;
//reponse hint? no delegated api equiv.

	for {
		select {
			case <-dctx.Done():
				log.Printf("jwt client disconncted\n")
				return nil, nil
			case resp = <-chan1:
				log.Printf("jwt got new token\n")
				count++
				break
		}
		if resp != nil {
			break
		}
		if count >= 2 {
			return nil, status.Errorf(codes.Unavailable, "failed to talk to either agent")
		}
	}

	svids := make([]*workload.JWTSVID, 0)
	for _, s := range resp.Svids {
		id := fmt.Sprintf("spiffe://%s%s", resp.Svids[0].Id.TrustDomain, resp.Svids[0].Id.Path)
		e := &workload.JWTSVID{SpiffeId: id, Svid: s.Token}
		//FIXME how might we return a hint? Not returned from the delegated api
		svids = append(svids, e)
	}
	res := &workload.JWTSVIDResponse{Svids: svids}
	log.Printf("wark3 %s\n", res)
	return res, nil
}

// Fetches the JWT bundles, formatted as JWKS documents, keyed by the
// SPIFFE ID of the trust domain. As this information changes, subsequent
// messages will be streamed from the server.
func (s *server) FetchJWTBundles(req *workload.JWTBundlesRequest, downstream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	var res *workload.JWTBundlesResponse = &workload.JWTBundlesResponse{};
	ctx := downstream.Context()
	pid := ctx.Value(callerPIDKey{}).(int)
	log.Printf("Calling pid: %d", pid)
	log.Printf("FetchJWTBundles")
//FIXME double check. does this scope down to the caller somehow?
	//ls.rawJwtBundles

	var bundleChan chan struct{}
	dctx := downstream.Context()
	pid = dctx.Value(callerPIDKey{}).(int)
	log.Printf("Calling pid: %d", pid)

	s.bundleLock.RLock()
	bundleChan = s.jwtBundleChan
        bundles := s.rawJwtBundles
	s.bundleLock.RUnlock()

	for {
		log.Printf("Sending back jwt bundle update\n")
		res.Bundles = bundles
		if err := downstream.Send(res); err != nil {
			return err
		}
		for {
			diff := false

			select {
				//FIXME squash duplicate sends.
				case <-dctx.Done():
					log.Printf("jwtfetch client disconncted\n")
					return nil
				case <-bundleChan:
					log.Printf("jwtfetch ca refreshed\n")
					s.bundleLock.RLock()
					bundles = s.rawJwtBundles
					bundleChan = s.jwtBundleChan
					s.bundleLock.RUnlock()
					diff = true
					break
			}
			if diff {
				break
			}
		}
	}

	log.Printf("FetchJWTBundles")
	return status.Errorf(codes.Unimplemented, "method FetchJWTBundles not implemented")
}

// Validates a JWT-SVID against the requested audience. Returns the SPIFFE
// ID of the JWT-SVID and JWT claims.
func (s *server) ValidateJWTSVID(ctx context.Context, downstream *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	//ctx = downstream.Context()
	pid := ctx.Value(callerPIDKey{}).(int)
	log.Printf("Calling pid: %d", pid)
	log.Printf("ValidateJWTSVID")
	return nil, status.Errorf(codes.Unimplemented, "method ValidateJWTSVID not implemented")
}

func addWatcherPID(ctx context.Context, _ string, _ any) (context.Context, error) {
	watcher, ok := peertracker.WatcherFromContext(ctx)
	if ok {
		pid := int(watcher.PID())
		ctx = context.WithValue(ctx, callerPIDKey{}, pid)
	}
	return ctx, nil
}

func parseX509Bundles(bun map[string][]byte) (*x509bundle.Set, error) {
	bundles := []*x509bundle.Bundle{}

	for tdID, b := range bun {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			return nil, err
		}
		b, err := x509bundle.ParseRaw(td, b)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}

	return x509bundle.NewSet(bundles...), nil
}

func setupClient(ls *server, clientName string, id int, mainSockName string, adminSocketName string, cs *clientSet) {
	//Raw client code: https://github.com/spiffe/go-spiffe/blob/main/v2/workloadapi/client.go#L255
	var dialOptions []grpc.DialOption
//	var conn *grpc.ClientConn

	dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	dconn, err := grpc.DialContext(context.Background(), adminSocketName, dialOptions...)
        if err != nil {
                log.Fatalf("Failed to dial context: %v", err)
        }

	ls.x509BundleUpdate = make(chan x509BundleUpdated)
	ls.jwtBundleUpdate = make(chan jwtBundleUpdated)
	cs.delegatedClient = agentdelegated.NewDelegatedIdentityClient(dconn)
	cs.debugClient = agentdebug.NewDebugClient(dconn)
	go func() {
		var lt int64 = 0
		var count = 0
		cs.clientOK = false
		for {
			resp, err := cs.debugClient.GetInfo(context.TODO(), nil)
			if err != nil {
				log.Printf("Failed getinfo: %v", err)
				count++
				cs.clientOK = false
			} else if lt != resp.LastSyncSuccess {
				count = 0
				lt = resp.LastSyncSuccess
				cs.clientOK = true
			} else {
				count++
			}
			if count >= 3 {
				cs.clientOK = false
			}
			if resp != nil {
				log.Printf("%s: %d %d %t", clientName, resp.LastSyncSuccess, count, cs.clientOK)
			}
			time.Sleep(5 * time.Second)
		}
	}()

	go func() {
		for {
			ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("workload.spiffe.io", "true")))
			defer cancel()
			stream, err := cs.delegatedClient.SubscribeToX509Bundles(ctx, &agentdelegated.SubscribeToX509BundlesRequest{})
			if err != nil {
				log.Printf("Failed to build x509 client: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			for {
				resp, err := stream.Recv()
				if err != nil {
					log.Printf("Failed to get x509 bundles: %v", err)
					time.Sleep(5 * time.Second)
					break
				}
				bundles, err := parseX509Bundles(resp.GetCaCertificates())
				if err != nil {
					log.Fatalf("Failed to parse x509 bundles: %v", err)
				}
				for _, bundle := range bundles.Bundles() {
					log.Printf("x509 Bundle: %s %d", bundle.TrustDomain(), len(bundle.X509Authorities()))
				}
				log.Printf("Pushing x509 bundle")
				ls.x509BundleUpdate <- x509BundleUpdated{id, bundles}
			}
		}
	}()

	go func() {
		for {
			ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("workload.spiffe.io", "true")))
			defer cancel()
			stream, err := cs.delegatedClient.SubscribeToJWTBundles(ctx, &agentdelegated.SubscribeToJWTBundlesRequest{})
			if err != nil {
				log.Printf("Failed to build jwt client: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			for {
				resp, err := stream.Recv()
				if err != nil {
					log.Printf("Failed to get jwt bundles: %v", err)
					time.Sleep(5 * time.Second)
					break
				}
				bundles := resp.GetBundles()
				jwksBundles := make(map[string]jose.JSONWebKeySet)
				for td, bundle := range bundles {
					log.Printf("jwt Bundle: %s %s", td, string(bundle))
					//log.Printf("jwt Bundle: %s %d", td, len(bundle))
					jwks := new(jose.JSONWebKeySet)
					if err := json.NewDecoder(bytes.NewReader(bundle)).Decode(jwks); err != nil {
						log.Printf("failed to decode key set: %v", err)
						//FIXME whats the right thing to do here?
						continue
					}
					jwksBundles[td] = *jwks
				}
				log.Printf("Pushing jwt bundle")
				ls.jwtBundleUpdate <- jwtBundleUpdated{id, jwksBundles}
			}
		}
	}()
}

func main() {
	var wg sync.WaitGroup
	var jwtWg sync.WaitGroup
	initBundle := true
	jwtInitBundle := true
	wg.Add(1)
	jwtWg.Add(1)
	flag.Parse()
	lf := &peertracker.ListenerFactory{}
        var lis *peertracker.Listener
        var err error
	//FIXME need to consider a config file rather then env vars.
	if os.Getenv("SPIRE_HA_AGENT_VSOCK") == "enabled" {
		port := os.Getenv("SPIRE_HA_AGENT_PORT")
		if port == "" {
			port = "997"
		}
		iport, err := strconv.Atoi(port)
		if err != nil {
			log.Fatalf("failed to parse port: %v", err)
		}
		lis, err = lf.ListenVSock(uint32(iport))
	} else {
		lis, err = lf.ListenUnix("unix", &net.UnixAddr{Name: "/var/run/spire/agent/sockets/main/public/api.sock", Net: "unix"})
	}
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var ls = &server{
		multi: os.Getenv("SPIRE_HA_AGENT_SINGLE") != "enabled",
	}

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.Chain(
		middleware.Preprocess(addWatcherPID),
	))
	s := grpc.NewServer(
		grpc.Creds(peertracker.NewCredentials()),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	setupClient(ls, "clientA", 0, "unix:///var/run/spire/agent/sockets/a/public/api.sock", "unix:///var/run/spire/agent/sockets/a/private/admin.sock", &ls.clients[0])
	setupClient(ls, "clientB", 1, "unix:///var/run/spire/agent/sockets/b/public/api.sock", "unix:///var/run/spire/agent/sockets/b/private/admin.sock", &ls.clients[1])

	go func() {
		for {
			time.Sleep(5 * time.Second)
			log.Printf("Clients: %t %t\n", ls.clients[0].clientOK, ls.clients[1].clientOK)
			//FIXME.... maybe want jwt to happen as soon as it detects not ok. Maybe want to wait on other client on fail to see if they both fail.
		}
	}()

	go func() {
		log.Printf("Listening for x509 bundle updates\n")
		for u := range ls.x509BundleUpdate {
			log.Printf("Got update for %d\n", u.id)
			ls.clients[u.id].bundle = u.bundle
			if ls.clients[0].bundle != nil && ls.clients[1].bundle != nil {
				log.Printf("We got two bundles\n")
				var rawBundles map[string][]byte = make(map[string][]byte)
				for _, bundle := range ls.clients[0].bundle.Bundles() {
					td := bundle.TrustDomain()
					if tdb, ok := ls.clients[1].bundle.Get(td); ok {
						for _, cert := range tdb.X509Authorities() {
							if !bundle.HasX509Authority(cert) {
								bundle.AddX509Authority(cert)
							}
						}
					}
					rawBundles[td.String()] = ConcatRawCertsFromCerts(bundle.X509Authorities())
				}
				if initBundle {
					wg.Done()
					initBundle = false
				}
				if reflect.DeepEqual(ls.rawBundles, rawBundles) {
					log.Printf("x509 bundles unchanged")
				} else {
					log.Printf("x590 bundles changed")
					ls.rawBundles = rawBundles
					ls.bundleLock.Lock()
					if ls.bundleChan != nil {
						close(ls.bundleChan)
					}
					ls.bundleChan = make(chan struct{})
					ls.bundleLock.Unlock()
				}
			}
		}
	}()

	go func() {
		log.Printf("Listening for jwt bundle updates\n")
		for u := range ls.jwtBundleUpdate {
			log.Printf("Got update for %d\n", u.id)
			ls.clients[u.id].jwtBundles = u.bundle
			if ls.clients[0].jwtBundles != nil && ls.clients[1].jwtBundles != nil {
				log.Printf("We got two jwt bundles\n")
				tmpBundles := make(map[string]jose.JSONWebKeySet)
				var rawBundles map[string][]byte = make(map[string][]byte)
				for td, bundle := range ls.clients[0].jwtBundles {
					kids := make(map[string]bool)
					var set jose.JSONWebKeySet
					for _, b := range bundle.Keys {
						kids[b.KeyID] = true
						set.Keys = append(set.Keys, b)
					}
					if tdb, ok := ls.clients[1].jwtBundles[td]; ok {
						for _, b := range tdb.Keys {
							if _, ok := kids[b.KeyID]; !ok {
								set.Keys = append(set.Keys, b)
							}
						}
					}
					tmpBundles[td] = set
//FIXME td's in 1 but not 0. Maybe same with x509?
					res, err := json.Marshal(tmpBundles[td])
					if err != nil {
//FIXME what is the best way to handle this
						log.Printf("Failed to marchal. %v", err)
						continue
					}
					rawBundles[td] = res
				}
				if jwtInitBundle {
					jwtWg.Done()
					jwtInitBundle = false
				}
				if reflect.DeepEqual(ls.rawJwtBundles, rawBundles) {
					log.Printf("jwt bundles unchanged")
				} else {
					log.Printf("jwt bundles changed")
					ls.rawJwtBundles = rawBundles
					ls.bundleLock.Lock()
					if ls.jwtBundleChan != nil {
						close(ls.jwtBundleChan)
					}
					ls.jwtBundleChan = make(chan struct{})
					ls.bundleLock.Unlock()
				}
			}
		}
	}()

	wg.Wait()
	jwtWg.Wait()
	log.Printf("Startup settled")

	workload.RegisterSpiffeWorkloadAPIServer(s, ls)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
