package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/spiffe/spire-ha-agent/pkg/peertracker"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	metadata "google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const haTrustDomainName = "spire-ha"

type brokerX509BundleUpdated struct {
	id      int
	bundles map[string]*x509bundle.Bundle
}

type brokerJWTBundleUpdated struct {
	id      int
	bundles map[string]jose.JSONWebKeySet
}

type brokerClientSet struct {
	client      broker.APIClient
	source      *workloadapi.X509Source
	trustDomain spiffeid.TrustDomain
	x509Bundles map[string]*x509bundle.Bundle
	jwtBundles  map[string]jose.JSONWebKeySet
}

type brokerServer struct {
	x509BundleUpdate chan brokerX509BundleUpdated
	jwtBundleUpdate  chan brokerJWTBundleUpdated
	rawBundles       map[string][]byte
	rawJwtBundles    map[string][]byte
	bundleChan       chan struct{}
	jwtBundleChan    chan struct{}
	bundleLock       sync.RWMutex
	localTD          spiffeid.TrustDomain
	clients          [2]brokerClientSet
	workload.UnimplementedSpiffeWorkloadAPIServer
	multi bool
}

// The broker API requires this metadata on every call or the server
// responds with InvalidArgument.
func brokerMD(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "broker.spiffe.io", "true")
}

func pidWorkloadReference(pid int) *broker.WorkloadReference {
	ref, err := anypb.New(&broker.WorkloadPIDReference{Pid: int32(pid)})
	if err != nil {
		log.Fatalf("failed to build workload reference: %v", err)
	}
	return &broker.WorkloadReference{Reference: ref}
}

// grpc.NewClient does not understand tcp:// targets; rewrite them to the
// dns resolver scheme. unix:// targets pass through natively.
func brokerTarget(addr string) string {
	if strings.HasPrefix(addr, "tcp://") {
		return "dns:///" + strings.TrimPrefix(addr, "tcp://")
	}
	return addr
}

func (bs *brokerServer) currentX509BundleChan() chan struct{} {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()
	return bs.bundleChan
}

func (bs *brokerServer) currentJWTBundleChan() chan struct{} {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()
	return bs.jwtBundleChan
}

func (bs *brokerServer) localTDName() string {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()
	return bs.localTD.Name()
}

func getBrokerX509SVIDs(dctx context.Context, pid int, client broker.APIClient, notify chan *broker.SubscribeToX509SVIDResponse) {
	for {
		upstream, err := client.SubscribeToX509SVID(brokerMD(dctx), &broker.SubscribeToX509SVIDRequest{Reference: pidWorkloadReference(pid)})
		if err != nil {
			if errors.Is(dctx.Err(), context.Canceled) {
				return
			}
			log.Printf("broker x509cert %d upstream error: %v", pid, err)
			time.Sleep(5 * time.Second)
			continue
		}
		for {
			resp, err := upstream.Recv()
			if err != nil {
				if errors.Is(dctx.Err(), context.Canceled) {
					log.Printf("broker x509cert %d canceled", pid)
					return
				}
				log.Printf("broker x509cert %d upstream error2: %v", pid, err)
				time.Sleep(5 * time.Second)
				break
			}
			log.Printf("broker x509cert %d upstream got cert", pid)
			select {
			case notify <- resp:
			case <-dctx.Done():
				return
			}
		}
	}
}

func getBrokerX509Bundles(dctx context.Context, pid int, client broker.APIClient, notify chan *broker.SubscribeToX509BundlesResponse) {
	for {
		upstream, err := client.SubscribeToX509Bundles(brokerMD(dctx), &broker.SubscribeToX509BundlesRequest{Reference: pidWorkloadReference(pid)})
		if err != nil {
			if errors.Is(dctx.Err(), context.Canceled) {
				return
			}
			log.Printf("broker x509bundles %d upstream error: %v", pid, err)
			time.Sleep(5 * time.Second)
			continue
		}
		for {
			resp, err := upstream.Recv()
			if err != nil {
				if errors.Is(dctx.Err(), context.Canceled) {
					log.Printf("broker x509bundles %d canceled", pid)
					return
				}
				log.Printf("broker x509bundles %d upstream error2: %v", pid, err)
				time.Sleep(5 * time.Second)
				break
			}
			select {
			case notify <- resp:
			case <-dctx.Done():
				return
			}
		}
	}
}

func getBrokerJWTBundles(dctx context.Context, pid int, client broker.APIClient, notify chan *broker.SubscribeToJWTBundlesResponse) {
	for {
		upstream, err := client.SubscribeToJWTBundles(brokerMD(dctx), &broker.SubscribeToJWTBundlesRequest{Reference: pidWorkloadReference(pid)})
		if err != nil {
			if errors.Is(dctx.Err(), context.Canceled) {
				return
			}
			log.Printf("broker jwtbundles %d upstream error: %v", pid, err)
			time.Sleep(5 * time.Second)
			continue
		}
		for {
			resp, err := upstream.Recv()
			if err != nil {
				if errors.Is(dctx.Err(), context.Canceled) {
					log.Printf("broker jwtbundles %d canceled", pid)
					return
				}
				log.Printf("broker jwtbundles %d upstream error2: %v", pid, err)
				time.Sleep(5 * time.Second)
				break
			}
			select {
			case notify <- resp:
			case <-dctx.Done():
				return
			}
		}
	}
}

func getBrokerJWT(dctx context.Context, pid int, audience []string, spiffeID string, client broker.APIClient, notify chan *broker.FetchJWTSVIDResponse) {
	resp, err := client.FetchJWTSVID(brokerMD(dctx), &broker.FetchJWTSVIDRequest{
		Reference: pidWorkloadReference(pid),
		Audience:  audience,
		SpiffeId:  spiffeID,
	})
	if err != nil {
		log.Printf("broker jwt %d upstream error: %v", pid, err)
	}
	select {
	case notify <- resp:
	case <-dctx.Done():
	}
}

// Converts a broker SVID response to a workload API response. The per-SVID
// bundle and federated bundles are taken from the merged view of both
// brokers when available so a workload can validate peers minted by either
// server; the response's inline bundles are the fallback until the merged
// state covers that trust domain.
func (bs *brokerServer) brokerResponseToWorkloadResponse(resp *broker.SubscribeToX509SVIDResponse) *workload.X509SVIDResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	res := &workload.X509SVIDResponse{
		FederatedBundles: make(map[string][]byte),
		Crl:              resp.GetCrl(),
	}
	for _, svid := range resp.GetSvids() {
		bundle := svid.GetBundle()
		if id, err := spiffeid.FromString(svid.GetSpiffeId()); err == nil {
			if merged, ok := bs.rawBundles[id.TrustDomain().Name()]; ok {
				bundle = merged
			}
		}
		res.Svids = append(res.Svids, &workload.X509SVID{
			SpiffeId:    svid.GetSpiffeId(),
			X509Svid:    svid.GetX509Svid(),
			X509SvidKey: svid.GetX509SvidKey(),
			Bundle:      bundle,
			Hint:        svid.GetHint(),
		})
	}
	for tdID, raw := range resp.GetFederatedBundles() {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			log.Printf("broker: bad federated bundle trust domain %q: %v", tdID, err)
			continue
		}
		// spire-ha authorities are folded into the local trust domain
		// bundle, never exposed as a federated domain.
		if td.Name() == haTrustDomainName {
			continue
		}
		val := raw
		if merged, ok := bs.rawBundles[td.Name()]; ok {
			val = merged
		}
		res.FederatedBundles[td.Name()] = val
	}
	return res
}

func (bs *brokerServer) brokerBundlesToWorkloadBundleResponse(resps ...*broker.SubscribeToX509BundlesResponse) *workload.X509BundlesResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	res := &workload.X509BundlesResponse{Bundles: make(map[string][]byte)}
	inline := make(map[string][][]byte)
	seenCrl := make(map[string]bool)
	for _, resp := range resps {
		if resp == nil {
			continue
		}
		for _, crl := range resp.GetCrl() {
			if !seenCrl[string(crl)] {
				seenCrl[string(crl)] = true
				res.Crl = append(res.Crl, crl)
			}
		}
		for tdID, raw := range resp.GetBundles() {
			td, err := spiffeid.TrustDomainFromString(tdID)
			if err != nil {
				log.Printf("broker: bad bundle trust domain %q: %v", tdID, err)
				continue
			}
			if td.Name() == haTrustDomainName {
				continue
			}
			inline[td.Name()] = append(inline[td.Name()], raw)
		}
	}
	for name, raws := range inline {
		if merged, ok := bs.rawBundles[name]; ok {
			res.Bundles[name] = merged
			continue
		}
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			continue
		}
		bundle := x509bundle.New(td)
		for _, raw := range raws {
			b, err := x509bundle.ParseRaw(td, raw)
			if err != nil {
				log.Printf("broker: failed to parse bundle for %s: %v", name, err)
				continue
			}
			for _, cert := range b.X509Authorities() {
				bundle.AddX509Authority(cert)
			}
		}
		res.Bundles[name] = ConcatRawCertsFromCerts(bundle.X509Authorities())
	}
	return res
}

func (bs *brokerServer) brokerJWTBundlesToWorkloadResponse(resps ...*broker.SubscribeToJWTBundlesResponse) *workload.JWTBundlesResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	res := &workload.JWTBundlesResponse{Bundles: make(map[string][]byte)}
	inline := make(map[string][][]byte)
	for _, resp := range resps {
		if resp == nil {
			continue
		}
		for tdID, raw := range resp.GetBundles() {
			td, err := spiffeid.TrustDomainFromString(tdID)
			if err != nil {
				log.Printf("broker: bad jwt bundle trust domain %q: %v", tdID, err)
				continue
			}
			if td.Name() == haTrustDomainName {
				continue
			}
			inline[td.Name()] = append(inline[td.Name()], raw)
		}
	}
	for name, raws := range inline {
		if merged, ok := bs.rawJwtBundles[name]; ok {
			res.Bundles[name] = merged
			continue
		}
		var set jose.JSONWebKeySet
		kids := make(map[string]bool)
		for _, raw := range raws {
			jwks := new(jose.JSONWebKeySet)
			if err := json.Unmarshal(raw, jwks); err != nil {
				log.Printf("broker: failed to decode jwt bundle for %s: %v", name, err)
				continue
			}
			for _, k := range jwks.Keys {
				if !kids[k.KeyID] {
					kids[k.KeyID] = true
					set.Keys = append(set.Keys, k)
				}
			}
		}
		out, err := json.Marshal(set)
		if err != nil {
			log.Printf("broker: failed to marshal jwt bundle for %s: %v", name, err)
			continue
		}
		res.Bundles[name] = out
	}
	return res
}

// Fetch X.509-SVIDs for all SPIFFE identities the workload is entitled to,
// as well as related information like trust bundles and CRLs. As this
// information changes, subsequent messages will be streamed from the
// server.
func (s *brokerServer) FetchX509SVID(req *workload.X509SVIDRequest, downstream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	dctx := downstream.Context()
	pid := dctx.Value(callerPIDKey{}).(int)
	log.Printf("broker x509fetch calling pid: %d", pid)

	chan1 := make(chan *broker.SubscribeToX509SVIDResponse)
	chan2 := make(chan *broker.SubscribeToX509SVIDResponse)
	go getBrokerX509SVIDs(dctx, pid, s.clients[0].client, chan1)
	if s.multi {
		go getBrokerX509SVIDs(dctx, pid, s.clients[1].client, chan2)
	}

	var resp *broker.SubscribeToX509SVIDResponse
	select {
	case <-dctx.Done():
		log.Printf("broker x509fetch client disconnected\n")
		return nil
	case resp = <-chan1:
		log.Printf("broker x509fetch got new certs\n")
	case resp = <-chan2:
		log.Printf("broker x509fetch got new certs2\n")
	}

	bundleChan := s.currentX509BundleChan()
	pb := s.brokerResponseToWorkloadResponse(resp)

	for {
		log.Printf("broker: sending back cert/bundle update\n")
		if err := downstream.Send(pb); err != nil {
			return err
		}
		for {
			diff := false

			select {
			case <-dctx.Done():
				log.Printf("broker x509fetch client disconnected\n")
				return nil
			case resp = <-chan1:
				log.Printf("broker x509fetch got new certs\n")
				pb = s.brokerResponseToWorkloadResponse(resp)
				diff = true
			case resp = <-chan2:
				log.Printf("broker x509fetch got new certs2\n")
				pb = s.brokerResponseToWorkloadResponse(resp)
				diff = true
			case <-bundleChan:
				log.Printf("broker x509fetch ca refreshed\n")
				bundleChan = s.currentX509BundleChan()
				npb := s.brokerResponseToWorkloadResponse(resp)
				if !proto.Equal(pb, npb) {
					pb = npb
					diff = true
				}
				log.Printf("diff: %t", diff)
			}
			if diff {
				break
			}
		}
	}
}

// Fetch trust bundles and CRLs. Useful for clients that only need to
// validate SVIDs without obtaining an SVID for themself. As this
// information changes, subsequent messages will be streamed from the
// server.
func (s *brokerServer) FetchX509Bundles(req *workload.X509BundlesRequest, downstream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	dctx := downstream.Context()
	pid := dctx.Value(callerPIDKey{}).(int)
	log.Printf("broker x509bundles calling pid: %d", pid)

	chan1 := make(chan *broker.SubscribeToX509BundlesResponse)
	chan2 := make(chan *broker.SubscribeToX509BundlesResponse)
	go getBrokerX509Bundles(dctx, pid, s.clients[0].client, chan1)
	if s.multi {
		go getBrokerX509Bundles(dctx, pid, s.clients[1].client, chan2)
	}

	var resp1, resp2 *broker.SubscribeToX509BundlesResponse
	select {
	case <-dctx.Done():
		log.Printf("broker x509bundles client disconnected\n")
		return nil
	case resp1 = <-chan1:
		log.Printf("broker x509bundles got new bundles\n")
	case resp2 = <-chan2:
		log.Printf("broker x509bundles got new bundles2\n")
	}

	bundleChan := s.currentX509BundleChan()
	bundles := s.brokerBundlesToWorkloadBundleResponse(resp1, resp2)

	for {
		log.Printf("broker: sending back bundle update\n")
		if err := downstream.Send(bundles); err != nil {
			return err
		}
		for {
			diff := false

			select {
			case <-dctx.Done():
				log.Printf("broker x509bundles client disconnected\n")
				return nil
			case resp1 = <-chan1:
				log.Printf("broker x509bundles got new bundles\n")
			case resp2 = <-chan2:
				log.Printf("broker x509bundles got new bundles2\n")
			case <-bundleChan:
				log.Printf("broker x509bundles ca refreshed\n")
				bundleChan = s.currentX509BundleChan()
			}
			nb := s.brokerBundlesToWorkloadBundleResponse(resp1, resp2)
			if !proto.Equal(bundles, nb) {
				bundles = nb
				diff = true
			}
			if diff {
				break
			}
		}
	}
}

// Fetch JWT-SVIDs for all SPIFFE identities the workload is entitled to,
// for the requested audience. If an optional SPIFFE ID is requested, only
// the JWT-SVID for that SPIFFE ID is returned.
func (s *brokerServer) FetchJWTSVID(dctx context.Context, downstream *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	log.Printf("broker FetchJWTSVID")
	pid := dctx.Value(callerPIDKey{}).(int)

	failLimit := 1
	chan1 := make(chan *broker.FetchJWTSVIDResponse)
	go getBrokerJWT(dctx, pid, downstream.Audience, downstream.SpiffeId, s.clients[0].client, chan1)
	if s.multi {
		failLimit = 2
		go getBrokerJWT(dctx, pid, downstream.Audience, downstream.SpiffeId, s.clients[1].client, chan1)
	}

	var count int
	var resp *broker.FetchJWTSVIDResponse
	for {
		select {
		case <-dctx.Done():
			log.Printf("broker jwt client disconnected\n")
			return nil, nil
		case resp = <-chan1:
			log.Printf("broker jwt got new token\n")
			count++
		}
		if resp != nil {
			break
		}
		if count >= failLimit {
			return nil, status.Errorf(codes.Unavailable, "failed to talk to either agent")
		}
	}

	svids := make([]*workload.JWTSVID, 0)
	for _, svid := range resp.Svids {
		svids = append(svids, &workload.JWTSVID{
			SpiffeId: svid.SpiffeId,
			Svid:     svid.Svid,
			Hint:     svid.Hint,
		})
	}
	return &workload.JWTSVIDResponse{Svids: svids}, nil
}

// Fetches the JWT bundles, formatted as JWKS documents, keyed by the
// SPIFFE ID of the trust domain. As this information changes, subsequent
// messages will be streamed from the server.
func (s *brokerServer) FetchJWTBundles(req *workload.JWTBundlesRequest, downstream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	dctx := downstream.Context()
	pid := dctx.Value(callerPIDKey{}).(int)
	log.Printf("broker jwtbundles calling pid: %d", pid)

	chan1 := make(chan *broker.SubscribeToJWTBundlesResponse)
	chan2 := make(chan *broker.SubscribeToJWTBundlesResponse)
	go getBrokerJWTBundles(dctx, pid, s.clients[0].client, chan1)
	if s.multi {
		go getBrokerJWTBundles(dctx, pid, s.clients[1].client, chan2)
	}

	var resp1, resp2 *broker.SubscribeToJWTBundlesResponse
	select {
	case <-dctx.Done():
		log.Printf("broker jwtbundles client disconnected\n")
		return nil
	case resp1 = <-chan1:
		log.Printf("broker jwtbundles got new bundles\n")
	case resp2 = <-chan2:
		log.Printf("broker jwtbundles got new bundles2\n")
	}

	bundleChan := s.currentJWTBundleChan()
	bundles := s.brokerJWTBundlesToWorkloadResponse(resp1, resp2)

	for {
		log.Printf("broker: sending back jwt bundle update\n")
		if err := downstream.Send(bundles); err != nil {
			return err
		}
		for {
			diff := false

			select {
			case <-dctx.Done():
				log.Printf("broker jwtbundles client disconnected\n")
				return nil
			case resp1 = <-chan1:
				log.Printf("broker jwtbundles got new bundles\n")
			case resp2 = <-chan2:
				log.Printf("broker jwtbundles got new bundles2\n")
			case <-bundleChan:
				log.Printf("broker jwtbundles ca refreshed\n")
				bundleChan = s.currentJWTBundleChan()
			}
			nb := s.brokerJWTBundlesToWorkloadResponse(resp1, resp2)
			if !proto.Equal(bundles, nb) {
				bundles = nb
				diff = true
			}
			if diff {
				break
			}
		}
	}
}

// Validates a JWT-SVID against the requested audience. Returns the SPIFFE
// ID of the JWT-SVID and JWT claims.
func (s *brokerServer) ValidateJWTSVID(ctx context.Context, downstream *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	pid := ctx.Value(callerPIDKey{}).(int)
	log.Printf("Calling pid: %d", pid)
	log.Printf("broker ValidateJWTSVID")
	return nil, status.Errorf(codes.Unimplemented, "method ValidateJWTSVID not implemented")
}

func setupBrokerClient(bs *brokerServer, clientName string, id int, brokerAddr string, workloadAddr string, cs *brokerClientSet) {
	var source *workloadapi.X509Source
	for {
		var err error
		log.Printf("%s: obtaining our identity from %s", clientName, workloadAddr)
		source, err = workloadapi.NewX509Source(context.Background(), workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAddr)))
		if err == nil {
			break
		}
		log.Printf("%s: failed to create X509 source from %s: %v", clientName, workloadAddr, err)
		time.Sleep(5 * time.Second)
	}
	// The source is intentionally never closed: it keeps rotating our SVID
	// so the broker mTLS client certificate stays fresh.
	cs.source = source
	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("%s: failed to get our own SVID: %v", clientName, err)
	}
	cs.trustDomain = svid.ID.TrustDomain()
	log.Printf("%s: our identity: %s", clientName, svid.ID)

	bs.bundleLock.Lock()
	if bs.localTD.IsZero() {
		bs.localTD = cs.trustDomain
		log.Printf("Our trust domain detected as: %s\n", bs.localTD.Name())
	} else if bs.localTD != cs.trustDomain {
		log.Fatalf("%s: trust domain mismatch: %s != %s", clientName, cs.trustDomain, bs.localTD)
	}
	bs.bundleLock.Unlock()

	serverID, err := spiffeid.FromPath(cs.trustDomain, "/spire-ha-agent")
	if err != nil {
		log.Fatalf("%s: failed to build broker server ID: %v", clientName, err)
	}
	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeID(serverID))
	conn, err := grpc.NewClient(brokerTarget(brokerAddr), grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("%s: failed to create broker client for %s: %v", clientName, brokerAddr, err)
	}
	cs.client = broker.NewAPIClient(conn)

	// Bundle subscriptions are scoped to a workload; we subscribe as
	// ourselves, so the spire-ha-agent's own registration entry (and its
	// federates_with list) controls which trust domains we serve.
	pid := os.Getpid()

	go func() {
		for {
			stream, err := cs.client.SubscribeToX509Bundles(brokerMD(context.Background()), &broker.SubscribeToX509BundlesRequest{Reference: pidWorkloadReference(pid)})
			if err != nil {
				log.Printf("%s: failed to subscribe to x509 bundles: %v", clientName, err)
				time.Sleep(5 * time.Second)
				continue
			}
			for {
				resp, err := stream.Recv()
				if err != nil {
					log.Printf("%s: failed to get x509 bundles: %v", clientName, err)
					time.Sleep(5 * time.Second)
					break
				}
				set, err := parseX509Bundles(resp.GetBundles())
				if err != nil {
					log.Printf("%s: failed to parse x509 bundles: %v", clientName, err)
					continue
				}
				bundles := make(map[string]*x509bundle.Bundle)
				for _, bundle := range set.Bundles() {
					log.Printf("%s: x509 Bundle: %s %d", clientName, bundle.TrustDomain(), len(bundle.X509Authorities()))
					bundles[bundle.TrustDomain().Name()] = bundle
				}
				log.Printf("%s: pushing x509 bundle", clientName)
				bs.x509BundleUpdate <- brokerX509BundleUpdated{id, bundles}
			}
		}
	}()

	go func() {
		for {
			stream, err := cs.client.SubscribeToJWTBundles(brokerMD(context.Background()), &broker.SubscribeToJWTBundlesRequest{Reference: pidWorkloadReference(pid)})
			if err != nil {
				log.Printf("%s: failed to subscribe to jwt bundles: %v", clientName, err)
				time.Sleep(5 * time.Second)
				continue
			}
			for {
				resp, err := stream.Recv()
				if err != nil {
					log.Printf("%s: failed to get jwt bundles: %v", clientName, err)
					time.Sleep(5 * time.Second)
					break
				}
				jwksBundles := make(map[string]jose.JSONWebKeySet)
				for tdID, bundle := range resp.GetBundles() {
					td, err := spiffeid.TrustDomainFromString(tdID)
					if err != nil {
						log.Printf("%s: bad jwt bundle trust domain %q: %v", clientName, tdID, err)
						continue
					}
					log.Printf("%s: jwt Bundle: %s %d", clientName, td.Name(), len(bundle))
					jwks := new(jose.JSONWebKeySet)
					if err := json.Unmarshal(bundle, jwks); err != nil {
						log.Printf("%s: failed to decode key set: %v", clientName, err)
						continue
					}
					jwksBundles[td.Name()] = *jwks
				}
				log.Printf("%s: pushing jwt bundle", clientName)
				bs.jwtBundleUpdate <- brokerJWTBundleUpdated{id, jwksBundles}
			}
		}
	}()
}

func brokerMain() {
	var wg sync.WaitGroup
	var jwtWg sync.WaitGroup
	wg.Add(1)
	jwtWg.Add(1)
	lf := &peertracker.ListenerFactory{}
	var lis *peertracker.Listener
	var err error
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
		socket := os.Getenv("SPIRE_HA_AGENT_SOCK")
		if socket == "" {
			socket = "/var/run/spire/agent/sockets/main/public/api.sock"
		}
		_ = os.Remove(socket)
		lis, err = lf.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err := os.Chmod(socket, 0777); err != nil {
			log.Fatalf("failed to permission the socket: %v", err)
		}
	}
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	bs := &brokerServer{
		multi:            os.Getenv("SPIRE_HA_AGENT_SINGLE") != "enabled",
		x509BundleUpdate: make(chan brokerX509BundleUpdated),
		jwtBundleUpdate:  make(chan brokerJWTBundleUpdated),
	}

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.Chain(
		middleware.Preprocess(addWatcherPID),
	))
	s := grpc.NewServer(
		grpc.Creds(peertracker.NewCredentials()),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	abroker := "unix:///var/run/spire/agent/sockets/a/broker/broker.sock"
	bbroker := "unix:///var/run/spire/agent/sockets/b/broker/broker.sock"
	aworkload := "unix:///var/run/spire/agent/sockets/a/public/api.sock"
	bworkload := "unix:///var/run/spire/agent/sockets/b/public/api.sock"
	abrokerName := "SPIRE_HA_AGENT_BROKER"
	aworkloadName := "SPIRE_HA_AGENT_WORKLOAD_SOCKET"
	if bs.multi {
		abrokerName = "SPIRE_HA_AGENT_BROKER_A"
		aworkloadName = "SPIRE_HA_AGENT_WORKLOAD_SOCKET_A"
	}
	if os.Getenv(abrokerName) != "" {
		abroker = os.Getenv(abrokerName)
	}
	if os.Getenv(aworkloadName) != "" {
		aworkload = os.Getenv(aworkloadName)
	}
	go setupBrokerClient(bs, "brokerA", 0, abroker, aworkload, &bs.clients[0])
	if bs.multi {
		if os.Getenv("SPIRE_HA_AGENT_BROKER_B") != "" {
			bbroker = os.Getenv("SPIRE_HA_AGENT_BROKER_B")
		}
		if os.Getenv("SPIRE_HA_AGENT_WORKLOAD_SOCKET_B") != "" {
			bworkload = os.Getenv("SPIRE_HA_AGENT_WORKLOAD_SOCKET_B")
		}
		go setupBrokerClient(bs, "brokerB", 1, bbroker, bworkload, &bs.clients[1])
	}

	go func() {
		initBundle := true
		log.Printf("Listening for x509 bundle updates\n")
		for u := range bs.x509BundleUpdate {
			log.Printf("Got x509 update for %d\n", u.id)
			log.Printf("Bundle count on update: %d\n", len(u.bundles))
			if len(u.bundles) < 1 {
				log.Printf("Bad bundle pushed by the broker.\n")
				os.Exit(1)
			}
			if _, ok := u.bundles[haTrustDomainName]; !ok && bs.multi {
				log.Printf("spire-ha trust bundle not found. Check the spire-ha-agent entry federation.\n")
			}
			bs.clients[u.id].x509Bundles = u.bundles

			totalBundles := len(bs.clients[0].x509Bundles) + len(bs.clients[1].x509Bundles)
			if totalBundles > 1 || !bs.multi {
				log.Printf("We got %d x509 bundles\n", totalBundles)
				localName := bs.localTDName()
				rawBundles := make(map[string][]byte)
				names := make(map[string]bool)
				for i := range bs.clients {
					for name := range bs.clients[i].x509Bundles {
						if name != haTrustDomainName {
							names[name] = true
						}
					}
				}
				for name := range names {
					td, err := spiffeid.TrustDomainFromString(name)
					if err != nil {
						log.Printf("Failed to parse trust domain %q. This should not happen.\n", name)
						continue
					}
					bundle := x509bundle.New(td)
					for i := range bs.clients {
						if b, ok := bs.clients[i].x509Bundles[name]; ok {
							for _, cert := range b.X509Authorities() {
								bundle.AddX509Authority(cert)
							}
						}
						// Fold the spire-ha cross-trust authorities into the
						// local trust domain bundle.
						if name == localName {
							if b, ok := bs.clients[i].x509Bundles[haTrustDomainName]; ok {
								for _, cert := range b.X509Authorities() {
									bundle.AddX509Authority(cert)
								}
							}
						}
					}
					rawBundles[name] = ConcatRawCertsFromCerts(bundle.X509Authorities())
				}
				if initBundle {
					log.Printf("x509 inited")
					wg.Done()
					initBundle = false
				}
				bs.bundleLock.Lock()
				if reflect.DeepEqual(bs.rawBundles, rawBundles) {
					log.Printf("x509 bundles unchanged")
				} else {
					log.Printf("x509 bundles changed")
					bs.rawBundles = rawBundles
					if bs.bundleChan != nil {
						close(bs.bundleChan)
					}
					bs.bundleChan = make(chan struct{})
				}
				bs.bundleLock.Unlock()
			}
		}
	}()

	go func() {
		jwtInitBundle := true
		log.Printf("Listening for jwt bundle updates\n")
		for u := range bs.jwtBundleUpdate {
			log.Printf("Got jwt update for %d\n", u.id)
			log.Printf("JWT bundle count on update: %d\n", len(u.bundles))
			if len(u.bundles) < 1 {
				log.Printf("Bad JWT bundle pushed by the broker.\n")
				os.Exit(1)
			}
			if _, ok := u.bundles[haTrustDomainName]; !ok && bs.multi {
				log.Printf("spire-ha trust bundle not found in JWT trust bundle. Check the spire-ha-agent entry federation.\n")
			}
			bs.clients[u.id].jwtBundles = u.bundles

			totalBundles := len(bs.clients[0].jwtBundles) + len(bs.clients[1].jwtBundles)
			if totalBundles > 1 || !bs.multi {
				log.Printf("We got %d jwt bundles\n", totalBundles)
				localName := bs.localTDName()
				rawBundles := make(map[string][]byte)
				names := make(map[string]bool)
				for i := range bs.clients {
					for name := range bs.clients[i].jwtBundles {
						if name != haTrustDomainName {
							names[name] = true
						}
					}
				}
				for name := range names {
					var set jose.JSONWebKeySet
					kids := make(map[string]bool)
					addKeys := func(ks jose.JSONWebKeySet) {
						for _, k := range ks.Keys {
							if !kids[k.KeyID] {
								kids[k.KeyID] = true
								set.Keys = append(set.Keys, k)
							}
						}
					}
					for i := range bs.clients {
						if ks, ok := bs.clients[i].jwtBundles[name]; ok {
							addKeys(ks)
						}
						// Fold the spire-ha cross-trust keys into the local
						// trust domain bundle.
						if name == localName {
							if ks, ok := bs.clients[i].jwtBundles[haTrustDomainName]; ok {
								addKeys(ks)
							}
						}
					}
					res, err := json.Marshal(set)
					if err != nil {
						log.Printf("Failed to marshal jwt bundle for %s. %v", name, err)
						continue
					}
					rawBundles[name] = res
				}
				if jwtInitBundle {
					log.Printf("jwt inited")
					jwtWg.Done()
					jwtInitBundle = false
				}
				bs.bundleLock.Lock()
				if reflect.DeepEqual(bs.rawJwtBundles, rawBundles) {
					log.Printf("jwt bundles unchanged")
				} else {
					log.Printf("jwt bundles changed")
					bs.rawJwtBundles = rawBundles
					if bs.jwtBundleChan != nil {
						close(bs.jwtBundleChan)
					}
					bs.jwtBundleChan = make(chan struct{})
				}
				bs.bundleLock.Unlock()
			}
		}
	}()

	wg.Wait()
	jwtWg.Wait()
	log.Printf("Startup settled")

	workload.RegisterSpiffeWorkloadAPIServer(s, bs)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
