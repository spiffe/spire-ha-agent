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
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/spire-ha-agent/pkg/peertracker"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	metadata "google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const haTrustDomainName = "spire-ha"

// bundlesSettled reports whether the delivered bundle maps cover both
// sides' authorities, i.e. workloads served from them can validate SVIDs
// minted by either side (anything less is split brain). Each side loads the
// other side's trust material into its own spire-ha bundle, so a single
// side is complete once it delivers its local bundle plus its spire-ha
// bundle; and both sides' local bundles together are complete with no
// spire-ha bundle at all. In single mode there is no other side to cover.
func bundlesSettled[V any](a, b map[string]V, localName string, multi bool) bool {
	if !multi {
		return len(a)+len(b) > 0
	}
	has := func(m map[string]V, name string) bool {
		_, ok := m[name]
		return ok
	}
	if has(a, localName) && has(a, haTrustDomainName) {
		return true
	}
	if has(b, localName) && has(b, haTrustDomainName) {
		return true
	}
	return has(a, localName) && has(b, localName)
}

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
	// Whether each of this side's two global bundle subscriptions is
	// currently established. These are the liveness signal: the streams are
	// quiet when nothing changes, so health means "the subscription is up",
	// never "we heard from it recently".
	x509SubUp bool
	jwtSubUp  bool
}

type brokerServer struct {
	x509BundleUpdate chan brokerX509BundleUpdated
	jwtBundleUpdate  chan brokerJWTBundleUpdated
	rawBundles       map[string][]byte
	rawJwtBundles    map[string][]byte
	// The merged bundles in parsed form, for verifying downstream broker
	// endpoint clients, and the SVID that endpoint serves as its own
	// certificate. Both are unused when the endpoint is not configured.
	mergedX509    map[string]*x509bundle.Bundle
	serverSVID    *x509svid.SVID
	bundleChan    chan struct{}
	jwtBundleChan chan struct{}
	// Closed and replaced whenever an upstream side's client becomes
	// available, so streams opened while a side was absent can start that
	// side's pump instead of staying pinned to whoever was up at open time.
	// Unlike bundleChan this is created up front: it fires after startup has
	// settled, so a handler that captured a nil channel would never wake.
	clientsChan chan struct{}
	metrics     *brokerMetrics
	bundleLock  sync.RWMutex
	localTD     spiffeid.TrustDomain
	clients     [2]brokerClientSet
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

func (bs *brokerServer) currentClientsChan() chan struct{} {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()
	return bs.clientsChan
}

// The upstream clients as of now. A side that has not finished setup yet is
// nil; callers that hold a long-lived stream must re-read this on a
// currentClientsChan wake rather than trusting the value they opened with.
func (bs *brokerServer) upstreamClients() (broker.APIClient, broker.APIClient) {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()
	return bs.clients[0].client, bs.clients[1].client
}

// Which upstream sides currently have a client, for logging: none, a, b or
// a+b. In single mode only side a exists.
func (bs *brokerServer) sidesAvailable() string {
	c0, c1 := bs.upstreamClients()
	switch {
	case c0 != nil && c1 != nil:
		return "a+b"
	case c0 != nil:
		return "a"
	case c1 != nil:
		return "b"
	default:
		return "none"
	}
}

func sideName(id int) string {
	if id == 0 {
		return "a"
	}
	return "b"
}

// Records whether one of a side's global bundle subscriptions is established,
// logging and exporting only on a transition so a healthy side stays quiet.
// cause is the error that took it down, nil when coming up.
func (bs *brokerServer) markSubscription(id int, clientName, stream string, up bool, cause error) {
	bs.bundleLock.Lock()
	var prev bool
	switch stream {
	case "x509":
		prev = bs.clients[id].x509SubUp
		bs.clients[id].x509SubUp = up
	case "jwt":
		prev = bs.clients[id].jwtSubUp
		bs.clients[id].jwtSubUp = up
	}
	changed := prev != up
	if changed && bs.metrics != nil {
		// Published under the same lock that computes it. A side's two
		// subscriptions recover concurrently, and writing the aggregate after
		// releasing the lock lets the goroutine that computed it before the
		// other stream came up land last, pinning the side to down while both
		// per-stream gauges read up.
		sideUp := bs.clients[id].x509SubUp && bs.clients[id].jwtSubUp
		bs.metrics.upstreamUp.WithLabelValues(sideName(id), stream).Set(boolGauge(up))
		bs.metrics.upstreamSideUp.WithLabelValues(sideName(id)).Set(boolGauge(sideUp))
	}
	bs.bundleLock.Unlock()

	if !changed {
		return
	}
	if up {
		log.Printf("%s: %s bundle subscription up", clientName, stream)
	} else {
		log.Printf("%s: %s bundle subscription down: %v", clientName, stream, cause)
	}
}

func boolGauge(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// Whether every one of a side's global bundle subscriptions is established.
func (bs *brokerServer) sideHealthy(id int) bool {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()
	return bs.clients[id].x509SubUp && bs.clients[id].jwtSubUp
}

// Which upstream sides are currently serving us: none, a, b or a+b. Unlike
// sidesAvailable this can go back down, because it tracks the subscriptions
// rather than whether setup ever completed.
func (bs *brokerServer) sidesHealthy() string {
	a := bs.sideHealthy(0)
	b := bs.multi && bs.sideHealthy(1)
	switch {
	case a && b:
		return "a+b"
	case a:
		return "a"
	case b:
		return "b"
	default:
		return "none"
	}
}

// Starts the upstream pump for every side that has a client and does not
// already have one on this stream, recording it in started. Streams call
// this when they open and again on every currentClientsChan wake, so a side
// that finishes setup after the stream opened joins it rather than being
// ignored for the life of the stream. Reports whether anything started.
func (bs *brokerServer) startPumps(started *[2]bool, start func(id int, client broker.APIClient)) bool {
	c0, c1 := bs.upstreamClients()
	joined := false
	for id, client := range [2]broker.APIClient{c0, c1} {
		if id == 1 && !bs.multi {
			continue
		}
		if client == nil || started[id] {
			continue
		}
		started[id] = true
		start(id, client)
		joined = true
	}
	return joined
}

func (bs *brokerServer) localTDName() string {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()
	return bs.localTD.Name()
}

// The workload reference is passed through verbatim rather than built from
// a PID here: the downstream broker endpoint forwards its caller's own
// reference, which may be any type the upstream attestors understand. tag
// identifies the stream in logs (a PID for workload API callers, the
// broker's SPIFFE ID for endpoint callers).
func getBrokerX509SVIDs(dctx context.Context, ref *broker.WorkloadReference, tag string, client broker.APIClient, notify chan *broker.SubscribeToX509SVIDResponse) {
	// A side that never finished setup (e.g. absent since our startup) has
	// no client yet; the other side's pump serves the stream alone.
	if client == nil {
		return
	}
	for {
		upstream, err := client.SubscribeToX509SVID(brokerMD(dctx), &broker.SubscribeToX509SVIDRequest{Reference: ref})
		if err != nil {
			if errors.Is(dctx.Err(), context.Canceled) {
				return
			}
			log.Printf("broker x509cert %s upstream error: %v", tag, err)
			time.Sleep(5 * time.Second)
			continue
		}
		for {
			resp, err := upstream.Recv()
			if err != nil {
				if errors.Is(dctx.Err(), context.Canceled) {
					log.Printf("broker x509cert %s canceled", tag)
					return
				}
				log.Printf("broker x509cert %s upstream error2: %v", tag, err)
				time.Sleep(5 * time.Second)
				break
			}
			log.Printf("broker x509cert %s upstream got cert", tag)
			select {
			case notify <- resp:
			case <-dctx.Done():
				return
			}
		}
	}
}

func getBrokerX509Bundles(dctx context.Context, ref *broker.WorkloadReference, tag string, client broker.APIClient, notify chan *broker.SubscribeToX509BundlesResponse) {
	if client == nil {
		return
	}
	for {
		upstream, err := client.SubscribeToX509Bundles(brokerMD(dctx), &broker.SubscribeToX509BundlesRequest{Reference: ref})
		if err != nil {
			if errors.Is(dctx.Err(), context.Canceled) {
				return
			}
			log.Printf("broker x509bundles %s upstream error: %v", tag, err)
			time.Sleep(5 * time.Second)
			continue
		}
		for {
			resp, err := upstream.Recv()
			if err != nil {
				if errors.Is(dctx.Err(), context.Canceled) {
					log.Printf("broker x509bundles %s canceled", tag)
					return
				}
				log.Printf("broker x509bundles %s upstream error2: %v", tag, err)
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

func getBrokerJWTBundles(dctx context.Context, ref *broker.WorkloadReference, tag string, client broker.APIClient, notify chan *broker.SubscribeToJWTBundlesResponse) {
	if client == nil {
		return
	}
	for {
		upstream, err := client.SubscribeToJWTBundles(brokerMD(dctx), &broker.SubscribeToJWTBundlesRequest{Reference: ref})
		if err != nil {
			if errors.Is(dctx.Err(), context.Canceled) {
				return
			}
			log.Printf("broker jwtbundles %s upstream error: %v", tag, err)
			time.Sleep(5 * time.Second)
			continue
		}
		for {
			resp, err := upstream.Recv()
			if err != nil {
				if errors.Is(dctx.Err(), context.Canceled) {
					log.Printf("broker jwtbundles %s canceled", tag)
					return
				}
				log.Printf("broker jwtbundles %s upstream error2: %v", tag, err)
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

func getBrokerJWT(dctx context.Context, ref *broker.WorkloadReference, tag string, audience []string, spiffeID string, client broker.APIClient, notify chan *broker.FetchJWTSVIDResponse) {
	var resp *broker.FetchJWTSVIDResponse
	// A side that never finished setup has no client yet; report the nil
	// response so the caller counts it as a failed side.
	if client != nil {
		var err error
		resp, err = client.FetchJWTSVID(brokerMD(dctx), &broker.FetchJWTSVIDRequest{
			Reference: ref,
			Audience:  audience,
			SpiffeId:  spiffeID,
		})
		if err != nil {
			log.Printf("broker jwt %s upstream error: %v", tag, err)
			resp = nil
		}
	}
	select {
	case notify <- resp:
	case <-dctx.Done():
	}
}

// Builds the per-SVID bundles (index-aligned with resp.Svids) and the
// federated bundles for one upstream SVID response, both keyed by bare trust
// domain name.
//
// An SVID's own trust domain is the local HA one, so its bundle is served
// from the merged A+B+spire-ha union: that is what lets a workload validate
// a peer minted by the other server. The response's inline bundle is the
// fallback until the merge covers that domain. Federated domains are passed
// through untouched (see the loop below), and spire-ha is folded away
// entirely -- its authorities live in the local trust domain bundle and it is
// never exposed as a federated domain.
//
// Shared with the downstream broker endpoint, which re-keys the result by
// trust domain SPIFFE ID as the Broker API requires. Caller must hold
// bundleLock (read).
func (bs *brokerServer) mergeSVIDParts(resp *broker.SubscribeToX509SVIDResponse) ([][]byte, map[string][]byte) {
	// Read directly rather than via localTDName(): callers already hold
	// bundleLock for read, and re-acquiring RLock deadlocks if a writer has
	// queued in between.
	localName := bs.localTD.Name()

	bundles := make([][]byte, 0, len(resp.GetSvids()))
	for _, svid := range resp.GetSvids() {
		bundle := svid.GetBundle()
		if id, err := spiffeid.FromString(svid.GetSpiffeId()); err == nil && id.TrustDomain().Name() == localName {
			if merged, ok := bs.rawBundles[localName]; ok {
				bundle = merged
			}
		}
		bundles = append(bundles, bundle)
	}
	federated := make(map[string][]byte)
	for tdID, raw := range resp.GetFederatedBundles() {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			log.Printf("broker: bad federated bundle trust domain %q: %v", tdID, err)
			continue
		}
		if td.Name() == haTrustDomainName {
			continue
		}
		// Passed through from the caller's own upstream response, never
		// substituted from our merged view: both sides are expected to carry
		// the same federation config, and the caller's federates_with list
		// is configured on its own registration entry, not on ours.
		federated[td.Name()] = raw
	}
	return bundles, federated
}

func (bs *brokerServer) brokerResponseToWorkloadResponse(resp *broker.SubscribeToX509SVIDResponse) *workload.X509SVIDResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	svidBundles, federated := bs.mergeSVIDParts(resp)
	res := &workload.X509SVIDResponse{
		FederatedBundles: federated,
		Crl:              resp.GetCrl(),
	}
	for i, svid := range resp.GetSvids() {
		res.Svids = append(res.Svids, &workload.X509SVID{
			SpiffeId:    svid.GetSpiffeId(),
			X509Svid:    svid.GetX509Svid(),
			X509SvidKey: svid.GetX509SvidKey(),
			Bundle:      svidBundles[i],
			Hint:        svid.GetHint(),
		})
	}
	return res
}

// Merges X509 bundle responses from both upstream brokers into a map keyed
// by bare trust domain name, plus the deduplicated CRLs. The local trust
// domain is served from the merged A+B+spire-ha union; every other domain is
// the union of whatever the caller's own responses carried for it. spire-ha
// is folded away. Caller must hold bundleLock (read).
func (bs *brokerServer) mergeX509BundleMaps(resps ...*broker.SubscribeToX509BundlesResponse) (map[string][]byte, [][]byte) {
	localName := bs.localTD.Name()
	bundles := make(map[string][]byte)
	var crls [][]byte
	inline := make(map[string][][]byte)
	seenCrl := make(map[string]bool)
	for _, resp := range resps {
		if resp == nil {
			continue
		}
		for _, crl := range resp.GetCrl() {
			if !seenCrl[string(crl)] {
				seenCrl[string(crl)] = true
				crls = append(crls, crl)
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
		// Only the local trust domain is served from the merged view (the
		// A+B+spire-ha union that makes it HA). Federated domains come
		// straight from the caller's own responses.
		if name == localName {
			if merged, ok := bs.rawBundles[name]; ok {
				bundles[name] = merged
				continue
			}
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
		bundles[name] = ConcatRawCertsFromCerts(bundle.X509Authorities())
	}
	return bundles, crls
}

func (bs *brokerServer) brokerBundlesToWorkloadBundleResponse(resps ...*broker.SubscribeToX509BundlesResponse) *workload.X509BundlesResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	bundles, crls := bs.mergeX509BundleMaps(resps...)
	return &workload.X509BundlesResponse{Bundles: bundles, Crl: crls}
}

// Merges JWT bundle responses from both upstream brokers into a map keyed by
// bare trust domain name. The local trust domain is served from the merged
// A+B+spire-ha union; every other domain is a KeyID-deduped union of
// whatever the caller's own responses carried for it. spire-ha is folded
// away. Caller must hold bundleLock (read).
func (bs *brokerServer) mergeJWTBundleMaps(resps ...*broker.SubscribeToJWTBundlesResponse) map[string][]byte {
	localName := bs.localTD.Name()
	bundles := make(map[string][]byte)
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
		// Merged view for the local trust domain only; federated domains
		// come straight from the caller's own responses.
		if name == localName {
			if merged, ok := bs.rawJwtBundles[name]; ok {
				bundles[name] = merged
				continue
			}
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
		bundles[name] = out
	}
	return bundles
}

func (bs *brokerServer) brokerJWTBundlesToWorkloadResponse(resps ...*broker.SubscribeToJWTBundlesResponse) *workload.JWTBundlesResponse {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	return &workload.JWTBundlesResponse{Bundles: bs.mergeJWTBundleMaps(resps...)}
}

// Fetch X.509-SVIDs for all SPIFFE identities the workload is entitled to,
// as well as related information like trust bundles and CRLs. As this
// information changes, subsequent messages will be streamed from the
// server.
func (s *brokerServer) FetchX509SVID(req *workload.X509SVIDRequest, downstream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	dctx := downstream.Context()
	pid := dctx.Value(callerPIDKey{}).(int)
	log.Printf("broker x509fetch calling pid: %d", pid)

	ref := pidWorkloadReference(pid)
	tag := strconv.Itoa(pid)
	chan1 := make(chan *broker.SubscribeToX509SVIDResponse)
	chan2 := make(chan *broker.SubscribeToX509SVIDResponse)
	var started [2]bool
	startPump := func(id int, client broker.APIClient) {
		if id == 0 {
			go getBrokerX509SVIDs(dctx, ref, tag, client, chan1)
		} else {
			go getBrokerX509SVIDs(dctx, ref, tag, client, chan2)
		}
	}
	clientsChan := s.currentClientsChan()
	s.startPumps(&started, startPump)
	log.Printf("broker x509fetch pid=%d: upstream sides available: %s", pid, s.sidesAvailable())

	var resp *broker.SubscribeToX509SVIDResponse
	for resp == nil {
		select {
		case <-dctx.Done():
			log.Printf("broker x509fetch client disconnected\n")
			return nil
		case resp = <-chan1:
			log.Printf("broker x509fetch got new certs\n")
		case resp = <-chan2:
			log.Printf("broker x509fetch got new certs2\n")
		case <-clientsChan:
			// A side finished setup after we opened. Without this the only
			// side we ever ask is whoever was up at open time, so a
			// workload only the late side knows about never gets an answer.
			clientsChan = s.currentClientsChan()
			if s.startPumps(&started, startPump) {
				log.Printf("broker x509fetch pid=%d: upstream side joined, starting pump (now %s)", pid, s.sidesAvailable())
			}
		}
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
			case <-clientsChan:
				clientsChan = s.currentClientsChan()
				if s.startPumps(&started, startPump) {
					log.Printf("broker x509fetch pid=%d: upstream side joined, starting pump (now %s)", pid, s.sidesAvailable())
				}
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

	ref := pidWorkloadReference(pid)
	tag := strconv.Itoa(pid)
	chan1 := make(chan *broker.SubscribeToX509BundlesResponse)
	chan2 := make(chan *broker.SubscribeToX509BundlesResponse)
	var started [2]bool
	startPump := func(id int, client broker.APIClient) {
		if id == 0 {
			go getBrokerX509Bundles(dctx, ref, tag, client, chan1)
		} else {
			go getBrokerX509Bundles(dctx, ref, tag, client, chan2)
		}
	}
	clientsChan := s.currentClientsChan()
	s.startPumps(&started, startPump)
	log.Printf("broker x509bundles pid=%d: upstream sides available: %s", pid, s.sidesAvailable())

	var resp1, resp2 *broker.SubscribeToX509BundlesResponse
	for resp1 == nil && resp2 == nil {
		select {
		case <-dctx.Done():
			log.Printf("broker x509bundles client disconnected\n")
			return nil
		case resp1 = <-chan1:
			log.Printf("broker x509bundles got new bundles\n")
		case resp2 = <-chan2:
			log.Printf("broker x509bundles got new bundles2\n")
		case <-clientsChan:
			clientsChan = s.currentClientsChan()
			if s.startPumps(&started, startPump) {
				log.Printf("broker x509bundles pid=%d: upstream side joined, starting pump (now %s)", pid, s.sidesAvailable())
			}
		}
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
			case <-clientsChan:
				clientsChan = s.currentClientsChan()
				if s.startPumps(&started, startPump) {
					log.Printf("broker x509bundles pid=%d: upstream side joined, starting pump (now %s)", pid, s.sidesAvailable())
				}
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

	// Unary, so the clients are re-read on every call and a late side is
	// picked up without any of the stream bookkeeping below.
	c0, c1 := s.upstreamClients()
	ref := pidWorkloadReference(pid)
	tag := strconv.Itoa(pid)
	failLimit := 1
	chan1 := make(chan *broker.FetchJWTSVIDResponse)
	go getBrokerJWT(dctx, ref, tag, downstream.Audience, downstream.SpiffeId, c0, chan1)
	if s.multi {
		failLimit = 2
		go getBrokerJWT(dctx, ref, tag, downstream.Audience, downstream.SpiffeId, c1, chan1)
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

	ref := pidWorkloadReference(pid)
	tag := strconv.Itoa(pid)
	chan1 := make(chan *broker.SubscribeToJWTBundlesResponse)
	chan2 := make(chan *broker.SubscribeToJWTBundlesResponse)
	var started [2]bool
	startPump := func(id int, client broker.APIClient) {
		if id == 0 {
			go getBrokerJWTBundles(dctx, ref, tag, client, chan1)
		} else {
			go getBrokerJWTBundles(dctx, ref, tag, client, chan2)
		}
	}
	clientsChan := s.currentClientsChan()
	s.startPumps(&started, startPump)
	log.Printf("broker jwtbundles pid=%d: upstream sides available: %s", pid, s.sidesAvailable())

	var resp1, resp2 *broker.SubscribeToJWTBundlesResponse
	for resp1 == nil && resp2 == nil {
		select {
		case <-dctx.Done():
			log.Printf("broker jwtbundles client disconnected\n")
			return nil
		case <-clientsChan:
			clientsChan = s.currentClientsChan()
			if s.startPumps(&started, startPump) {
				log.Printf("broker jwtbundles pid=%d: upstream side joined, starting pump (now %s)", pid, s.sidesAvailable())
			}
		case resp1 = <-chan1:
			log.Printf("broker jwtbundles got new bundles\n")
		case resp2 = <-chan2:
			log.Printf("broker jwtbundles got new bundles2\n")
		}
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
			case <-clientsChan:
				clientsChan = s.currentClientsChan()
				if s.startPumps(&started, startPump) {
					log.Printf("broker jwtbundles pid=%d: upstream side joined, starting pump (now %s)", pid, s.sidesAvailable())
				}
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

func setupBrokerClient(bs *brokerServer, clientName string, id int, brokerAddr string, workloadAddr string, keepaliveTime, keepaliveTimeout time.Duration, cs *brokerClientSet) {
	var source *workloadapi.X509Source
	for {
		var err error
		log.Printf("%s: obtaining our identity from %s", clientName, workloadAddr)
		// NewX509Source blocks until an SVID is actually issued, silently
		// retrying every failure (missing socket, no identity issued, ...)
		// internally. Bound each attempt and hand go-spiffe a real logger so
		// a side that won't issue us an identity shows up in the logs
		// instead of hanging silently forever. The timeout only bounds
		// initialization; the source's rotation watch runs on its own
		// background context.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		source, err = workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAddr), workloadapi.WithLogger(logger.Std)))
		cancel()
		if err == nil {
			break
		}
		log.Printf("%s: failed to obtain identity from %s: %v", clientName, workloadAddr, err)
		time.Sleep(5 * time.Second)
	}
	// The source is intentionally never closed: it keeps rotating our SVID
	// so the broker mTLS client certificate stays fresh.
	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("%s: failed to get our own SVID: %v", clientName, err)
	}
	trustDomain := svid.ID.TrustDomain()
	log.Printf("%s: our identity: %s", clientName, svid.ID)

	// The source is published under the lock the downstream broker
	// endpoint's SVID picker reads it with.
	bs.bundleLock.Lock()
	cs.source = source
	cs.trustDomain = trustDomain
	if bs.localTD.IsZero() {
		bs.localTD = trustDomain
		log.Printf("Our trust domain detected as: %s\n", bs.localTD.Name())
	} else if bs.localTD != trustDomain {
		log.Fatalf("%s: trust domain mismatch: %s != %s", clientName, trustDomain, bs.localTD)
	}
	bs.bundleLock.Unlock()

	// Keep the downstream broker endpoint's server certificate current:
	// re-pick whenever this side delivers a new SVID, rather than
	// re-evaluating both sources on every handshake.
	bs.recomputeServerSVID()
	go func() {
		for range source.Updated() {
			bs.recomputeServerSVID()
		}
	}()

	// FIXME its hard to know what the remote id is.
	// serverID, err := spiffeid.FromPath(cs.trustDomain, "/spire-ha-agent")
	// if err != nil {
	//	log.Fatalf("%s: failed to build broker server ID: %v", clientName, err)
	// }
	// creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeID(serverID))
	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeAny())
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if keepaliveTime > 0 {
		// Keepalive exists to catch a wedged connection (silent drop, black
		// holed TCP), where Recv would otherwise block forever and the side
		// would keep reporting healthy. Everything else -- process death,
		// socket close, RST, RPC errors -- already surfaces as a stream error.
		//
		// The default interval is 5m because that is the floor a stock server
		// permits, and this is verified rather than assumed: grpc-go applies
		// EnforcementPolicy{MinTime: 5m} whenever the server sets none
		// (internal/transport/defaults.go, http2_server.go), maxPingStrikes is
		// 2, so the third too-frequent ping earns a GOAWAY ENHANCE_YOUR_CALM
		// "too_many_pings" and the connection dies -- the very failure this is
		// meant to detect. It is HTTP/2 PING handling in the shared
		// http2_server, so unix sockets are NOT exempt. The strike counter
		// resets only when the server writes application data, and our bundle
		// subscriptions are quiet by design, so strikes accumulate rather than
		// being forgiven. SPIRE's broker endpoint sets no keepalive options,
		// so it inherits that default; lower this only once SPIRE lets the
		// enforcement policy be configured.
		//
		// PermitWithoutStream is false so we do not ping during the brief
		// window when both subscriptions are in their retry sleep.
		dialOpts = append(dialOpts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                keepaliveTime,
			Timeout:             keepaliveTimeout,
			PermitWithoutStream: false,
		}))
	}
	conn, err := grpc.NewClient(brokerTarget(brokerAddr), dialOpts...)
	if err != nil {
		log.Fatalf("%s: failed to create broker client for %s: %v", clientName, brokerAddr, err)
	}
	// Publishing the client and waking the waiters happen under the same
	// lock the stream handlers read it with, so a stream that wakes is
	// guaranteed to observe the client that woke it.
	bs.bundleLock.Lock()
	cs.client = broker.NewAPIClient(conn)
	close(bs.clientsChan)
	bs.clientsChan = make(chan struct{})
	bs.bundleLock.Unlock()
	log.Printf("%s: client ready. upstream sides available: %s", clientName, bs.sidesAvailable())

	// Bundle subscriptions are scoped to a workload; we subscribe as
	// ourselves, so the spire-ha-agent's own registration entry (and its
	// federates_with list) controls which trust domains we serve.
	pid := os.Getpid()

	go func() {
		for {
			stream, err := cs.client.SubscribeToX509Bundles(brokerMD(context.Background()), &broker.SubscribeToX509BundlesRequest{Reference: pidWorkloadReference(pid)})
			if err != nil {
				log.Printf("%s: failed to subscribe to x509 bundles: %v", clientName, err)
				bs.markSubscription(id, clientName, "x509", false, err)
				time.Sleep(5 * time.Second)
				continue
			}
			for {
				resp, err := stream.Recv()
				if err != nil {
					log.Printf("%s: failed to get x509 bundles: %v", clientName, err)
					bs.markSubscription(id, clientName, "x509", false, err)
					time.Sleep(5 * time.Second)
					break
				}
				// Marked up before parsing, so a malformed bundle (which stays
				// on the stream) does not read as the side being down.
				bs.markSubscription(id, clientName, "x509", true, nil)
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
				bs.markSubscription(id, clientName, "jwt", false, err)
				time.Sleep(5 * time.Second)
				continue
			}
			for {
				resp, err := stream.Recv()
				if err != nil {
					log.Printf("%s: failed to get jwt bundles: %v", clientName, err)
					bs.markSubscription(id, clientName, "jwt", false, err)
					time.Sleep(5 * time.Second)
					break
				}
				bs.markSubscription(id, clientName, "jwt", true, nil)
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

func brokerMain(configPath string) {
	conf, err := loadBrokerConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	var wg sync.WaitGroup
	var jwtWg sync.WaitGroup
	wg.Add(1)
	jwtWg.Add(1)
	if conf.keepaliveTime > 0 && conf.keepaliveTime < safeKeepaliveTime {
		log.Printf("WARNING: upstream_keepalive.time %s is below %s; a SPIRE agent that does not configure a keepalive enforcement policy will answer pings that frequent with GOAWAY too_many_pings and drop the connection",
			conf.keepaliveTime, safeKeepaliveTime)
	}

	bs := &brokerServer{
		multi:            !conf.single,
		x509BundleUpdate: make(chan brokerX509BundleUpdated),
		jwtBundleUpdate:  make(chan brokerJWTBundleUpdated),
		clientsChan:      make(chan struct{}),
		metrics:          newBrokerMetrics(),
	}
	bs.metrics.init(bs.multi)
	// Served before the settle wait: "both sides down" is exactly what you
	// want to see while startup is still blocked.
	if conf.metrics != nil {
		bs.metrics.serve(conf.metrics.bindAddress)
	}

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.Chain(
		middleware.Preprocess(addWatcherPID),
	))
	s := grpc.NewServer(
		grpc.Creds(peertracker.NewCredentials()),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	// Periodic summary. Slower than delegated mode's 5s line because the
	// transition logs from markSubscription carry the real signal.
	go func() {
		for {
			time.Sleep(30 * time.Second)
			log.Printf("upstream sides healthy: %s", bs.sidesHealthy())
		}
	}()

	go setupBrokerClient(bs, "brokerA", 0, conf.brokerA, conf.workloadA, conf.keepaliveTime, conf.keepaliveTimeout, &bs.clients[0])
	if bs.multi {
		go setupBrokerClient(bs, "brokerB", 1, conf.brokerB, conf.workloadB, conf.keepaliveTime, conf.keepaliveTimeout, &bs.clients[1])
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

			localName := bs.localTDName()
			if bundlesSettled(bs.clients[0].x509Bundles, bs.clients[1].x509Bundles, localName, bs.multi) {
				totalBundles := len(bs.clients[0].x509Bundles) + len(bs.clients[1].x509Bundles)
				log.Printf("We got %d x509 bundles\n", totalBundles)
				rawBundles := make(map[string][]byte)
				// Kept in parsed form too, for verifying downstream broker
				// endpoint client certificates.
				parsedBundles := make(map[string]*x509bundle.Bundle)
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
					parsedBundles[name] = bundle
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
					bs.mergedX509 = parsedBundles
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

			localName := bs.localTDName()
			if bundlesSettled(bs.clients[0].jwtBundles, bs.clients[1].jwtBundles, localName, bs.multi) {
				totalBundles := len(bs.clients[0].jwtBundles) + len(bs.clients[1].jwtBundles)
				log.Printf("We got %d jwt bundles\n", totalBundles)
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
	// A lone side satisfies bundlesSettled when it carries the other side's
	// authorities in its spire-ha bundle, so say outright which sides we
	// actually have rather than leaving it to be inferred from the pump logs.
	log.Printf("Startup settled. upstream sides available: %s, healthy: %s", bs.sidesAvailable(), bs.sidesHealthy())

	// Both downstream surfaces come up only now that merged bundles exist:
	// the broker endpoint needs them to verify its clients, and an unserved
	// socket would hang callers rather than refuse them.
	if conf.endpoint != nil {
		startBrokerEndpoint(bs, conf.endpoint)
	}

	// The workload API socket is created only now that the server can
	// actually answer on it. A socket that exists but is never served turns
	// every workload's dial into a silent hang until its own timeout;
	// connection refused is retried cleanly and keeps readiness observable.
	lf := &peertracker.ListenerFactory{}
	var lis *peertracker.Listener
	if conf.vsockEnabled {
		lis, err = lf.ListenVSock(conf.vsockPort)
	} else {
		_ = os.Remove(conf.socket)
		lis, err = lf.ListenUnix("unix", &net.UnixAddr{Name: conf.socket, Net: "unix"})
		if err == nil {
			if cerr := os.Chmod(conf.socket, 0777); cerr != nil {
				log.Fatalf("failed to permission the socket: %v", cerr)
			}
		}
	}
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	workload.RegisterSpiffeWorkloadAPIServer(s, bs)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
