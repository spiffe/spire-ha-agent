package main

// Envoy SDS (Secret Discovery Service v3) support for broker mode.
//
// Mirrors the SPIRE agent's SDS handler (pkg/agent/endpoints/sdsv3): the
// service is registered on the Workload API socket, Envoy is identified as a
// workload by its PID, and TLS certificate / validation context secrets are
// resolved by the same resource naming rules and the same configuration
// options. The data comes from the upstream SPIFFE Broker API the same way
// FetchX509SVID gets it, so the local trust domain bundle is the merged
// A+B+spire-ha union.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"strconv"

	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultSDSDefaultSVIDName       = "default"
	defaultSDSDefaultBundleName     = "ROOTCA"
	defaultSDSDefaultAllBundlesName = "ALL"

	disableSPIFFECertValidationKey = "disable_spiffe_cert_validation"
	spiffeCertValidatorName        = "envoy.tls.cert_validator.spiffe"
)

// ---- configuration ----

// The `sds` block of the broker mode config file. Option names and defaults
// match the SPIRE agent's `sds` block.
type sdsFileConfig struct {
	DefaultSVIDName             *string `yaml:"default_svid_name"`
	DefaultBundleName           *string `yaml:"default_bundle_name"`
	DefaultAllBundlesName       *string `yaml:"default_all_bundles_name"`
	DisableSPIFFECertValidation *bool   `yaml:"disable_spiffe_cert_validation"`
}

type sdsConfig struct {
	defaultSVIDName             string
	defaultBundleName           string
	defaultAllBundlesName       string
	disableSPIFFECertValidation bool
}

// Resolves the SDS configuration. Returns nil when the SDS API is disabled
// (disable_sds_api: true); otherwise SDS is on, with SPIRE's defaults for
// anything the file leaves out.
func resolveSDSConfig(fc *sdsFileConfig, disable *bool) *sdsConfig {
	if disable != nil && *disable {
		return nil
	}
	conf := &sdsConfig{
		defaultSVIDName:       defaultSDSDefaultSVIDName,
		defaultBundleName:     defaultSDSDefaultBundleName,
		defaultAllBundlesName: defaultSDSDefaultAllBundlesName,
	}
	if fc != nil {
		if fc.DefaultSVIDName != nil {
			conf.defaultSVIDName = *fc.DefaultSVIDName
		}
		if fc.DefaultBundleName != nil {
			conf.defaultBundleName = *fc.DefaultBundleName
		}
		if fc.DefaultAllBundlesName != nil {
			conf.defaultAllBundlesName = *fc.DefaultAllBundlesName
		}
		if fc.DisableSPIFFECertValidation != nil {
			conf.disableSPIFFECertValidation = *fc.DisableSPIFFECertValidation
		}
	}
	if conf.defaultAllBundlesName == conf.defaultBundleName {
		log.Printf(`sds: "default_bundle_name" and "default_all_bundles_name" have the same value %q; "default_all_bundles_name" will be ignored. Configure distinct values or use the defaults.`, conf.defaultBundleName)
	}
	return conf
}

// Registers the SDS v3 service on the Workload API gRPC server. A nil config
// means the SDS API is disabled.
func registerSDS(s *grpc.Server, bs *brokerServer, conf *sdsConfig) {
	if conf == nil {
		log.Printf("sds: SDS API disabled")
		return
	}
	secret_v3.RegisterSecretDiscoveryServiceServer(s, newSDSHandler(*conf, &brokerSDSSource{bs: bs}))
	log.Printf("sds: serving the Envoy SDS v3 API on the workload API socket")
}

// ---- workload snapshot ----

type sdsIdentity struct {
	spiffeID string
	chain    []byte // ASN.1 DER certificates, concatenated, leaf first
	key      []byte // PKCS#8 DER
}

// Everything a workload is entitled to at one point in time: the SDS
// equivalent of the SPIRE agent cache's X509WorkloadUpdate.
type sdsUpdate struct {
	// In upstream order. The first one backs the default SVID name.
	identities []sdsIdentity
	localTD    spiffeid.TrustDomain
	// Local trust domain authorities (concatenated DER); nil when unknown.
	bundle []byte
	// Federated trust domain authorities (concatenated DER).
	federated map[spiffeid.TrustDomain][]byte
}

func (u *sdsUpdate) equal(o *sdsUpdate) bool {
	if u == nil || o == nil {
		return u == o
	}
	if u.localTD != o.localTD || !bytes.Equal(u.bundle, o.bundle) ||
		(u.bundle == nil) != (o.bundle == nil) ||
		len(u.identities) != len(o.identities) || len(u.federated) != len(o.federated) {
		return false
	}
	for i, id := range u.identities {
		oid := o.identities[i]
		if id.spiffeID != oid.spiffeID || !bytes.Equal(id.chain, oid.chain) || !bytes.Equal(id.key, oid.key) {
			return false
		}
	}
	for td, raw := range u.federated {
		oraw, ok := o.federated[td]
		if !ok || !bytes.Equal(raw, oraw) {
			return false
		}
	}
	return true
}

// Builds the SDS snapshot for an upstream broker SVID response, with the
// same bundle semantics FetchX509SVID applies: the local trust domain is
// served from the merged A+B+spire-ha view, federated bundles are passed
// through from the caller's own response, and spire-ha is never exposed.
func (bs *brokerServer) sdsSnapshot(resp *broker.SubscribeToX509SVIDResponse) *sdsUpdate {
	bs.bundleLock.RLock()
	defer bs.bundleLock.RUnlock()

	upd := &sdsUpdate{
		localTD:   bs.localTD,
		federated: make(map[spiffeid.TrustDomain][]byte),
	}
	if merged, ok := bs.rawBundles[bs.localTD.Name()]; ok {
		upd.bundle = merged
	}
	_, federated := bs.mergeSVIDParts(resp)
	for name, raw := range federated {
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			log.Printf("sds: bad federated bundle trust domain %q: %v", name, err)
			continue
		}
		if td == bs.localTD {
			continue
		}
		upd.federated[td] = raw
	}
	for _, svid := range resp.GetSvids() {
		upd.identities = append(upd.identities, sdsIdentity{
			spiffeID: svid.GetSpiffeId(),
			chain:    svid.GetX509Svid(),
			key:      svid.GetX509SvidKey(),
		})
	}
	return upd
}

// ---- snapshot source ----

// Where the handler gets a workload's snapshots from. The caller is
// identified by the context (peer PID).
type sdsSource interface {
	// Delivers the caller's current snapshot as soon as one is known and a
	// new one whenever it changes, until ctx is done. A slow reader only
	// ever sees the latest snapshot.
	subscribe(ctx context.Context) (<-chan *sdsUpdate, error)
	// Returns the caller's current snapshot.
	fetch(ctx context.Context) (*sdsUpdate, error)
}

// The real source: per-stream upstream broker subscriptions on both sides,
// exactly as FetchX509SVID does it.
type brokerSDSSource struct {
	bs *brokerServer
}

func (s *brokerSDSSource) subscribe(ctx context.Context) (<-chan *sdsUpdate, error) {
	pid, ok := ctx.Value(callerPIDKey{}).(int)
	if !ok {
		return nil, status.Error(codes.Internal, "peer tracker watcher missing from context")
	}
	log.Printf("sds: calling pid: %d", pid)

	out := make(chan *sdsUpdate, 1)
	go s.run(ctx, pid, out)
	return out, nil
}

func (s *brokerSDSSource) run(ctx context.Context, pid int, out chan *sdsUpdate) {
	bs := s.bs
	ref := pidWorkloadReference(pid)
	tag := strconv.Itoa(pid)
	chan1 := make(chan *broker.SubscribeToX509SVIDResponse)
	chan2 := make(chan *broker.SubscribeToX509SVIDResponse)
	var started [2]bool
	startPump := func(id int, client broker.APIClient) {
		if id == 0 {
			go getBrokerX509SVIDs(ctx, ref, tag, client, chan1)
		} else {
			go getBrokerX509SVIDs(ctx, ref, tag, client, chan2)
		}
	}
	clientsChan := bs.currentClientsChan()
	bundleChan := bs.currentX509BundleChan()
	bs.startPumps(&started, startPump)
	log.Printf("sds pid=%d: upstream sides available: %s", pid, bs.sidesAvailable())

	var resp *broker.SubscribeToX509SVIDResponse
	var last *sdsUpdate
	for {
		select {
		case <-ctx.Done():
			return
		case resp = <-chan1:
		case resp = <-chan2:
		case <-bundleChan:
			bundleChan = bs.currentX509BundleChan()
		case <-clientsChan:
			// A side finished setup after the stream opened; let it join.
			clientsChan = bs.currentClientsChan()
			if bs.startPumps(&started, startPump) {
				log.Printf("sds pid=%d: upstream side joined, starting pump (now %s)", pid, bs.sidesAvailable())
			}
			continue
		}
		if resp == nil {
			continue
		}
		upd := bs.sdsSnapshot(resp)
		if upd.equal(last) {
			continue
		}
		last = upd
		// Latest wins: this goroutine is the only sender, so after
		// draining a stale snapshot the send cannot block.
		select {
		case out <- upd:
		default:
			select {
			case <-out:
			default:
			}
			out <- upd
		}
	}
}

func (s *brokerSDSSource) fetch(ctx context.Context) (*sdsUpdate, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := s.subscribe(ctx)
	if err != nil {
		return nil, err
	}
	select {
	case upd := <-ch:
		return upd, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---- handler ----

type sdsHandler struct {
	secret_v3.UnimplementedSecretDiscoveryServiceServer

	c      sdsConfig
	source sdsSource

	hooks struct {
		// test hook used to synchronize receipt of a stream request
		received chan struct{}
	}
}

func newSDSHandler(c sdsConfig, source sdsSource) *sdsHandler {
	return &sdsHandler{c: c, source: source}
}

func (h *sdsHandler) StreamSecrets(stream secret_v3.SecretDiscoveryService_StreamSecretsServer) error {
	updch, err := h.source.subscribe(stream.Context())
	if err != nil {
		log.Printf("sds: subscribe failed: %v", err)
		return err
	}

	reqch := make(chan *discovery_v3.DiscoveryRequest, 1)
	errch := make(chan error, 1)

	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				if status.Code(err) == codes.Canceled || errors.Is(err, io.EOF) {
					err = nil
				}
				errch <- err
				return
			}
			select {
			case reqch <- req:
			case <-stream.Context().Done():
				return
			}
		}
	}()

	var versionCounter int64
	versionInfo := strconv.FormatInt(versionCounter, 10)
	var lastNonce string
	var lastNode *core_v3.Node
	var upd *sdsUpdate
	var lastReq *discovery_v3.DiscoveryRequest
	for {
		select {
		case newReq := <-reqch:
			log.Printf("sds: received StreamSecrets request: resource_names=%q version_info=%q nonce=%q",
				newReq.ResourceNames, newReq.VersionInfo, newReq.ResponseNonce)
			h.triggerReceivedHook()

			// If there's error detail, always log it
			if newReq.ErrorDetail != nil {
				log.Printf("sds: Envoy reported errors applying secrets: resource_names=%q error=%q",
					newReq.ResourceNames, newReq.ErrorDetail.Message)
			}

			// If we've previously sent a nonce, this must be a reply
			if lastNonce != "" {
				// The nonce should match the last sent nonce, otherwise
				// it's stale and the request should be ignored.
				if lastNonce != newReq.ResponseNonce {
					log.Printf("sds: received unexpected nonce %q (expected %q); ignoring request", newReq.ResponseNonce, lastNonce)
					continue
				}

				if newReq.VersionInfo == "" || newReq.VersionInfo != versionInfo {
					// The caller has failed to apply the last update. A
					// NACK might also contain an update to the resource
					// names, so we need to continue processing.
					log.Printf("sds: client rejected expected version %q and rolled back to %q", versionInfo, newReq.VersionInfo)
				}
				// If the current request does not contain node
				// information, use the information from a previous
				// request (if any)
				if newReq.Node == nil {
					newReq.Node = lastNode
				}
			}

			// We need to send updates if the requested resource list has
			// changed either explicitly, or implicitly because this is
			// the first request.
			sendUpdates := lastReq == nil || subListChanged(lastReq.ResourceNames, newReq.ResourceNames)

			// save request so that all future workload updates lead to
			// SDS updates for the last request
			lastReq = newReq

			if !sendUpdates {
				continue
			}

			if upd == nil {
				// Workload update has not been received yet, defer
				// sending updates until then
				continue
			}

		case upd = <-updch:
			versionCounter++
			versionInfo = strconv.FormatInt(versionCounter, 10)
			if lastReq == nil {
				// Nothing has been requested yet.
				continue
			}
		case err := <-errch:
			if err != nil {
				log.Printf("sds: received error from stream secrets server: %v", err)
			}
			return err
		}

		resp, err := h.buildResponse(versionInfo, lastReq, upd)
		if err != nil {
			log.Printf("sds: error building stream secrets response: %v", err)
			return err
		}

		log.Printf("sds: sending StreamSecrets response: version_info=%q nonce=%q count=%d", resp.VersionInfo, resp.Nonce, len(resp.Resources))
		if err := stream.Send(resp); err != nil {
			log.Printf("sds: error sending secrets over stream: %v", err)
			return err
		}

		// remember the last nonce
		lastNonce = resp.Nonce

		// Remember Node info if it exists
		if lastReq.Node != nil {
			lastNode = lastReq.Node
		}
	}
}

func subListChanged(oldSubs []string, newSubs []string) bool {
	if len(oldSubs) != len(newSubs) {
		return true
	}
	subMap := make(map[string]bool)
	for _, sub := range oldSubs {
		subMap[sub] = true
	}
	for _, sub := range newSubs {
		if !subMap[sub] {
			return true
		}
	}
	return false
}

func (h *sdsHandler) DeltaSecrets(secret_v3.SecretDiscoveryService_DeltaSecretsServer) error {
	return status.Error(codes.Unimplemented, "Method is not implemented")
}

func (h *sdsHandler) FetchSecrets(ctx context.Context, req *discovery_v3.DiscoveryRequest) (*discovery_v3.DiscoveryResponse, error) {
	upd, err := h.source.fetch(ctx)
	if err != nil {
		log.Printf("sds: fetch failed: resource_names=%q: %v", req.ResourceNames, err)
		return nil, err
	}

	resp, err := h.buildResponse("", req, upd)
	if err != nil {
		log.Printf("sds: error building fetch secrets response: resource_names=%q: %v", req.ResourceNames, err)
		return nil, err
	}

	log.Printf("sds: sending FetchSecrets response: resource_names=%q count=%d", req.ResourceNames, len(resp.Resources))
	return resp, nil
}

func (h *sdsHandler) buildResponse(versionInfo string, req *discovery_v3.DiscoveryRequest, upd *sdsUpdate) (resp *discovery_v3.DiscoveryResponse, err error) {
	if upd == nil {
		return nil, status.Error(codes.Unavailable, "no identities available for the workload yet")
	}
	resp = &discovery_v3.DiscoveryResponse{
		TypeUrl:     req.TypeUrl,
		VersionInfo: versionInfo,
	}

	// provide a nonce for streaming requests
	if versionInfo != "" {
		if resp.Nonce, err = nextNonce(); err != nil {
			return nil, err
		}
	}

	// build a convenient set of names for lookups
	names := make(map[string]bool)
	for _, name := range req.ResourceNames {
		if name != "" {
			names[name] = true
		}
	}
	returnAllEntries := len(names) == 0

	builder, err := h.getValidationContextBuilder(req, upd)
	if err != nil {
		return nil, err
	}

	if upd.bundle != nil {
		localID := upd.localTD.IDString()
		switch {
		case returnAllEntries || names[localID]:
			validationContext, err := builder.buildOne(localID, upd.localTD)
			if err != nil {
				return nil, err
			}
			delete(names, localID)
			resp.Resources = append(resp.Resources, validationContext)

		case names[h.c.defaultBundleName]:
			validationContext, err := builder.buildOne(h.c.defaultBundleName, upd.localTD)
			if err != nil {
				return nil, err
			}
			delete(names, h.c.defaultBundleName)
			resp.Resources = append(resp.Resources, validationContext)

		case names[h.c.defaultAllBundlesName]:
			validationContext, err := builder.buildAll(h.c.defaultAllBundlesName)
			if err != nil {
				return nil, err
			}
			delete(names, h.c.defaultAllBundlesName)
			resp.Resources = append(resp.Resources, validationContext)
		}
	}

	// Sorted so the resource order is stable (SPIRE iterates the map).
	federated := make([]spiffeid.TrustDomain, 0, len(upd.federated))
	for td := range upd.federated {
		federated = append(federated, td)
	}
	sort.Slice(federated, func(i, j int) bool { return federated[i].Name() < federated[j].Name() })
	for _, td := range federated {
		if returnAllEntries || names[td.IDString()] {
			validationContext, err := builder.buildOne(td.IDString(), td)
			if err != nil {
				return nil, err
			}
			delete(names, td.IDString())
			resp.Resources = append(resp.Resources, validationContext)
		}
	}

	for i, identity := range upd.identities {
		switch {
		case returnAllEntries || names[identity.spiffeID]:
			tlsCertificate, err := buildTLSCertificate(identity, "")
			if err != nil {
				return nil, err
			}
			delete(names, identity.spiffeID)
			resp.Resources = append(resp.Resources, tlsCertificate)
		case i == 0 && names[h.c.defaultSVIDName]:
			tlsCertificate, err := buildTLSCertificate(identity, h.c.defaultSVIDName)
			if err != nil {
				return nil, err
			}
			delete(names, h.c.defaultSVIDName)
			resp.Resources = append(resp.Resources, tlsCertificate)
		}
	}

	if len(names) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "workload is not authorized for the requested identities %q", sortedNames(names))
	}

	return resp, nil
}

func (h *sdsHandler) triggerReceivedHook() {
	if h.hooks.received != nil {
		h.hooks.received <- struct{}{}
	}
}

// ---- validation context builders ----

type validationContextBuilder interface {
	buildOne(resourceName string, td spiffeid.TrustDomain) (*anypb.Any, error)
	buildAll(resourceName string) (*anypb.Any, error)
}

func (h *sdsHandler) getValidationContextBuilder(req *discovery_v3.DiscoveryRequest, upd *sdsUpdate) (validationContextBuilder, error) {
	bundles := make(map[spiffeid.TrustDomain][]byte, len(upd.federated)+1)
	for td, raw := range upd.federated {
		pemBytes, err := derToPEM(raw)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "invalid bundle for trust domain %q: %v", td.IDString(), err)
		}
		bundles[td] = pemBytes
	}
	if upd.bundle != nil {
		pemBytes, err := derToPEM(upd.bundle)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "invalid bundle for trust domain %q: %v", upd.localTD.IDString(), err)
		}
		bundles[upd.localTD] = pemBytes
	}

	if !h.isSPIFFECertValidationDisabled(req) && supportsSPIFFEAuthExtension(req) {
		return &spiffeBuilder{bundles: bundles}, nil
	}
	return &rootCABuilder{bundles: bundles}, nil
}

// Plain trusted CA validation contexts, for Envoy releases without the
// SPIFFE certificate validator or when it is disabled.
type rootCABuilder struct {
	bundles map[spiffeid.TrustDomain][]byte // PEM
}

func (b *rootCABuilder) buildOne(resourceName string, td spiffeid.TrustDomain) (*anypb.Any, error) {
	caBytes, ok := b.bundles[td]
	if !ok {
		return nil, status.Errorf(codes.Internal, "no bundle found for trust domain: %q", td.IDString())
	}
	return anypb.New(&tls_v3.Secret{
		Name: resourceName,
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				TrustedCa: inlineBytes(caBytes),
			},
		},
	})
}

func (b *rootCABuilder) buildAll(string) (*anypb.Any, error) {
	return nil, status.Error(codes.Internal, `unable to use "SPIFFE validator" on Envoy below 1.17`)
}

// Validation contexts using Envoy's SPIFFE certificate validator.
type spiffeBuilder struct {
	bundles map[spiffeid.TrustDomain][]byte // PEM
}

func (b *spiffeBuilder) buildOne(resourceName string, td spiffeid.TrustDomain) (*anypb.Any, error) {
	caBytes, ok := b.bundles[td]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no bundle found for trust domain: %q", td.IDString())
	}
	return spiffeValidationContext(resourceName, []*tls_v3.SPIFFECertValidatorConfig_TrustDomain{{
		Name:        td.Name(),
		TrustBundle: inlineBytes(caBytes),
	}})
}

func (b *spiffeBuilder) buildAll(resourceName string) (*anypb.Any, error) {
	trustDomains := make([]*tls_v3.SPIFFECertValidatorConfig_TrustDomain, 0, len(b.bundles))
	for td, caBytes := range b.bundles {
		trustDomains = append(trustDomains, &tls_v3.SPIFFECertValidatorConfig_TrustDomain{
			Name:        td.Name(),
			TrustBundle: inlineBytes(caBytes),
		})
	}
	sort.Slice(trustDomains, func(i, j int) bool { return trustDomains[i].Name < trustDomains[j].Name })
	return spiffeValidationContext(resourceName, trustDomains)
}

func spiffeValidationContext(resourceName string, trustDomains []*tls_v3.SPIFFECertValidatorConfig_TrustDomain) (*anypb.Any, error) {
	typedConfig, err := anypb.New(&tls_v3.SPIFFECertValidatorConfig{TrustDomains: trustDomains})
	if err != nil {
		return nil, err
	}
	return anypb.New(&tls_v3.Secret{
		Name: resourceName,
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				CustomValidatorConfig: &core_v3.TypedExtensionConfig{
					Name:        spiffeCertValidatorName,
					TypedConfig: typedConfig,
				},
			},
		},
	})
}

// The SPIFFE certificate validator shipped in Envoy 1.18. Envoys that do not
// report a version are assumed to support it.
func supportsSPIFFEAuthExtension(req *discovery_v3.DiscoveryRequest) bool {
	if buildVersion := req.Node.GetUserAgentBuildVersion(); buildVersion != nil && buildVersion.Version != nil {
		version := buildVersion.Version
		return (version.MajorNumber == 1 && version.MinorNumber > 17) || version.MajorNumber > 1
	}
	return true
}

// The configured default can be overridden per Envoy instance through the
// node metadata.
func (h *sdsHandler) isSPIFFECertValidationDisabled(req *discovery_v3.DiscoveryRequest) bool {
	disabled := h.c.disableSPIFFECertValidation
	if v, ok := req.Node.GetMetadata().GetFields()[disableSPIFFECertValidationKey]; ok {
		if override, err := parseBool(v); err == nil {
			disabled = override
		}
	}
	return disabled
}

func parseBool(v *structpb.Value) (bool, error) {
	switch v := v.GetKind().(type) {
	case *structpb.Value_BoolValue:
		return v.BoolValue, nil
	case *structpb.Value_StringValue:
		return strconv.ParseBool(v.StringValue)
	}
	return false, fmt.Errorf("unsupported value type %T", v)
}

// ---- secret helpers ----

func buildTLSCertificate(identity sdsIdentity, defaultSVIDName string) (*anypb.Any, error) {
	name := identity.spiffeID
	if defaultSVIDName != "" {
		name = defaultSVIDName
	}

	certsPEM, err := derToPEM(identity.chain)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid X509-SVID for %q: %v", identity.spiffeID, err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(identity.key); err != nil {
		return nil, status.Errorf(codes.Internal, "invalid X509-SVID key for %q: %v", identity.spiffeID, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: identity.key})

	return anypb.New(&tls_v3.Secret{
		Name: name,
		Type: &tls_v3.Secret_TlsCertificate{
			TlsCertificate: &tls_v3.TlsCertificate{
				CertificateChain: inlineBytes(certsPEM),
				PrivateKey:       inlineBytes(keyPEM),
			},
		},
	})
}

func inlineBytes(b []byte) *core_v3.DataSource {
	return &core_v3.DataSource{
		Specifier: &core_v3.DataSource_InlineBytes{InlineBytes: b},
	}
}

// Converts concatenated ASN.1 DER certificates to concatenated PEM blocks.
func derToPEM(der []byte) ([]byte, error) {
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for _, cert := range certs {
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func nextNonce() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate nonce: %v", err)
	}
	return hex.EncodeToString(b), nil
}

func sortedNames(names map[string]bool) []string {
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
