package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	syncStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "spiffe_trust_bundle_sync_success",
			Help: "Status of trust bundle synchronization (1 = Success, 0 = Failure/Missing)",
		},
		[]string{"trust_domain"},
	)
)

func init() {
	prometheus.MustRegister(syncStatus)
}

func main() {
	mode := flag.String("mode", "regular", "Operating mode: 'regular' or 'spire-ha'")
	tdList := flag.String("trust-domains", "", "Comma-separated list of additional trust domains")
	promAddr := flag.String("prom-addr", "", "Address for Prometheus metrics")
	flag.Parse()

	targetDomains := make(map[string]spiffeid.TrustDomain)

	if *mode == "spire-ha" {
		localTDStr := os.Getenv("SPIFFE_TRUST_DOMAIN")
		if localTDStr != "" {
			td, err := spiffeid.TrustDomainFromString(localTDStr)
			if err == nil {
				targetDomains["spire-ha"] = td
			}
		} else {
			fmt.Printf("SPIFFE_TRUST_DOMAIN must be specified\n")
			os.Exit(1)
		}
	}

	if *tdList != "" {
		for _, d := range strings.Split(*tdList, ",") {
			d = strings.TrimSpace(d)
			if td, err := spiffeid.TrustDomainFromString(d); err == nil {
				targetDomains[d] = td
			}
		}
	}
	serverSocket := os.Getenv("SPIRE_SERVER_SOCKET")
	if serverSocket == "" {
		fmt.Printf("SPIRE_SERVER_SOCKET must be specified\n")
		os.Exit(1)
	}

	for label, _ := range targetDomains {
		metric := syncStatus.WithLabelValues(label)
		metric.Set(0)
	}

	if promAddr != nil && *promAddr != "" {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			fmt.Printf("Prometheus metrics available at http://localhost%s/metrics\n", *promAddr)
			if err := http.ListenAndServe(*promAddr, nil); err != nil {
				fmt.Printf("Metrics server failed: %v\n", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bundleSource, err := workloadapi.NewBundleSource(ctx)
	if err != nil {
		fmt.Printf("Failed to create BundleSource: %v\n", err)
		os.Exit(1)
	}
	defer bundleSource.Close()

	fmt.Println("Starting bundle synchronization loop...")
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		for label, td := range targetDomains {
			syncBundle(bundleSource, td, label, serverSocket)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			continue
		}
	}
}

func syncBundle(source *workloadapi.BundleSource, td spiffeid.TrustDomain, label string, serverSocket string) {
	metric := syncStatus.WithLabelValues(label)

	bundle, err := source.GetBundleForTrustDomain(td)
	if err != nil {
		fmt.Printf("[%s] Bundle for %s not yet available in Workload API: %v\n", label, td, err)
		metric.Set(0)
		return
	}

	if err := pushToServer(bundle, label, serverSocket); err != nil {
		fmt.Printf("[%s] Push to SPIRE server failed: %v\n", label, err)
		metric.Set(0)
		return
	}

	fmt.Printf("[%s] Successfully synchronized bundle for %s\n", label, td)
	metric.Set(1)
}

func pushToServer(bundle *spiffebundle.Bundle, targetName string, serverSocket string) error {
	x509Authorities := []*types.X509Certificate{}
	for _, x509Cert := range bundle.X509Authorities() {
		x509Authorities = append(x509Authorities, &types.X509Certificate{
			Asn1: x509Cert.Raw,
		})
	}

	jwtAuthorities := []*types.JWTKey{}
	for keyID, jwtKey := range bundle.JWTAuthorities() {
		marshaledKey, err := x509.MarshalPKIXPublicKey(jwtKey)
		if err != nil {
			return fmt.Errorf("failed to marshal JWT public key %s: %w", keyID, err)
		}
		jwtAuthorities = append(jwtAuthorities, &types.JWTKey{
			PublicKey: marshaledKey,
			KeyId:     keyID,
		})
	}

	apiBundle := &types.Bundle{
		TrustDomain:     targetName,
		X509Authorities: x509Authorities,
		JwtAuthorities:  jwtAuthorities,
	}

	conn, err := grpc.Dial(serverSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dialing server: %w", err)
	}
	defer conn.Close()

	client := bundlev1.NewBundleClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.BatchSetFederatedBundle(ctx, &bundlev1.BatchSetFederatedBundleRequest{
		Bundle: []*types.Bundle{apiBundle},
	})
	if err != nil {
		return fmt.Errorf("gRPC call failed: %w", err)
	}

	if len(resp.Results) > 0 && resp.Results[0].Status.Code != 0 {
		return fmt.Errorf("server error (%d): %s", resp.Results[0].Status.Code, resp.Results[0].Status.Message)
	}

	return nil
}
