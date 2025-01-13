package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
	var rawBundles map[string]string
	if os.Getenv("SPIFFE_TRUST_DOMAIN") == "" {
		fmt.Printf("SPIFFE_TRUST_DOMAIN must be set.")
		os.Exit(1)
	}
	tde := os.Getenv("SPIFFE_TRUST_DOMAIN")
	data, err := os.ReadFile("jwt_bundle.json")
	if err != nil {
		fmt.Printf("Failed to read jwt_bundle.json: %s", err)
		os.Exit(2)
	}
	json.Unmarshal(data, &rawBundles)
	decBundle := make([]byte, base64.StdEncoding.DecodedLen(len(rawBundles[tde])))
	n, err := base64.StdEncoding.Decode(decBundle, []byte(rawBundles[tde]))
	if err != nil {
		fmt.Printf("Failed to decode jwt_bundle.json: %s\n", err)
		os.Exit(3)
	}
	bundle := decBundle[:n]
	td, err := spiffeid.TrustDomainFromString("spiffe://spire-ha")
	if err != nil {
		fmt.Printf("Could not build trust domain object: %s\n", err)
		os.Exit(4)
	}
	jbundle, err := jwtbundle.Parse(td, bundle)
	if err != nil {
		fmt.Printf("Failed to parse jwt_bundle.json: %s\n", err)
		os.Exit(5)
	}
	sb := spiffebundle.FromJWTAuthorities(td, jbundle.JWTAuthorities())
	xb, err := x509bundle.Load(td, "ca.crt")
	if err != nil {
		fmt.Printf("Failed to load ca.crt: %s\n", err)
		os.Exit(6)
	}
	for _, a := range xb.X509Authorities() {
		sb.AddX509Authority(a)
	}
	final, err := sb.Marshal()
	if err != nil {
		fmt.Printf("Failed to marshal the bundle: %s\n", err)
		os.Exit(7)
	}
	fmt.Printf("%s\n", final)
}
