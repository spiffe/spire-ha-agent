package main

// Unit tests for the delegated identity API -> Workload API JWT-SVID conversion.

import (
	"testing"

	workload "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	agentdelegated "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

func delegatedSVID(trustDomain, path, token, hint string) *apitypes.JWTSVID {
	return &apitypes.JWTSVID{
		Id:    &apitypes.SPIFFEID{TrustDomain: trustDomain, Path: path},
		Token: token,
		Hint:  hint,
	}
}

func checkSVID(t *testing.T, got *workload.JWTSVID, wantID, wantToken, wantHint string) {
	t.Helper()
	if got.GetSpiffeId() != wantID {
		t.Errorf("spiffe id: got %q, want %q", got.GetSpiffeId(), wantID)
	}
	if got.GetSvid() != wantToken {
		t.Errorf("token: got %q, want %q", got.GetSvid(), wantToken)
	}
	if got.GetHint() != wantHint {
		t.Errorf("hint: got %q, want %q", got.GetHint(), wantHint)
	}
}

// A single hinted SVID round-trips with its hint intact. The delegated API
// carries a hint field, so there is no reason to drop it on the way through.
func TestJWTSVIDsFromDelegatedPropagatesHint(t *testing.T) {
	got := jwtSVIDsFromDelegated(&agentdelegated.FetchJWTSVIDsResponse{
		Svids: []*apitypes.JWTSVID{
			delegatedSVID("example.org", "/kubelet", "token-a", "image-pull"),
		},
	})

	if len(got) != 1 {
		t.Fatalf("got %d svids, want 1", len(got))
	}
	checkSVID(t, got[0], "spiffe://example.org/kubelet", "token-a", "image-pull")
}

// Every SVID must carry its own SPIFFE ID, not the first one's. A workload
// entitled to two identities distinguished only by hint depends on this.
func TestJWTSVIDsFromDelegatedKeepsPerSVIDIdentity(t *testing.T) {
	got := jwtSVIDsFromDelegated(&agentdelegated.FetchJWTSVIDsResponse{
		Svids: []*apitypes.JWTSVID{
			delegatedSVID("example.org", "/kubelet/node2.example.org", "token-kubelet", "kubelet"),
			delegatedSVID("example.org", "/kubelet", "token-pull", "image-pull"),
		},
	})

	if len(got) != 2 {
		t.Fatalf("got %d svids, want 2", len(got))
	}
	checkSVID(t, got[0], "spiffe://example.org/kubelet/node2.example.org", "token-kubelet", "kubelet")
	checkSVID(t, got[1], "spiffe://example.org/kubelet", "token-pull", "image-pull")
}

// Hints are optional, so an unhinted SVID alongside a hinted one keeps an
// empty hint rather than inheriting its neighbour's.
func TestJWTSVIDsFromDelegatedMixedHints(t *testing.T) {
	got := jwtSVIDsFromDelegated(&agentdelegated.FetchJWTSVIDsResponse{
		Svids: []*apitypes.JWTSVID{
			delegatedSVID("example.org", "/plain", "token-plain", ""),
			delegatedSVID("example.org", "/hinted", "token-hinted", "internal"),
		},
	})

	if len(got) != 2 {
		t.Fatalf("got %d svids, want 2", len(got))
	}
	checkSVID(t, got[0], "spiffe://example.org/plain", "token-plain", "")
	checkSVID(t, got[1], "spiffe://example.org/hinted", "token-hinted", "internal")
}

func TestJWTSVIDsFromDelegatedEmptyAndNil(t *testing.T) {
	for _, tt := range []struct {
		name string
		resp *agentdelegated.FetchJWTSVIDsResponse
	}{
		{"nil response", nil},
		{"no svids", &agentdelegated.FetchJWTSVIDsResponse{}},
		{"empty svids", &agentdelegated.FetchJWTSVIDsResponse{Svids: []*apitypes.JWTSVID{}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := jwtSVIDsFromDelegated(tt.resp)
			if got == nil {
				t.Fatal("got nil slice, want empty non-nil slice")
			}
			if len(got) != 0 {
				t.Fatalf("got %d svids, want 0", len(got))
			}
		})
	}
}
