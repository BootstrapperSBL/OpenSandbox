// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestHandleDelete_DropEstablishedQueryPassesLearnedIPs(t *testing.T) {
	initial, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"deb.debian.org"}]}`)
	require.NoError(t, err)
	nft := &stubNft{
		domains: map[string][]netip.Addr{
			"deb.debian.org": {netip.MustParseAddr("203.0.113.10")},
		},
		dropMatched: 2,
	}
	srv := &policyServer{
		proxy:           &stubProxy{updated: initial},
		nft:             nft,
		enforcementMode: "dns+nft",
	}

	req := httptest.NewRequest(http.MethodDelete, "/policy?dropEstablished=true", strings.NewReader(`["deb.debian.org"]`))
	w := httptest.NewRecorder()
	srv.handlePolicy(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nft.lastDrops.Addrs)

	var resp policyStatusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.DroppedEstablished)
	require.Equal(t, 2, *resp.DroppedEstablished)
}

func TestHandleDelete_WithoutDropEstablishedLeavesConntrackAlone(t *testing.T) {
	initial, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"deb.debian.org"}]}`)
	require.NoError(t, err)
	nft := &stubNft{
		domains: map[string][]netip.Addr{
			"deb.debian.org": {netip.MustParseAddr("203.0.113.10")},
		},
	}
	srv := &policyServer{
		proxy:           &stubProxy{updated: initial},
		nft:             nft,
		enforcementMode: "dns+nft",
	}

	req := httptest.NewRequest(http.MethodDelete, "/policy", strings.NewReader(`["deb.debian.org"]`))
	w := httptest.NewRecorder()
	srv.handlePolicy(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.True(t, nft.lastDrops.Empty())
	require.Equal(t, 1, nft.calls)

	var resp policyStatusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Nil(t, resp.DroppedEstablished)
}

func TestDropEstablishedRequested(t *testing.T) {
	require.True(t, dropEstablishedRequested(httptest.NewRequest(http.MethodDelete, "/policy?dropEstablished=true", nil)))
	require.True(t, dropEstablishedRequested(httptest.NewRequest(http.MethodDelete, "/policy?dropEstablished=1", nil)))
	require.False(t, dropEstablishedRequested(httptest.NewRequest(http.MethodDelete, "/policy", nil)))
	require.False(t, dropEstablishedRequested(httptest.NewRequest(http.MethodDelete, "/policy?dropEstablished=false", nil)))
}
