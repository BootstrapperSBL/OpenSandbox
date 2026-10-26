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

package iptables

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGatewayDNSRedirectScriptExactIPv4IPv6Set(t *testing.T) {
	script, err := gatewayDNSRedirectScript([]netip.Addr{
		netip.MustParseAddr("10.0.0.10"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("::ffff:10.0.0.1"),
		netip.MustParseAddr("fd00::1"),
		netip.MustParseAddr("10.0.0.10"),
	}, 15353)
	require.NoError(t, err)
	require.Contains(t, script, "delete table inet "+gatewayDNSNftTable+"\nadd table inet "+gatewayDNSNftTable)
	require.Contains(t, script, "add chain inet "+gatewayDNSNftTable+" gw { type nat hook prerouting priority dstnat; }")
	assert.Equal(t, 6, strings.Count(script, "add rule "), "three unique gateways each need UDP and TCP rules")
	assert.Contains(t, script, "ip daddr 10.0.0.1 udp dport 53 redirect to :15353")
	assert.Contains(t, script, "ip daddr 10.0.0.1 tcp dport 53 redirect to :15353")
	assert.Contains(t, script, "ip daddr 10.0.0.10 udp dport 53 redirect to :15353")
	assert.Contains(t, script, "ip daddr 10.0.0.10 tcp dport 53 redirect to :15353")
	assert.Contains(t, script, "ip6 daddr fd00::1 udp dport 53 redirect to :15353")
	assert.Contains(t, script, "ip6 daddr fd00::1 tcp dport 53 redirect to :15353")
	assert.NotContains(t, script, "ip6 daddr ::ffff:10.0.0.1", "mapped IPv4 must normalize to one IPv4 gateway")
}

func TestGatewayDNSRedirectScriptEmptySetAndValidation(t *testing.T) {
	empty, err := gatewayDNSRedirectScript(nil, 15353)
	require.NoError(t, err)
	assert.Equal(t, "delete table inet "+gatewayDNSNftTable+"\n", empty)
	assert.Error(t, func() error {
		_, err := gatewayDNSRedirectScript([]netip.Addr{netip.Addr{}}, 15353)
		return err
	}())
	assert.Error(t, func() error {
		_, err := gatewayDNSRedirectScript(nil, 0)
		return err
	}())
}

func TestReplaceGatewayDNSRedirectsRetriesMissingTableWithoutDelete(t *testing.T) {
	var scripts []string
	r := redirectRunner{runNft: func(_ context.Context, script string) ([]byte, error) {
		scripts = append(scripts, script)
		if len(scripts) == 1 {
			return []byte("Error: No such file or directory\n" + script), errors.New("exit status 1")
		}
		return nil, nil
	}}

	err := replaceGatewayDNSRedirects(r, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, 15353)
	require.NoError(t, err)
	require.Len(t, scripts, 2)
	assert.Contains(t, scripts[0], "delete table inet "+gatewayDNSNftTable)
	assert.NotContains(t, scripts[1], "delete table inet "+gatewayDNSNftTable)
	assert.Contains(t, scripts[1], "add table inet "+gatewayDNSNftTable)
	assert.Contains(t, scripts[1], "ip daddr 10.0.0.1")
}

func TestReplaceGatewayDNSRedirectsTreatsMissingEmptyTableAsSuccess(t *testing.T) {
	calls := 0
	r := redirectRunner{runNft: func(_ context.Context, script string) ([]byte, error) {
		calls++
		assert.Equal(t, "delete table inet "+gatewayDNSNftTable+"\n", script)
		return []byte("Error: No such file or directory\n" + script), errors.New("exit status 1")
	}}

	require.NoError(t, replaceGatewayDNSRedirects(r, nil, 15353))
	assert.Equal(t, 1, calls, "no retry is needed when the desired set is empty")
}

func TestReplaceGatewayDNSRedirectsPropagatesFailures(t *testing.T) {
	t.Run("non-missing error", func(t *testing.T) {
		calls := 0
		r := redirectRunner{runNft: func(_ context.Context, _ string) ([]byte, error) {
			calls++
			return []byte("syntax error"), errors.New("exit status 1")
		}}
		assert.Error(t, replaceGatewayDNSRedirects(r, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, 15353))
		assert.Equal(t, 1, calls)
	})
	t.Run("failed missing-table retry", func(t *testing.T) {
		calls := 0
		r := redirectRunner{runNft: func(_ context.Context, script string) ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte("Error: No such file or directory\n" + script), errors.New("exit status 1")
			}
			return []byte("nft busy"), errors.New("exit status 1")
		}}
		err := replaceGatewayDNSRedirects(r, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, 15353)
		assert.ErrorContains(t, err, "retry")
		assert.Equal(t, 2, calls)
	})
}
