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

package nftables

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestComputeEstablishedDrops_RemovedDomainUsesLearnedIPs(t *testing.T) {
	oldPol, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"deb.debian.org"}]}`)
	require.NoError(t, err)
	newPol, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[]}`)
	require.NoError(t, err)

	drops := ComputeEstablishedDrops(oldPol, newPol, map[string][]netip.Addr{
		"deb.debian.org": {netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")},
	})
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("2001:db8::10"),
	}, drops.Addrs)
	require.Empty(t, drops.Prefixes)
}

func TestComputeEstablishedDrops_KeepsSurvivingDomainLease(t *testing.T) {
	oldPol, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"deb.debian.org"},{"action":"allow","target":"pypi.org"}]}`)
	require.NoError(t, err)
	newPol, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"pypi.org"}]}`)
	require.NoError(t, err)

	drops := ComputeEstablishedDrops(oldPol, newPol, map[string][]netip.Addr{
		"deb.debian.org": {netip.MustParseAddr("203.0.113.10")},
		"pypi.org":       {netip.MustParseAddr("198.51.100.2")},
	})
	require.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.10")}, drops.Addrs)
}

func TestComputeEstablishedDrops_RemovedStaticIPAndCIDR(t *testing.T) {
	oldPol, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[{"action":"allow","target":"1.1.1.1"},{"action":"allow","target":"203.0.113.0/24"}]}`)
	require.NoError(t, err)
	newPol, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[]}`)
	require.NoError(t, err)

	drops := ComputeEstablishedDrops(oldPol, newPol, nil)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, drops.Addrs)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, drops.Prefixes)
}

func TestComputeEstablishedDrops_NewDenyCutsDefaultAllow(t *testing.T) {
	oldPol, err := policy.ParsePolicy(`{"defaultAction":"allow","egress":[]}`)
	require.NoError(t, err)
	newPol, err := policy.ParsePolicy(`{"defaultAction":"allow","egress":[{"action":"deny","target":"9.9.9.9"}]}`)
	require.NoError(t, err)

	drops := ComputeEstablishedDrops(oldPol, newPol, nil)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("9.9.9.9")}, drops.Addrs)
}

func TestApplyStaticDropEstablished_EmitsDropsBeforeEstablishedAccept(t *testing.T) {
	var scripts []string
	m := NewManagerWithRunner(func(_ context.Context, script string) ([]byte, error) {
		scripts = append(scripts, script)
		return nil, nil
	})
	p, err := policy.ParsePolicy(`{"defaultAction":"deny","egress":[]}`)
	require.NoError(t, err)

	matched, err := m.ApplyStaticDropEstablished(context.Background(), p, EstablishedDrops{
		Addrs:    []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	require.NoError(t, err)
	require.Equal(t, 0, matched) // no /proc conntrack in unit test
	require.Len(t, scripts, 1)

	script := scripts[0]
	dropIP := strings.Index(script, "ip daddr 203.0.113.10 ct state established,related drop")
	dropCIDR := strings.Index(script, "ip daddr 198.51.100.0/24 ct state established,related drop")
	established := strings.Index(script, "ct state established,related accept")
	require.GreaterOrEqual(t, dropIP, 0, script)
	require.GreaterOrEqual(t, dropCIDR, 0, script)
	require.GreaterOrEqual(t, established, 0, script)
	require.Less(t, dropIP, established)
	require.Less(t, dropCIDR, established)
}

func TestCountMatchingConntrackFlowsData(t *testing.T) {
	data := []byte(`
ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=203.0.113.10 sport=12345 dport=80 src=203.0.113.10 dst=10.0.0.2 sport=80 dport=12345 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=1.1.1.1 sport=12346 dport=443 src=1.1.1.1 dst=10.0.0.2 sport=443 dport=12346 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 30 src=10.0.0.2 dst=203.0.113.10 sport=53 dport=53 [UNREPLIED] src=203.0.113.10 dst=10.0.0.2 sport=53 dport=53 mark=0 zone=0 use=2
`)
	n := countMatchingConntrackFlowsData(data, EstablishedDrops{
		Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	})
	require.Equal(t, 1, n)
}
