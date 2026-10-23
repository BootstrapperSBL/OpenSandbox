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
	"net/netip"
	"sort"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
)

// EstablishedDrops lists destinations that a policy change no longer allows.
// ApplyStaticDropEstablished installs drop rules for these destinations ahead
// of the usual `ct state established,related accept`, so keep-alive flows to
// removed allows die on the next packet instead of surviving on conntrack.
type EstablishedDrops struct {
	Addrs    []netip.Addr
	Prefixes []netip.Prefix
}

// Empty reports whether there is nothing to drop.
func (d EstablishedDrops) Empty() bool {
	return len(d.Addrs) == 0 && len(d.Prefixes) == 0
}

// Matches reports whether addr is covered by this drop set.
func (d EstablishedDrops) Matches(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, a := range d.Addrs {
		if a == addr {
			return true
		}
	}
	for _, p := range d.Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// SnapshotResolvedDomains returns a copy of the DNS-learned address map the
// manager currently tracks. Safe to call without holding an external lock.
func (m *Manager) SnapshotResolvedDomains() map[string][]netip.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]netip.Addr, len(m.domains))
	for domain, entry := range m.domains {
		if entry == nil || len(entry.addresses) == 0 {
			continue
		}
		addrs := make([]netip.Addr, 0, len(entry.addresses))
		for addr := range entry.addresses {
			addrs = append(addrs, addr)
		}
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
		out[domain] = addrs
	}
	return out
}

// ComputeEstablishedDrops derives the destinations a policy change removed.
// priorDomains is the pre-apply DNS-learned map (from SnapshotResolvedDomains).
//
// A destination is dropped when the new policy no longer allows it via a
// surviving domain lease or a portless IP/CIDR allow (EvaluateIP). Removed
// static allow CIDRs are retained as prefixes so every address in the range is
// covered without enumerating them.
func ComputeEstablishedDrops(oldPol, newPol *policy.NetworkPolicy, priorDomains map[string][]netip.Addr) EstablishedDrops {
	if newPol == nil {
		newPol = policy.DefaultDenyPolicy()
	}

	survivingDomainIPs := make(map[netip.Addr]struct{})
	var addrs []netip.Addr
	seenAddr := make(map[netip.Addr]struct{})
	addAddr := func(addr netip.Addr) {
		if !addr.IsValid() {
			return
		}
		addr = addr.Unmap()
		if _, ok := seenAddr[addr]; ok {
			return
		}
		seenAddr[addr] = struct{}{}
		addrs = append(addrs, addr)
	}

	for domain, ips := range priorDomains {
		if newPol.Evaluate(domain) == policy.ActionAllow {
			for _, ip := range ips {
				if ip.IsValid() {
					survivingDomainIPs[ip.Unmap()] = struct{}{}
				}
			}
			continue
		}
		for _, ip := range ips {
			addAddr(ip)
		}
	}

	var prefixes []netip.Prefix
	seenPrefix := make(map[string]struct{})
	addPrefix := func(pfx netip.Prefix) {
		if !pfx.IsValid() {
			return
		}
		key := pfx.Masked().String()
		if _, ok := seenPrefix[key]; ok {
			return
		}
		seenPrefix[key] = struct{}{}
		prefixes = append(prefixes, pfx.Masked())
	}

	if oldPol != nil {
		for _, r := range oldPol.Egress {
			if r.Action != policy.ActionAllow || len(r.Ports) > 0 || len(r.PortRanges) > 0 {
				continue
			}
			switch {
			case r.Target != "" && looksLikeIP(r):
				ip := parseRuleIP(r)
				if ip.IsValid() && newPol.EvaluateIP(ip) != policy.ActionAllow {
					if _, keep := survivingDomainIPs[ip.Unmap()]; !keep {
						addAddr(ip)
					}
				}
			case r.Target != "" && looksLikeCIDR(r):
				pfx := parseRulePrefix(r)
				if pfx.IsValid() && !prefixStillAllowed(newPol, pfx) {
					addPrefix(pfx)
				}
			}
		}
	}

	// New deny rules for literal IP/CIDR must also cut established flows even
	// when the previous policy was default-allow with no explicit allow entry.
	for _, r := range newPol.Egress {
		if r.Action != policy.ActionDeny || len(r.Ports) > 0 || len(r.PortRanges) > 0 {
			continue
		}
		if looksLikeIP(r) {
			addAddr(parseRuleIP(r))
			continue
		}
		if looksLikeCIDR(r) {
			addPrefix(parseRulePrefix(r))
		}
	}

	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	return EstablishedDrops{Addrs: addrs, Prefixes: prefixes}
}

func looksLikeIP(r policy.EgressRule) bool {
	_, err := netip.ParseAddr(r.Target)
	return err == nil
}

func looksLikeCIDR(r policy.EgressRule) bool {
	_, err := netip.ParsePrefix(r.Target)
	return err == nil
}

func parseRuleIP(r policy.EgressRule) netip.Addr {
	ip, err := netip.ParseAddr(r.Target)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func parseRulePrefix(r policy.EgressRule) netip.Prefix {
	pfx, err := netip.ParsePrefix(r.Target)
	if err != nil {
		return netip.Prefix{}
	}
	return pfx
}

// prefixStillAllowed reports whether every address in pfx is still allowed by
// newPol's portless IP/CIDR evaluation. A covering allow CIDR or default-allow
// keeps it; an overlapping deny or default-deny without a covering allow drops it.
func prefixStillAllowed(newPol *policy.NetworkPolicy, pfx netip.Prefix) bool {
	if newPol == nil || !pfx.IsValid() {
		return false
	}
	// Sample the network address and (when distinct) the last address. Exact
	// coverage of large ranges is left to EvaluateIP on live flows; this only
	// decides whether to keep the whole removed prefix as a drop target.
	if newPol.EvaluateIP(pfx.Addr()) != policy.ActionAllow {
		return false
	}
	last := lastAddr(pfx)
	if last.IsValid() && last != pfx.Addr() && newPol.EvaluateIP(last) != policy.ActionAllow {
		return false
	}
	return true
}

func lastAddr(pfx netip.Prefix) netip.Addr {
	if !pfx.IsValid() {
		return netip.Addr{}
	}
	addr := pfx.Addr()
	bits := pfx.Bits()
	if addr.Is4() {
		var b [4]byte
		copy(b[:], addr.AsSlice())
		hostBits := 32 - bits
		if hostBits <= 0 {
			return addr
		}
		mask := uint32((1 << hostBits) - 1)
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v |= mask
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	var b [16]byte
	copy(b[:], addr.AsSlice())
	hostBits := 128 - bits
	for i := 15; hostBits > 0; i-- {
		take := hostBits
		if take > 8 {
			take = 8
		}
		b[i] |= byte((1 << take) - 1)
		hostBits -= take
	}
	return netip.AddrFrom16(b)
}
