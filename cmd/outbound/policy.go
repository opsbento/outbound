// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

type ipLookup func(context.Context, string, string) ([]netip.Addr, error)

func validDomain(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func buildPolicy(ctx context.Context, cfg config, lookup ipLookup) ([]netip.Prefix, error) {
	unique := make(map[netip.Prefix]struct{})
	for _, raw := range cfg.Allowlist.CIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, err
		}
		unique[prefix.Masked()] = struct{}{}
	}
	for _, domain := range cfg.Allowlist.Domains {
		if strings.HasPrefix(domain, "*.") {
			continue // Wildcards are populated from observed DNS answers.
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addresses, err := lookup(lookupCtx, "ip", domain)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("resolve allowed domain %q: %v", domain, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve allowed domain %q: no addresses", domain)
		}
		for _, address := range addresses {
			address = address.Unmap()
			if !address.IsValid() {
				return nil, fmt.Errorf("invalid DNS address for %q", domain)
			}
			unique[netip.PrefixFrom(address, address.BitLen())] = struct{}{}
		}
	}
	if cfg.Settings.Mode == "enforce" && len(unique) == 0 && len(cfg.Allowlist.Domains) == 0 {
		return nil, fmt.Errorf("enforce mode requires at least one resolved domain or CIDR")
	}
	if len(unique) > cfg.Settings.MaxIPEntries || len(unique) > 4096 {
		return nil, fmt.Errorf("policy has %d IP prefixes; max_ip_entries is %d (eBPF limit 4096)", len(unique), cfg.Settings.MaxIPEntries)
	}
	prefixes := make([]netip.Prefix, 0, len(unique))
	for prefix := range unique {
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func defaultIPLookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
