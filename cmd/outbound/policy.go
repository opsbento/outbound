// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type ipLookup func(context.Context, string, string) ([]netip.Addr, error)

type ipRule struct {
	Prefix netip.Prefix
	Ports  portSet
}

func ipPolicyDigest(rules []ipRule) string {
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, fmt.Sprintf("%s:%v", rule.Prefix.Masked(), rule.Ports))
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		_, _ = fmt.Fprintln(hash, name)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

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

func buildPolicy(ctx context.Context, cfg config, lookup ipLookup) ([]ipRule, error) {
	unique := make(map[netip.Prefix]portSet)
	for _, rule := range cfg.Allowlist.CIDRs {
		prefix, err := netip.ParsePrefix(rule.Name)
		if err != nil {
			return nil, err
		}
		unique[prefix.Masked()] = newPortSet(rule.Ports)
	}
	for _, rule := range cfg.Allowlist.Domains {
		domain := rule.Name
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
			prefix := netip.PrefixFrom(address, address.BitLen())
			value := newPortSet(rule.Ports)
			if old, ok := unique[prefix]; ok {
				value, err = mergePorts(old, value)
				if err != nil {
					return nil, fmt.Errorf("merge IP policy for %s: %w", prefix, err)
				}
			}
			unique[prefix] = value
		}
	}
	if cfg.Settings.Mode == "enforce" && len(unique) == 0 && len(cfg.Allowlist.Domains) == 0 {
		return nil, fmt.Errorf("enforce mode requires at least one resolved domain or CIDR")
	}
	if len(unique) > cfg.Settings.MaxIPEntries || len(unique) > 4096 {
		return nil, fmt.Errorf("policy has %d IP prefixes; max_ip_entries is %d (eBPF limit 4096)", len(unique), cfg.Settings.MaxIPEntries)
	}
	rules := make([]ipRule, 0, len(unique))
	for prefix, ports := range unique {
		rules = append(rules, ipRule{Prefix: prefix, Ports: ports})
	}
	return rules, nil
}

func defaultIPLookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
