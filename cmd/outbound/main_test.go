// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestDestinationKeyEndpoint(t *testing.T) {
	tests := []struct {
		key  destinationKey
		want netip.Addr
	}{
		{destinationKey{Family: 4, Port: 80, Address: [16]byte{8, 8, 8, 8}}, netip.MustParseAddr("8.8.8.8")},
		{destinationKey{Family: 6, Port: 443, Address: [16]byte{15: 1}}, netip.MustParseAddr("::1")},
	}
	for _, tc := range tests {
		got, err := tc.key.endpoint()
		if err != nil || got.IP != tc.want || got.Port != tc.key.Port {
			t.Fatalf("endpoint(%v) = %v, %v", tc.key, got, err)
		}
	}
}

func TestDestinationKeyTransport(t *testing.T) {
	if got := (destinationKey{Protocol: 6}).transport(); got != "TCP" {
		t.Fatalf("TCP protocol = %q", got)
	}
	if got := (destinationKey{Protocol: 17}).transport(); got != "UDP" {
		t.Fatalf("QUIC protocol = %q", got)
	}
}

func TestPolicyControlMatchesEBPFLayout(t *testing.T) {
	if size := unsafe.Sizeof(policyControl{}); size != 12 {
		t.Fatalf("policy control map value is %d bytes, want 12", size)
	}
}

func TestFormatDestination(t *testing.T) {
	remote := endpoint{IP: netip.MustParseAddr("8.8.8.8"), Port: 443}
	if got := formatDestination("audit", "TCP", remote, "dns.google", true); got != "AUDIT ALLOW TCP dst=8.8.8.8:443 ptr=dns.google" {
		t.Fatalf("formatted line = %q", got)
	}
	if got := formatDestination("enforce", "TCP", remote, "", false); got != "ENFORCE BLOCK TCP dst=8.8.8.8:443" {
		t.Fatalf("blocked line = %q", got)
	}
	if got := formatDestination("enforce", "UDP", remote, "", false); got != "ENFORCE BLOCK UDP dst=8.8.8.8:443" {
		t.Fatalf("blocked QUIC line = %q", got)
	}
}

func TestBuildPolicyResolvesExactDomainAndKeepsCIDR(t *testing.T) {
	var cfg config
	cfg.Settings.Mode = "enforce"
	cfg.Settings.MaxIPEntries = 10
	cfg.Allowlist.Domains = []string{"example.com"}
	cfg.Allowlist.CIDRs = []string{"169.254.169.254/32"}
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "example.com" {
			t.Fatalf("unexpected host %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
	}
	prefixes, err := buildPolicy(context.Background(), cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[netip.Prefix]bool)
	for _, prefix := range prefixes {
		got[prefix] = true
	}
	for _, want := range []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32"), netip.MustParsePrefix("93.184.215.14/32")} {
		if !got[want] {
			t.Fatalf("missing %s in %v", want, prefixes)
		}
	}
}

func TestBuildPolicyRejectsPartialDNSFailure(t *testing.T) {
	var cfg config
	cfg.Settings.Mode = "enforce"
	cfg.Settings.MaxIPEntries = 10
	cfg.Allowlist.CIDRs = []string{"169.254.169.254/32"}
	cfg.Allowlist.Domains = []string{"missing.example"}
	_, err := buildPolicy(context.Background(), cfg, func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("DNS unavailable")
	})
	if err == nil {
		t.Fatal("partial DNS failure must reject new policy")
	}
}

func TestWildcardDNSName(t *testing.T) {
	key, err := wildcardDNSName("*.AmazonAWS.com")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := wildcardDNSName("*.amazonaws.com")
	if err != nil || key != lower || key.First == 0 || key.Second == 0 {
		t.Fatalf("wildcard hash mismatch: %v, %v, %v", key, lower, err)
	}
	other, err := wildcardDNSName("*.ubuntu.com")
	if err != nil || key == other {
		t.Fatalf("distinct wildcard suffixes must have distinct keys: %v, %v, %v", key, other, err)
	}
	if _, err := wildcardDNSName("*."); err == nil {
		t.Fatal("empty wildcard suffix must be rejected")
	}
}

func TestExactDNSNameHash(t *testing.T) {
	key, err := dnsNameHash("Go.Dev")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := dnsNameHash("go.dev")
	if err != nil || key != lower {
		t.Fatalf("exact DNS hash is not case insensitive: %v, %v, %v", key, lower, err)
	}
	wildcard, err := wildcardDNSName("*.go.dev")
	if err != nil || key != wildcard {
		t.Fatalf("exact and wildcard map keys for the same suffix differ: %v, %v, %v", key, wildcard, err)
	}
	if _, err := dnsNameHash("*.go.dev"); err == nil {
		t.Fatal("exact DNS name must reject wildcard syntax")
	}
}

func TestWildcardPolicyWaitsForObservedDNS(t *testing.T) {
	var cfg config
	cfg.Settings.Mode = "enforce"
	cfg.Settings.MaxIPEntries = 10
	cfg.Allowlist.Domains = []string{"*.amazonaws.com"}
	prefixes, err := buildPolicy(context.Background(), cfg, func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("wildcard must not be sent to DNS as a literal hostname")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 0 {
		t.Fatalf("wildcard policy = %v, want DNS-learned addresses only", prefixes)
	}
}

func TestTimestampWriterAddsTimestampToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbound.log")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (timestampWriter{file}).Write([]byte("AUDIT ALLOW TCP dst=8.8.8.8:443\n")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Z AUDIT ALLOW TCP dst=8.8.8.8:443\n") {
		t.Fatalf("file log line = %q", data)
	}
}

func TestAuditConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "version: v1\nsettings:\n  mode: audit\n  dns_refresh_interval: 30s\n  max_ip_entries: 1024\nallowlist:\n  domains: []\n  cidrs: []\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(data, "mode: audit", "mode: audit\n  log_level: invalid", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("invalid log level must be rejected")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(data, "mode: audit", "mode: audit\n  log_file: relative.log", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("relative log file path must be rejected")
	}

	if err := os.WriteFile(path, []byte(strings.Replace(data, "mode: audit", "mode: enforce", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal("enforce mode must be accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(data, "domains: []", "domains: [\"*.amazonaws.com\"]", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("wildcard without proxy must be accepted: %v", err)
	}
}

func TestConfigRejectsTrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "version: v1\nsettings:\n  mode: audit\n  max_ip_entries: 1024\nallowlist:\n  domains: []\n  cidrs: []\n---\nsettings:\n  mode: enforce\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("multiple YAML documents must be rejected")
	}
}

func TestCoverAllUDPConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "version: v1\nsettings:\n  mode: audit\n  cover_all_udp: true\n  max_ip_entries: 1024\nallowlist:\n  domains: []\n  cidrs: []\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Settings.CoverAllUDP {
		t.Fatal("cover_all_udp was not loaded")
	}
}

func TestNewDestinationRemainsVisibleWhenDeduplicationIsFull(t *testing.T) {
	now := time.Now()
	seen := map[string]time.Time{"existing": now}
	if !shouldLogObservation(seen, "new", now, 1) {
		t.Fatal("new destination was hidden when deduplication was full")
	}
	if shouldLogObservation(seen, "existing", now, 1) {
		t.Fatal("existing destination should still be deduplicated")
	}
}
