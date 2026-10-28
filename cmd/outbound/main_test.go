// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	if size := unsafe.Sizeof(portSet{}); size != 36 {
		t.Fatalf("port set map value is %d bytes, want 36", size)
	}
	if size := unsafe.Sizeof(dnsName{}); size != 168 {
		t.Fatalf("DNS name map value is %d bytes, want 168", size)
	}
}

func TestDestinationRecord(t *testing.T) {
	remote := endpoint{IP: netip.MustParseAddr("8.8.8.8"), Port: 443}
	allowed := destinationRecord("audit", "TCP", remote, "dns.google", true)
	if allowed.Decision != "ALLOW" || allowed.DestinationIP != "8.8.8.8" || allowed.DestinationPort != 443 || allowed.Domain != "dns.google" || allowed.DomainSource != "dns_answer" {
		t.Fatalf("allowed record = %+v", allowed)
	}
	blocked := destinationRecord("enforce", "UDP", remote, "", false)
	if blocked.Decision != "BLOCK" || blocked.Level != "WARN" || blocked.Transport != "UDP" || blocked.Domain != "" || blocked.DomainSource != "" {
		t.Fatalf("blocked record = %+v", blocked)
	}
	if got := destinationRecord("audit", "TCP", remote, "", false).Decision; got != "WOULD_BLOCK" {
		t.Fatalf("audit decision = %q", got)
	}
}

func TestDNSNameFromWire(t *testing.T) {
	var name dnsName
	copy(name.Wire[:], []byte{6, 'G', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0})
	name.Length = 12
	if got := name.domain(); got != "google.com" {
		t.Fatalf("DNS name = %q", got)
	}
	name.Ambiguous = 1
	if got := name.domain(); got != "" {
		t.Fatalf("ambiguous IP must not be attributed to %q", got)
	}
	name.Ambiguous = 0
	name.Wire[0] = 0xc0
	if got := name.domain(); got != "" {
		t.Fatalf("compressed or invalid DNS name = %q", got)
	}
}

func TestBuildPolicyResolvesExactDomainAndKeepsCIDR(t *testing.T) {
	var cfg config
	cfg.Settings.Mode = "enforce"
	cfg.Settings.MaxIPEntries = 10
	cfg.Allowlist.Domains = []policyRule{{Name: "example.com"}}
	cfg.Allowlist.CIDRs = []policyRule{{Name: "169.254.169.254/32"}}
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
	for _, rule := range prefixes {
		got[rule.Prefix] = true
	}
	for _, want := range []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32"), netip.MustParsePrefix("93.184.215.14/32")} {
		if !got[want] {
			t.Fatalf("missing %s in %v", want, prefixes)
		}
	}
}

func TestCIDRPortRules(t *testing.T) {
	var cfg config
	cfg.Settings.Mode = "enforce"
	cfg.Settings.MaxIPEntries = 10
	cfg.Allowlist.CIDRs = []policyRule{
		{Name: "10.10.10.10/32", Ports: []uint16{22, 2222}},
		{Name: "10.10.10.20/32", Ports: []uint16{3000}},
	}
	rules, err := buildPolicy(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		switch rule.Prefix.Addr().String() {
		case "10.10.10.10":
			if !rule.Ports.allows(22) || !rule.Ports.allows(2222) || rule.Ports.allows(3000) {
				t.Fatalf("SSH rule permits wrong ports: %+v", rule)
			}
		case "10.10.10.20":
			if !rule.Ports.allows(3000) || rule.Ports.allows(22) {
				t.Fatalf("application rule permits wrong ports: %+v", rule)
			}
		default:
			t.Fatalf("unexpected rule: %+v", rule)
		}
	}
}

func TestExactDomainAndCIDRPortsMergeOnSameIP(t *testing.T) {
	var cfg config
	cfg.Settings.Mode = "enforce"
	cfg.Settings.MaxIPEntries = 10
	cfg.Allowlist.CIDRs = []policyRule{{Name: "10.10.10.10/32", Ports: []uint16{22}}}
	cfg.Allowlist.Domains = []policyRule{{Name: "example.com", Ports: []uint16{3000}}}
	rules, err := buildPolicy(context.Background(), cfg, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.10.10.10")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || !rules[0].Ports.allows(22) || !rules[0].Ports.allows(3000) || rules[0].Ports.allows(443) {
		t.Fatalf("merged ports = %+v", rules)
	}
}

func TestConfigParsesPortRulesAndRejectsInvalidPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	base := "version: v1\nsettings:\n  mode: enforce\n  max_ip_entries: 1024\n  cover_all_udp: true\nallowlist:\n  domains:\n    - domain: '*.example.com'\n      ports: [1138, 2218]\n  cidrs:\n    - cidr: 10.10.10.10/32\n      ports: [22]\n    - cidr: 10.10.10.20/32\n      ports: [3000]\n"
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Allowlist.Domains) != 1 || cfg.Allowlist.Domains[0].Ports[1] != 2218 || cfg.Allowlist.CIDRs[1].Ports[0] != 3000 {
		t.Fatalf("port rules were not parsed: %+v", cfg.Allowlist)
	}
	for _, ports := range []string{"[0]", "[22, 22]", "[65536]"} {
		data := strings.Replace(base, "ports: [22]", "ports: "+ports, 1)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatalf("invalid ports %s accepted", ports)
		}
	}
}

func TestIPPolicyDigestIgnoresMapIterationOrder(t *testing.T) {
	a := netip.MustParsePrefix("203.0.113.0/24")
	b := netip.MustParsePrefix("2001:db8::/32")
	if ipPolicyDigest([]ipRule{{Prefix: a}, {Prefix: b}}) != ipPolicyDigest([]ipRule{{Prefix: b}, {Prefix: a}}) {
		t.Fatal("IP policy digest must not depend on map iteration order")
	}
	if ipPolicyDigest([]ipRule{{Prefix: a}}) == ipPolicyDigest([]ipRule{{Prefix: a}, {Prefix: b}}) {
		t.Fatal("different IP policies must have different digests")
	}
	if ipPolicyDigest([]ipRule{{Prefix: a, Ports: newPortSet([]uint16{22})}}) == ipPolicyDigest([]ipRule{{Prefix: a, Ports: newPortSet([]uint16{3000})}}) {
		t.Fatal("port changes must change policy digest")
	}
}

func TestBuildPolicyRejectsPartialDNSFailure(t *testing.T) {
	var cfg config
	cfg.Settings.Mode = "enforce"
	cfg.Settings.MaxIPEntries = 10
	cfg.Allowlist.CIDRs = []policyRule{{Name: "169.254.169.254/32"}}
	cfg.Allowlist.Domains = []policyRule{{Name: "missing.example"}}
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
	cfg.Allowlist.Domains = []policyRule{{Name: "*.amazonaws.com"}}
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

func TestAuditLoggerWritesJSONLine(t *testing.T) {
	var output bytes.Buffer
	logger := &auditLogger{output: &output, mode: "enforce", hash: "policy-hash"}
	if err := logger.write(auditRecord{Level: "INFO", Event: "service_started", PolicyEntries: 2}); err != nil {
		t.Fatal(err)
	}
	var record auditRecord
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatalf("invalid JSON line: %v", err)
	}
	if record.SchemaVersion != 1 || record.Event != "service_started" || record.Mode != "enforce" || record.PolicySHA256 != "policy-hash" || record.PolicyEntries != 2 {
		t.Fatalf("audit record = %+v", record)
	}
	if _, err := time.Parse(time.RFC3339Nano, record.Time); err != nil {
		t.Fatalf("invalid UTC timestamp %q: %v", record.Time, err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestAuditLoggerReportsWriteFailure(t *testing.T) {
	logger := &auditLogger{output: failingWriter{}}
	if err := logger.write(auditRecord{Event: "service_started"}); err == nil {
		t.Fatal("log write failure must be reported")
	}
}

func TestAuditConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "version: v1\nsettings:\n  mode: audit\n  dns_refresh_interval: 30s\n  max_ip_entries: 1024\n  cover_all_udp: true\nallowlist:\n  domains: []\n  cidrs: []\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%x", sha256.Sum256([]byte(data))); cfg.PolicySHA256 != want {
		t.Fatalf("policy SHA-256 = %q, want %q", cfg.PolicySHA256, want)
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
	data := "version: v1\nsettings:\n  mode: audit\n  max_ip_entries: 1024\n  cover_all_udp: true\nallowlist:\n  domains: []\n  cidrs: []\n---\nsettings:\n  mode: enforce\n"
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
	if err := os.WriteFile(path, []byte(strings.Replace(data, "cover_all_udp: true", "cover_all_udp: false", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("partial UDP coverage must be rejected")
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
	if !shouldLogObservation(seen, "existing", now.Add(5*time.Minute), 1) {
		t.Fatal("an allowed destination must be logged again after five minutes")
	}
}
