// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

type config struct {
	Version  string `yaml:"version"`
	Settings struct {
		Mode               string `yaml:"mode"`
		LogLevel           string `yaml:"log_level"`
		LogFile            string `yaml:"log_file"`
		LogReverseDNS      bool   `yaml:"log_reverse_dns"`
		DNSRefreshInterval string `yaml:"dns_refresh_interval"`
		MaxIPEntries       int    `yaml:"max_ip_entries"`
		CoverAllUDP        bool   `yaml:"cover_all_udp"`
	} `yaml:"settings"`
	Allowlist struct {
		Domains []string `yaml:"domains"`
		CIDRs   []string `yaml:"cidrs"`
	} `yaml:"allowlist"`
}

var version = "development"

func loadConfig(path string) (config, error) {
	var cfg config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err != nil {
			return cfg, fmt.Errorf("read trailing configuration: %w", err)
		}
		return cfg, errors.New("configuration must contain exactly one YAML document")
	}

	if cfg.Version != "v1" {
		return cfg, fmt.Errorf("unsupported config version %q", cfg.Version)
	}

	if cfg.Settings.Mode != "audit" && cfg.Settings.Mode != "enforce" {
		return cfg, errors.New("mode must be either 'audit' or 'enforce'")
	}

	if cfg.Settings.LogLevel == "" {
		cfg.Settings.LogLevel = "info"
	}
	switch cfg.Settings.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return cfg, fmt.Errorf("invalid log_level %q: use debug, info, warn, or error", cfg.Settings.LogLevel)
	}

	if cfg.Settings.MaxIPEntries < 1 {
		return cfg, errors.New("max_ip_entries must be positive")
	}

	if cfg.Settings.LogFile != "" && !filepath.IsAbs(cfg.Settings.LogFile) {
		return cfg, errors.New("log_file must be an absolute path")
	}

	if cfg.Settings.DNSRefreshInterval == "" {
		cfg.Settings.DNSRefreshInterval = "1m"
	}
	if duration, err := time.ParseDuration(cfg.Settings.DNSRefreshInterval); err != nil || duration <= 0 {
		return cfg, fmt.Errorf("dns_refresh_interval must be positive: %q", cfg.Settings.DNSRefreshInterval)
	}

	seenCIDRs := make(map[netip.Prefix]bool)
	for _, cidr := range cfg.Allowlist.CIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return cfg, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		if prefix.Addr().Is4In6() {
			return cfg, fmt.Errorf("IPv4-mapped CIDR %q is not supported", cidr)
		}
		prefix = prefix.Masked()
		if seenCIDRs[prefix] {
			return cfg, fmt.Errorf("duplicate CIDR %q", cidr)
		}
		seenCIDRs[prefix] = true
	}
	seenDomains := make(map[string]bool)
	wildcardCount := 0
	exactCount := 0
	for _, domain := range cfg.Allowlist.Domains {
		if strings.HasPrefix(domain, "*.") {
			if _, err := wildcardDNSName(domain); err != nil {
				return cfg, err
			}
			wildcardCount++
		} else {
			if _, err := dnsNameHash(domain); err != nil {
				return cfg, err
			}
			exactCount++
		}
		name := strings.ToLower(domain)
		if seenDomains[name] {
			return cfg, fmt.Errorf("duplicate domain %q", domain)
		}
		seenDomains[name] = true
	}
	if wildcardCount > 64 || exactCount > 64 {
		return cfg, errors.New("at most 64 wildcard and 64 exact domains are supported")
	}

	return cfg, nil
}

type endpoint struct {
	IP   netip.Addr
	Port uint16
}

type timestampWriter struct{ file *os.File }

func (writer timestampWriter) Write(line []byte) (int, error) {
	if _, err := fmt.Fprintf(writer.file, "%s %s", time.Now().UTC().Format(time.RFC3339), line); err != nil {
		return 0, err
	}
	return len(line), nil
}

func run(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	var output io.Writer = os.Stdout
	if cfg.Settings.LogFile != "" {
		file, err := os.OpenFile(cfg.Settings.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		defer file.Close()
		output = io.MultiWriter(os.Stdout, timestampWriter{file})
	}
	logger := log.New(output, "", 0)
	logEvents := cfg.Settings.LogLevel == "debug" || cfg.Settings.LogLevel == "info"
	logWarnings := cfg.Settings.LogLevel != "error"
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	policy, err := buildPolicy(ctx, cfg, defaultIPLookup)
	if err != nil {
		return err
	}
	monitor, err := openConnectMonitor(policy, cfg.Settings.Mode == "enforce", cfg.Settings.CoverAllUDP, cfg.Allowlist.Domains)
	if err != nil {
		return err
	}
	defer monitor.Close()
	if logEvents {
		logger.Printf("%s monitoring started (TCP and %s; policy entries: %d, reverse DNS: %t)", strings.ToUpper(cfg.Settings.Mode), map[bool]string{true: "all UDP", false: "UDP 443"}[cfg.Settings.CoverAllUDP], len(policy), cfg.Settings.LogReverseDNS)
	}
	if err := notifySystemdReady(); err != nil {
		return fmt.Errorf("notify systemd readiness: %w", err)
	}

	type observedDestination struct {
		remote    endpoint
		transport string
		allowed   bool
	}
	var lookups chan observedDestination
	var workers sync.WaitGroup
	if logEvents && cfg.Settings.LogReverseDNS {
		lookups = make(chan observedDestination, 64)
		for range 4 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for observed := range lookups {
					logger.Print(formatDestination(cfg.Settings.Mode, observed.transport, observed.remote, reverseDNS(ctx, observed.remote.IP), observed.allowed))
				}
			}()
		}
	}
	defer func() {
		if lookups != nil {
			close(lookups)
			workers.Wait()
		}
	}()

	seen := make(map[string]time.Time)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	refreshInterval, _ := time.ParseDuration(cfg.Settings.DNSRefreshInterval)
	nextRefresh := time.Now().Add(refreshInterval)
	for {
		now := time.Now()
		if !now.Before(nextRefresh) {
			updated, err := buildPolicy(ctx, cfg, defaultIPLookup)
			if err == nil {
				err = monitor.RefreshPolicy(updated, cfg.Settings.Mode == "enforce", cfg.Settings.CoverAllUDP)
			}
			if err != nil && logWarnings {
				logger.Printf("WARN policy refresh failed; previous policy retained: %v", err)
			}
			nextRefresh = time.Now().Add(refreshInterval)
		}
		for key, last := range seen {
			if now.Sub(last) > 5*time.Minute {
				delete(seen, key)
			}
		}
		emit := func(remote endpoint, transport string, allowed bool) {
			key := transport + ":" + remote.IP.String() + ":" + strconv.Itoa(int(remote.Port)) + ":" + strconv.FormatBool(allowed)
			if !shouldLogObservation(seen, key, now, cfg.Settings.MaxIPEntries) {
				return
			}
			if !logEvents {
				return
			}
			if lookups == nil {
				logger.Print(formatDestination(cfg.Settings.Mode, transport, remote, "", allowed))
				return
			}
			select {
			case lookups <- observedDestination{remote, transport, allowed}:
			default:
				logger.Print(formatDestination(cfg.Settings.Mode, transport, remote, "", allowed))
			}
		}
		if err := monitor.Drain(emit); err != nil && logWarnings {
			logger.Printf("WARN eBPF drain failed: %v", err)
		}
		select {
		case <-ctx.Done():
			if logEvents {
				logger.Printf("%s HTTP(S) monitoring stopped", strings.ToUpper(cfg.Settings.Mode))
			}
			return nil
		case <-ticker.C:
		}
	}
}

func shouldLogObservation(seen map[string]time.Time, key string, now time.Time, maxEntries int) bool {
	if _, exists := seen[key]; exists {
		seen[key] = now
		return false
	}
	if len(seen) < maxEntries {
		seen[key] = now
	}
	return true
}

func notifySystemdReady() error {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	_, err = connection.Write([]byte("READY=1"))
	return err
}

func reverseDNS(ctx context.Context, ip netip.Addr) string {
	lookupCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func formatDestination(mode, transport string, remote endpoint, ptr string, allowed bool) string {
	decision := "ALLOW"
	if !allowed {
		decision = "WOULD_BLOCK"
		if mode == "enforce" {
			decision = "BLOCK"
		}
	}
	line := strings.ToUpper(mode) + " " + decision + " " + transport + " dst=" + net.JoinHostPort(remote.IP.String(), strconv.Itoa(int(remote.Port)))
	if ptr != "" {
		line += " ptr=" + ptr
	}
	return line
}

func main() {
	configPath := flag.String("config", "/etc/outbound/config.yaml", "path to YAML configuration")
	checkConfigOnly := flag.Bool("check-config", false, "validate configuration and resolve allowlisted domains, then exit")
	checkEBPFOnly := flag.Bool("check-ebpf", false, "load and verify eBPF programs without attaching them, then exit")
	detachPolicyOnly := flag.Bool("detach-policy", false, "remove pinned eBPF policy links after stopping the service")
	policyStatusOnly := flag.Bool("policy-status", false, "verify all pinned eBPF policy links are attached")
	showVersion := flag.Bool("version", false, "print the binary version")
	flag.Parse()
	if *showVersion {
		fmt.Printf("outbound %s\n", version)
		return
	}
	if *policyStatusOnly {
		if err := policyStatus(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *detachPolicyOnly {
		if err := detachPolicy(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("pinned eBPF policy detached")
		return
	}
	if *checkEBPFOnly {
		if err := checkEBPF(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("eBPF programs valid")
		return
	}
	if *checkConfigOnly {
		cfg, err := loadConfig(*configPath)
		if err == nil {
			_, err = buildPolicy(context.Background(), cfg, defaultIPLookup)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("configuration valid")
		return
	}
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
