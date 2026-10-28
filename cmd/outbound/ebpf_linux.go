// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed connect.bpf.o
var connectObject []byte

type destinationKey struct {
	Family   uint8
	Protocol uint8
	Port     uint16
	Address  [16]byte
}

func (key destinationKey) transport() string {
	if key.Protocol == 17 {
		return "UDP"
	}
	return "TCP"
}

type observation struct {
	Timestamp uint64
	Allowed   uint32
	Pad       uint32
}

type policyControl struct {
	Enforce     uint32
	Slot        uint32
	CoverAllUDP uint32
}

type ipv4Key struct {
	Prefixlen uint32
	Address   [4]byte
}

type ipv6Key struct {
	Prefixlen uint32
	Address   [16]byte
}

type dnsSuffixHash struct {
	First  uint64
	Second uint64
}

func dnsNameHash(name string) (dnsSuffixHash, error) {
	var wire [128]byte
	length := 0
	if !validDomain(name) {
		return dnsSuffixHash{}, fmt.Errorf("invalid DNS domain %q", name)
	}
	for _, label := range strings.Split(strings.ToLower(name), ".") {
		if length+len(label)+2 > len(wire) {
			return dnsSuffixHash{}, fmt.Errorf("domain %q exceeds 128 DNS bytes", name)
		}
		wire[length] = byte(len(label))
		length++
		length += copy(wire[length:], label)
	}
	length++ // DNS root label; Wire is already zero initialized.
	var hash dnsSuffixHash
	for i := length - 1; i >= 0; i-- {
		hash.First = hash.First*131 + uint64(wire[i])
		hash.Second = hash.Second*137 + uint64(wire[i])
	}
	return hash, nil
}

func wildcardDNSName(pattern string) (dnsSuffixHash, error) {
	if !strings.HasPrefix(pattern, "*.") {
		return dnsSuffixHash{}, fmt.Errorf("invalid wildcard domain %q", pattern)
	}
	return dnsNameHash(strings.TrimPrefix(pattern, "*."))
}

func (key destinationKey) endpoint() (endpoint, error) {
	switch key.Family {
	case 4:
		return endpoint{IP: netip.AddrFrom4([4]byte(key.Address[:4])), Port: key.Port}, nil
	case 6:
		return endpoint{IP: netip.AddrFrom16(key.Address), Port: key.Port}, nil
	default:
		return endpoint{}, fmt.Errorf("unknown address family %d", key.Family)
	}
}

type connectMonitor struct {
	collection *ebpf.Collection
	links      []link.Link
	slot       uint32
}

const policyPinDir = "/sys/fs/bpf/outbound"

var policyPrograms = []struct {
	name   string
	attach ebpf.AttachType
}{
	{"egress_connect4", ebpf.AttachCGroupInet4Connect},
	{"egress_connect6", ebpf.AttachCGroupInet6Connect},
	{"egress_udp_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg},
	{"egress_udp_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg},
	{"observe_dns_reply", ebpf.AttachCGroupInetIngress},
}

func pinnedPolicyExists() (bool, error) {
	for _, program := range policyPrograms {
		_, err := os.Stat(filepath.Join(policyPinDir, program.name))
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func detachPolicy() error {
	for _, program := range policyPrograms {
		err := os.Remove(filepath.Join(policyPinDir, program.name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove pinned %s: %w", program.name, err)
		}
	}
	return nil
}

func policyStatus() error {
	for _, program := range policyPrograms {
		path := filepath.Join(policyPinDir, program.name)
		pinned, err := link.LoadPinnedLink(path, nil)
		if err != nil {
			return fmt.Errorf("pinned policy %s unavailable: %w", program.name, err)
		}
		info, err := pinned.Info()
		pinned.Close()
		if err != nil {
			return fmt.Errorf("inspect pinned policy %s: %w", program.name, err)
		}
		if info.Cgroup() == nil {
			return fmt.Errorf("pinned policy %s is not attached to a cgroup", program.name)
		}
		fmt.Printf("%s: attached (link %d)\n", program.name, info.ID)
	}
	return nil
}

func attachPolicyProgram(program *ebpf.Program, name string, attach ebpf.AttachType, persist bool) (link.Link, error) {
	path := filepath.Join(policyPinDir, name)
	if persist {
		pinned, err := link.LoadPinnedLink(path, nil)
		if err == nil {
			if err := pinned.Update(program); err != nil {
				pinned.Close()
				return nil, fmt.Errorf("update pinned %s: %w", name, err)
			}
			return pinned, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("open pinned %s: %w", name, err)
		}
	}
	attached, err := link.AttachCgroup(link.CgroupOptions{
		Path: "/sys/fs/cgroup", Attach: attach, Program: program,
	})
	if err != nil {
		return nil, fmt.Errorf("attach %s to root cgroup: %w", name, err)
	}
	if persist {
		if err := attached.Pin(path); err != nil {
			attached.Close()
			return nil, fmt.Errorf("pin %s: %w", name, err)
		}
	}
	return attached, nil
}

func loadConnectCollection() (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(connectObject))
	if err != nil {
		return nil, fmt.Errorf("load embedded eBPF object: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load eBPF programs: %w", err)
	}
	return collection, nil
}

func checkEBPF() error {
	collection, err := loadConnectCollection()
	if err != nil {
		return err
	}
	collection.Close()
	return nil
}

func openConnectMonitor(policy []netip.Prefix, enforce, coverAllUDP bool, domains []string) (_ *connectMonitor, err error) {
	if enforce {
		if err := os.MkdirAll(policyPinDir, 0700); err != nil {
			return nil, fmt.Errorf("create policy pin directory: %w", err)
		}
	} else {
		pinned, err := pinnedPolicyExists()
		if err != nil {
			return nil, fmt.Errorf("inspect pinned policy: %w", err)
		}
		if pinned {
			return nil, errors.New("pinned enforce policy remains active; stop outbound and run --detach-policy before switching to audit")
		}
	}
	collection, err := loadConnectCollection()
	if err != nil {
		return nil, err
	}
	monitor := &connectMonitor{collection: collection}
	defer func() {
		if err != nil {
			monitor.Close()
		}
	}()
	if err := monitor.applyPolicy(policy, enforce, coverAllUDP, 0); err != nil {
		return nil, err
	}
	wildcardMap := collection.Maps["dns_wildcards"]
	exactMap := collection.Maps["dns_exact"]
	if wildcardMap == nil || exactMap == nil {
		return nil, errors.New("eBPF DNS domain maps are missing")
	}
	for _, domain := range domains {
		wildcard := strings.HasPrefix(domain, "*.")
		var key dnsSuffixHash
		var keyErr error
		if wildcard {
			key, keyErr = wildcardDNSName(domain)
		} else {
			key, keyErr = dnsNameHash(domain)
		}
		if keyErr != nil {
			return nil, keyErr
		}
		value := uint8(1)
		target := exactMap
		if wildcard {
			target = wildcardMap
		}
		if err := target.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("load DNS domain %q: %w", domain, err)
		}
	}
	for _, program := range policyPrograms {
		if program.name == "observe_dns_reply" && len(domains) == 0 && !enforce {
			continue
		}
		p := collection.Programs[program.name]
		if p == nil {
			return nil, fmt.Errorf("missing eBPF program %s", program.name)
		}
		attached, attachErr := attachPolicyProgram(p, program.name, program.attach, enforce)
		if attachErr != nil {
			return nil, attachErr
		}
		monitor.links = append(monitor.links, attached)
	}
	return monitor, nil
}

func (monitor *connectMonitor) applyPolicy(prefixes []netip.Prefix, enforce, coverAllUDP bool, slot uint32) error {
	v4 := monitor.collection.Maps[fmt.Sprintf("ipv4_policy_%d", slot)]
	v6 := monitor.collection.Maps[fmt.Sprintf("ipv6_policy_%d", slot)]
	control := monitor.collection.Maps["control"]
	if v4 == nil || v6 == nil || control == nil {
		return errors.New("eBPF policy maps are missing")
	}
	if err := clearPolicyMap(v4, ipv4Key{}); err != nil {
		return err
	}
	if err := clearPolicyMap(v6, ipv6Key{}); err != nil {
		return err
	}
	for _, prefix := range prefixes {
		value := uint8(1)
		if prefix.Addr().Is4() {
			key := ipv4Key{Prefixlen: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
			if err := v4.Update(&key, &value, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("insert IPv4 prefix %s: %w", prefix, err)
			}
		} else {
			key := ipv6Key{Prefixlen: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
			if err := v6.Update(&key, &value, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("insert IPv6 prefix %s: %w", prefix, err)
			}
		}
	}
	var mode uint32
	if enforce {
		mode = 1
	}
	key := uint32(0)
	var udpMode uint32
	if coverAllUDP {
		udpMode = 1
	}
	state := policyControl{Enforce: mode, Slot: slot, CoverAllUDP: udpMode}
	if err := control.Update(&key, &state, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("activate eBPF policy: %w", err)
	}
	monitor.slot = slot
	return nil
}

func (monitor *connectMonitor) RefreshPolicy(prefixes []netip.Prefix, enforce, coverAllUDP bool) error {
	return monitor.applyPolicy(prefixes, enforce, coverAllUDP, 1-monitor.slot)
}

func clearPolicyMap(m *ebpf.Map, keyType any) error {
	var keys []any
	iter := m.Iterate()
	var value uint8
	switch keyType.(type) {
	case ipv4Key:
		var key ipv4Key
		for iter.Next(&key, &value) {
			keys = append(keys, key)
		}
	case ipv6Key:
		var key ipv6Key
		for iter.Next(&key, &value) {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func (monitor *connectMonitor) Close() {
	for _, attached := range monitor.links {
		_ = attached.Close()
	}
	monitor.collection.Close()
}

func (monitor *connectMonitor) Drain(emit func(endpoint, string, bool)) error {
	destinations := monitor.collection.Maps["destinations"]
	if destinations == nil {
		return errors.New("eBPF destinations map is missing")
	}
	iterator := destinations.Iterate()
	var key destinationKey
	var event observation
	for iterator.Next(&key, &event) {
		remote, decodeErr := key.endpoint()
		if decodeErr == nil && remote.Port != 0 {
			emit(remote, key.transport(), event.Allowed != 0)
		}
		if err := destinations.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete observed destination: %w", err)
		}
	}
	return iterator.Err()
}
