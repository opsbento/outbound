// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"sort"

	"go.yaml.in/yaml/v3"
)

const maxPortsPerRule = 16

// Empty ports means any port. The scalar form preserves the v1 configuration.
type policyRule struct {
	Name  string
	Ports []uint16
	kind  string
}

func (r *policyRule) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		if err := node.Decode(&r.Name); err != nil {
			return err
		}
		r.Ports = nil
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("allowlist entry must be a string or mapping")
	}
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "cidr", "domain", "ports":
		default:
			return fmt.Errorf("unknown allowlist field %q", node.Content[i].Value)
		}
	}
	var fields struct {
		CIDR   string   `yaml:"cidr"`
		Domain string   `yaml:"domain"`
		Ports  []uint16 `yaml:"ports"`
	}
	if err := node.Decode(&fields); err != nil {
		return err
	}
	if (fields.CIDR == "") == (fields.Domain == "") {
		return fmt.Errorf("allowlist entry must specify exactly one of cidr or domain")
	}
	if fields.CIDR != "" {
		r.Name = fields.CIDR
		r.kind = "cidr"
	} else {
		r.Name = fields.Domain
		r.kind = "domain"
	}
	if len(fields.Ports) > maxPortsPerRule {
		return fmt.Errorf("allowlist entry %q exceeds %d ports", r.Name, maxPortsPerRule)
	}
	seen := make(map[uint16]bool)
	for _, port := range fields.Ports {
		if port == 0 || seen[port] {
			return fmt.Errorf("allowlist entry %q has invalid or duplicate port %d", r.Name, port)
		}
		seen[port] = true
	}
	r.Ports = append(r.Ports[:0], fields.Ports...)
	sort.Slice(r.Ports, func(i, j int) bool { return r.Ports[i] < r.Ports[j] })
	return nil
}

type portSet struct {
	Count uint32
	Ports [maxPortsPerRule]uint16
}

func newPortSet(ports []uint16) portSet {
	var value portSet
	value.Count = uint32(len(ports))
	copy(value.Ports[:], ports)
	return value
}

func (value portSet) allows(port uint16) bool {
	if value.Count == 0 {
		return true
	}
	for _, allowed := range value.Ports[:value.Count] {
		if allowed == port {
			return true
		}
	}
	return false
}

func mergePorts(left, right portSet) (portSet, error) {
	if left.Count == 0 || right.Count == 0 {
		return portSet{}, nil
	}
	seen := make(map[uint16]bool)
	for _, port := range left.Ports[:left.Count] {
		seen[port] = true
	}
	for _, port := range right.Ports[:right.Count] {
		seen[port] = true
	}
	if len(seen) > maxPortsPerRule {
		return portSet{}, fmt.Errorf("combined rules exceed %d ports", maxPortsPerRule)
	}
	ports := make([]uint16, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return newPortSet(ports), nil
}
