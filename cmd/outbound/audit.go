// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// A destination record represents an observation, not an individual connection.
type auditRecord struct {
	Time            string `json:"time"`
	SchemaVersion   int    `json:"schema_version"`
	Level           string `json:"level"`
	Event           string `json:"event"`
	Service         string `json:"service"`
	Host            string `json:"host,omitempty"`
	BootID          string `json:"boot_id,omitempty"`
	Version         string `json:"version"`
	Mode            string `json:"mode,omitempty"`
	PolicySHA256    string `json:"policy_sha256,omitempty"`
	IPPolicySHA256  string `json:"ip_policy_sha256,omitempty"`
	Decision        string `json:"decision,omitempty"`
	Transport       string `json:"transport,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort uint16 `json:"destination_port,omitempty"`
	PTR             string `json:"ptr,omitempty"`
	Aggregation     string `json:"aggregation,omitempty"`
	PolicyEntries   int    `json:"policy_entries,omitempty"`
	UDPCoverage     string `json:"udp_coverage,omitempty"`
	Error           string `json:"error,omitempty"`
}

type auditLogger struct {
	mu     sync.Mutex
	output io.Writer
	mode   string
	hash   string
	host   string
	bootID string
}

func (logger *auditLogger) write(record auditRecord) error {
	record.Time = time.Now().UTC().Format(time.RFC3339Nano)
	record.SchemaVersion = 1
	record.Service = "outbound"
	record.Host = logger.host
	record.BootID = logger.bootID
	record.Version = version
	record.Mode = logger.mode
	record.PolicySHA256 = logger.hash
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	encoded = append(encoded, '\n')
	logger.mu.Lock()
	defer logger.mu.Unlock()
	n, err := logger.output.Write(encoded)
	if err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	if n != len(encoded) {
		return io.ErrShortWrite
	}
	return nil
}

func destinationRecord(mode, transport string, remote endpoint, ptr string, allowed bool) auditRecord {
	decision := "ALLOW"
	level := "INFO"
	if !allowed {
		decision = "WOULD_BLOCK"
		if mode == "enforce" {
			decision = "BLOCK"
		}
		level = "WARN"
	}
	return auditRecord{
		Level:           level,
		Event:           "destination_observed",
		Decision:        decision,
		Transport:       transport,
		DestinationIP:   remote.IP.String(),
		DestinationPort: remote.Port,
		PTR:             ptr,
		Aggregation:     "latest_per_destination_per_drain",
	}
}
