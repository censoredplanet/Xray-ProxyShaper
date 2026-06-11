// Package proxyshaper integrates the host proxyshaper filter into Xray transport.
package proxyshaper

import (
	"context"
	"fmt"
	"net"
	"sync"

	hostproxyshaper "proxyshaper"
)

// GeneratedFlowConfig configures generator-backed bootstrap flows.
type GeneratedFlowConfig struct {
	GeneratorPath      string `json:"generatorPath,omitempty"`
	TrafficProfilePath string `json:"trafficProfilePath,omitempty"`
	ModelPath          string `json:"modelPath,omitempty"`
	NumFlows           uint32 `json:"numFlows,omitempty"`
	FlowLength         uint32 `json:"flowLength,omitempty"`
}

type Config struct {
	Mode          string                 `json:"mode"`
	Slots         []hostproxyshaper.Slot `json:"slots,omitempty"`
	Seed          *uint64                `json:"seed,omitempty"`
	DisableTiming bool                   `json:"disableTiming,omitempty"`
	GeneratedFlow *GeneratedFlowConfig   `json:"generatedFlow,omitempty"`
}

// Manager holds the bootstrap filter for both roles and creates per-connection
// wrappers via Wrap.
// Thread-safe.
type Manager struct {
	mu           sync.Mutex
	clientFilter *hostproxyshaper.Filter
	serverFilter *hostproxyshaper.Filter
}

// NewManager creates a Manager from config.
func NewManager(ctx context.Context, cfg *Config) (*Manager, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = "bootstrap"
	}
	if mode != "bootstrap" {
		return nil, fmt.Errorf("proxyshaper: unsupported mode %q; only bootstrap is implemented", mode)
	}

	if cfg.Seed != nil {
		return nil, fmt.Errorf("proxyshaper: bootstrap mode no longer accepts \"seed\"; the row selector is derived from negotiated TLS session secrets")
	}

	var generatedFlow *hostproxyshaper.GeneratedFlowConfig
	if cfg.GeneratedFlow != nil {
		generatedFlow = &hostproxyshaper.GeneratedFlowConfig{
			GeneratorPath:      cfg.GeneratedFlow.GeneratorPath,
			TrafficProfilePath: cfg.GeneratedFlow.TrafficProfilePath,
			ModelPath:          cfg.GeneratedFlow.ModelPath,
			NumFlows:           int(cfg.GeneratedFlow.NumFlows),
			FlowLength:         int(cfg.GeneratedFlow.FlowLength),
		}
	}

	clientCfg := hostproxyshaper.Config{
		Role:          "client",
		Mode:          mode,
		DisableTiming: cfg.DisableTiming,
		GeneratedFlow: generatedFlow,
	}
	clientFilter, err := hostproxyshaper.NewFilter(ctx, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("proxyshaper: create client filter: %w", err)
	}

	serverCfg := hostproxyshaper.Config{
		Role:          "server",
		Mode:          mode,
		DisableTiming: cfg.DisableTiming,
		GeneratedFlow: generatedFlow,
	}
	serverFilter, err := hostproxyshaper.NewFilter(ctx, serverCfg)
	if err != nil {
		clientFilter.Close(ctx)
		return nil, fmt.Errorf("proxyshaper: create server filter: %w", err)
	}

	return &Manager{
		clientFilter: clientFilter,
		serverFilter: serverFilter,
	}, nil
}

// WrapClient wraps a post-TLS connection for the dialer (client) side.
// The returned net.Conn is what the proxy protocol reads and writes through.
func (m *Manager) WrapClient(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return m.clientFilter.Wrap(ctx, conn)
}

// WrapServer wraps a post-TLS connection for the listener (server) side.
func (m *Manager) WrapServer(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return m.serverFilter.Wrap(ctx, conn)
}

// Close releases the bootstrap filter resources for both filters.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	if err := m.clientFilter.Close(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := m.serverFilter.Close(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
