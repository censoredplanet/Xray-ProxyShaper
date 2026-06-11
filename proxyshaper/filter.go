// proxyshaper shapes the early TLS records of a connection according to a
// bootstrap-derived schedule.
//
// Architecture during the schedule window:
//
//     [proxy] <-- appPair --> [proxyshaper] <-- [outer conn]
//                                                   |
//                                             [TLS / network]
//
// proxyshaper derives the bootstrap row from post-handshake TLS exporter
// material, sleeps until each record boundary when timing is enabled, frames
// real proxy bytes into outbound records, deframes inbound records, and writes
// each outbound record to the outer connection in one Write call. For a
// *tls.Conn outer, one Write produces one TLS record (application-layer
// guarantee). TCP segments below TLS are controlled by the kernel and may not
// be 1:1 with TLS records (MSS fragmentation, middlebox re-segmentation).
//
// After the schedule window, proxyshaper switches to native io.Copy between the
// proxy's socket pair and the outer conn.

package proxyshaper

import (
	"bytes"
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// frameHeaderSize is the 2-byte big-endian payload length that precedes
// real data in each derived bootstrap record. The remainder is random padding.
const frameHeaderSize = 2

const (
	tlsRecordHeaderSize               = 5
	tls12GCMWireOverhead              = tlsRecordHeaderSize + 8 + 16
	tls12ChaCha20Poly1305WireOverhead = tlsRecordHeaderSize + 16
	tls13AEADWireOverhead             = tlsRecordHeaderSize + 1 + 16
	maxSupportedTLSRecordOverhead     = tls12GCMWireOverhead

	// Bootstrap record 0 no longer carries a transmitted seed. Both ends
	// derive the same uint64 selector from negotiated outer TLS session
	// secrets, while record 0 starts with a fixed encrypted marker and then uses
	// any remaining capacity for normal framed proxy payload.
	bootstrapPayloadMagic    uint32 = 0x50536870 // "PShp"
	bootstrapMarkerSize             = 4
	bootstrapSeedDeriveLabel        = "proxyshaper-v1"
	bootstrapDerivedSeedSize        = 8
	bootstrapMinRecordSize          = maxSupportedTLSRecordOverhead + frameHeaderSize + bootstrapMarkerSize
	bootstrapRecordCount            = 10
)

// proxyReadTimeout is how long the scheduler waits for proxy data when
// building a derived bootstrap frame for an "our turn" record. This balances:
//   - Too short: proxy hasn't written yet → empty frame (wastes record capacity)
//   - Too long: delays the schedule, distorts inter-packet timing
//
// 50ms is generous for loopback writes (< 1ms typical) and covers
// goroutine scheduling jitter under load.
const proxyReadTimeout = 50 * time.Millisecond

// generatedFlowCommandTimeout bounds one external generator invocation. Inbound
// wraps use context.Background(), so the generator needs its own deadline to
// keep forked process trees from accumulating indefinitely.
const generatedFlowCommandTimeout = 5 * time.Second

// generatedFlowMaxOutputBytes is intentionally much larger than a valid
// 5x10 generated-flow CSV response, while still preventing a misbehaving
// generator from being buffered into process memory without bound.
const generatedFlowMaxOutputBytes = 1 << 20

// Bootstrap configs no longer accept or require a transmitted seed. The
// proxyshaper derives the row-selection seed from post-handshake outer TLS channel-
// binding material, so only the derived CSV profiles travel through Config.
type Config struct {
	Role           string   `json:"role"`
	Mode           string   `json:"mode"`
	Records        []Record `json:"records,omitempty"`
	RelativeTiming bool     `json:"relative_timing,omitempty"`
	DisableTiming  bool     `json:"disable_timing,omitempty"`
	// GeneratedFlow is used only for bootstrap+disableTiming when the
	// schedule source comes from the external generator.
	GeneratedFlow *GeneratedFlowConfig `json:"generated_flow,omitempty"`
}

type Record struct {
	Size     uint32 `json:"size"`
	Dir      string `json:"dir"`
	OffsetMs uint64 `json:"offset_ms"`
	OffsetUs uint64 `json:"offset_us,omitempty"`
}

// GeneratedFlowConfig carries the external generator inputs for the
// bootstrap+disableTiming path. The runtime derives the initial seed from
// outer TLS exporter material, asks the generator for 5 candidate 10-packet
// flows, keeps the first valid one, and increments the seed deterministically
// until one passes local bootstrap size checks.
type GeneratedFlowConfig struct {
	GeneratorPath      string                                                               `json:"generator_path,omitempty"`
	TrafficProfilePath string                                                               `json:"traffic_profile_path,omitempty"`
	ModelPath          string                                                               `json:"model_path,omitempty"`
	NumFlows           int                                                                  `json:"num_flows,omitempty"`
	FlowLength         int                                                                  `json:"flow_length,omitempty"`
	Generate           func(context.Context, GeneratedFlowConfig, uint64) ([]string, error) `json:"-"`
}

type limitedOutputBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedOutputBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		b.truncated = true
		return len(p), nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) < remaining {
			remaining = len(p)
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return len(p), nil
}

func (b *limitedOutputBuffer) String() string {
	return b.buf.String()
}

func (b *limitedOutputBuffer) Truncated() bool {
	return b.truncated
}

// Config record sizes are interpreted as target encrypted TLS record sizes,
// including the 5-byte TLS record header. proxyshaper learns the negotiated TLS
// version/cipher after handshake, subtracts the corresponding record overhead,
// and executes the remaining plaintext budgets directly.
//
// Timing representation:
//   - older sideband payloads may still carry OffsetMs fields, but the active
//     bootstrap path uses OffsetUs
//   - bootstrap CSV schedules may also set DisableTiming to execute purely by
//     packet ordering and size without sleeping

func (c *Config) isOurTurn(record Record) bool {
	return (c.Role == "client" && record.Dir == "out") ||
		(c.Role == "server" && record.Dir == "in")
}

func (c *Config) validateBootstrap() error {
	if c.Mode != "" && c.Mode != "bootstrap" {
		return fmt.Errorf("unsupported mode %q: only bootstrap is implemented", c.Mode)
	}
	// Bootstrap now has exactly one maintained source:
	// generator-backed disable-timing synthesis. Fixed CSV profile selection
	// has been removed from the supported runtime surface.
	if c.GeneratedFlow == nil {
		return fmt.Errorf("bootstrap mode requires generated_flow")
	}
	// Generated flows are currently defined only for the no-timing
	// bootstrap path, with a fixed 5x10 candidate matrix per seed.
	if !c.DisableTiming {
		return fmt.Errorf("bootstrap generated_flow requires disable_timing")
	}
	if c.GeneratedFlow.NumFlows != 5 {
		return fmt.Errorf("bootstrap generated_flow num_flows must be 5, got %d", c.GeneratedFlow.NumFlows)
	}
	if c.GeneratedFlow.FlowLength != bootstrapRecordCount {
		return fmt.Errorf("bootstrap generated_flow flow_length must be %d, got %d", bootstrapRecordCount, c.GeneratedFlow.FlowLength)
	}
	if c.GeneratedFlow.Generate == nil {
		if c.GeneratedFlow.GeneratorPath == "" {
			return fmt.Errorf("bootstrap generated_flow requires generator_path")
		}
		if c.GeneratedFlow.TrafficProfilePath == "" {
			return fmt.Errorf("bootstrap generated_flow requires traffic_profile_path")
		}
		if c.GeneratedFlow.ModelPath == "" {
			return fmt.Errorf("bootstrap generated_flow requires model_path")
		}
	}
	return nil
}

func recordDelayDuration(record Record) time.Duration {
	if record.OffsetUs > 0 {
		return time.Duration(record.OffsetUs) * time.Microsecond
	}
	return time.Duration(record.OffsetMs) * time.Millisecond
}

// runGeneratedFlowCommand shells out to the generator binary for the
// no-timing bootstrap path and returns one signed-size CSV row per candidate
// flow. Stdout carries the generated rows; stderr is folded into the returned
// error so runtime failures are diagnosable from logs.
func runGeneratedFlowCommand(ctx context.Context, cfg GeneratedFlowConfig, seed uint64) ([]string, error) {
	if cfg.Generate != nil {
		return cfg.Generate(ctx, cfg, seed)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, generatedFlowCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(
		cmdCtx,
		cfg.GeneratorPath,
		"generate",
		"--traffic-profile", cfg.TrafficProfilePath,
		"--model", cfg.ModelPath,
		"--seed", strconv.FormatUint(seed, 10),
		"--num-flows", strconv.Itoa(cfg.NumFlows),
		"--flow-length", strconv.Itoa(cfg.FlowLength),
	)
	configureGeneratedFlowCommand(cmd)
	defer cleanupGeneratedFlowCommand(cmd)

	var stdout, stderr limitedOutputBuffer
	stdout.limit = generatedFlowMaxOutputBytes
	stderr.limit = generatedFlowMaxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if stdout.Truncated() || stderr.Truncated() {
		return nil, fmt.Errorf("generate seed %d: output exceeded %d bytes", seed, generatedFlowMaxOutputBytes)
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		return nil, fmt.Errorf("generate seed %d: %w: %s", seed, err, detail)
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	rows := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rows = append(rows, line)
	}
	return rows, nil
}

// generatedFlowRowToRecords validates one generated signed-size row
// against the minimum bootstrap packet sizes for the negotiated TLS record
// overhead of this specific connection, rather than the historical worst-case
// overhead used by the removed fixed-CSV path.
func generatedFlowRowToRecords(row string, cfg GeneratedFlowConfig, tlsOverhead uint32) ([]Record, error) {
	fields := strings.Split(strings.TrimSpace(row), ",")
	if len(fields) != cfg.FlowLength {
		return nil, fmt.Errorf("expected %d packet sizes, got %d", cfg.FlowLength, len(fields))
	}

	records := make([]Record, cfg.FlowLength)
	for i, field := range fields {
		signedSize, err := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("record %d parse %q: %w", i, field, err)
		}
		if signedSize == 0 {
			return nil, fmt.Errorf("record %d size must not be 0", i)
		}

		dir := "out"
		size := signedSize
		if signedSize < 0 {
			dir = "in"
			size = -signedSize
		}
		if size > int64(^uint32(0)) {
			return nil, fmt.Errorf("record %d size %d exceeds uint32", i, size)
		}

		minSize := uint32(tlsOverhead + frameHeaderSize)
		if i == 0 {
			minSize = tlsOverhead + frameHeaderSize + bootstrapMarkerSize
		}
		if uint32(size) < minSize {
			return nil, fmt.Errorf("record %d size %d < minimum %d", i, size, minSize)
		}

		records[i] = Record{
			Size:     uint32(size),
			Dir:      dir,
			OffsetUs: 0,
		}
	}
	return records, nil
}

// deriveGeneratedProfile deterministically retries generator seeds until
// one of the emitted candidate rows passes bootstrap size validation for the
// negotiated TLS overhead on this connection. Both peers make the same
// TLS-derived start-seed choice, inspect rows in the same order, and apply the
// same seed+1 retry rule.
func deriveGeneratedProfile(ctx context.Context, cfg GeneratedFlowConfig, seed uint64, tlsOverhead uint32) (derivedProfile, error) {
	currentSeed := seed
	for {
		rows, err := runGeneratedFlowCommand(ctx, cfg, currentSeed)
		if err != nil {
			return derivedProfile{}, err
		}
		for i, row := range rows {
			records, err := generatedFlowRowToRecords(row, cfg, tlsOverhead)
			if err == nil {
				// Emit the selected generated row to stderr so failed lab runs
				// can be correlated with the exact per-connection shape that won the
				// deterministic seed+retry loop.
				fmt.Fprintf(os.Stderr, "proxyshaper generated-flow seed=%d selected=flow_%d row=%s\n", currentSeed, i, row)
				return derivedProfile{
					Index:   i,
					Name:    fmt.Sprintf("generated_seed_%d_flow_%d", currentSeed, i),
					Records: records,
				}, nil
			}
		}
		if currentSeed == ^uint64(0) {
			return derivedProfile{}, fmt.Errorf("generator exhausted seed space without finding a valid flow")
		}
		currentSeed++
	}
}

// closeWriter is the interface for TCP half-close. *net.TCPConn
// implements this; *tls.Conn does not (TLS has no half-close).
type closeWriter interface {
	CloseWrite() error
}

// Filter wraps post-TLS connections with the bootstrap-only scheduler.
// Thread-safe: Wrap can be called concurrently for multiple connections.
type Filter struct {
	config  Config
	counter atomic.Uint64
}

func NewFilter(_ context.Context, cfg Config) (*Filter, error) {
	// proxyshaper now exposes only the TLS-derived bootstrap pipeline.
	// Callers may no longer select legacy dummy/shape entry points.
	if cfg.Mode == "" {
		cfg.Mode = "bootstrap"
	}
	if err := cfg.validateBootstrap(); err != nil {
		return nil, fmt.Errorf("invalid bootstrap config: %w", err)
	}

	return &Filter{config: cfg}, nil
}

func (f *Filter) Close(ctx context.Context) error {
	return nil
}

func tlsRecordWireOverhead(version, cipherSuite uint16) (uint32, error) {
	switch version {
	case gotls.VersionTLS13:
		switch cipherSuite {
		case gotls.TLS_AES_128_GCM_SHA256,
			gotls.TLS_AES_256_GCM_SHA384,
			gotls.TLS_CHACHA20_POLY1305_SHA256:
			return tls13AEADWireOverhead, nil
		default:
			return 0, fmt.Errorf("unsupported TLS 1.3 cipher suite 0x%04x", cipherSuite)
		}
	case gotls.VersionTLS12:
		switch cipherSuite {
		case gotls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			gotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			gotls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			gotls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			gotls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			gotls.TLS_RSA_WITH_AES_256_GCM_SHA384:
			return tls12GCMWireOverhead, nil
		case gotls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			gotls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
			return tls12ChaCha20Poly1305WireOverhead, nil
		default:
			return 0, fmt.Errorf("unsupported TLS 1.2 cipher suite 0x%04x", cipherSuite)
		}
	default:
		return 0, fmt.Errorf("unsupported TLS version 0x%04x", version)
	}
}

// tlsConnectionStateValue extracts the concrete TLS/uTLS ConnectionState
// value from the wrapped outer connection without importing implementation-
// specific state types into the proxyshaper package.
func tlsConnectionStateValue(conn net.Conn) (reflect.Value, error) {
	method := reflect.ValueOf(conn).MethodByName("ConnectionState")
	if !method.IsValid() {
		return reflect.Value{}, fmt.Errorf("outer conn %T does not expose ConnectionState", conn)
	}
	if method.Type().NumIn() != 0 || method.Type().NumOut() != 1 {
		return reflect.Value{}, fmt.Errorf("outer conn %T has incompatible ConnectionState signature", conn)
	}

	state := method.Call(nil)[0]
	if state.Kind() == reflect.Pointer {
		if state.IsNil() {
			return reflect.Value{}, fmt.Errorf("outer conn %T returned nil TLS state", conn)
		}
		state = state.Elem()
	}
	if state.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("outer conn %T returned non-struct TLS state", conn)
	}
	return state, nil
}

func tlsStateFromConn(conn net.Conn) (uint16, uint16, error) {
	state, err := tlsConnectionStateValue(conn)
	if err != nil {
		return 0, 0, err
	}

	versionField := state.FieldByName("Version")
	cipherField := state.FieldByName("CipherSuite")
	if !versionField.IsValid() || !cipherField.IsValid() {
		return 0, 0, fmt.Errorf("outer conn %T TLS state missing Version/CipherSuite", conn)
	}
	if versionField.Kind() != reflect.Uint16 || cipherField.Kind() != reflect.Uint16 {
		return 0, 0, fmt.Errorf("outer conn %T TLS state Version/CipherSuite have unexpected types", conn)
	}

	return uint16(versionField.Uint()), uint16(cipherField.Uint()), nil
}

// tlsExportKeyingMaterial reflects into the concrete TLS/uTLS
// ConnectionState so bootstrap mode can derive seed bytes from TLS 1.3
// exporter material without importing implementation-specific state types into
// the proxyshaper package.
func tlsExportKeyingMaterial(conn net.Conn, label string, context []byte, length int) ([]byte, error) {
	state, err := tlsConnectionStateValue(conn)
	if err != nil {
		return nil, err
	}

	method := state.MethodByName("ExportKeyingMaterial")
	if !method.IsValid() {
		statePtr := reflect.New(state.Type())
		statePtr.Elem().Set(state)
		method = statePtr.MethodByName("ExportKeyingMaterial")
	}
	if !method.IsValid() {
		return nil, fmt.Errorf("outer conn %T TLS state does not expose ExportKeyingMaterial", conn)
	}
	if method.Type().NumIn() != 3 || method.Type().NumOut() != 2 {
		return nil, fmt.Errorf("outer conn %T TLS exporter has incompatible signature", conn)
	}

	contextBytes := context
	if contextBytes == nil {
		contextBytes = []byte(nil)
	}
	results := method.Call([]reflect.Value{
		reflect.ValueOf(label),
		reflect.ValueOf(contextBytes),
		reflect.ValueOf(length),
	})

	keyingMaterial, ok := results[0].Interface().([]byte)
	if !ok {
		return nil, fmt.Errorf("outer conn %T TLS exporter returned non-[]byte keying material", conn)
	}
	if errVal := results[1].Interface(); errVal != nil {
		err, ok := errVal.(error)
		if !ok {
			return nil, fmt.Errorf("outer conn %T TLS exporter returned non-error failure", conn)
		}
		return nil, err
	}
	return keyingMaterial, nil
}

func ensureHandshake(ctx context.Context, conn net.Conn) error {
	if hc, ok := conn.(interface{ HandshakeContext(context.Context) error }); ok {
		return hc.HandshakeContext(ctx)
	}
	if h, ok := conn.(interface{ Handshake() error }); ok {
		return h.Handshake()
	}
	return nil
}

// executionConfigForOuter converts target encrypted TLS record sizes into
// the plaintext budgets that the proxyshaper must actually execute for this specific
// post-handshake connection.
func executionConfigForOuter(ctx context.Context, cfg Config, outer net.Conn) (Config, error) {
	overhead := uint32(0)
	version, cipherSuite, err := tlsStateFromConn(outer)
	if err == nil && version == 0 {
		if err := ensureHandshake(ctx, outer); err != nil {
			return Config{}, fmt.Errorf("outer handshake: %w", err)
		}
		version, cipherSuite, err = tlsStateFromConn(outer)
	}
	if err == nil {
		overhead, err = tlsRecordWireOverhead(version, cipherSuite)
		if err != nil {
			return Config{}, err
		}
	}

	execCfg := cfg
	execCfg.Records = make([]Record, len(cfg.Records))
	for i, record := range cfg.Records {
		if record.Size <= overhead {
			return Config{}, fmt.Errorf(
				"record %d target size %d too small for negotiated TLS overhead %d",
				i, record.Size, overhead,
			)
		}
		execCfg.Records[i] = record
		execCfg.Records[i].Size = record.Size - overhead
	}
	return execCfg, nil
}

// Wrap shapes the configured early schedule of a connection. outer is the real
// network conn (typically *tls.Conn from Xray's transport layer).
// Returns a net.Conn for the proxy to use.
//
// Bootstrap config validation happens synchronously before Wrap returns. If
// setup fails, Wrap returns an error and the caller never receives a broken
// conn. Only the schedule execution and passthrough run asynchronously.
func (f *Filter) Wrap(ctx context.Context, outer net.Conn) (net.Conn, error) {
	// App-side pair: proxy reads/writes proxyEnd; proxyshaper bridges appHostEnd.
	proxyEnd, appHostEnd, err := TCPConnPair()
	if err != nil {
		return nil, fmt.Errorf("app pair: %w", err)
	}

	name := fmt.Sprintf("proxyshaper-%d", f.counter.Add(1))
	go func() {
		f.runBootstrapAndPassthrough(ctx, name, outer, appHostEnd)
	}()

	return proxyEnd, nil
}

// scheduleWindowDeadline returns an absolute deadline that covers the
// derived bootstrap schedule execution. The current deployment always uses the
// record-relative 1..9 path after record 0, so we sum every record delay because the
// anchor resets after each completed record.
//
// The framed mediator can also add up to one proxyReadTimeout of sender-side
// delay per record while it waits for proxy bytes. We conservatively budget one
// proxyReadTimeout per record plus a 5-second margin for I/O and goroutine
// scheduling jitter.
func (f *Filter) scheduleWindowDeadline(cfg Config) time.Time {
	const margin = 5 * time.Second
	delayBudget := time.Duration(0)
	extraWait := time.Duration(len(cfg.Records)) * proxyReadTimeout
	for _, record := range cfg.Records {
		delay := recordDelayDuration(record)
		if cfg.RelativeTiming {
			delayBudget += delay
		} else if delay > delayBudget {
			delayBudget = delay
		}
	}
	if cfg.DisableTiming {
		delayBudget = 0
	}
	return time.Now().Add(delayBudget + extraWait + margin)
}

// runBootstrapAndPassthrough executes the bootstrap marker record,
// derives one of the configured 10-record CSV rows from negotiated TLS session
// secrets on both ends, then runs records 1..9 of that row as a fresh
// record-relative derived phase. Both TLS 1.2 and TLS 1.3 use TLS exporters so
// both endpoints deterministically take the same derivation path. The timing
// anchor resets after every completed derived record, which gives the requested
// consecutive-send and turnaround timing semantics.
func (f *Filter) runBootstrapAndPassthrough(
	ctx context.Context, name string,
	outer net.Conn, appHostEnd *net.TCPConn,
) {
	defer outer.Close()
	defer appHostEnd.Close()

	derived, err := f.runBootstrapPhase(ctx, name, outer, appHostEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxyshaper[%s]: %v\n", name, err)
		return
	}

	phaseCfg := Config{
		Role:           f.config.Role,
		Records:        derived.Records[1:],
		RelativeTiming: true,
		DisableTiming:  f.config.DisableTiming,
	}
	execCfg, err := executionConfigForOuter(ctx, phaseCfg, outer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxyshaper[%s]: %v\n", name, err)
		return
	}
	if err := f.runSchedulePhase(ctx, execCfg, outer, appHostEnd); err != nil {
		fmt.Fprintf(os.Stderr, "proxyshaper[%s]: %v\n", name, err)
		return
	}
	f.runPassthrough(outer, appHostEnd)
}

type derivedProfile struct {
	Index   int
	Records []Record
	Name    string
}

func (f *Filter) runBootstrapPhase(
	ctx context.Context, name string,
	outer net.Conn, appHostEnd *net.TCPConn,
) (derivedProfile, error) {
	_ = name

	// Bootstrap record 0 is carried natively:
	//   - client and server first derive the same bootstrap seed from the
	//     negotiated outer TLS session secrets
	//   - both sides derive the CSV row locally from that seed
	//   - whichever side owns derived record 0 sends one shaped bootstrap record
	//     sized for that row's record 0
	//   - the peer validates the marker prefix and forwards any remaining
	//     payload bytes before continuing
	//
	if err := ensureHandshake(ctx, outer); err != nil {
		return derivedProfile{}, fmt.Errorf("bootstrap handshake: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	outer.SetDeadline(deadline)
	defer outer.SetDeadline(time.Time{})

	// The bootstrap selector is now derived from post-handshake TLS
	// channel-binding material that never appears on the wire. This removes the
	// explicit seed exchange while still giving both endpoints the same
	// per-session row choice.
	// The per-connection bootstrap source is now always the
	// generator-backed disable-timing synthesizer.
	derived, err := f.deriveBootstrapProfile(ctx, outer)
	if err != nil {
		return derivedProfile{}, err
	}
	// Record 0 direction is driven by the derived row itself rather
	// than by a fixed client-send/server-read split. EKM already gives both
	// peers the same row, so either side can own the bootstrap marker send.
	if err := f.runBootstrapRecord0(ctx, outer, appHostEnd, derived); err != nil {
		return derivedProfile{}, err
	}
	return derived, nil
}

func (f *Filter) runSchedulePhase(
	ctx context.Context,
	cfg Config,
	outer net.Conn, appHostEnd *net.TCPConn,
) error {
	outer.SetDeadline(f.scheduleWindowDeadline(cfg))
	defer outer.SetDeadline(time.Time{})
	return f.executeSchedule(ctx, cfg, outer, appHostEnd)
}

func (f *Filter) runPassthrough(outer net.Conn, appHostEnd *net.TCPConn) {

	// Schedule complete. Switch to native passthrough: proxy <-> outer.
	//
	// Each goroutine, when its io.Copy returns, propagates shutdown to
	// the other direction:
	// - CloseWrite sends FIN to the destination (TCP half-close) so the
	//   peer sees EOF while the reverse direction can still drain.
	// - For *tls.Conn (no half-close support), we fall back to full
	//   Close, which terminates both directions immediately. This is
	//   correct for TLS (close_notify shuts down the whole session).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(outer, appHostEnd) // proxy → network
		// Proxy finished sending. Signal to peer.
		if cw, ok := outer.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			outer.Close() // TLS: no half-close
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(appHostEnd, outer) // network → proxy
		// Peer finished sending. Signal to proxy.
		appHostEnd.CloseWrite()
	}()
	wg.Wait()
}

// bootstrapPayload prefixes record-0 proxy bytes with the encrypted
// protocol marker. The seed itself stays local to each endpoint and is derived
// from post-handshake TLS channel-binding material.
func bootstrapPayload(proxyPayload []byte) []byte {
	buf := make([]byte, bootstrapMarkerSize+len(proxyPayload))
	binary.BigEndian.PutUint32(buf[0:4], bootstrapPayloadMagic)
	copy(buf[bootstrapMarkerSize:], proxyPayload)
	return buf
}

// parseBootstrapPayload validates the encrypted bootstrap marker after
// the peer has already derived the expected record-0 size from outer TLS
// channel-binding material, and returns any proxy payload carried after it.
func parseBootstrapPayload(payload []byte) ([]byte, error) {
	if len(payload) < bootstrapMarkerSize {
		return nil, fmt.Errorf("bootstrap payload size mismatch: got %d want at least %d", len(payload), bootstrapMarkerSize)
	}
	if binary.BigEndian.Uint32(payload[0:4]) != bootstrapPayloadMagic {
		return nil, fmt.Errorf("bootstrap payload magic mismatch")
	}
	return payload[bootstrapMarkerSize:], nil
}

func (f *Filter) bootstrapExecutionRecord(ctx context.Context, outer net.Conn, record Record) (Record, error) {
	phaseCfg := Config{
		Role:    f.config.Role,
		Records: []Record{record},
	}
	execCfg, err := executionConfigForOuter(ctx, phaseCfg, outer)
	if err != nil {
		return Record{}, err
	}
	return execCfg.Records[0], nil
}

// bootstrapSeedBytesFromTLSState converts negotiated TLS session state
// into the shared 8-byte selector seed used for per-connection CSV row
// selection. Both TLS 1.2 and TLS 1.3 now use the TLS exporter so the
// deployment only depends on one shared secret primitive.
func bootstrapSeedBytesFromTLSState(outer net.Conn) ([]byte, error) {
	version, _, err := tlsStateFromConn(outer)
	if err != nil {
		return nil, fmt.Errorf("read negotiated TLS version: %w", err)
	}

	switch version {
	case gotls.VersionTLS12, gotls.VersionTLS13:
		seedBytes, err := tlsExportKeyingMaterial(outer, bootstrapSeedDeriveLabel, nil, bootstrapDerivedSeedSize)
		if err != nil {
			return nil, fmt.Errorf("derive TLS 0x%04x seed from exporter: %w", version, err)
		}
		if len(seedBytes) != bootstrapDerivedSeedSize {
			return nil, fmt.Errorf("TLS exporter returned %d bytes, want %d", len(seedBytes), bootstrapDerivedSeedSize)
		}
		return seedBytes, nil
	default:
		return nil, fmt.Errorf("unsupported TLS version 0x%04x for bootstrap derivation", version)
	}
}

// deriveBootstrapProfile converts negotiated TLS session secrets into a
// generator-backed no-timing flow. The same negotiated TLS overhead used later
// for execution is also used here to decide which candidate rows are valid.
func (f *Filter) deriveBootstrapProfile(ctx context.Context, outer net.Conn) (derivedProfile, error) {
	seedBytes, err := bootstrapSeedBytesFromTLSState(outer)
	if err != nil {
		return derivedProfile{}, fmt.Errorf("bootstrap: derive seed from TLS state: %w", err)
	}
	seed := binary.BigEndian.Uint64(seedBytes)
	version, cipherSuite, err := tlsStateFromConn(outer)
	if err != nil {
		return derivedProfile{}, fmt.Errorf("bootstrap: read negotiated TLS state: %w", err)
	}
	tlsOverhead, err := tlsRecordWireOverhead(version, cipherSuite)
	if err != nil {
		return derivedProfile{}, fmt.Errorf("bootstrap: determine TLS record overhead: %w", err)
	}
	// Disable-timing bootstrap synthesizes the 10 signed packet sizes on
	// demand from the external generator. The TLS-derived seed remains the
	// synchronization root, while the negotiated overhead narrows the local
	// candidate filter to what this connection can actually execute.
	derived, err := deriveGeneratedProfile(ctx, *f.config.GeneratedFlow, seed, tlsOverhead)
	if err != nil {
		return derivedProfile{}, fmt.Errorf("bootstrap: generate disable-timing flow from seed %d: %w", seed, err)
	}
	return derived, nil
}

// runBootstrapRecord0 executes the bootstrap marker exchange for the
// derived row's record 0. The sender/receiver are chosen from record 0 direction
// itself, not from a hard-coded client/server split.
func (f *Filter) runBootstrapRecord0(ctx context.Context, outer net.Conn, appHostEnd *net.TCPConn, derived derivedProfile) error {
	record0 := derived.Records[0]
	if f.config.isOurTurn(record0) {
		return f.runBootstrapMarkerSender(ctx, outer, appHostEnd, record0)
	}
	return f.runBootstrapMarkerReceiver(ctx, outer, appHostEnd, record0)
}

// The record-0 sender writes a bootstrap marker plus any immediately
// available proxy payload once both sides have independently derived the same
// CSV row from negotiated TLS session secrets.
func (f *Filter) runBootstrapMarkerSender(ctx context.Context, outer net.Conn, appHostEnd *net.TCPConn, record Record) error {
	execRecord, err := f.bootstrapExecutionRecord(ctx, outer, record)
	if err != nil {
		return err
	}
	maxProxyPayload := int(execRecord.Size) - frameHeaderSize - bootstrapMarkerSize
	proxyPayload, err := readAvailable(appHostEnd, maxProxyPayload, proxyReadTimeout)
	if err != nil {
		return fmt.Errorf("bootstrap: read proxy data: %w", err)
	}
	frame := buildFrame(execRecord.Size, bootstrapPayload(proxyPayload))
	if err := writeAll(outer, frame); err != nil {
		return fmt.Errorf("bootstrap: write frame to outer: %w", err)
	}
	return nil
}

// The record-0 receiver derives the same record-0 size locally from
// negotiated TLS session secrets, reads exactly that bootstrap record, and
// validates the encrypted marker before forwarding any carried proxy payload
// and starting the derived shape schedule.
func (f *Filter) runBootstrapMarkerReceiver(ctx context.Context, outer net.Conn, appHostEnd *net.TCPConn, record Record) error {
	execRecord, err := f.bootstrapExecutionRecord(ctx, outer, record)
	if err != nil {
		return err
	}
	frameBuf := make([]byte, execRecord.Size)
	if _, err := io.ReadFull(outer, frameBuf); err != nil {
		return fmt.Errorf("bootstrap: read frame from outer: %w", err)
	}
	if int(execRecord.Size) < frameHeaderSize {
		return fmt.Errorf("bootstrap: derived record %d too small for frame header", execRecord.Size)
	}
	payloadLen := uint32(binary.BigEndian.Uint16(frameBuf[:frameHeaderSize]))
	maxPayload := execRecord.Size - uint32(frameHeaderSize)
	if payloadLen > maxPayload {
		return fmt.Errorf("bootstrap: frame payload_length %d exceeds derived capacity %d (record.Size=%d)",
			payloadLen, maxPayload, execRecord.Size)
	}
	if payloadLen < bootstrapMarkerSize {
		return fmt.Errorf("bootstrap: frame payload_length %d want at least %d", payloadLen, bootstrapMarkerSize)
	}
	payload := frameBuf[frameHeaderSize : frameHeaderSize+int(payloadLen)]
	proxyPayload, err := parseBootstrapPayload(payload)
	if err != nil {
		return fmt.Errorf("bootstrap: parse payload: %w", err)
	}
	if len(proxyPayload) > 0 {
		if err := writeAll(appHostEnd, proxyPayload); err != nil {
			return fmt.Errorf("bootstrap: write payload to proxy: %w", err)
		}
	}
	return nil
}

// executeSchedule runs the derived bootstrap records directly in proxyshaper with
// record-relative timing and framed payload handling.
func (f *Filter) executeSchedule(ctx context.Context, cfg Config, outer net.Conn, appHostEnd *net.TCPConn) error {
	start := time.Now()
	relativeAnchor := start
	for i, record := range cfg.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		anchor := start
		if cfg.RelativeTiming {
			anchor = relativeAnchor
		}
		if !cfg.DisableTiming {
			if err := sleepUntilContext(ctx, anchor.Add(recordDelayDuration(record))); err != nil {
				return err
			}
		}
		if cfg.isOurTurn(record) {
			if err := f.derivedRecordOurTurn(i, record, outer, appHostEnd); err != nil {
				return err
			}
		} else {
			if err := f.derivedRecordPeerTurn(i, record, outer, appHostEnd); err != nil {
				return err
			}
		}
		if cfg.RelativeTiming {
			relativeAnchor = time.Now()
		}
	}
	return nil
}

// derivedRecordOurTurn handles one outbound TLS record in the derived bootstrap phase.
//
// Sequence:
//  1. Read available proxy data from appHostEnd (non-blocking, up to capacity)
//  2. Build frame and write to outer
//
// If no proxy data is available (e.g., proxy hasn't written yet), the
// frame carries payload_length=0 and is entirely random padding. This
// preserves the on-wire record size regardless of proxy readiness.
func (f *Filter) derivedRecordOurTurn(idx int, record Record, outer net.Conn, appHostEnd *net.TCPConn) error {
	// Step 1: Read whatever proxy data is available, up to the frame's
	// payload capacity (record.Size - frame header).
	//
	// Timing note: this wait happens AFTER the scheduled record delay,
	// so the outer Write (step 3) occurs up to proxyReadTimeout (50ms) later
	// than the scheduled record delay. This is a deliberate trade-off: we accept mild record
	// timing jitter in exchange for higher utilization. For the primary use
	// case (VLESS header written before the schedule starts), the data is
	// already in the buffer and readAvailable returns immediately — zero jitter.
	maxPayload := int(record.Size) - frameHeaderSize
	payload, err := readAvailable(appHostEnd, maxPayload, proxyReadTimeout)
	if err != nil {
		return fmt.Errorf("record %d: read proxy data: %w", idx, err)
	}

	// Step 2: Build the frame.
	frame := buildFrame(record.Size, payload)

	// Step 3: One Write to outer → one TLS record.
	if err := writeAll(outer, frame); err != nil {
		return fmt.Errorf("record %d: write frame to outer: %w", idx, err)
	}
	return nil
}

// derivedRecordPeerTurn handles one inbound TLS record in the derived bootstrap phase.
//
// Sequence:
//  1. Read record.Size bytes from outer (peer's framed data)
//  2. Parse and validate the frame header
//  3. Deliver real payload to proxy via appHostEnd
func (f *Filter) derivedRecordPeerTurn(idx int, record Record, outer net.Conn, appHostEnd *net.TCPConn) error {
	// Step 1: Read the full record from the network.
	frameBuf := make([]byte, record.Size)
	if _, err := io.ReadFull(outer, frameBuf); err != nil {
		return fmt.Errorf("record %d: read frame from outer: %w", idx, err)
	}

	// Step 2: Parse the frame header.
	if int(record.Size) < frameHeaderSize {
		return fmt.Errorf("record %d: size %d too small for frame header", idx, record.Size)
	}
	payloadLen := uint32(binary.BigEndian.Uint16(frameBuf[:frameHeaderSize]))
	maxPayload := record.Size - uint32(frameHeaderSize)
	if payloadLen > maxPayload {
		return fmt.Errorf("record %d: frame payload_length %d exceeds capacity %d (record.Size=%d)",
			idx, payloadLen, maxPayload, record.Size)
	}

	// Step 3: Deliver real payload to the proxy (skip padding).
	if payloadLen > 0 {
		realData := frameBuf[frameHeaderSize : frameHeaderSize+int(payloadLen)]
		if err := writeAll(appHostEnd, realData); err != nil {
			return fmt.Errorf("record %d: write payload to proxy: %w", idx, err)
		}
	}
	return nil
}

// buildFrame constructs a derived-bootstrap frame of exactly recordSize bytes:
//
//	[2-byte BE payload_length][payload][random padding]
//
// If payload is empty, the frame is header + all-random padding.
func buildFrame(recordSize uint32, payload []byte) []byte {
	frame := make([]byte, recordSize)
	binary.BigEndian.PutUint16(frame[:frameHeaderSize], uint16(len(payload)))
	copy(frame[frameHeaderSize:], payload)
	// Fill remaining bytes with random padding so the record is
	// indistinguishable from random data to a passive observer.
	padStart := frameHeaderSize + len(payload)
	if padStart < len(frame) {
		rand.Read(frame[padStart:])
	}
	return frame
}

// readAvailable waits up to timeout for the first proxy byte, then
// greedily drains only what is already buffered in the loopback socket.
// A single Read call may return any positive prefix of what the OS has
// buffered, so we need follow-up reads to maximize record utilization. But we
// must not keep blocking after the buffer is drained, or a small prebuffered
// VLESS header would consume the full proxyReadTimeout and shift the record on
// the wire.
//
// The algorithm is therefore two-phase:
//  1. One blocking read with deadline = now + timeout to wait for the first byte.
//  2. Immediate-deadline reads to drain bytes that are already buffered right now.
//
// The timeout remains a wall-clock budget for "wait until the first byte
// arrives". Once any byte has arrived, additional reads are non-blocking in
// effect and return immediately when the kernel buffer is empty.
//
// Returns 0 bytes without error if the timeout expires with no data at all.
// Only hard errors (connection reset, peer EOF) are propagated.
func readAvailable(conn *net.TCPConn, maxBytes int, timeout time.Duration) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, nil
	}
	// Phase 1: wait up to timeout for the first byte.
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{}) // clear for future I/O

	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return buf[:0], nil
		}
		if n > 0 {
			return buf[:n], nil
		}
		return nil, err
	}
	total := n
	if total >= maxBytes {
		return buf[:total], nil
	}

	// Phase 2: drain only what is already buffered. An immediate deadline
	// turns subsequent reads into a non-blocking-ish drain: buffered bytes are
	// returned right away, and an empty recv buffer surfaces as a timeout.
	for total < maxBytes {
		conn.SetReadDeadline(time.Now())
		n, err = conn.Read(buf[total:])
		total += n
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return buf[:total], nil
			}
			if total > 0 {
				return buf[:total], nil
			}
			return nil, err
		}
		if n == 0 {
			return buf[:total], nil
		}
	}
	return buf[:total], nil
}

// writeAll writes the full buffer to w. Go's io.Writer contract says
// n < len(p) implies err != nil, so for conforming writers (stdlib TCP,
// TLS) the loop body executes once. The loop exists as defense against
// non-conforming wrappers that could silently drop bytes.
//
// TLS invariant note: outer is typically a *tls.Conn or *utls.UConn. Both
// encrypt and flush the entire plaintext in a single Write call — they never
// return a short write without an error. If the loop somehow did retry on a
// *tls.Conn, each Write call would produce a separate TLS record, violating
// the one-Write-one-record invariant that traffic shaping depends on.
// In practice this path is unreachable for TLS outer conns.
func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if n > 0 {
			buf = buf[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("write returned 0 bytes without error")
		}
	}
	return nil
}

func sleepUntilContext(ctx context.Context, target time.Time) error {
	delay := time.Until(target)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
