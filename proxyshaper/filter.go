// proxyshaper shapes the first post-handshake TLS records, then switches to
// passthrough.

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

const frameHeaderSize = 2

const (
	tlsRecordHeaderSize               = 5
	tls12GCMWireOverhead              = tlsRecordHeaderSize + 8 + 16
	tls12ChaCha20Poly1305WireOverhead = tlsRecordHeaderSize + 16
	tls13AEADWireOverhead             = tlsRecordHeaderSize + 1 + 16
	maxSupportedTLSRecordOverhead     = tls12GCMWireOverhead

	bootstrapPayloadMagic    uint32 = 0x50536870 // "PShp"
	bootstrapMarkerSize             = 4
	bootstrapSeedDeriveLabel        = "proxyshaper-v1"
	bootstrapDerivedSeedSize        = 8
	bootstrapMinRecordSize          = maxSupportedTLSRecordOverhead + frameHeaderSize + bootstrapMarkerSize
	bootstrapRecordCount            = 10
)

// Wait briefly for proxy bytes before sending padding-only records.
const proxyReadTimeout = 50 * time.Millisecond

const generatedFlowCommandTimeout = 5 * time.Second

const generatedFlowMaxOutputBytes = 1 << 20

type Config struct {
	Role    string   `json:"role"`
	Mode    string   `json:"mode"`
	Records []Record `json:"records,omitempty"`

	GeneratedFlow *GeneratedFlowConfig `json:"generated_flow,omitempty"`
}

type Record struct {
	Size uint32 `json:"size"`
	Dir  string `json:"dir"`
}

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

func (c *Config) isOurTurn(record Record) bool {
	return (c.Role == "client" && record.Dir == "out") ||
		(c.Role == "server" && record.Dir == "in")
}

func (c *Config) validateBootstrap() error {
	if c.Mode != "" && c.Mode != "bootstrap" {
		return fmt.Errorf("unsupported mode %q: only bootstrap is implemented", c.Mode)
	}
	if c.GeneratedFlow == nil {
		return fmt.Errorf("bootstrap mode requires generated_flow")
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

// runGeneratedFlowCommand returns one signed-size CSV row per candidate flow.
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

// generatedFlowRowToRecords validates one generated signed-size row.
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
			Size: uint32(size),
			Dir:  dir,
		}
	}
	return records, nil
}

// deriveGeneratedProfile uses the same seed+retry rule on both peers.
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

type closeWriter interface {
	CloseWrite() error
}

// Filter wraps post-TLS connections.
type Filter struct {
	config  Config
	counter atomic.Uint64
}

func NewFilter(_ context.Context, cfg Config) (*Filter, error) {
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

// Reflection keeps this package independent of concrete TLS/uTLS state types.
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

// executionConfigForOuter converts wire-size targets to plaintext budgets.
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

// Wrap returns the connection used by the proxy protocol.
func (f *Filter) Wrap(ctx context.Context, outer net.Conn) (net.Conn, error) {
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

// scheduleWindowDeadline bounds the shaped bootstrap phase.
func (f *Filter) scheduleWindowDeadline(cfg Config) time.Time {
	const margin = 5 * time.Second
	extraWait := time.Duration(len(cfg.Records)) * proxyReadTimeout
	return time.Now().Add(extraWait + margin)
}

// runBootstrapAndPassthrough runs record 0, records 1-9, then passthrough.
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
		Role:    f.config.Role,
		Records: derived.Records[1:],
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

	if err := ensureHandshake(ctx, outer); err != nil {
		return derivedProfile{}, fmt.Errorf("bootstrap handshake: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	outer.SetDeadline(deadline)
	defer outer.SetDeadline(time.Time{})

	derived, err := f.deriveBootstrapProfile(ctx, outer)
	if err != nil {
		return derivedProfile{}, err
	}
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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(outer, appHostEnd)
		if cw, ok := outer.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			outer.Close()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(appHostEnd, outer)
		appHostEnd.CloseWrite()
	}()
	wg.Wait()
}

func bootstrapPayload(proxyPayload []byte) []byte {
	buf := make([]byte, bootstrapMarkerSize+len(proxyPayload))
	binary.BigEndian.PutUint32(buf[0:4], bootstrapPayloadMagic)
	copy(buf[bootstrapMarkerSize:], proxyPayload)
	return buf
}

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

// bootstrapSeedBytesFromTLSState derives the shared row-selection seed.
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

// deriveBootstrapProfile selects a generator row for this TLS session.
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
	derived, err := deriveGeneratedProfile(ctx, *f.config.GeneratedFlow, seed, tlsOverhead)
	if err != nil {
		return derivedProfile{}, fmt.Errorf("bootstrap: generate flow from seed %d: %w", seed, err)
	}
	return derived, nil
}

func (f *Filter) runBootstrapRecord0(ctx context.Context, outer net.Conn, appHostEnd *net.TCPConn, derived derivedProfile) error {
	record0 := derived.Records[0]
	if f.config.isOurTurn(record0) {
		return f.runBootstrapMarkerSender(ctx, outer, appHostEnd, record0)
	}
	return f.runBootstrapMarkerReceiver(ctx, outer, appHostEnd, record0)
}

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

func (f *Filter) executeSchedule(ctx context.Context, cfg Config, outer net.Conn, appHostEnd *net.TCPConn) error {
	for i, record := range cfg.Records {
		if err := ctx.Err(); err != nil {
			return err
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
	}
	return nil
}

func (f *Filter) derivedRecordOurTurn(idx int, record Record, outer net.Conn, appHostEnd *net.TCPConn) error {
	maxPayload := int(record.Size) - frameHeaderSize
	payload, err := readAvailable(appHostEnd, maxPayload, proxyReadTimeout)
	if err != nil {
		return fmt.Errorf("record %d: read proxy data: %w", idx, err)
	}

	frame := buildFrame(record.Size, payload)

	if err := writeAll(outer, frame); err != nil {
		return fmt.Errorf("record %d: write frame to outer: %w", idx, err)
	}
	return nil
}

func (f *Filter) derivedRecordPeerTurn(idx int, record Record, outer net.Conn, appHostEnd *net.TCPConn) error {
	frameBuf := make([]byte, record.Size)
	if _, err := io.ReadFull(outer, frameBuf); err != nil {
		return fmt.Errorf("record %d: read frame from outer: %w", idx, err)
	}

	if int(record.Size) < frameHeaderSize {
		return fmt.Errorf("record %d: size %d too small for frame header", idx, record.Size)
	}
	payloadLen := uint32(binary.BigEndian.Uint16(frameBuf[:frameHeaderSize]))
	maxPayload := record.Size - uint32(frameHeaderSize)
	if payloadLen > maxPayload {
		return fmt.Errorf("record %d: frame payload_length %d exceeds capacity %d (record.Size=%d)",
			idx, payloadLen, maxPayload, record.Size)
	}

	if payloadLen > 0 {
		realData := frameBuf[frameHeaderSize : frameHeaderSize+int(payloadLen)]
		if err := writeAll(appHostEnd, realData); err != nil {
			return fmt.Errorf("record %d: write payload to proxy: %w", idx, err)
		}
	}
	return nil
}

// buildFrame returns: [2-byte payload length][payload][padding].
func buildFrame(recordSize uint32, payload []byte) []byte {
	frame := make([]byte, recordSize)
	binary.BigEndian.PutUint16(frame[:frameHeaderSize], uint16(len(payload)))
	copy(frame[frameHeaderSize:], payload)
	padStart := frameHeaderSize + len(payload)
	if padStart < len(frame) {
		rand.Read(frame[padStart:])
	}
	return frame
}

// readAvailable waits for one byte, then drains whatever is already buffered.
func readAvailable(conn *net.TCPConn, maxBytes int, timeout time.Duration) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, nil
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

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

// writeAll keeps the short-write case explicit.
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
