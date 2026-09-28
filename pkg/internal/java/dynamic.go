// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/gobwas/glob"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	javaDynamicReadyEvent = 36 // bpf/common/event_defs.h
	maxJavaSymbols        = 100000
	maxJavaSymbolBytes    = 64 << 20
)

const (
	javaListMethods byte = iota + 1
	javaAttachMethod
	javaDetachMethod
	javaClaimSession
)

type javaEndpoint struct {
	port     uint32
	token    [16]byte
	revision uint64
}

type DynamicRegistry struct {
	ctx     context.Context
	timeout time.Duration
	mu      sync.Mutex
	targets map[app.PID]*DynamicTarget
	symbols *javaSymbolCache
}

func NewDynamicRegistry(ctx context.Context, cfg config.DynamicInstrumentationConfig, events *ebpfcommon.EBPFEventContext) *DynamicRegistry {
	registry := &DynamicRegistry{ctx: ctx, timeout: cfg.RequestTimeout, targets: map[app.PID]*DynamicTarget{}, symbols: newJavaSymbolCache(cfg)}
	events.RegisterInternalEventHandler(javaDynamicReadyEvent, registry.handleReady)
	return registry
}

func (r *DynamicRegistry) Target(pid app.PID, tracer *ebpf.ProcessTracer) *DynamicTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	start, _ := procs.StartTime(pid)
	if prior := r.targets[pid]; prior != nil && prior.startTime == start && prior.tracer == tracer {
		return prior
	}
	target := &DynamicTarget{ctx: r.ctx, timeout: r.timeout, pid: pid, tracer: tracer, startTime: start, symbols: r.symbols, cookies: map[string]uint64{}}
	_, _ = rand.Read(target.session[:])
	r.targets[pid] = target
	return target
}

func (r *DynamicRegistry) Remove(pid app.PID) {
	r.mu.Lock()
	delete(r.targets, pid)
	r.symbols.remove(pid)
	r.mu.Unlock()
}

func (r *DynamicRegistry) handleReady(record *ringbuf.Record) error {
	data := record.RawSample
	if len(data) < 40 {
		return errors.New("short Java dynamic agent announcement")
	}
	pid := app.PID(binary.LittleEndian.Uint32(data[4:8]))
	r.mu.Lock()
	target := r.targets[pid]
	r.mu.Unlock()
	if target == nil {
		return nil
	}
	port := binary.LittleEndian.Uint32(data[8:12])
	if port == 0 || port > 65535 {
		return errors.New("invalid Java dynamic agent port")
	}
	target.mu.Lock()
	target.endpoint.port = port
	copy(target.endpoint.token[:], data[16:32])
	target.endpoint.revision = binary.LittleEndian.Uint64(data[32:40])
	target.mu.Unlock()
	return nil
}

type DynamicTarget struct {
	ctx          context.Context
	timeout      time.Duration
	pid          app.PID
	startTime    uint64
	rpcMu        sync.Mutex
	session      [16]byte
	claimedToken [16]byte
	tracer       *ebpf.ProcessTracer
	probesMu     sync.Mutex
	cookies      map[string]uint64
	mu           sync.Mutex
	endpoint     javaEndpoint
	observed     uint64
	symbolsMu    sync.Mutex
	symbols      *javaSymbolCache
}

func (t *DynamicTarget) LiveSymbolsChanged() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := t.observed != t.endpoint.revision
	t.observed = t.endpoint.revision
	return changed
}

func (t *DynamicTarget) ResolveLiveSymbols(pid app.PID, pattern string) ([]string, error) {
	if pid != t.pid {
		return nil, errors.New("java target PID mismatch")
	}
	matcher, err := glob.Compile(pattern)
	if err != nil {
		return nil, err
	}
	t.symbolsMu.Lock()
	defer t.symbolsMu.Unlock()
	t.mu.Lock()
	revision := t.endpoint.revision
	t.mu.Unlock()
	if revision == 0 {
		return nil, errors.New("java dynamic agent is not ready; javaagent.enabled must be true")
	}
	key := javaSymbolIdentity{pid: t.pid, start: t.startTime, revision: revision}
	symbols, cached := t.symbols.get(key)
	if !cached {
		symbols, err = t.command(t.ctx, javaListMethods, "", 0)
		if err != nil {
			return nil, err
		}
		t.symbols.put(key, symbols)
	}
	var matched []string
	for _, symbol := range symbols {
		if symbol == pattern || matcher.Match(symbol) {
			matched = append(matched, symbol)
		}
	}
	if len(matched) == 0 && pattern != "*" {
		return nil, fmt.Errorf("no loaded Java method matches %q", pattern)
	}
	return matched, nil
}

func (t *DynamicTarget) AttachLiveSpan(pid app.PID, _ uint32, span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) (io.Closer, error) {
	if pid != t.pid {
		return nil, errors.New("java target PID mismatch")
	}
	if !span.IsFunctionSpan() {
		return nil, errors.New("java dynamic probes require function_span")
	}
	for _, attr := range span.Attrs {
		if !attr.Type.IsString() {
			return nil, errors.New("java method arguments are captured as strings")
		}
	}
	t.probesMu.Lock()
	defer t.probesMu.Unlock()
	method := span.FunctionSymbol()
	prior := t.cookies[method]
	registration, err := t.tracer.RegisterJavaSpan(pid, span, cookie, id, generation)
	if err != nil {
		return nil, err
	}
	if _, err = t.command(t.ctx, javaAttachMethod, span.FunctionSymbol(), cookie); err != nil {
		_ = registration.Close()
		rollback := context.WithoutCancel(t.ctx)
		_, detachErr := t.command(rollback, javaDetachMethod, "", cookie)
		if prior != 0 {
			_, restoreErr := t.command(rollback, javaAttachMethod, method, prior)
			err = errors.Join(err, restoreErr)
		}
		return nil, errors.Join(err, detachErr)
	}
	t.cookies[method] = cookie
	return &javaDynamicProbe{target: t, cookie: cookie, method: method, registration: registration}, nil
}

type javaDynamicProbe struct {
	target       *DynamicTarget
	cookie       uint64
	method       string
	registration io.Closer
	once         sync.Once
	err          error
}

func (p *javaDynamicProbe) Invocations() (uint64, error) {
	return p.registration.(interface{ Invocations() (uint64, error) }).Invocations()
}

func (p *javaDynamicProbe) Close() error {
	p.target.probesMu.Lock()
	defer p.target.probesMu.Unlock()
	_, remoteErr := p.target.command(context.WithoutCancel(p.target.ctx), javaDetachMethod, "", p.cookie)
	if start, err := procs.StartTime(p.target.pid); errors.Is(err, os.ErrNotExist) || (err == nil && start != p.target.startTime) {
		remoteErr = nil
	}
	if remoteErr == nil && p.target.cookies[p.method] == p.cookie {
		delete(p.target.cookies, p.method)
	}
	p.once.Do(func() { p.err = p.registration.Close() })
	return errors.Join(remoteErr, p.err)
}

func (t *DynamicTarget) command(parent context.Context, operation byte, method string, cookie uint64) ([]string, error) {
	t.rpcMu.Lock()
	defer t.rpcMu.Unlock()
	start, err := procs.StartTime(t.pid)
	if err != nil {
		return nil, err
	}
	if start != t.startTime {
		return nil, errors.New("java target process identity changed")
	}
	ctx, cancel := context.WithTimeout(parent, t.timeout)
	defer cancel()
	t.mu.Lock()
	endpoint := t.endpoint
	t.mu.Unlock()
	if t.claimedToken != endpoint.token {
		if _, err := t.exchange(ctx, endpoint, javaClaimSession, "", 0); err != nil {
			return nil, err
		}
		t.claimedToken = endpoint.token
	}
	return t.exchange(ctx, endpoint, operation, method, cookie)
}

func (t *DynamicTarget) exchange(ctx context.Context, endpoint javaEndpoint, operation byte, method string, cookie uint64) ([]string, error) {
	if endpoint.port == 0 {
		return nil, errors.New("java dynamic agent is not ready")
	}
	var connection net.Conn
	err := netns.WithNetNS(int(t.pid), func() error {
		var err error
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(endpoint.port))))
		return err
	})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	if err = connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	var request bytes.Buffer
	request.Write(endpoint.token[:])
	request.Write(t.session[:])
	request.WriteByte(operation)
	if operation == javaAttachMethod {
		_ = binary.Write(&request, binary.BigEndian, uint32(len(method)))
		request.WriteString(method)
	}
	if operation == javaAttachMethod || operation == javaDetachMethod {
		_ = binary.Write(&request, binary.BigEndian, cookie)
	}
	if _, err = io.Copy(connection, &request); err != nil {
		return nil, err
	}
	var status [1]byte
	if _, err = io.ReadFull(connection, status[:]); err != nil {
		return nil, err
	}
	if status[0] != 0 {
		message, err := readJavaString(connection)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(message)
	}
	if operation != javaListMethods {
		return nil, nil
	}
	var count uint32
	if err = binary.Read(connection, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count > maxJavaSymbols {
		return nil, fmt.Errorf("java symbol list exceeds %d methods", maxJavaSymbols)
	}
	symbols := make([]string, 0, count)
	size := 0
	for range count {
		symbol, err := readJavaString(connection)
		if err != nil {
			return nil, err
		}
		size += len(symbol)
		if size > maxJavaSymbolBytes {
			return nil, errors.New("java symbol catalog exceeds byte limit")
		}
		symbols = append(symbols, symbol)
	}
	slices.Sort(symbols)
	return symbols, nil
}

func readJavaString(reader io.Reader) (string, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return "", err
	}
	if size > 65536 {
		return "", errors.New("java control string exceeds limit")
	}
	text := make([]byte, size)
	_, err := io.ReadFull(reader, text)
	return string(text), err
}
