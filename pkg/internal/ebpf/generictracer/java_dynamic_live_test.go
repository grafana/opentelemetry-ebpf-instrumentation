// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && jvm_live

package generictracer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestJavaDynamicSpansLive(t *testing.T) {
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	jar := os.Getenv("OBI_JAVA_AGENT_JAR")
	require.NotEmpty(t, jar, "set OBI_JAVA_AGENT_JAR to the built agent")
	directory := t.TempDir()
	source := filepath.Join(directory, "DynamicTarget.java")
	require.NoError(t, os.WriteFile(source, []byte(javaDynamicTargetSource), 0o600))
	out, err := exec.Command("javac", source).CombinedOutput()
	require.NoError(t, err, string(out))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serverHTTP := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), ReadHeaderTimeout: time.Second}
	go func() { _ = serverHTTP.Serve(listener) }()
	t.Cleanup(func() { _ = serverHTTP.Close() })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	cmd := exec.Command("java", "-javaagent:"+jar+"=dynamicInstrumentation=true", "-cp", directory, "DynamicTarget", port)
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(output)
	tid, err := strconv.Atoi(scanJavaInt(t, scanner))
	require.NoError(t, err)
	pid := app.PID(cmd.Process.Pid)

	cfg := obi.DefaultConfig
	cfg.DynamicInstrumentation.Enabled = true
	cfg.EBPF.BpfDebug = true
	filters := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
	tracer := New(filters, &cfg, imetrics.NoopReporter{})
	events := ebpfcommon.NewEBPFEventContext()
	events.CommonPIDsFilter = filters
	pt := obiebpf.NewProcessTracer(obiebpf.Generic, []obiebpf.Tracer{tracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, pt.Init(events, &cfg))
	fi := javaProcessFileInfo(t, pid)
	pt.AllowPID(pid, fi.Ns(), fi)
	ctx, cancel := context.WithCancel(context.Background())
	registry := javaagent.NewDynamicRegistry(ctx, cfg.DynamicInstrumentation, events)
	target := registry.Target(pid, pt)
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100))
	spans := queue.Subscribe(msg.SubscriberName("dynamic-java-test"))
	done := make(chan struct{})
	go func() { defer close(done); pt.Run(ctx, events, queue) }()
	t.Cleanup(func() { cancel(); <-done; queue.Close() })
	require.Eventually(t, func() bool {
		names, err := target.ResolveLiveSymbols(pid, "DynamicTarget.*")
		return err == nil && len(names) >= 3
	}, 15*time.Second, 100*time.Millisecond)

	var traceID trace.TraceID
	var serverID trace.SpanID
	traceID[0] = 23
	serverID[0] = 42
	key := BpfTraceKeyT{P_key: BpfPidKeyT{Tid: uint32(tid), Pid: uint32(pid), Ns: fi.Ns()}}
	server := BpfTpInfoPidT{Tp: BpfTpInfoT{TraceId: traceID, SpanId: serverID, Flags: 1, Ts: uint64(timing.MonoTimeNow())}, Pid: uint32(pid), Valid: 1}
	require.NoError(t, tracer.bpfObjects.ServerTraces.Update(&key, &server, ebpf.UpdateAny))
	probes := make([]io.Closer, 0, 2)
	countTaskContexts := func() int {
		iterator := tracer.bpfObjects.JavaDynamicTaskContexts.Iterate()
		var taskKey BpfJavaDynamicTaskKey
		var taskContext BpfJavaDynamicContext
		count := 0
		for iterator.Next(&taskKey, &taskContext) {
			count++
		}
		require.NoError(t, iterator.Err())
		return count
	}
	for i, method := range []string{"outer", "inner"} {
		spec := config.CustomSpanSpec{Name: method, On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget." + method}}
		probe, err := target.AttachLiveSpan(pid, fi.Ns(), &spec, uint64(i+1), method, 1)
		require.NoError(t, err)
		probes = append(probes, probe)
	}
	sendJavaCommandExpectInt(t, input, scanner, "CALL", "42", "outer must return before task release")
	sendJavaCommandExpectInt(t, input, scanner, "RELEASE", "43", "task result")
	received := map[string]request.Span{}
	var client request.Span
	deadline := time.After(10 * time.Second)
	for len(received) < 2 || !client.SpanID.IsValid() {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan {
					received[span.Method] = span
				}
				if span.Type == request.EventTypeHTTPClient {
					client = span
				}
			}
		case <-deadline:
			t.Fatalf("missing Java spans: %+v", received)
		}
	}
	outer, inner := received["outer"], received["inner"]
	t.Logf("observed IDs: outer trace=%s span=%s parent=%s; inner trace=%s span=%s parent=%s; client trace=%s span=%s parent=%s", outer.TraceID, outer.SpanID, outer.ParentSpanID, inner.TraceID, inner.SpanID, inner.ParentSpanID, client.TraceID, client.SpanID, client.ParentSpanID)
	requireSpanParentChain(t, traceID, serverID, outer, inner, client)
	require.Equal(t, "42", outer.CustomSpan.Attrs["arg0"])
	require.Equal(t, "hello", outer.CustomSpan.Attrs["arg1"])
	require.Equal(t, "42", outer.CustomSpan.Attrs["return0"])
	for i, probe := range probes {
		count, err := probe.(interface{ Invocations() (uint64, error) }).Invocations()
		require.NoError(t, err)
		require.Equal(t, uint64(1), count)
		require.NoError(t, probe.Close())
		var value uint64
		require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(i+1), &value), ebpf.ErrKeyNotExist)
	}
	sendJavaCommandExpectInt(t, input, scanner, "CALL", "42", "outer must return before task release")
	sendJavaCommandExpectInt(t, input, scanner, "RELEASE", "43", "task result")
	select {
	case batch := <-spans:
		for _, span := range batch {
			require.NotEqual(t, request.EventTypeCustomSpan, span.Type, fmt.Sprintf("custom span after deletion: %+v", span))
		}
	case <-time.After(200 * time.Millisecond):
	}
	var current BpfJavaDynamicContext
	require.ErrorIs(t, tracer.bpfObjects.JavaDynamicSpans.Lookup(&key, &current), ebpf.ErrKeyNotExist)
	var restored BpfTpInfoPidT
	require.NoError(t, tracer.bpfObjects.ServerTraces.Lookup(&key, &restored))
	require.Equal(t, server, restored, "custom spans must preserve automatic server state")

	for _, scenario := range []struct {
		command   string
		release   string
		outerName string
		innerName string
	}{
		{command: "CALL_SCHEDULED", release: "RELEASE_SCHEDULED", outerName: "outerScheduled", innerName: "innerScheduled"},
		{command: "CALL_SCHEDULED_RUNNABLE", release: "RELEASE_SCHEDULED_RUNNABLE", outerName: "outerScheduledRunnable", innerName: "innerScheduledRunnable"},
		{command: "CALL_FORKJOIN", release: "RELEASE_FORKJOIN", outerName: "outerForkJoin", innerName: "innerForkJoin"},
		{command: "CALL_FORKJOIN_SUBMIT", release: "RELEASE_FORKJOIN_SUBMIT", outerName: "outerForkJoinSubmit", innerName: "innerForkJoinSubmit"},
	} {
		outerProbe, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: scenario.outerName, On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget." + scenario.outerName}}, 3, scenario.outerName, 1)
		require.NoError(t, err)
		innerProbe, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: scenario.innerName, On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget." + scenario.innerName}}, 4, scenario.innerName, 1)
		require.NoError(t, err)
		sendJavaCommandExpectInt(t, input, scanner, scenario.command, "42", scenario.outerName+" must return before worker release")
		sendJavaCommandExpectInt(t, input, scanner, scenario.release, "43", "worker result")

		found := map[string]request.Span{}
		var nestedClient request.Span
		deadline := time.After(10 * time.Second)
		for len(found) < 2 || !nestedClient.SpanID.IsValid() {
			select {
			case batch := <-spans:
				for _, span := range batch {
					if span.Type == request.EventTypeCustomSpan && (span.Method == scenario.outerName || span.Method == scenario.innerName) {
						found[span.Method] = span
					}
					if span.Type == request.EventTypeHTTPClient {
						nestedClient = span
					}
				}
			case <-deadline:
				t.Fatalf("missing %s/%s spans: %+v", scenario.outerName, scenario.innerName, found)
			}
		}
		outer, inner := found[scenario.outerName], found[scenario.innerName]
		t.Logf("%s: outer span=%s parent=%s; inner span=%s parent=%s", scenario.outerName, outer.SpanID, outer.ParentSpanID, inner.SpanID, inner.ParentSpanID)
		require.Equal(t, serverID, outer.ParentSpanID)
		require.Equal(t, outer.SpanID, inner.ParentSpanID, scenario.innerName+" must inherit the submitting dynamic span")
		require.Equal(t, inner.SpanID, nestedClient.ParentSpanID)
		for i, probe := range []io.Closer{outerProbe, innerProbe} {
			count, err := probe.(interface{ Invocations() (uint64, error) }).Invocations()
			require.NoError(t, err)
			require.Equal(t, uint64(1), count)
			require.NoError(t, probe.Close())
			var value uint64
			require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(i+3), &value), ebpf.ErrKeyNotExist)
		}
	}

	// Verify an exceptional scheduled task exits its scope and the same worker
	// carries a fresh context on the subsequent task.
	exceptionOuter, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "outerScheduledException", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.outerScheduledException"}}, 9, "outerScheduledException", 1)
	require.NoError(t, err)
	exceptionInner, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "innerScheduledExceptionRecovery", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.innerScheduledExceptionRecovery"}}, 10, "innerScheduledExceptionRecovery", 1)
	require.NoError(t, err)
	_, err = io.WriteString(input, "CALL_SCHEDULED_EXCEPTION\n")
	require.NoError(t, err)
	require.Equal(t, "42", scanJavaInt(t, scanner), "exception/recovery scenario return marker")
	exceptionSpans := map[string]request.Span{}
	var exceptionClient request.Span
	exceptionDeadline := time.After(10 * time.Second)
	for len(exceptionSpans) < 2 || !exceptionClient.SpanID.IsValid() {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && (span.Method == "outerScheduledException" || span.Method == "innerScheduledExceptionRecovery") {
					exceptionSpans[span.Method] = span
				}
				if span.Type == request.EventTypeHTTPClient {
					exceptionClient = span
				}
			}
		case <-exceptionDeadline:
			t.Fatalf("timed out waiting for exception recovery spans: %+v", exceptionSpans)
		}
	}
	exceptionOuterSpan := exceptionSpans["outerScheduledException"]
	exceptionInnerSpan := exceptionSpans["innerScheduledExceptionRecovery"]
	require.Equal(t, serverID, exceptionOuterSpan.ParentSpanID)
	require.Equal(t, exceptionOuterSpan.SpanID, exceptionInnerSpan.ParentSpanID)
	require.Equal(t, exceptionInnerSpan.SpanID, exceptionClient.ParentSpanID)
	for i, probe := range []io.Closer{exceptionOuter, exceptionInner} {
		count, err := probe.(interface{ Invocations() (uint64, error) }).Invocations()
		require.NoError(t, err)
		require.Equal(t, uint64(1), count)
		require.NoError(t, probe.Close())
		var value uint64
		require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(i+9), &value), ebpf.ErrKeyNotExist)
	}

	// A task rejected while its submitter span is active must not retain that
	// context if the same task object is later run without an executor handoff.
	rejectedOuter, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "outerRejectedTask", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.outerRejectedTask"}}, 11, "outerRejectedTask", 1)
	require.NoError(t, err)
	rejectedInner, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "innerRejectedTask", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.innerRejectedTask"}}, 12, "innerRejectedTask", 1)
	require.NoError(t, err)
	_, err = io.WriteString(input, "CALL_REJECTED_TASK\n")
	require.NoError(t, err)
	require.Equal(t, "42", scanJavaInt(t, scanner), "rejected submitter return marker")
	_, err = io.WriteString(input, "RUN_REJECTED_TASK\n")
	require.NoError(t, err)
	require.Equal(t, "42", scanJavaInt(t, scanner), "raw task execution marker")
	rejectedSpans := map[string]request.Span{}
	rejectedDeadline := time.After(10 * time.Second)
	for len(rejectedSpans) < 2 {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && (span.Method == "outerRejectedTask" || span.Method == "innerRejectedTask") {
					rejectedSpans[span.Method] = span
				}
			}
		case <-rejectedDeadline:
			t.Fatalf("timed out waiting for rejected-task spans: %+v", rejectedSpans)
		}
	}
	rejectedOuterSpan := rejectedSpans["outerRejectedTask"]
	rejectedInnerSpan := rejectedSpans["innerRejectedTask"]
	require.Equal(t, serverID, rejectedOuterSpan.ParentSpanID)
	require.NotEqual(t, rejectedOuterSpan.SpanID, rejectedInnerSpan.ParentSpanID, "rejected task must not keep its submitter's stale dynamic context")
	for i, probe := range []io.Closer{rejectedOuter, rejectedInner} {
		count, err := probe.(interface{ Invocations() (uint64, error) }).Invocations()
		require.NoError(t, err)
		require.Equal(t, uint64(1), count)
		require.NoError(t, probe.Close())
		var value uint64
		require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(i+11), &value), ebpf.ErrKeyNotExist)
	}

	// Cancellation must delete the context captured before scheduling a
	// Runnable, even though the scheduler has not run that task yet.
	contextsBeforeCancellation := countTaskContexts()
	cancelOuter, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "outerCancelledTask", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.outerCancelledTask"}}, 13, "outerCancelledTask", 1)
	require.NoError(t, err)
	_, err = io.WriteString(input, "CALL_SCHEDULED_CANCELLED\n")
	require.NoError(t, err)
	require.Equal(t, "42", scanJavaInt(t, scanner), "cancelled submitter return marker")
	require.Eventually(t, func() bool { return countTaskContexts() > contextsBeforeCancellation }, 5*time.Second, 10*time.Millisecond, "scheduled task context was not captured")
	_, err = io.WriteString(input, "CANCEL_SCHEDULED\n")
	require.NoError(t, err)
	require.Equal(t, "42", scanJavaInt(t, scanner), "scheduled task cancellation marker")
	require.Eventually(t, func() bool { return countTaskContexts() == contextsBeforeCancellation }, 5*time.Second, 10*time.Millisecond, "cancellation left a stale dynamic task context")
	cancelInner, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "innerCancelledTask", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.innerCancelledTask"}}, 14, "innerCancelledTask", 1)
	require.NoError(t, err)
	_, err = io.WriteString(input, "RUN_CANCELLED_TASK\n")
	require.NoError(t, err)
	require.Equal(t, "43", scanJavaInt(t, scanner), "post-cancellation worker reuse marker")
	cancelSpans := map[string]request.Span{}
	var cancelClientSpan request.Span
	cancelDeadline := time.After(10 * time.Second)
	for len(cancelSpans) < 2 || !cancelClientSpan.SpanID.IsValid() {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && (span.Method == "outerCancelledTask" || span.Method == "innerCancelledTask") {
					cancelSpans[span.Method] = span
				}
				if span.Type == request.EventTypeHTTPClient {
					cancelClientSpan = span
				}
			}
		case <-cancelDeadline:
			t.Fatalf("timed out waiting for cancellation cleanup spans: %+v", cancelSpans)
		}
	}
	cancelOuterSpan := cancelSpans["outerCancelledTask"]
	cancelInnerSpan := cancelSpans["innerCancelledTask"]
	require.Equal(t, serverID, cancelInnerSpan.ParentSpanID, "post-cancellation task must use fresh server context")
	require.NotEqual(t, cancelOuterSpan.SpanID, cancelInnerSpan.ParentSpanID, "cancelled task context leaked to a reused worker")
	require.Equal(t, cancelInnerSpan.SpanID, cancelClientSpan.ParentSpanID)
	cancelCount, err := cancelOuter.(interface{ Invocations() (uint64, error) }).Invocations()
	require.NoError(t, err)
	require.Equal(t, uint64(1), cancelCount)
	require.NoError(t, cancelOuter.Close())
	cancelInnerCount, err := cancelInner.(interface{ Invocations() (uint64, error) }).Invocations()
	require.NoError(t, err)
	require.Equal(t, uint64(1), cancelInnerCount)
	require.NoError(t, cancelInner.Close())

	// Exercise schedule(Runnable) without holding the worker behind a latch. A
	// ScheduledFuture wrapper can start on the prestarted worker before the
	// schedule call returns, so this probes the capture/submit-return race.
	const raceRuns = 64
	raceOuter, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "outerScheduledRunnableRace", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.outerScheduledRunnableRace"}}, 7, "outerScheduledRunnableRace", 1)
	require.NoError(t, err)
	raceInner, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "innerScheduledRunnableRace", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.innerScheduledRunnableRace"}}, 8, "innerScheduledRunnableRace", 1)
	require.NoError(t, err)
	_, err = io.WriteString(input, "CALL_SCHEDULED_RUNNABLE_RACE\n")
	require.NoError(t, err)
	require.Equal(t, "42", scanJavaInt(t, scanner), "race scenario return marker")
	var raceOuterSpan request.Span
	raceInnerSpans := make([]request.Span, 0, raceRuns)
	raceDeadline := time.After(10 * time.Second)
	for raceOuterSpan.SpanID == (trace.SpanID{}) || len(raceInnerSpans) < raceRuns {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type != request.EventTypeCustomSpan {
					continue
				}
				switch span.Method {
				case "outerScheduledRunnableRace":
					raceOuterSpan = span
				case "innerScheduledRunnableRace":
					raceInnerSpans = append(raceInnerSpans, span)
				}
			}
		case <-raceDeadline:
			t.Fatalf("timed out waiting for race spans: outer=%+v inner=%d/%d", raceOuterSpan, len(raceInnerSpans), raceRuns)
		}
	}
	for _, span := range raceInnerSpans {
		require.Equal(t, raceOuterSpan.SpanID, span.ParentSpanID, "scheduled runnable must retain its submitter context")
	}
	for i, probe := range []io.Closer{raceOuter, raceInner} {
		count, err := probe.(interface{ Invocations() (uint64, error) }).Invocations()
		require.NoError(t, err)
		want := uint64(1)
		if i == 1 {
			want = raceRuns
		}
		require.Equal(t, want, count)
		require.NoError(t, probe.Close())
		var value uint64
		require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(i+7), &value), ebpf.ErrKeyNotExist)
	}

	// A task submitted from inside another selected method should inherit the
	// innermost method span, not just the original request/thread context.
	nestedOuter, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "outerNestedTask", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.outerNestedTask"}}, 15, "outerNestedTask", 1)
	require.NoError(t, err)
	nestedInner, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "innerNestedTask", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.innerNestedTask"}}, 16, "innerNestedTask", 1)
	require.NoError(t, err)
	nestedChild, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "innerNestedChild", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.innerNestedChild"}}, 17, "innerNestedChild", 1)
	require.NoError(t, err)
	sendJavaCommandExpectInt(t, input, scanner, "CALL_NESTED_TASK", "42", "nested submitter return marker")
	sendJavaCommandExpectInt(t, input, scanner, "RELEASE_NESTED_TASK", "43", "nested task result marker")
	nestedSpans := map[string]request.Span{}
	var nestedClient request.Span
	nestedDeadline := time.After(10 * time.Second)
	for len(nestedSpans) < 3 || !nestedClient.SpanID.IsValid() {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && (span.Method == "outerNestedTask" || span.Method == "innerNestedTask" || span.Method == "innerNestedChild") {
					nestedSpans[span.Method] = span
				}
				if span.Type == request.EventTypeHTTPClient {
					nestedClient = span
				}
			}
		case <-nestedDeadline:
			t.Fatalf("timed out waiting for nested-task spans: %+v", nestedSpans)
		}
	}
	requireSpanParentChain(t, traceID, serverID,
		nestedSpans["outerNestedTask"],
		nestedSpans["innerNestedTask"],
		nestedSpans["innerNestedChild"],
		nestedClient,
	)
	for i, probe := range []io.Closer{nestedOuter, nestedInner, nestedChild} {
		count, err := probe.(interface{ Invocations() (uint64, error) }).Invocations()
		require.NoError(t, err)
		require.Equal(t, uint64(1), count)
		require.NoError(t, probe.Close())
		var value uint64
		require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(i+15), &value), ebpf.ErrKeyNotExist)
	}

	virtualProbe, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "outerVirtualThread", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.outerVirtualThread"}}, 18, "outerVirtualThread", 1)
	require.NoError(t, err)
	_, err = io.WriteString(input, "CALL_VIRTUAL\n")
	require.NoError(t, err)
	require.Equal(t, "43", scanJavaInt(t, scanner), "virtual-thread dynamic method return")
	var virtualSpan, virtualClient request.Span
	virtualDeadline := time.After(10 * time.Second)
	for !virtualSpan.SpanID.IsValid() || !virtualClient.SpanID.IsValid() {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && span.Method == "outerVirtualThread" {
					virtualSpan = span
				}
				if span.Type == request.EventTypeHTTPClient {
					virtualClient = span
				}
			}
		case <-virtualDeadline:
			t.Fatalf("timed out waiting for virtual-thread spans: dynamic=%+v client=%+v", virtualSpan, virtualClient)
		}
	}
	t.Logf("virtual-thread dynamic span=%s parent=%s; client span=%s parent=%s", virtualSpan.SpanID, virtualSpan.ParentSpanID, virtualClient.SpanID, virtualClient.ParentSpanID)
	require.Equal(t, virtualSpan.TraceID, virtualClient.TraceID)
	require.Equal(t, virtualSpan.SpanID, virtualClient.ParentSpanID, "client request on a virtual thread must inherit the active dynamic span")
	virtualInvocations, err := virtualProbe.(interface{ Invocations() (uint64, error) }).Invocations()
	require.NoError(t, err)
	require.Equal(t, uint64(1), virtualInvocations)
	require.NoError(t, virtualProbe.Close())
	var virtualCookie uint64
	require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(18), &virtualCookie), ebpf.ErrKeyNotExist)
	require.Eventually(t, func() bool {
		iterator := tracer.bpfObjects.JavaVtThreads.Iterate()
		var key BpfPidKeyT
		var virtualID uint64
		for iterator.Next(&key, &virtualID) {
			if key.Pid == uint32(pid) && key.Ns == fi.Ns() {
				return false
			}
		}
		return iterator.Err() == nil
	}, time.Second, 10*time.Millisecond, "virtual-thread mount mapping must be removed after unmount")

	var benchmarkSpans atomic.Int64
	go func() {
		for batch := range spans {
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && span.Method == "benchWork" {
					benchmarkSpans.Add(1)
				}
			}
		}
	}()
	const benchWarmup = 10000
	runBenchmark := func(iterations int) int64 {
		t.Helper()
		_, err := fmt.Fprintf(input, "BENCH %d\n", iterations)
		require.NoError(t, err)
		fields := strings.Fields(scanJavaPrefix(t, scanner, "BENCH_RESULT "))
		require.Len(t, fields, 3)
		require.Equal(t, "BENCH_RESULT", fields[0])
		nanos, err := strconv.ParseInt(fields[1], 10, 64)
		require.NoError(t, err)
		return nanos
	}
	measurements := func(iterations int, instrumented bool) []int64 {
		values := make([]int64, 0, 3)
		for range 3 {
			elapsed := runBenchmark(iterations)
			values = append(values, elapsed)
		}
		return values
	}
	baseline := measurements(100000, false)
	attachStarted := time.Now()
	benchProbe, err := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{Name: "benchWork", On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget.benchWork"}}, 19, "benchWork", 1)
	require.NoError(t, err)
	attachPause := time.Since(attachStarted)
	instrumented := measurements(10000, true)
	benchInvocations, err := benchProbe.(interface{ Invocations() (uint64, error) }).Invocations()
	require.NoError(t, err)
	require.Equal(t, uint64(60000), benchInvocations, "10k warmup plus 3x10k measured calls")
	require.NoError(t, benchProbe.Close())
	var benchCookie uint64
	require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(19), &benchCookie), ebpf.ErrKeyNotExist)
	sort.Slice(baseline, func(i, j int) bool { return baseline[i] < baseline[j] })
	sort.Slice(instrumented, func(i, j int) bool { return instrumented[i] < instrumented[j] })
	t.Logf("live dynamic attach latency (registry request + Java retransform): %s", attachPause)
	t.Logf("successful-ioctl hot method: baseline median=%.2f ns/call (100k calls); instrumented median=%.2f ns/call (10k calls); additional=%.2f ns/call; baseline samples=%v instrumented samples=%v; delivered span events=%d (best-effort)", float64(baseline[1])/100000, float64(instrumented[1])/10000, float64(instrumented[1])/10000-float64(baseline[1])/100000, baseline, instrumented, benchmarkSpans.Load())
}

func TestJavaDynamicMapCapacityLive(t *testing.T) {
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	cfg := obi.DefaultConfig
	filters := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
	tracer := New(filters, &cfg, imetrics.NoopReporter{})
	events := ebpfcommon.NewEBPFEventContext()
	events.CommonPIDsFilter = filters
	pt := obiebpf.NewProcessTracer(obiebpf.Generic, []obiebpf.Tracer{tracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, pt.Init(events, &cfg))
	t.Cleanup(func() { require.NoError(t, pt.Close()) })

	contextValue := BpfJavaDynamicContext{Cookie: 1}
	spanMap := tracer.bpfObjects.JavaDynamicSpans
	spanLimit := int(spanMap.MaxEntries())
	spanKeys := make([]BpfTraceKeyT, spanLimit+1)
	for i := range spanKeys {
		spanKeys[i] = BpfTraceKeyT{ExtraId: 0xfedcba9876543210, P_key: BpfPidKeyT{Tid: uint32(i + 1), Pid: 0x7fffffff, Ns: 0x7ffffffe}}
	}
	t.Cleanup(func() {
		for _, key := range spanKeys {
			_ = spanMap.Delete(&key)
		}
	})
	started := time.Now()
	for i, key := range spanKeys {
		require.NoError(t, spanMap.Update(&key, &contextValue, ebpf.UpdateAny), "span entry %d", i)
	}
	spanElapsed := time.Since(started)
	spanIteratorCount := countJavaDynamicMapEntries[BpfTraceKeyT, BpfJavaDynamicContext](t, spanMap)
	spanCount := countPresentJavaDynamicMapEntries[BpfTraceKeyT, BpfJavaDynamicContext](t, spanMap, spanKeys)
	require.LessOrEqual(t, spanCount, spanLimit)
	var span BpfJavaDynamicContext
	require.ErrorIs(t, spanMap.Lookup(&spanKeys[0], &span), ebpf.ErrKeyNotExist, "LRU span map should evict its oldest entry")
	require.NoError(t, spanMap.Lookup(&spanKeys[len(spanKeys)-1], &span))
	t.Logf("java_dynamic_spans: max_entries=%d present_test_keys=%d iterator_count=%d updates=%d elapsed=%s", spanLimit, spanCount, spanIteratorCount, len(spanKeys), spanElapsed)

	taskMap := tracer.bpfObjects.JavaDynamicTaskContexts
	taskLimit := int(taskMap.MaxEntries())
	taskKeys := make([]BpfJavaDynamicTaskKey, taskLimit+1)
	for i := range taskKeys {
		taskKeys[i] = BpfJavaDynamicTaskKey{Pid: 0x7ffffffd, TaskId: uint64(i + 1)}
	}
	t.Cleanup(func() {
		for _, key := range taskKeys {
			_ = taskMap.Delete(&key)
		}
	})
	started = time.Now()
	for i, key := range taskKeys {
		require.NoError(t, taskMap.Update(&key, &contextValue, ebpf.UpdateAny), "task context entry %d", i)
	}
	taskElapsed := time.Since(started)
	taskIteratorCount := countJavaDynamicMapEntries[BpfJavaDynamicTaskKey, BpfJavaDynamicContext](t, taskMap)
	taskCount := countPresentJavaDynamicMapEntries[BpfJavaDynamicTaskKey, BpfJavaDynamicContext](t, taskMap, taskKeys)
	require.LessOrEqual(t, taskCount, taskLimit)
	require.ErrorIs(t, taskMap.Lookup(&taskKeys[0], &span), ebpf.ErrKeyNotExist, "LRU task-context map should evict its oldest entry")
	require.NoError(t, taskMap.Lookup(&taskKeys[len(taskKeys)-1], &span))
	t.Logf("java_dynamic_task_contexts: max_entries=%d present_test_keys=%d iterator_count=%d updates=%d elapsed=%s", taskLimit, taskCount, taskIteratorCount, len(taskKeys), taskElapsed)

	scopeMap := tracer.bpfObjects.JavaDynamicTaskScopes
	scopeLimit := int(scopeMap.MaxEntries())
	scopeInitial := countJavaDynamicMapEntries[uint64, BpfJavaDynamicTaskScopeState](t, scopeMap)
	require.LessOrEqual(t, scopeInitial, scopeLimit)
	scopeInsertions := scopeLimit - scopeInitial
	scopeKeys := make([]uint64, scopeInsertions+1)
	for i := range scopeKeys {
		scopeKeys[i] = 0xf000000000000000 + uint64(i)
	}
	t.Cleanup(func() {
		for _, key := range scopeKeys {
			_ = scopeMap.Delete(&key)
		}
	})
	scopeValue := BpfJavaDynamicTaskScopeState{Depth: 1}
	started = time.Now()
	for i, key := range scopeKeys[:scopeInsertions] {
		require.NoError(t, scopeMap.Update(&key, &scopeValue, ebpf.UpdateAny), "task scope entry %d", i)
	}
	scopeElapsed := time.Since(started)
	scopeCount := countJavaDynamicMapEntries[uint64, BpfJavaDynamicTaskScopeState](t, scopeMap)
	require.Equal(t, scopeLimit, scopeCount)
	err := scopeMap.Update(&scopeKeys[scopeInsertions], &scopeValue, ebpf.UpdateAny)
	require.Error(t, err, "non-LRU task-scope map should reject an entry at capacity")
	var state BpfJavaDynamicTaskScopeState
	require.ErrorIs(t, scopeMap.Lookup(&scopeKeys[scopeInsertions], &state), ebpf.ErrKeyNotExist)
	t.Logf("java_dynamic_task_scopes: max_entries=%d initial=%d occupancy=%d updates=%d elapsed=%s; extra insert rejected: %v", scopeLimit, scopeInitial, scopeCount, scopeInsertions, scopeElapsed, err)

	backupMap := tracer.bpfObjects.JavaDynamicTaskBackups
	backupLimit := int(backupMap.MaxEntries())
	backupInitial := countJavaDynamicMapEntries[BpfJavaDynamicTaskScopeKey, BpfJavaDynamicTaskScopeFrame](t, backupMap)
	require.LessOrEqual(t, backupInitial, backupLimit)
	backupInsertions := backupLimit - backupInitial
	backupKeys := make([]BpfJavaDynamicTaskScopeKey, backupInsertions+1)
	for i := range backupKeys {
		backupKeys[i] = BpfJavaDynamicTaskScopeKey{PidTgid: 0xe000000000000000 + uint64(i), Depth: 1}
	}
	t.Cleanup(func() {
		for _, key := range backupKeys {
			_ = backupMap.Delete(&key)
		}
	})
	frame := BpfJavaDynamicTaskScopeFrame{Captured: 1, Previous: contextValue}
	started = time.Now()
	for i, key := range backupKeys[:backupInsertions] {
		require.NoError(t, backupMap.Update(&key, &frame, ebpf.UpdateAny), "task backup entry %d", i)
	}
	backupElapsed := time.Since(started)
	backupCount := countJavaDynamicMapEntries[BpfJavaDynamicTaskScopeKey, BpfJavaDynamicTaskScopeFrame](t, backupMap)
	require.Equal(t, backupLimit, backupCount)
	err = backupMap.Update(&backupKeys[backupInsertions], &frame, ebpf.UpdateAny)
	require.Error(t, err, "non-LRU task-backup map should reject an entry at capacity")
	require.ErrorIs(t, backupMap.Lookup(&backupKeys[backupInsertions], &frame), ebpf.ErrKeyNotExist)
	t.Logf("java_dynamic_task_backups: max_entries=%d initial=%d occupancy=%d updates=%d elapsed=%s; extra insert rejected: %v", backupLimit, backupInitial, backupCount, backupInsertions, backupElapsed, err)

	spanBytes := uint64(spanLimit) * uint64(unsafe.Sizeof(BpfTraceKeyT{}))
	spanBytes += uint64(spanLimit) * uint64(unsafe.Sizeof(BpfJavaDynamicContext{}))
	taskBytes := uint64(taskLimit) * uint64(unsafe.Sizeof(BpfJavaDynamicTaskKey{}))
	taskBytes += uint64(taskLimit) * uint64(unsafe.Sizeof(BpfJavaDynamicContext{}))
	scopeBytes := uint64(scopeLimit) * uint64(unsafe.Sizeof(uint64(0)))
	scopeBytes += uint64(scopeLimit) * uint64(unsafe.Sizeof(BpfJavaDynamicTaskScopeState{}))
	backupBytes := uint64(backupLimit) * uint64(unsafe.Sizeof(BpfJavaDynamicTaskScopeKey{}))
	backupBytes += uint64(backupLimit) * uint64(unsafe.Sizeof(BpfJavaDynamicTaskScopeFrame{}))
	maxPayload := spanBytes + taskBytes + scopeBytes + backupBytes
	t.Logf("dynamic map fixed key/value payload at max_entries: spans=%d B task_contexts=%d B task_scopes=%d B task_backups=%d B total=%d B (%.3f MiB; excludes kernel hash/LRU metadata, allocator rounding, and other OBI maps)", spanBytes, taskBytes, scopeBytes, backupBytes, maxPayload, float64(maxPayload)/(1024*1024))
}

func countJavaDynamicMapEntries[K, V any](t *testing.T, bpfMap *ebpf.Map) int {
	t.Helper()
	iterator := bpfMap.Iterate()
	var key K
	var value V
	count := 0
	for iterator.Next(&key, &value) {
		count++
	}
	require.NoError(t, iterator.Err())
	return count
}

func countPresentJavaDynamicMapEntries[K, V any](t *testing.T, bpfMap *ebpf.Map, keys []K) int {
	t.Helper()
	var value V
	count := 0
	for _, key := range keys {
		err := bpfMap.Lookup(&key, &value)
		if err == nil {
			count++
		} else {
			require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
		}
	}
	return count
}

func scanJavaInt(t *testing.T, scanner *bufio.Scanner) string {
	t.Helper()
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := strconv.Atoi(line); err == nil {
			return line
		}
	}
	require.NoError(t, scanner.Err())
	t.Fatal("Java process exited without printing the expected integer")
	return ""
}

// sendJavaCommandExpectInt makes the fixture's command/reply handshake explicit
// at each call site without hiding the command ordering from the test.
func sendJavaCommandExpectInt(t *testing.T, input io.Writer, scanner *bufio.Scanner, command, want, message string) {
	t.Helper()
	_, err := fmt.Fprintln(input, command)
	require.NoError(t, err)
	require.Equal(t, want, scanJavaInt(t, scanner), message)
}

// requireSpanParentChain asserts that each span continues the trace and is a
// child of the preceding span. The first parent is supplied separately (for
// example, the automatic server span).
func requireSpanParentChain(t *testing.T, traceID trace.TraceID, parent trace.SpanID, spans ...request.Span) {
	t.Helper()
	for _, span := range spans {
		require.Equalf(t, traceID, span.TraceID, "span %q should continue the expected trace", span.Method)
		require.Equalf(t, parent, span.ParentSpanID, "span %q should be a child of the preceding span", span.Method)
		parent = span.SpanID
	}
}

func scanJavaPrefix(t *testing.T, scanner *bufio.Scanner, prefix string) string {
	t.Helper()
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	require.NoError(t, scanner.Err())
	t.Fatalf("Java process exited without printing a line prefixed with %q", prefix)
	return ""
}

const javaDynamicTargetSource = `
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
public class DynamicTarget {
 private static int port;
 private static final ExecutorService executor = Executors.newSingleThreadExecutor();
 private static final ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1);
 static { scheduler.prestartCoreThread(); }
 private static final CountDownLatch release = new CountDownLatch(1);
 private static final CountDownLatch scheduledRelease = new CountDownLatch(1);
 private static final CountDownLatch scheduledRunnableRelease = new CountDownLatch(1);
 private static final CountDownLatch forkJoinRelease = new CountDownLatch(1);
 private static final CountDownLatch forkJoinSubmitRelease = new CountDownLatch(1);
 private static Future<Integer> pending;
 private static ScheduledFuture<Integer> pendingScheduled;
 private static ScheduledFuture<?> pendingScheduledRunnable;
 private static ScheduledFuture<Integer> pendingCancelledCallable;
 private static volatile int scheduledRunnableResult;
 private static volatile int scheduledExceptionRecoveryResult;
 private static RejectedTask rejectedTask;
 private static final Executor rejectingExecutor = new RejectingExecutor();
 private static ForkJoinTask<Integer> pendingForkJoin;
 private static final ForkJoinPool forkJoinPool = new ForkJoinPool(1);
 private static final ExecutorService nestedExecutor = Executors.newFixedThreadPool(2);
 private static Future<Integer> pendingNested;
 public static int outer(int x, String text) throws Exception {
  pending = executor.submit(() -> { release.await(); return inner(x); });
  return x;
 }
 public static int inner(int x) throws Exception {
  request();
  return x + 1;
 }
 public static int outerScheduled(int x) {
  pendingScheduled = scheduler.schedule(() -> { scheduledRelease.await(); return innerScheduled(x); }, 0, TimeUnit.MILLISECONDS);
  return x;
 }
 public static int innerScheduled(int x) throws Exception {
  request();
  return x + 1;
 }
 public static int outerScheduledRunnable(int x) {
  pendingScheduledRunnable = scheduler.schedule(new Runnable() {
   @Override public void run() {
    try { scheduledRunnableRelease.await(); scheduledRunnableResult = innerScheduledRunnable(x); }
    catch (Exception error) { throw new RuntimeException(error); }
   }
  }, 0, TimeUnit.MILLISECONDS);
  return x;
 }
 public static int innerScheduledRunnable(int x) throws Exception {
  request();
  return x + 1;
 }
 public static int outerScheduledException(int x) throws Exception {
  try {
   scheduler.schedule((Callable<Integer>) () -> { throw new IllegalStateException("expected scheduled-task failure"); }, 0, TimeUnit.MILLISECONDS).get();
   throw new AssertionError("scheduled task should fail");
  } catch (ExecutionException expected) {
   if (!(expected.getCause() instanceof IllegalStateException)) throw expected;
  }
  scheduler.schedule(new Runnable() {
   @Override public void run() {
    try { scheduledExceptionRecoveryResult = innerScheduledExceptionRecovery(x); }
    catch (Exception error) { throw new RuntimeException(error); }
   }
  }, 0, TimeUnit.MILLISECONDS).get();
  return x;
 }
 public static int innerScheduledExceptionRecovery(int x) throws Exception {
  request();
  return x + 1;
 }
 public static int outerCancelledTask(int x) {
  pendingCancelledCallable = scheduler.schedule(() -> { throw new AssertionError("cancelled task must not run"); }, 1, TimeUnit.HOURS);
  return x;
 }
 public static int innerCancelledTask(int x) throws Exception { request(); return x + 1; }
 public static int outerRejectedTask(int x) {
  rejectedTask = new RejectedTask(x);
  try { rejectingExecutor.execute(rejectedTask); throw new AssertionError("task should be rejected"); }
  catch (RejectedExecutionException expected) {}
  return x;
 }
 public static int innerRejectedTask(int x) { return x + 1; }
 private static final class RejectedTask implements Runnable {
  private final int value;
  private RejectedTask(int value) { this.value = value; }
  @Override public void run() { innerRejectedTask(value); }
 }
 private static final class RejectingExecutor implements Executor {
  @Override public void execute(Runnable task) { throw new RejectedExecutionException("expected rejection"); }
 }
 public static int outerScheduledRunnableRace(int x) throws Exception {
  for (int i = 0; i < 64; i++) {
   scheduler.schedule(new Runnable() {
    @Override public void run() {
     try { innerScheduledRunnableRace(x); }
     catch (Exception error) { throw new RuntimeException(error); }
    }
   }, 0, TimeUnit.MILLISECONDS).get();
  }
  return x;
 }
 public static int innerScheduledRunnableRace(int x) throws Exception {
  request();
  return x + 1;
 }
 public static int outerForkJoin(int x) {
  pendingForkJoin = ForkJoinTask.adapt((Callable<Integer>) () -> { forkJoinRelease.await(); return innerForkJoin(x); });
  pendingForkJoin.fork();
  return x;
 }
 public static int innerForkJoin(int x) throws Exception {
  request();
  return x + 1;
 }
 public static int outerForkJoinSubmit(int x) {
  pendingForkJoin = ForkJoinTask.adapt((Callable<Integer>) () -> { forkJoinSubmitRelease.await(); return innerForkJoinSubmit(x); });
  forkJoinPool.submit(pendingForkJoin);
  return x;
 }
 public static int innerForkJoinSubmit(int x) throws Exception {
  request();
  return x + 1;
 }
 public static int outerNestedTask(int x) {
  pendingNested = nestedExecutor.submit(() -> { innerNestedTask(x); return x + 1; });
  return x;
 }
 public static int innerNestedTask(int x) throws Exception {
  return nestedExecutor.submit(() -> innerNestedChild(x)).get();
 }
 public static int innerNestedChild(int x) throws Exception { request(); return x + 1; }
 public static int outerVirtualThread(int x) throws Exception { request(); return x + 1; }
 private static volatile long benchSink;
 public static int benchWork(int x) { benchSink += x; return x + 1; }
 private static void request() throws Exception {
  try (Socket socket = new Socket("127.0.0.1", port)) {
   socket.getOutputStream().write("GET /nested HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
   while (socket.getInputStream().read() != -1) {}
  }
 }
 public static void main(String[] args) throws Exception {
  port = Integer.parseInt(args[0]);
  Class<?> nativeLib = Class.forName("io.opentelemetry.obi.java.Agent$NativeLib", true, null);
  System.out.println(nativeLib.getMethod("gettid").invoke(null));
  BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
  String line;
  while ((line = input.readLine()) != null) {
   if (line.equals("CALL")) System.out.println(outer(42, "hello"));
   else if (line.equals("RELEASE")) { release.countDown(); System.out.println(pending.get()); }
   else if (line.equals("CALL_SCHEDULED")) System.out.println(outerScheduled(42));
   else if (line.equals("RELEASE_SCHEDULED")) { scheduledRelease.countDown(); System.out.println(pendingScheduled.get()); }
   else if (line.equals("CALL_SCHEDULED_RUNNABLE")) System.out.println(outerScheduledRunnable(42));
   else if (line.equals("RELEASE_SCHEDULED_RUNNABLE")) { scheduledRunnableRelease.countDown(); pendingScheduledRunnable.get(); System.out.println(scheduledRunnableResult); }
   else if (line.equals("CALL_SCHEDULED_EXCEPTION")) System.out.println(outerScheduledException(42));
   else if (line.equals("CALL_SCHEDULED_CANCELLED")) System.out.println(outerCancelledTask(42));
   else if (line.equals("CANCEL_SCHEDULED")) { if (!pendingCancelledCallable.cancel(false)) throw new AssertionError("scheduled task cancellation failed"); System.out.println(42); }
   else if (line.equals("RUN_CANCELLED_TASK")) System.out.println(scheduler.schedule(() -> innerCancelledTask(42), 0, TimeUnit.MILLISECONDS).get());
   else if (line.equals("CALL_REJECTED_TASK")) System.out.println(outerRejectedTask(42));
   else if (line.equals("RUN_REJECTED_TASK")) { Thread worker = new Thread(rejectedTask); worker.start(); worker.join(); System.out.println(42); }
   else if (line.equals("CALL_SCHEDULED_RUNNABLE_RACE")) System.out.println(outerScheduledRunnableRace(42));
   else if (line.equals("CALL_FORKJOIN")) System.out.println(outerForkJoin(42));
   else if (line.equals("RELEASE_FORKJOIN")) { forkJoinRelease.countDown(); System.out.println(pendingForkJoin.join()); }
   else if (line.equals("CALL_FORKJOIN_SUBMIT")) System.out.println(outerForkJoinSubmit(42));
   else if (line.equals("RELEASE_FORKJOIN_SUBMIT")) { forkJoinSubmitRelease.countDown(); System.out.println(pendingForkJoin.join()); }
   else if (line.equals("CALL_NESTED_TASK")) System.out.println(outerNestedTask(42));
   else if (line.equals("CALL_VIRTUAL")) {
    FutureTask<Integer> task = new FutureTask<>(() -> outerVirtualThread(42));
    Thread.startVirtualThread(task);
    System.out.println(task.get());
   }
   else if (line.startsWith("BENCH ")) {
    int iterations = Integer.parseInt(line.substring(6));
    for (int i = 0; i < 10000; i++) benchWork(i);
    long started = System.nanoTime();
    for (int i = 0; i < iterations; i++) benchWork(i);
    System.out.println("BENCH_RESULT " + (System.nanoTime() - started) + " " + benchSink);
   }
   else if (line.equals("RELEASE_NESTED_TASK")) System.out.println(pendingNested.get());
  }
 }
}
`
