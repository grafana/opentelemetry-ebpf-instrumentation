// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

//go:noinline
func inner(text string, number int) (string, int) {
	runtime.Gosched()
	return text + "!", number + 1
}

//go:noinline
func outer(text string, number int) (string, int) {
	var stack [64 << 10]byte
	stack[0] = byte(number)
	text, number = inner(text, number)
	runtime.KeepAlive(&stack)
	return text, number
}

//go:noinline
func outerAsync(text string, number int) (string, int) {
	done := make(chan struct{})
	go func() {
		text, number = inner(text, number)
		close(done)
	}()
	<-done
	return text, number
}

type delayedResult struct {
	text   string
	number int
}

//go:noinline
func outerDetached(text string, number int, start <-chan struct{}, done chan<- delayedResult) {
	go func() {
		<-start
		text, number := inner(text, number)
		done <- delayedResult{text: text, number: number}
	}()
}

func callDetached(text string, number int) (string, int) {
	start := make(chan struct{})
	done := make(chan delayedResult)
	outerDetached(text, number, start, done)
	close(start)
	result := <-done
	return result.text, result.number
}

//go:noinline
func echo(w http.ResponseWriter, url string) {
	echoRequest(url, "/echoBack")
	if w != nil {
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
	}
}

func echoRequest(url, path string) {
	response, err := http.Get(url + path)
	if err != nil {
		panic(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

//go:noinline
func echoAsync(w http.ResponseWriter, url string) {
	done := make(chan struct{})
	go func() {
		echo(w, url)
		echoRequest(url, "/afterEcho")
		close(done)
	}()
	<-done
}

//go:noinline
func HTTPHandler(w http.ResponseWriter, url string) {
	echoAsync(w, url)
	echoRequest(url, "/afterAsync")
	fmt.Fprint(w, "echo done")
}

//go:noinline
func blockedEcho(url string, release <-chan struct{}) {
	fmt.Println("BLOCKED")
	<-release
	echoRequest(url, "/detachedProbe")
}

type exportedSpan struct {
	Name, Trace, ID, Parent string
}

type sdkRecorder struct {
	sync.Mutex
	started, exported []exportedSpan
}

func sdkSpan(span sdktrace.ReadOnlySpan) exportedSpan {
	return exportedSpan{span.Name(), span.SpanContext().TraceID().String(), span.SpanContext().SpanID().String(), span.Parent().SpanID().String()}
}

func (r *sdkRecorder) OnStart(_ context.Context, span sdktrace.ReadWriteSpan) {
	r.Lock()
	defer r.Unlock()
	r.started = append(r.started, sdkSpan(span))
}

func (*sdkRecorder) OnEnd(sdktrace.ReadOnlySpan)      {}
func (*sdkRecorder) ForceFlush(context.Context) error { return nil }
func (*sdkRecorder) Shutdown(context.Context) error   { return nil }
func (r *sdkRecorder) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	r.Lock()
	defer r.Unlock()
	for _, span := range spans {
		r.exported = append(r.exported, sdkSpan(span))
	}
	return nil
}

//go:noinline
func sdkInner(ctx context.Context, tracer trace.Tracer) {
	clientCtx, client := tracer.Start(ctx, "sdk.client", trace.WithSpanKind(trace.SpanKindClient))
	_, grandchild := tracer.Start(clientCtx, "sdk.grandchild")
	grandchild.End()
	client.End()
	_, sibling := tracer.Start(ctx, "sdk.sibling")
	sibling.End()
	_, root := tracer.Start(ctx, "sdk.newroot", trace.WithNewRoot())
	root.End()
	parent := trace.SpanContextFromContext(ctx)
	_, unrelated := tracer.Start(trace.ContextWithSpanContext(ctx, parent.WithSpanID(trace.SpanID{1})), "sdk.unrelated")
	unrelated.End()
	_, remote := tracer.Start(trace.ContextWithRemoteSpanContext(ctx, parent), "sdk.remote")
	remote.End()
}

//go:noinline
func sdkOuter(ctx context.Context, tracer trace.Tracer, async bool) {
	if async {
		done := make(chan struct{})
		go func() {
			sdkInner(ctx, tracer)
			close(done)
		}()
		<-done
		return
	}
	sdkInner(ctx, tracer)
}

func main() {
	recorder := &sdkRecorder{}
	options := []sdktrace.TracerProviderOption{sdktrace.WithSyncer(recorder), sdktrace.WithSpanProcessor(recorder), sdktrace.WithResource(resource.NewSchemaless(
		attribute.String("service.name", "otel-remotedice"),
		attribute.String("service.namespace", "manual"),
	))}
	if os.Getenv("OBI_TEST_SDK_UNSAMPLED") == "1" {
		options = append(options, sdktrace.WithSampler(sdktrace.NeverSample()))
	}
	provider := sdktrace.NewTracerProvider(options...)
	tracer := provider.Tracer("dynamic-probe-test")
	downstream := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "echo back")
	}))
	defer downstream.Close()
	server := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/echo" {
			HTTPHandler(w, downstream.URL)
			return
		}
		call := outer
		if request.URL.Path == "/async" {
			call = outerAsync
		} else if request.URL.Path == "/detached" {
			call = callDetached
		}
		text, number := call("hello", 7)
		fmt.Fprintf(w, "%s %d", text, number)
	}))
	defer server.Close()
	fmt.Println("READY=" + server.URL)
	scanner := bufio.NewScanner(os.Stdin)
	release := make(chan struct{})
	released := make(chan struct{})
	for scanner.Scan() {
		if scanner.Text() == "EXIT" {
			return
		}
		if scanner.Text() == "BLOCKED" {
			go func() {
				_, parent := tracer.Start(context.Background(), "sdk.blocked")
				fmt.Printf("BLOCKED_CONTEXT=%s %s\n", parent.SpanContext().TraceID(), parent.SpanContext().SpanID())
				blockedEcho(downstream.URL, release)
				parent.End()
				close(released)
			}()
			continue
		}
		if scanner.Text() == "RELEASE" {
			close(release)
			<-released
			fmt.Println("RELEASED")
			continue
		}
		if strings.HasPrefix(scanner.Text(), "HTTP") {
			url := server.URL
			if scanner.Text() == "HTTP_ASYNC" {
				url += "/async"
			} else if scanner.Text() == "HTTP_DETACHED" {
				url += "/detached"
			}
			response, err := http.Get(url)
			if err != nil {
				panic(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				panic(err)
			}
			fmt.Printf("HTTP_RESULT=%s\n", body)
			continue
		}
		if strings.HasPrefix(scanner.Text(), "SDK_CLIENT") {
			recorder.Lock()
			recorder.started, recorder.exported = nil, nil
			recorder.Unlock()
			ctx, server := tracer.Start(context.Background(), "sdk.server", trace.WithSpanKind(trace.SpanKindServer))
			if scanner.Text() == "SDK_CLIENT_INHERITED" {
				done := make(chan struct{})
				go func() {
					sdkInner(ctx, tracer)
					close(done)
				}()
				<-done
			} else {
				sdkOuter(ctx, tracer, scanner.Text() == "SDK_CLIENT_ASYNC")
			}
			_, after := tracer.Start(ctx, "sdk.after")
			after.End()
			server.End()
			recorder.Lock()
			data, err := json.Marshal(struct{ Started, Exported []exportedSpan }{recorder.started, recorder.exported})
			recorder.Unlock()
			if err != nil {
				panic(err)
			}
			fmt.Printf("SDK_EXPORTED=%s\n", data)
			continue
		}
		_, parent := tracer.Start(context.Background(), "sdk.parent")
		if scanner.Text() == "SDK_ECHO" {
			echoAsync(nil, downstream.URL)
			echoRequest(downstream.URL, "/afterAsync")
			fmt.Printf("SDK_RESULT=%s %s\n", parent.SpanContext().TraceID(), parent.SpanContext().SpanID())
			parent.End()
			continue
		}
		call := outer
		if scanner.Text() == "ASYNC" {
			call = outerAsync
		} else if scanner.Text() == "DETACHED" {
			call = callDetached
		}
		text, number := call("hello", 7)
		fmt.Printf("RESULT=%s %s %s %d\n", parent.SpanContext().TraceID(), parent.SpanContext().SpanID(), text, number)
		parent.End()
	}
}

func newHTTPServer(handler http.Handler) *httptest.Server {
	// Black-box context correlation assumes service ports are below the ephemeral range.
	const firstServicePort, lastServicePort = 18080, 18180
	for port := firstServicePort; port <= lastServicePort; port++ {
		listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			panic(err)
		}
		server := httptest.NewUnstartedServer(handler)
		server.Listener.Close()
		server.Listener = listener
		server.Start()
		return server
	}
	panic("no free HTTP fixture port")
}
