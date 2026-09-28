// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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
func echo(url string) {
	response, err := http.Get(url + "/echoBack")
	if err != nil {
		panic(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

//go:noinline
func echoAsync(url string) {
	done := make(chan struct{})
	go func() {
		echo(url)
		close(done)
	}()
	<-done
}

func main() {
	provider := sdktrace.NewTracerProvider()
	tracer := provider.Tracer("dynamic-probe-test")
	downstream := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "echo back")
	}))
	defer downstream.Close()
	server := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/echo" {
			echoAsync(downstream.URL)
			fmt.Fprint(w, "echo done")
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
	for scanner.Scan() {
		if scanner.Text() == "EXIT" {
			return
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
		_, parent := tracer.Start(context.Background(), "sdk.parent")
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
