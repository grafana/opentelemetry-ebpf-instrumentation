// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"

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

func main() {
	provider := sdktrace.NewTracerProvider()
	tracer := provider.Tracer("dynamic-probe-test")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		text, number := outer("hello", 7)
		fmt.Fprintf(w, "%s %d", text, number)
	}))
	defer server.Close()
	fmt.Println("READY")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "EXIT" {
			return
		}
		if scanner.Text() == "HTTP" {
			response, err := http.Get(server.URL)
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
		text, number := outer("hello", 7)
		fmt.Printf("RESULT=%s %s %s %d\n", parent.SpanContext().TraceID(), parent.SpanContext().SpanID(), text, number)
		parent.End()
	}
}
