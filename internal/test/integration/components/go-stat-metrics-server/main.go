// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	go serveRuntimeMetrics()
	go forceGC()

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("Server listening on :8080.")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	message, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Printf("Received: %s", message)

	conn.Write([]byte("ACK\n"))
}

func serveRuntimeMetrics() {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsGC),
	))

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	if err := http.ListenAndServe(":9090", mux); err != nil {
		fmt.Printf("Runtime metrics endpoint failed: %v\n", err)
	}
}

func forceGC() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		runtime.GC()
	}
}
