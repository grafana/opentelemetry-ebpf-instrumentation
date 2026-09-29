// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agentctl // import "go.opentelemetry.io/obi/pkg/internal/agentctl"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/netns"
)

const (
	List byte = iota + 1
	Attach
	Detach
	Claim
)

// Exchange implements the private agent protocol used by Java and Node.js.
func Exchange(ctx context.Context, pid app.PID, port uint32, token, session [16]byte, operation byte, method string, cookie uint64) ([]string, error) {
	if port == 0 || port > 65535 {
		return nil, errors.New("dynamic agent is not ready")
	}
	var connection net.Conn
	err := netns.WithNetNS(int(pid), func() error {
		var err error
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		return err
	})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	var request bytes.Buffer
	request.Write(token[:])
	request.Write(session[:])
	request.WriteByte(operation)
	if operation == Attach {
		_ = binary.Write(&request, binary.BigEndian, uint32(len(method)))
		request.WriteString(method)
	}
	if operation == Attach || operation == Detach {
		_ = binary.Write(&request, binary.BigEndian, cookie)
	}
	if _, err := io.Copy(connection, &request); err != nil {
		return nil, err
	}
	var status [1]byte
	if _, err := io.ReadFull(connection, status[:]); err != nil {
		return nil, err
	}
	if status[0] != 0 {
		message, err := ReadString(connection)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(message)
	}
	if operation != List {
		return nil, nil
	}
	var count uint32
	if err := binary.Read(connection, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count > 100000 {
		return nil, fmt.Errorf("agent symbol list exceeds limit: %d", count)
	}
	symbols := make([]string, 0, count)
	size := 0
	for range count {
		symbol, err := ReadString(connection)
		if err != nil {
			return nil, err
		}
		size += len(symbol)
		if size > 64<<20 {
			return nil, errors.New("agent symbol catalog exceeds byte limit")
		}
		symbols = append(symbols, symbol)
	}
	slices.Sort(symbols)
	return symbols, nil
}

func ReadString(reader io.Reader) (string, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return "", err
	}
	if size > 65536 {
		return "", errors.New("agent control string exceeds limit")
	}
	text := make([]byte, size)
	_, err := io.ReadFull(reader, text)
	return string(text), err
}
