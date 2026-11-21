// Package broker is API Gateway's narrow view of the NATS message broker:
// core request/reply only. The Gateway publishes no stream message.
package broker

import (
	"context"
	"errors"
)

var (
	// ErrNoResponders: no service is subscribed to the request subject.
	ErrNoResponders = errors.New("broker: no responders")
	// ErrTimeout: the owner did not reply within the request timeout.
	ErrTimeout = errors.New("broker: request timed out")
	// ErrUnavailable: the Gateway's own broker connection is down.
	ErrUnavailable = errors.New("broker: connection unavailable")
)

// Request is one core NATS request. Header values are single strings.
type Request struct {
	Subject string
	Header  map[string]string
	Body    []byte
}

// Reply is the owner's answer: its NATS headers (status, ETag, ...) and body.
type Reply struct {
	Header map[string]string
	Body   []byte
}

// Requester sends one request and waits for its one reply. It never retries.
type Requester interface {
	Request(ctx context.Context, request Request) (Reply, error)
}
