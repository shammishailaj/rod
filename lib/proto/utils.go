package proto

import (
	"context"
)

// Client interface to send the request.
// So that this lib doesn't handle any thing has side effect.
type Client interface {
	Call(ctx context.Context, sessionID, methodName string, params interface{}) (res []byte, err error)
}

// Event interface
type Event interface {
	MethodName() string
}

// Call parameters
type Call struct {
	Context   context.Context
	Client    Client
	SessionID string
}

// E panics err if err not nil
func E(err error) {
	if err != nil {
		panic(err)
	}
}
