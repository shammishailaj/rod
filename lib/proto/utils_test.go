package proto_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ysmood/kit"
	"github.com/ysmood/rod/lib/proto"
)

type Client struct {
	sessionID  string
	methodName string
	params     interface{}
	err        error
	ret        interface{}
}

var _ proto.Client = &Client{}

func (c *Client) Call(ctx context.Context, sessionID, methodName string, params interface{}) (res []byte, err error) {
	c.sessionID = sessionID
	c.methodName = methodName
	c.params = params
	return kit.MustToJSONBytes(c.ret), c.err
}

func TestE(t *testing.T) {
	assert.Panics(t, func() {
		proto.E(errors.New("err"))
	})
}
