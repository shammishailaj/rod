// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// MediaEnable Enables the Media domain
type MediaEnable struct {
}

// MediaEnableResult type
type MediaEnableResult struct {
}

// Call of the command, sessionID is optional.
func (m MediaEnable) Call(c *Call) (*MediaEnableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MediaEnable", m)
	if err != nil {
		return nil, err
	}

	var res MediaEnableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MediaDisable Disables the Media domain.
type MediaDisable struct {
}

// MediaDisableResult type
type MediaDisableResult struct {
}

// Call of the command, sessionID is optional.
func (m MediaDisable) Call(c *Call) (*MediaDisableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MediaDisable", m)
	if err != nil {
		return nil, err
	}

	var res MediaDisableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}
