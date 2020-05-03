// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// SecurityDisable Disables tracking security state changes.
type SecurityDisable struct {
}

// SecurityDisableResult type
type SecurityDisableResult struct {
}

// Call of the command, sessionID is optional.
func (m SecurityDisable) Call(c *Call) (*SecurityDisableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "SecurityDisable", m)
	if err != nil {
		return nil, err
	}

	var res SecurityDisableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// SecurityEnable Enables tracking security state changes.
type SecurityEnable struct {
}

// SecurityEnableResult type
type SecurityEnableResult struct {
}

// Call of the command, sessionID is optional.
func (m SecurityEnable) Call(c *Call) (*SecurityEnableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "SecurityEnable", m)
	if err != nil {
		return nil, err
	}

	var res SecurityEnableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// SecuritySetIgnoreCertificateErrors (experimental) Enable/disable whether all certificate errors should be ignored.
type SecuritySetIgnoreCertificateErrors struct {
	// Ignore If true, all certificate errors will be ignored.
	Ignore bool `json:"ignore"`
}

// SecuritySetIgnoreCertificateErrorsResult type
type SecuritySetIgnoreCertificateErrorsResult struct {
}

// Call of the command, sessionID is optional.
func (m SecuritySetIgnoreCertificateErrors) Call(c *Call) (*SecuritySetIgnoreCertificateErrorsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "SecuritySetIgnoreCertificateErrors", m)
	if err != nil {
		return nil, err
	}

	var res SecuritySetIgnoreCertificateErrorsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// SecurityHandleCertificateError (deprecated) Handles a certificate error that fired a certificateError event.
type SecurityHandleCertificateError struct {
	// EventID The ID of the event.
	EventID int64 `json:"eventId"`

	// Action The action to take on the certificate error.
	Action *SecurityCertificateErrorAction `json:"action"`
}

// SecurityHandleCertificateErrorResult type
type SecurityHandleCertificateErrorResult struct {
}

// Call of the command, sessionID is optional.
func (m SecurityHandleCertificateError) Call(c *Call) (*SecurityHandleCertificateErrorResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "SecurityHandleCertificateError", m)
	if err != nil {
		return nil, err
	}

	var res SecurityHandleCertificateErrorResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// SecuritySetOverrideCertificateErrors (deprecated) Enable/disable overriding certificate errors. If enabled, all certificate error events need to
// be handled by the DevTools client and should be answered with `handleCertificateError` commands.
type SecuritySetOverrideCertificateErrors struct {
	// Override If true, certificate errors will be overridden.
	Override bool `json:"override"`
}

// SecuritySetOverrideCertificateErrorsResult type
type SecuritySetOverrideCertificateErrorsResult struct {
}

// Call of the command, sessionID is optional.
func (m SecuritySetOverrideCertificateErrors) Call(c *Call) (*SecuritySetOverrideCertificateErrorsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "SecuritySetOverrideCertificateErrors", m)
	if err != nil {
		return nil, err
	}

	var res SecuritySetOverrideCertificateErrorsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}