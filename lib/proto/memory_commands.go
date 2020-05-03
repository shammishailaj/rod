// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// MemoryGetDOMCounters ...
type MemoryGetDOMCounters struct {
}

// MemoryGetDOMCountersResult type
type MemoryGetDOMCountersResult struct {
	// Documents ...
	Documents int64 `json:"documents"`

	// Nodes ...
	Nodes int64 `json:"nodes"`

	// JsEventListeners ...
	JsEventListeners int64 `json:"jsEventListeners"`
}

// Call of the command, sessionID is optional.
func (m MemoryGetDOMCounters) Call(c *Call) (*MemoryGetDOMCountersResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemoryGetDOMCounters", m)
	if err != nil {
		return nil, err
	}

	var res MemoryGetDOMCountersResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemoryPrepareForLeakDetection ...
type MemoryPrepareForLeakDetection struct {
}

// MemoryPrepareForLeakDetectionResult type
type MemoryPrepareForLeakDetectionResult struct {
}

// Call of the command, sessionID is optional.
func (m MemoryPrepareForLeakDetection) Call(c *Call) (*MemoryPrepareForLeakDetectionResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemoryPrepareForLeakDetection", m)
	if err != nil {
		return nil, err
	}

	var res MemoryPrepareForLeakDetectionResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemoryForciblyPurgeJavaScriptMemory Simulate OomIntervention by purging V8 memory.
type MemoryForciblyPurgeJavaScriptMemory struct {
}

// MemoryForciblyPurgeJavaScriptMemoryResult type
type MemoryForciblyPurgeJavaScriptMemoryResult struct {
}

// Call of the command, sessionID is optional.
func (m MemoryForciblyPurgeJavaScriptMemory) Call(c *Call) (*MemoryForciblyPurgeJavaScriptMemoryResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemoryForciblyPurgeJavaScriptMemory", m)
	if err != nil {
		return nil, err
	}

	var res MemoryForciblyPurgeJavaScriptMemoryResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemorySetPressureNotificationsSuppressed Enable/disable suppressing memory pressure notifications in all processes.
type MemorySetPressureNotificationsSuppressed struct {
	// Suppressed If true, memory pressure notifications will be suppressed.
	Suppressed bool `json:"suppressed"`
}

// MemorySetPressureNotificationsSuppressedResult type
type MemorySetPressureNotificationsSuppressedResult struct {
}

// Call of the command, sessionID is optional.
func (m MemorySetPressureNotificationsSuppressed) Call(c *Call) (*MemorySetPressureNotificationsSuppressedResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemorySetPressureNotificationsSuppressed", m)
	if err != nil {
		return nil, err
	}

	var res MemorySetPressureNotificationsSuppressedResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemorySimulatePressureNotification Simulate a memory pressure notification in all processes.
type MemorySimulatePressureNotification struct {
	// Level Memory pressure level of the notification.
	Level *MemoryPressureLevel `json:"level"`
}

// MemorySimulatePressureNotificationResult type
type MemorySimulatePressureNotificationResult struct {
}

// Call of the command, sessionID is optional.
func (m MemorySimulatePressureNotification) Call(c *Call) (*MemorySimulatePressureNotificationResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemorySimulatePressureNotification", m)
	if err != nil {
		return nil, err
	}

	var res MemorySimulatePressureNotificationResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemoryStartSampling Start collecting native memory profile.
type MemoryStartSampling struct {
	// SamplingInterval Average number of bytes between samples.
	SamplingInterval int64 `json:"samplingInterval,omitempty"`

	// SuppressRandomness Do not randomize intervals between samples.
	SuppressRandomness bool `json:"suppressRandomness,omitempty"`
}

// MemoryStartSamplingResult type
type MemoryStartSamplingResult struct {
}

// Call of the command, sessionID is optional.
func (m MemoryStartSampling) Call(c *Call) (*MemoryStartSamplingResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemoryStartSampling", m)
	if err != nil {
		return nil, err
	}

	var res MemoryStartSamplingResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemoryStopSampling Stop collecting native memory profile.
type MemoryStopSampling struct {
}

// MemoryStopSamplingResult type
type MemoryStopSamplingResult struct {
}

// Call of the command, sessionID is optional.
func (m MemoryStopSampling) Call(c *Call) (*MemoryStopSamplingResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemoryStopSampling", m)
	if err != nil {
		return nil, err
	}

	var res MemoryStopSamplingResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemoryGetAllTimeSamplingProfile Retrieve native memory allocations profile
// collected since renderer process startup.
type MemoryGetAllTimeSamplingProfile struct {
}

// MemoryGetAllTimeSamplingProfileResult type
type MemoryGetAllTimeSamplingProfileResult struct {
	// Profile ...
	Profile *MemorySamplingProfile `json:"profile"`
}

// Call of the command, sessionID is optional.
func (m MemoryGetAllTimeSamplingProfile) Call(c *Call) (*MemoryGetAllTimeSamplingProfileResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemoryGetAllTimeSamplingProfile", m)
	if err != nil {
		return nil, err
	}

	var res MemoryGetAllTimeSamplingProfileResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemoryGetBrowserSamplingProfile Retrieve native memory allocations profile
// collected since browser process startup.
type MemoryGetBrowserSamplingProfile struct {
}

// MemoryGetBrowserSamplingProfileResult type
type MemoryGetBrowserSamplingProfileResult struct {
	// Profile ...
	Profile *MemorySamplingProfile `json:"profile"`
}

// Call of the command, sessionID is optional.
func (m MemoryGetBrowserSamplingProfile) Call(c *Call) (*MemoryGetBrowserSamplingProfileResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemoryGetBrowserSamplingProfile", m)
	if err != nil {
		return nil, err
	}

	var res MemoryGetBrowserSamplingProfileResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// MemoryGetSamplingProfile Retrieve native memory allocations profile collected since last
// `startSampling` call.
type MemoryGetSamplingProfile struct {
}

// MemoryGetSamplingProfileResult type
type MemoryGetSamplingProfileResult struct {
	// Profile ...
	Profile *MemorySamplingProfile `json:"profile"`
}

// Call of the command, sessionID is optional.
func (m MemoryGetSamplingProfile) Call(c *Call) (*MemoryGetSamplingProfileResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "MemoryGetSamplingProfile", m)
	if err != nil {
		return nil, err
	}

	var res MemoryGetSamplingProfileResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}