// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// BackgroundServiceRecordingStateChanged Called when the recording state for the service has been updated.
type BackgroundServiceRecordingStateChanged struct {
	// IsRecording ...
	IsRecording bool `json:"isRecording"`

	// Service ...
	Service *BackgroundServiceServiceName `json:"service"`
}

// MethodName interface
func (evt BackgroundServiceRecordingStateChanged) MethodName() string {
	return "BackgroundService.recordingStateChanged"
}

// Load json
func (evt BackgroundServiceRecordingStateChanged) Load(b []byte) *BackgroundServiceRecordingStateChanged {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// BackgroundServiceBackgroundServiceEventReceived Called with all existing backgroundServiceEvents when enabled, and all new
// events afterwards if enabled and recording.
type BackgroundServiceBackgroundServiceEventReceived struct {
	// BackgroundServiceEvent ...
	BackgroundServiceEvent *BackgroundServiceBackgroundServiceEvent `json:"backgroundServiceEvent"`
}

// MethodName interface
func (evt BackgroundServiceBackgroundServiceEventReceived) MethodName() string {
	return "BackgroundService.backgroundServiceEventReceived"
}

// Load json
func (evt BackgroundServiceBackgroundServiceEventReceived) Load(b []byte) *BackgroundServiceBackgroundServiceEventReceived {
	E(json.Unmarshal(b, &evt))
	return &evt
}