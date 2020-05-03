// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// TargetAttachedToTarget (experimental) Issued when attached to target because of auto-attach or `attachToTarget` command.
type TargetAttachedToTarget struct {
	// SessionID Identifier assigned to the session used to send/receive messages.
	SessionID *TargetSessionID `json:"sessionId"`

	// TargetInfo ...
	TargetInfo *TargetTargetInfo `json:"targetInfo"`

	// WaitingForDebugger ...
	WaitingForDebugger bool `json:"waitingForDebugger"`
}

// MethodName interface
func (evt TargetAttachedToTarget) MethodName() string {
	return "Target.attachedToTarget"
}

// Load json
func (evt TargetAttachedToTarget) Load(b []byte) *TargetAttachedToTarget {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// TargetDetachedFromTarget (experimental) Issued when detached from target for any reason (including `detachFromTarget` command). Can be
// issued multiple times per target if multiple sessions have been attached to it.
type TargetDetachedFromTarget struct {
	// SessionID Detached session identifier.
	SessionID *TargetSessionID `json:"sessionId"`

	// TargetID (deprecated) Deprecated.
	TargetID *TargetTargetID `json:"targetId,omitempty"`
}

// MethodName interface
func (evt TargetDetachedFromTarget) MethodName() string {
	return "Target.detachedFromTarget"
}

// Load json
func (evt TargetDetachedFromTarget) Load(b []byte) *TargetDetachedFromTarget {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// TargetReceivedMessageFromTarget Notifies about a new protocol message received from the session (as reported in
// `attachedToTarget` event).
type TargetReceivedMessageFromTarget struct {
	// SessionID Identifier of a session which sends a message.
	SessionID *TargetSessionID `json:"sessionId"`

	// Message ...
	Message string `json:"message"`

	// TargetID (deprecated) Deprecated.
	TargetID *TargetTargetID `json:"targetId,omitempty"`
}

// MethodName interface
func (evt TargetReceivedMessageFromTarget) MethodName() string {
	return "Target.receivedMessageFromTarget"
}

// Load json
func (evt TargetReceivedMessageFromTarget) Load(b []byte) *TargetReceivedMessageFromTarget {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// TargetTargetCreated Issued when a possible inspection target is created.
type TargetTargetCreated struct {
	// TargetInfo ...
	TargetInfo *TargetTargetInfo `json:"targetInfo"`
}

// MethodName interface
func (evt TargetTargetCreated) MethodName() string {
	return "Target.targetCreated"
}

// Load json
func (evt TargetTargetCreated) Load(b []byte) *TargetTargetCreated {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// TargetTargetDestroyed Issued when a target is destroyed.
type TargetTargetDestroyed struct {
	// TargetID ...
	TargetID *TargetTargetID `json:"targetId"`
}

// MethodName interface
func (evt TargetTargetDestroyed) MethodName() string {
	return "Target.targetDestroyed"
}

// Load json
func (evt TargetTargetDestroyed) Load(b []byte) *TargetTargetDestroyed {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// TargetTargetCrashed Issued when a target has crashed.
type TargetTargetCrashed struct {
	// TargetID ...
	TargetID *TargetTargetID `json:"targetId"`

	// Status Termination status type.
	Status string `json:"status"`

	// ErrorCode Termination error code.
	ErrorCode int64 `json:"errorCode"`
}

// MethodName interface
func (evt TargetTargetCrashed) MethodName() string {
	return "Target.targetCrashed"
}

// Load json
func (evt TargetTargetCrashed) Load(b []byte) *TargetTargetCrashed {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// TargetTargetInfoChanged Issued when some information about a target has changed. This only happens between
// `targetCreated` and `targetDestroyed`.
type TargetTargetInfoChanged struct {
	// TargetInfo ...
	TargetInfo *TargetTargetInfo `json:"targetInfo"`
}

// MethodName interface
func (evt TargetTargetInfoChanged) MethodName() string {
	return "Target.targetInfoChanged"
}

// Load json
func (evt TargetTargetInfoChanged) Load(b []byte) *TargetTargetInfoChanged {
	E(json.Unmarshal(b, &evt))
	return &evt
}
