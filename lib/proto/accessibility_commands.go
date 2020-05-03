// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// AccessibilityDisable Disables the accessibility domain.
type AccessibilityDisable struct {
}

// AccessibilityDisableResult type
type AccessibilityDisableResult struct {
}

// Call of the command, sessionID is optional.
func (m AccessibilityDisable) Call(c *Call) (*AccessibilityDisableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "AccessibilityDisable", m)
	if err != nil {
		return nil, err
	}

	var res AccessibilityDisableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// AccessibilityEnable Enables the accessibility domain which causes `AXNodeId`s to remain consistent between method calls.
// This turns on accessibility for the page, which can impact performance until accessibility is disabled.
type AccessibilityEnable struct {
}

// AccessibilityEnableResult type
type AccessibilityEnableResult struct {
}

// Call of the command, sessionID is optional.
func (m AccessibilityEnable) Call(c *Call) (*AccessibilityEnableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "AccessibilityEnable", m)
	if err != nil {
		return nil, err
	}

	var res AccessibilityEnableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// AccessibilityGetPartialAXTree (experimental) Fetches the accessibility node and partial accessibility tree for this DOM node, if it exists.
type AccessibilityGetPartialAXTree struct {
	// NodeID Identifier of the node to get the partial accessibility tree for.
	NodeID *DOMNodeID `json:"nodeId,omitempty"`

	// BackendNodeID Identifier of the backend node to get the partial accessibility tree for.
	BackendNodeID *DOMBackendNodeID `json:"backendNodeId,omitempty"`

	// ObjectID JavaScript object id of the node wrapper to get the partial accessibility tree for.
	ObjectID *RuntimeRemoteObjectID `json:"objectId,omitempty"`

	// FetchRelatives Whether to fetch this nodes ancestors, siblings and children. Defaults to true.
	FetchRelatives bool `json:"fetchRelatives,omitempty"`
}

// AccessibilityGetPartialAXTreeResult type
type AccessibilityGetPartialAXTreeResult struct {
	// Nodes The `Accessibility.AXNode` for this DOM node, if it exists, plus its ancestors, siblings and
	// children, if requested.
	Nodes []*AccessibilityAXNode `json:"nodes"`
}

// Call of the command, sessionID is optional.
func (m AccessibilityGetPartialAXTree) Call(c *Call) (*AccessibilityGetPartialAXTreeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "AccessibilityGetPartialAXTree", m)
	if err != nil {
		return nil, err
	}

	var res AccessibilityGetPartialAXTreeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// AccessibilityGetFullAXTree (experimental) Fetches the entire accessibility tree
type AccessibilityGetFullAXTree struct {
}

// AccessibilityGetFullAXTreeResult type
type AccessibilityGetFullAXTreeResult struct {
	// Nodes ...
	Nodes []*AccessibilityAXNode `json:"nodes"`
}

// Call of the command, sessionID is optional.
func (m AccessibilityGetFullAXTree) Call(c *Call) (*AccessibilityGetFullAXTreeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "AccessibilityGetFullAXTree", m)
	if err != nil {
		return nil, err
	}

	var res AccessibilityGetFullAXTreeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}
