// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// DOMSnapshotDisable Disables DOM snapshot agent for the given page.
type DOMSnapshotDisable struct {
}

// DOMSnapshotDisableResult type
type DOMSnapshotDisableResult struct {
}

// Call of the command, sessionID is optional.
func (m DOMSnapshotDisable) Call(c *Call) (*DOMSnapshotDisableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DOMSnapshotDisable", m)
	if err != nil {
		return nil, err
	}

	var res DOMSnapshotDisableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DOMSnapshotEnable Enables DOM snapshot agent for the given page.
type DOMSnapshotEnable struct {
}

// DOMSnapshotEnableResult type
type DOMSnapshotEnableResult struct {
}

// Call of the command, sessionID is optional.
func (m DOMSnapshotEnable) Call(c *Call) (*DOMSnapshotEnableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DOMSnapshotEnable", m)
	if err != nil {
		return nil, err
	}

	var res DOMSnapshotEnableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DOMSnapshotGetSnapshot (deprecated) Returns a document snapshot, including the full DOM tree of the root node (including iframes,
// template contents, and imported documents) in a flattened array, as well as layout and
// white-listed computed style information for the nodes. Shadow DOM in the returned DOM tree is
// flattened.
type DOMSnapshotGetSnapshot struct {
	// ComputedStyleWhitelist Whitelist of computed styles to return.
	ComputedStyleWhitelist []string `json:"computedStyleWhitelist"`

	// IncludeEventListeners Whether or not to retrieve details of DOM listeners (default false).
	IncludeEventListeners bool `json:"includeEventListeners,omitempty"`

	// IncludePaintOrder Whether to determine and include the paint order index of LayoutTreeNodes (default false).
	IncludePaintOrder bool `json:"includePaintOrder,omitempty"`

	// IncludeUserAgentShadowTree Whether to include UA shadow tree in the snapshot (default false).
	IncludeUserAgentShadowTree bool `json:"includeUserAgentShadowTree,omitempty"`
}

// DOMSnapshotGetSnapshotResult type
type DOMSnapshotGetSnapshotResult struct {
	// DomNodes The nodes in the DOM tree. The DOMNode at index 0 corresponds to the root document.
	DomNodes []*DOMSnapshotDOMNode `json:"domNodes"`

	// LayoutTreeNodes The nodes in the layout tree.
	LayoutTreeNodes []*DOMSnapshotLayoutTreeNode `json:"layoutTreeNodes"`

	// ComputedStyles Whitelisted ComputedStyle properties for each node in the layout tree.
	ComputedStyles []*DOMSnapshotComputedStyle `json:"computedStyles"`
}

// Call of the command, sessionID is optional.
func (m DOMSnapshotGetSnapshot) Call(c *Call) (*DOMSnapshotGetSnapshotResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DOMSnapshotGetSnapshot", m)
	if err != nil {
		return nil, err
	}

	var res DOMSnapshotGetSnapshotResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DOMSnapshotCaptureSnapshot Returns a document snapshot, including the full DOM tree of the root node (including iframes,
// template contents, and imported documents) in a flattened array, as well as layout and
// white-listed computed style information for the nodes. Shadow DOM in the returned DOM tree is
// flattened.
type DOMSnapshotCaptureSnapshot struct {
	// ComputedStyles Whitelist of computed styles to return.
	ComputedStyles []string `json:"computedStyles"`

	// IncludePaintOrder Whether to include layout object paint orders into the snapshot.
	IncludePaintOrder bool `json:"includePaintOrder,omitempty"`

	// IncludeDOMRects Whether to include DOM rectangles (offsetRects, clientRects, scrollRects) into the snapshot
	IncludeDOMRects bool `json:"includeDOMRects,omitempty"`
}

// DOMSnapshotCaptureSnapshotResult type
type DOMSnapshotCaptureSnapshotResult struct {
	// Documents The nodes in the DOM tree. The DOMNode at index 0 corresponds to the root document.
	Documents []*DOMSnapshotDocumentSnapshot `json:"documents"`

	// Strings Shared string table that all string properties refer to with indexes.
	Strings []string `json:"strings"`
}

// Call of the command, sessionID is optional.
func (m DOMSnapshotCaptureSnapshot) Call(c *Call) (*DOMSnapshotCaptureSnapshotResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DOMSnapshotCaptureSnapshot", m)
	if err != nil {
		return nil, err
	}

	var res DOMSnapshotCaptureSnapshotResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}
