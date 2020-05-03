// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// DOMAttributeModified Fired when `Element`'s attribute is modified.
type DOMAttributeModified struct {
	// NodeID Id of the node that has changed.
	NodeID *DOMNodeID `json:"nodeId"`

	// Name Attribute name.
	Name string `json:"name"`

	// Value Attribute value.
	Value string `json:"value"`
}

// MethodName interface
func (evt DOMAttributeModified) MethodName() string {
	return "DOM.attributeModified"
}

// Load json
func (evt DOMAttributeModified) Load(b []byte) *DOMAttributeModified {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMAttributeRemoved Fired when `Element`'s attribute is removed.
type DOMAttributeRemoved struct {
	// NodeID Id of the node that has changed.
	NodeID *DOMNodeID `json:"nodeId"`

	// Name A ttribute name.
	Name string `json:"name"`
}

// MethodName interface
func (evt DOMAttributeRemoved) MethodName() string {
	return "DOM.attributeRemoved"
}

// Load json
func (evt DOMAttributeRemoved) Load(b []byte) *DOMAttributeRemoved {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMCharacterDataModified Mirrors `DOMCharacterDataModified` event.
type DOMCharacterDataModified struct {
	// NodeID Id of the node that has changed.
	NodeID *DOMNodeID `json:"nodeId"`

	// CharacterData New text value.
	CharacterData string `json:"characterData"`
}

// MethodName interface
func (evt DOMCharacterDataModified) MethodName() string {
	return "DOM.characterDataModified"
}

// Load json
func (evt DOMCharacterDataModified) Load(b []byte) *DOMCharacterDataModified {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMChildNodeCountUpdated Fired when `Container`'s child node count has changed.
type DOMChildNodeCountUpdated struct {
	// NodeID Id of the node that has changed.
	NodeID *DOMNodeID `json:"nodeId"`

	// ChildNodeCount New node count.
	ChildNodeCount int64 `json:"childNodeCount"`
}

// MethodName interface
func (evt DOMChildNodeCountUpdated) MethodName() string {
	return "DOM.childNodeCountUpdated"
}

// Load json
func (evt DOMChildNodeCountUpdated) Load(b []byte) *DOMChildNodeCountUpdated {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMChildNodeInserted Mirrors `DOMNodeInserted` event.
type DOMChildNodeInserted struct {
	// ParentNodeID Id of the node that has changed.
	ParentNodeID *DOMNodeID `json:"parentNodeId"`

	// PreviousNodeID If of the previous siblint.
	PreviousNodeID *DOMNodeID `json:"previousNodeId"`

	// Node Inserted node data.
	Node *DOMNode `json:"node"`
}

// MethodName interface
func (evt DOMChildNodeInserted) MethodName() string {
	return "DOM.childNodeInserted"
}

// Load json
func (evt DOMChildNodeInserted) Load(b []byte) *DOMChildNodeInserted {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMChildNodeRemoved Mirrors `DOMNodeRemoved` event.
type DOMChildNodeRemoved struct {
	// ParentNodeID Parent id.
	ParentNodeID *DOMNodeID `json:"parentNodeId"`

	// NodeID Id of the node that has been removed.
	NodeID *DOMNodeID `json:"nodeId"`
}

// MethodName interface
func (evt DOMChildNodeRemoved) MethodName() string {
	return "DOM.childNodeRemoved"
}

// Load json
func (evt DOMChildNodeRemoved) Load(b []byte) *DOMChildNodeRemoved {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMDistributedNodesUpdated (experimental) Called when distrubution is changed.
type DOMDistributedNodesUpdated struct {
	// InsertionPointID Insertion point where distrubuted nodes were updated.
	InsertionPointID *DOMNodeID `json:"insertionPointId"`

	// DistributedNodes Distributed nodes for given insertion point.
	DistributedNodes []*DOMBackendNode `json:"distributedNodes"`
}

// MethodName interface
func (evt DOMDistributedNodesUpdated) MethodName() string {
	return "DOM.distributedNodesUpdated"
}

// Load json
func (evt DOMDistributedNodesUpdated) Load(b []byte) *DOMDistributedNodesUpdated {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMDocumentUpdated Fired when `Document` has been totally updated. Node ids are no longer valid.
type DOMDocumentUpdated struct {
}

// MethodName interface
func (evt DOMDocumentUpdated) MethodName() string {
	return "DOM.documentUpdated"
}

// Load json
func (evt DOMDocumentUpdated) Load(b []byte) *DOMDocumentUpdated {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMInlineStyleInvalidated (experimental) Fired when `Element`'s inline style is modified via a CSS property modification.
type DOMInlineStyleInvalidated struct {
	// NodeIds Ids of the nodes for which the inline styles have been invalidated.
	NodeIds []*DOMNodeID `json:"nodeIds"`
}

// MethodName interface
func (evt DOMInlineStyleInvalidated) MethodName() string {
	return "DOM.inlineStyleInvalidated"
}

// Load json
func (evt DOMInlineStyleInvalidated) Load(b []byte) *DOMInlineStyleInvalidated {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMPseudoElementAdded (experimental) Called when a pseudo element is added to an element.
type DOMPseudoElementAdded struct {
	// ParentID Pseudo element's parent element id.
	ParentID *DOMNodeID `json:"parentId"`

	// PseudoElement The added pseudo element.
	PseudoElement *DOMNode `json:"pseudoElement"`
}

// MethodName interface
func (evt DOMPseudoElementAdded) MethodName() string {
	return "DOM.pseudoElementAdded"
}

// Load json
func (evt DOMPseudoElementAdded) Load(b []byte) *DOMPseudoElementAdded {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMPseudoElementRemoved (experimental) Called when a pseudo element is removed from an element.
type DOMPseudoElementRemoved struct {
	// ParentID Pseudo element's parent element id.
	ParentID *DOMNodeID `json:"parentId"`

	// PseudoElementID The removed pseudo element id.
	PseudoElementID *DOMNodeID `json:"pseudoElementId"`
}

// MethodName interface
func (evt DOMPseudoElementRemoved) MethodName() string {
	return "DOM.pseudoElementRemoved"
}

// Load json
func (evt DOMPseudoElementRemoved) Load(b []byte) *DOMPseudoElementRemoved {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMSetChildNodes Fired when backend wants to provide client with the missing DOM structure. This happens upon
// most of the calls requesting node ids.
type DOMSetChildNodes struct {
	// ParentID Parent node id to populate with children.
	ParentID *DOMNodeID `json:"parentId"`

	// Nodes Child nodes array.
	Nodes []*DOMNode `json:"nodes"`
}

// MethodName interface
func (evt DOMSetChildNodes) MethodName() string {
	return "DOM.setChildNodes"
}

// Load json
func (evt DOMSetChildNodes) Load(b []byte) *DOMSetChildNodes {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMShadowRootPopped (experimental) Called when shadow root is popped from the element.
type DOMShadowRootPopped struct {
	// HostID Host element id.
	HostID *DOMNodeID `json:"hostId"`

	// RootID Shadow root id.
	RootID *DOMNodeID `json:"rootId"`
}

// MethodName interface
func (evt DOMShadowRootPopped) MethodName() string {
	return "DOM.shadowRootPopped"
}

// Load json
func (evt DOMShadowRootPopped) Load(b []byte) *DOMShadowRootPopped {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// DOMShadowRootPushed (experimental) Called when shadow root is pushed into the element.
type DOMShadowRootPushed struct {
	// HostID Host element id.
	HostID *DOMNodeID `json:"hostId"`

	// Root Shadow root.
	Root *DOMNode `json:"root"`
}

// MethodName interface
func (evt DOMShadowRootPushed) MethodName() string {
	return "DOM.shadowRootPushed"
}

// Load json
func (evt DOMShadowRootPushed) Load(b []byte) *DOMShadowRootPushed {
	E(json.Unmarshal(b, &evt))
	return &evt
}