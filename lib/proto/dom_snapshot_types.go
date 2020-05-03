// This file is generated by "./lib/proto/cmd/gen"

package proto

// DOMSnapshotDOMNode A Node in the DOM tree.
type DOMSnapshotDOMNode struct {
	// NodeType `Node`'s nodeType.
	NodeType int64 `json:"nodeType"`

	// NodeName `Node`'s nodeName.
	NodeName string `json:"nodeName"`

	// NodeValue `Node`'s nodeValue.
	NodeValue string `json:"nodeValue"`

	// TextValue Only set for textarea elements, contains the text value.
	TextValue string `json:"textValue,omitempty"`

	// InputValue Only set for input elements, contains the input's associated text value.
	InputValue string `json:"inputValue,omitempty"`

	// InputChecked Only set for radio and checkbox input elements, indicates if the element has been checked
	InputChecked bool `json:"inputChecked,omitempty"`

	// OptionSelected Only set for option elements, indicates if the element has been selected
	OptionSelected bool `json:"optionSelected,omitempty"`

	// BackendNodeID `Node`'s id, corresponds to DOM.Node.backendNodeId.
	BackendNodeID *DOMBackendNodeID `json:"backendNodeId"`

	// ChildNodeIndexes The indexes of the node's child nodes in the `domNodes` array returned by `getSnapshot`, if
	// any.
	ChildNodeIndexes []int64 `json:"childNodeIndexes,omitempty"`

	// Attributes Attributes of an `Element` node.
	Attributes []*DOMSnapshotNameValue `json:"attributes,omitempty"`

	// PseudoElementIndexes Indexes of pseudo elements associated with this node in the `domNodes` array returned by
	// `getSnapshot`, if any.
	PseudoElementIndexes []int64 `json:"pseudoElementIndexes,omitempty"`

	// LayoutNodeIndex The index of the node's related layout tree node in the `layoutTreeNodes` array returned by
	// `getSnapshot`, if any.
	LayoutNodeIndex int64 `json:"layoutNodeIndex,omitempty"`

	// DocumentURL Document URL that `Document` or `FrameOwner` node points to.
	DocumentURL string `json:"documentURL,omitempty"`

	// BaseURL Base URL that `Document` or `FrameOwner` node uses for URL completion.
	BaseURL string `json:"baseURL,omitempty"`

	// ContentLanguage Only set for documents, contains the document's content language.
	ContentLanguage string `json:"contentLanguage,omitempty"`

	// DocumentEncoding Only set for documents, contains the document's character set encoding.
	DocumentEncoding string `json:"documentEncoding,omitempty"`

	// PublicID `DocumentType` node's publicId.
	PublicID string `json:"publicId,omitempty"`

	// SystemID `DocumentType` node's systemId.
	SystemID string `json:"systemId,omitempty"`

	// FrameID Frame ID for frame owner elements and also for the document node.
	FrameID *PageFrameID `json:"frameId,omitempty"`

	// ContentDocumentIndex The index of a frame owner element's content document in the `domNodes` array returned by
	// `getSnapshot`, if any.
	ContentDocumentIndex int64 `json:"contentDocumentIndex,omitempty"`

	// PseudoType Type of a pseudo element node.
	PseudoType *DOMPseudoType `json:"pseudoType,omitempty"`

	// ShadowRootType Shadow root type.
	ShadowRootType *DOMShadowRootType `json:"shadowRootType,omitempty"`

	// IsClickable Whether this DOM node responds to mouse clicks. This includes nodes that have had click
	// event listeners attached via JavaScript as well as anchor tags that naturally navigate when
	// clicked.
	IsClickable bool `json:"isClickable,omitempty"`

	// EventListeners Details of the node's event listeners, if any.
	EventListeners []*DOMDebuggerEventListener `json:"eventListeners,omitempty"`

	// CurrentSourceURL The selected url for nodes with a srcset attribute.
	CurrentSourceURL string `json:"currentSourceURL,omitempty"`

	// OriginURL The url of the script (if any) that generates this node.
	OriginURL string `json:"originURL,omitempty"`

	// ScrollOffsetX Scroll offsets, set when this node is a Document.
	ScrollOffsetX float64 `json:"scrollOffsetX,omitempty"`

	// ScrollOffsetY ...
	ScrollOffsetY float64 `json:"scrollOffsetY,omitempty"`
}

// DOMSnapshotInlineTextBox Details of post layout rendered text positions. The exact layout should not be regarded as
// stable and may change between versions.
type DOMSnapshotInlineTextBox struct {
	// BoundingBox The bounding box in document coordinates. Note that scroll offset of the document is ignored.
	BoundingBox *DOMRect `json:"boundingBox"`

	// StartCharacterIndex The starting index in characters, for this post layout textbox substring. Characters that
	// would be represented as a surrogate pair in UTF-16 have length 2.
	StartCharacterIndex int64 `json:"startCharacterIndex"`

	// NumCharacters The number of characters in this post layout textbox substring. Characters that would be
	// represented as a surrogate pair in UTF-16 have length 2.
	NumCharacters int64 `json:"numCharacters"`
}

// DOMSnapshotLayoutTreeNode Details of an element in the DOM tree with a LayoutObject.
type DOMSnapshotLayoutTreeNode struct {
	// DomNodeIndex The index of the related DOM node in the `domNodes` array returned by `getSnapshot`.
	DomNodeIndex int64 `json:"domNodeIndex"`

	// BoundingBox The bounding box in document coordinates. Note that scroll offset of the document is ignored.
	BoundingBox *DOMRect `json:"boundingBox"`

	// LayoutText Contents of the LayoutText, if any.
	LayoutText string `json:"layoutText,omitempty"`

	// InlineTextNodes The post-layout inline text nodes, if any.
	InlineTextNodes []*DOMSnapshotInlineTextBox `json:"inlineTextNodes,omitempty"`

	// StyleIndex Index into the `computedStyles` array returned by `getSnapshot`.
	StyleIndex int64 `json:"styleIndex,omitempty"`

	// PaintOrder Global paint order index, which is determined by the stacking order of the nodes. Nodes
	// that are painted together will have the same index. Only provided if includePaintOrder in
	// getSnapshot was true.
	PaintOrder int64 `json:"paintOrder,omitempty"`

	// IsStackingContext Set to true to indicate the element begins a new stacking context.
	IsStackingContext bool `json:"isStackingContext,omitempty"`
}

// DOMSnapshotComputedStyle A subset of the full ComputedStyle as defined by the request whitelist.
type DOMSnapshotComputedStyle struct {
	// Properties Name/value pairs of computed style properties.
	Properties []*DOMSnapshotNameValue `json:"properties"`
}

// DOMSnapshotNameValue A name/value pair.
type DOMSnapshotNameValue struct {
	// Name Attribute/property name.
	Name string `json:"name"`

	// Value Attribute/property value.
	Value string `json:"value"`
}

// DOMSnapshotStringIndex Index of the string in the strings table.
type DOMSnapshotStringIndex int64

// DOMSnapshotArrayOfStrings Index of the string in the strings table.
type DOMSnapshotArrayOfStrings []*DOMSnapshotStringIndex

// DOMSnapshotRareStringData Data that is only present on rare nodes.
type DOMSnapshotRareStringData struct {
	// Index ...
	Index []int64 `json:"index"`

	// Value ...
	Value []*DOMSnapshotStringIndex `json:"value"`
}

// DOMSnapshotRareBooleanData ...
type DOMSnapshotRareBooleanData struct {
	// Index ...
	Index []int64 `json:"index"`
}

// DOMSnapshotRareIntegerData ...
type DOMSnapshotRareIntegerData struct {
	// Index ...
	Index []int64 `json:"index"`

	// Value ...
	Value []int64 `json:"value"`
}

// DOMSnapshotRectangle ...
type DOMSnapshotRectangle []float64

// DOMSnapshotDocumentSnapshot Document snapshot.
type DOMSnapshotDocumentSnapshot struct {
	// DocumentURL Document URL that `Document` or `FrameOwner` node points to.
	DocumentURL *DOMSnapshotStringIndex `json:"documentURL"`

	// Title Document title.
	Title *DOMSnapshotStringIndex `json:"title"`

	// BaseURL Base URL that `Document` or `FrameOwner` node uses for URL completion.
	BaseURL *DOMSnapshotStringIndex `json:"baseURL"`

	// ContentLanguage Contains the document's content language.
	ContentLanguage *DOMSnapshotStringIndex `json:"contentLanguage"`

	// EncodingName Contains the document's character set encoding.
	EncodingName *DOMSnapshotStringIndex `json:"encodingName"`

	// PublicID `DocumentType` node's publicId.
	PublicID *DOMSnapshotStringIndex `json:"publicId"`

	// SystemID `DocumentType` node's systemId.
	SystemID *DOMSnapshotStringIndex `json:"systemId"`

	// FrameID Frame ID for frame owner elements and also for the document node.
	FrameID *DOMSnapshotStringIndex `json:"frameId"`

	// Nodes A table with dom nodes.
	Nodes *DOMSnapshotNodeTreeSnapshot `json:"nodes"`

	// Layout The nodes in the layout tree.
	Layout *DOMSnapshotLayoutTreeSnapshot `json:"layout"`

	// TextBoxes The post-layout inline text nodes.
	TextBoxes *DOMSnapshotTextBoxSnapshot `json:"textBoxes"`

	// ScrollOffsetX Horizontal scroll offset.
	ScrollOffsetX float64 `json:"scrollOffsetX,omitempty"`

	// ScrollOffsetY Vertical scroll offset.
	ScrollOffsetY float64 `json:"scrollOffsetY,omitempty"`

	// ContentWidth Document content width.
	ContentWidth float64 `json:"contentWidth,omitempty"`

	// ContentHeight Document content height.
	ContentHeight float64 `json:"contentHeight,omitempty"`
}

// DOMSnapshotNodeTreeSnapshot Table containing nodes.
type DOMSnapshotNodeTreeSnapshot struct {
	// ParentIndex Parent node index.
	ParentIndex []int64 `json:"parentIndex,omitempty"`

	// NodeType `Node`'s nodeType.
	NodeType []int64 `json:"nodeType,omitempty"`

	// NodeName `Node`'s nodeName.
	NodeName []*DOMSnapshotStringIndex `json:"nodeName,omitempty"`

	// NodeValue `Node`'s nodeValue.
	NodeValue []*DOMSnapshotStringIndex `json:"nodeValue,omitempty"`

	// BackendNodeID `Node`'s id, corresponds to DOM.Node.backendNodeId.
	BackendNodeID []*DOMBackendNodeID `json:"backendNodeId,omitempty"`

	// Attributes Attributes of an `Element` node. Flatten name, value pairs.
	Attributes []*DOMSnapshotArrayOfStrings `json:"attributes,omitempty"`

	// TextValue Only set for textarea elements, contains the text value.
	TextValue *DOMSnapshotRareStringData `json:"textValue,omitempty"`

	// InputValue Only set for input elements, contains the input's associated text value.
	InputValue *DOMSnapshotRareStringData `json:"inputValue,omitempty"`

	// InputChecked Only set for radio and checkbox input elements, indicates if the element has been checked
	InputChecked *DOMSnapshotRareBooleanData `json:"inputChecked,omitempty"`

	// OptionSelected Only set for option elements, indicates if the element has been selected
	OptionSelected *DOMSnapshotRareBooleanData `json:"optionSelected,omitempty"`

	// ContentDocumentIndex The index of the document in the list of the snapshot documents.
	ContentDocumentIndex *DOMSnapshotRareIntegerData `json:"contentDocumentIndex,omitempty"`

	// PseudoType Type of a pseudo element node.
	PseudoType *DOMSnapshotRareStringData `json:"pseudoType,omitempty"`

	// IsClickable Whether this DOM node responds to mouse clicks. This includes nodes that have had click
	// event listeners attached via JavaScript as well as anchor tags that naturally navigate when
	// clicked.
	IsClickable *DOMSnapshotRareBooleanData `json:"isClickable,omitempty"`

	// CurrentSourceURL The selected url for nodes with a srcset attribute.
	CurrentSourceURL *DOMSnapshotRareStringData `json:"currentSourceURL,omitempty"`

	// OriginURL The url of the script (if any) that generates this node.
	OriginURL *DOMSnapshotRareStringData `json:"originURL,omitempty"`
}

// DOMSnapshotLayoutTreeSnapshot Table of details of an element in the DOM tree with a LayoutObject.
type DOMSnapshotLayoutTreeSnapshot struct {
	// NodeIndex Index of the corresponding node in the `NodeTreeSnapshot` array returned by `captureSnapshot`.
	NodeIndex []int64 `json:"nodeIndex"`

	// Styles Array of indexes specifying computed style strings, filtered according to the `computedStyles` parameter passed to `captureSnapshot`.
	Styles []*DOMSnapshotArrayOfStrings `json:"styles"`

	// Bounds The absolute position bounding box.
	Bounds []*DOMSnapshotRectangle `json:"bounds"`

	// Text Contents of the LayoutText, if any.
	Text []*DOMSnapshotStringIndex `json:"text"`

	// StackingContexts Stacking context information.
	StackingContexts *DOMSnapshotRareBooleanData `json:"stackingContexts"`

	// PaintOrders Global paint order index, which is determined by the stacking order of the nodes. Nodes
	// that are painted together will have the same index. Only provided if includePaintOrder in
	// captureSnapshot was true.
	PaintOrders []int64 `json:"paintOrders,omitempty"`

	// OffsetRects The offset rect of nodes. Only available when includeDOMRects is set to true
	OffsetRects []*DOMSnapshotRectangle `json:"offsetRects,omitempty"`

	// ScrollRects The scroll rect of nodes. Only available when includeDOMRects is set to true
	ScrollRects []*DOMSnapshotRectangle `json:"scrollRects,omitempty"`

	// ClientRects The client rect of nodes. Only available when includeDOMRects is set to true
	ClientRects []*DOMSnapshotRectangle `json:"clientRects,omitempty"`
}

// DOMSnapshotTextBoxSnapshot Table of details of the post layout rendered text positions. The exact layout should not be regarded as
// stable and may change between versions.
type DOMSnapshotTextBoxSnapshot struct {
	// LayoutIndex Index of the layout tree node that owns this box collection.
	LayoutIndex []int64 `json:"layoutIndex"`

	// Bounds The absolute position bounding box.
	Bounds []*DOMSnapshotRectangle `json:"bounds"`

	// Start The starting index in characters, for this post layout textbox substring. Characters that
	// would be represented as a surrogate pair in UTF-16 have length 2.
	Start []int64 `json:"start"`

	// Length The number of characters in this post layout textbox substring. Characters that would be
	// represented as a surrogate pair in UTF-16 have length 2.
	Length []int64 `json:"length"`
}
