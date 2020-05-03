// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// CSSAddRule Inserts a new rule with the given `ruleText` in a stylesheet with given `styleSheetId`, at the
// position specified by `location`.
type CSSAddRule struct {
	// StyleSheetID The css style sheet identifier where a new rule should be inserted.
	StyleSheetID *CSSStyleSheetID `json:"styleSheetId"`

	// RuleText The text of a new rule.
	RuleText string `json:"ruleText"`

	// Location Text position of a new rule in the target style sheet.
	Location *CSSSourceRange `json:"location"`
}

// CSSAddRuleResult type
type CSSAddRuleResult struct {
	// Rule The newly created rule.
	Rule *CSSCSSRule `json:"rule"`
}

// Call of the command, sessionID is optional.
func (m CSSAddRule) Call(c *Call) (*CSSAddRuleResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSAddRule", m)
	if err != nil {
		return nil, err
	}

	var res CSSAddRuleResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSCollectClassNames Returns all class names from specified stylesheet.
type CSSCollectClassNames struct {
	// StyleSheetID ...
	StyleSheetID *CSSStyleSheetID `json:"styleSheetId"`
}

// CSSCollectClassNamesResult type
type CSSCollectClassNamesResult struct {
	// ClassNames Class name list.
	ClassNames []string `json:"classNames"`
}

// Call of the command, sessionID is optional.
func (m CSSCollectClassNames) Call(c *Call) (*CSSCollectClassNamesResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSCollectClassNames", m)
	if err != nil {
		return nil, err
	}

	var res CSSCollectClassNamesResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSCreateStyleSheet Creates a new special "via-inspector" stylesheet in the frame with given `frameId`.
type CSSCreateStyleSheet struct {
	// FrameID Identifier of the frame where "via-inspector" stylesheet should be created.
	FrameID *PageFrameID `json:"frameId"`
}

// CSSCreateStyleSheetResult type
type CSSCreateStyleSheetResult struct {
	// StyleSheetID Identifier of the created "via-inspector" stylesheet.
	StyleSheetID *CSSStyleSheetID `json:"styleSheetId"`
}

// Call of the command, sessionID is optional.
func (m CSSCreateStyleSheet) Call(c *Call) (*CSSCreateStyleSheetResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSCreateStyleSheet", m)
	if err != nil {
		return nil, err
	}

	var res CSSCreateStyleSheetResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSDisable Disables the CSS agent for the given page.
type CSSDisable struct {
}

// CSSDisableResult type
type CSSDisableResult struct {
}

// Call of the command, sessionID is optional.
func (m CSSDisable) Call(c *Call) (*CSSDisableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSDisable", m)
	if err != nil {
		return nil, err
	}

	var res CSSDisableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSEnable Enables the CSS agent for the given page. Clients should not assume that the CSS agent has been
// enabled until the result of this command is received.
type CSSEnable struct {
}

// CSSEnableResult type
type CSSEnableResult struct {
}

// Call of the command, sessionID is optional.
func (m CSSEnable) Call(c *Call) (*CSSEnableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSEnable", m)
	if err != nil {
		return nil, err
	}

	var res CSSEnableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSForcePseudoState Ensures that the given node will have specified pseudo-classes whenever its style is computed by
// the browser.
type CSSForcePseudoState struct {
	// NodeID The element id for which to force the pseudo state.
	NodeID *DOMNodeID `json:"nodeId"`

	// ForcedPseudoClasses Element pseudo classes to force when computing the element's style.
	ForcedPseudoClasses []string `json:"forcedPseudoClasses"`
}

// CSSForcePseudoStateResult type
type CSSForcePseudoStateResult struct {
}

// Call of the command, sessionID is optional.
func (m CSSForcePseudoState) Call(c *Call) (*CSSForcePseudoStateResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSForcePseudoState", m)
	if err != nil {
		return nil, err
	}

	var res CSSForcePseudoStateResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSGetBackgroundColors ...
type CSSGetBackgroundColors struct {
	// NodeID Id of the node to get background colors for.
	NodeID *DOMNodeID `json:"nodeId"`
}

// CSSGetBackgroundColorsResult type
type CSSGetBackgroundColorsResult struct {
	// BackgroundColors The range of background colors behind this element, if it contains any visible text. If no
	// visible text is present, this will be undefined. In the case of a flat background color,
	// this will consist of simply that color. In the case of a gradient, this will consist of each
	// of the color stops. For anything more complicated, this will be an empty array. Images will
	// be ignored (as if the image had failed to load).
	BackgroundColors []string `json:"backgroundColors,omitempty"`

	// ComputedFontSize The computed font size for this node, as a CSS computed value string (e.g. '12px').
	ComputedFontSize string `json:"computedFontSize,omitempty"`

	// ComputedFontWeight The computed font weight for this node, as a CSS computed value string (e.g. 'normal' or
	// '100').
	ComputedFontWeight string `json:"computedFontWeight,omitempty"`
}

// Call of the command, sessionID is optional.
func (m CSSGetBackgroundColors) Call(c *Call) (*CSSGetBackgroundColorsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSGetBackgroundColors", m)
	if err != nil {
		return nil, err
	}

	var res CSSGetBackgroundColorsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSGetComputedStyleForNode Returns the computed style for a DOM node identified by `nodeId`.
type CSSGetComputedStyleForNode struct {
	// NodeID ...
	NodeID *DOMNodeID `json:"nodeId"`
}

// CSSGetComputedStyleForNodeResult type
type CSSGetComputedStyleForNodeResult struct {
	// ComputedStyle Computed style for the specified DOM node.
	ComputedStyle []*CSSCSSComputedStyleProperty `json:"computedStyle"`
}

// Call of the command, sessionID is optional.
func (m CSSGetComputedStyleForNode) Call(c *Call) (*CSSGetComputedStyleForNodeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSGetComputedStyleForNode", m)
	if err != nil {
		return nil, err
	}

	var res CSSGetComputedStyleForNodeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSGetInlineStylesForNode Returns the styles defined inline (explicitly in the "style" attribute and implicitly, using DOM
// attributes) for a DOM node identified by `nodeId`.
type CSSGetInlineStylesForNode struct {
	// NodeID ...
	NodeID *DOMNodeID `json:"nodeId"`
}

// CSSGetInlineStylesForNodeResult type
type CSSGetInlineStylesForNodeResult struct {
	// InlineStyle Inline style for the specified DOM node.
	InlineStyle *CSSCSSStyle `json:"inlineStyle,omitempty"`

	// AttributesStyle Attribute-defined element style (e.g. resulting from "width=20 height=100%").
	AttributesStyle *CSSCSSStyle `json:"attributesStyle,omitempty"`
}

// Call of the command, sessionID is optional.
func (m CSSGetInlineStylesForNode) Call(c *Call) (*CSSGetInlineStylesForNodeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSGetInlineStylesForNode", m)
	if err != nil {
		return nil, err
	}

	var res CSSGetInlineStylesForNodeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSGetMatchedStylesForNode Returns requested styles for a DOM node identified by `nodeId`.
type CSSGetMatchedStylesForNode struct {
	// NodeID ...
	NodeID *DOMNodeID `json:"nodeId"`
}

// CSSGetMatchedStylesForNodeResult type
type CSSGetMatchedStylesForNodeResult struct {
	// InlineStyle Inline style for the specified DOM node.
	InlineStyle *CSSCSSStyle `json:"inlineStyle,omitempty"`

	// AttributesStyle Attribute-defined element style (e.g. resulting from "width=20 height=100%").
	AttributesStyle *CSSCSSStyle `json:"attributesStyle,omitempty"`

	// MatchedCSSRules CSS rules matching this node, from all applicable stylesheets.
	MatchedCSSRules []*CSSRuleMatch `json:"matchedCSSRules,omitempty"`

	// PseudoElements Pseudo style matches for this node.
	PseudoElements []*CSSPseudoElementMatches `json:"pseudoElements,omitempty"`

	// Inherited A chain of inherited styles (from the immediate node parent up to the DOM tree root).
	Inherited []*CSSInheritedStyleEntry `json:"inherited,omitempty"`

	// CSSKeyframesRules A list of CSS keyframed animations matching this node.
	CSSKeyframesRules []*CSSCSSKeyframesRule `json:"cssKeyframesRules,omitempty"`
}

// Call of the command, sessionID is optional.
func (m CSSGetMatchedStylesForNode) Call(c *Call) (*CSSGetMatchedStylesForNodeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSGetMatchedStylesForNode", m)
	if err != nil {
		return nil, err
	}

	var res CSSGetMatchedStylesForNodeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSGetMediaQueries Returns all media queries parsed by the rendering engine.
type CSSGetMediaQueries struct {
}

// CSSGetMediaQueriesResult type
type CSSGetMediaQueriesResult struct {
	// Medias ...
	Medias []*CSSCSSMedia `json:"medias"`
}

// Call of the command, sessionID is optional.
func (m CSSGetMediaQueries) Call(c *Call) (*CSSGetMediaQueriesResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSGetMediaQueries", m)
	if err != nil {
		return nil, err
	}

	var res CSSGetMediaQueriesResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSGetPlatformFontsForNode Requests information about platform fonts which we used to render child TextNodes in the given
// node.
type CSSGetPlatformFontsForNode struct {
	// NodeID ...
	NodeID *DOMNodeID `json:"nodeId"`
}

// CSSGetPlatformFontsForNodeResult type
type CSSGetPlatformFontsForNodeResult struct {
	// Fonts Usage statistics for every employed platform font.
	Fonts []*CSSPlatformFontUsage `json:"fonts"`
}

// Call of the command, sessionID is optional.
func (m CSSGetPlatformFontsForNode) Call(c *Call) (*CSSGetPlatformFontsForNodeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSGetPlatformFontsForNode", m)
	if err != nil {
		return nil, err
	}

	var res CSSGetPlatformFontsForNodeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSGetStyleSheetText Returns the current textual content for a stylesheet.
type CSSGetStyleSheetText struct {
	// StyleSheetID ...
	StyleSheetID *CSSStyleSheetID `json:"styleSheetId"`
}

// CSSGetStyleSheetTextResult type
type CSSGetStyleSheetTextResult struct {
	// Text The stylesheet text.
	Text string `json:"text"`
}

// Call of the command, sessionID is optional.
func (m CSSGetStyleSheetText) Call(c *Call) (*CSSGetStyleSheetTextResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSGetStyleSheetText", m)
	if err != nil {
		return nil, err
	}

	var res CSSGetStyleSheetTextResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSSetEffectivePropertyValueForNode Find a rule with the given active property for the given node and set the new value for this
// property
type CSSSetEffectivePropertyValueForNode struct {
	// NodeID The element id for which to set property.
	NodeID *DOMNodeID `json:"nodeId"`

	// PropertyName ...
	PropertyName string `json:"propertyName"`

	// Value ...
	Value string `json:"value"`
}

// CSSSetEffectivePropertyValueForNodeResult type
type CSSSetEffectivePropertyValueForNodeResult struct {
}

// Call of the command, sessionID is optional.
func (m CSSSetEffectivePropertyValueForNode) Call(c *Call) (*CSSSetEffectivePropertyValueForNodeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSSetEffectivePropertyValueForNode", m)
	if err != nil {
		return nil, err
	}

	var res CSSSetEffectivePropertyValueForNodeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSSetKeyframeKey Modifies the keyframe rule key text.
type CSSSetKeyframeKey struct {
	// StyleSheetID ...
	StyleSheetID *CSSStyleSheetID `json:"styleSheetId"`

	// Range ...
	Range *CSSSourceRange `json:"range"`

	// KeyText ...
	KeyText string `json:"keyText"`
}

// CSSSetKeyframeKeyResult type
type CSSSetKeyframeKeyResult struct {
	// KeyText The resulting key text after modification.
	KeyText *CSSValue `json:"keyText"`
}

// Call of the command, sessionID is optional.
func (m CSSSetKeyframeKey) Call(c *Call) (*CSSSetKeyframeKeyResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSSetKeyframeKey", m)
	if err != nil {
		return nil, err
	}

	var res CSSSetKeyframeKeyResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSSetMediaText Modifies the rule selector.
type CSSSetMediaText struct {
	// StyleSheetID ...
	StyleSheetID *CSSStyleSheetID `json:"styleSheetId"`

	// Range ...
	Range *CSSSourceRange `json:"range"`

	// Text ...
	Text string `json:"text"`
}

// CSSSetMediaTextResult type
type CSSSetMediaTextResult struct {
	// Media The resulting CSS media rule after modification.
	Media *CSSCSSMedia `json:"media"`
}

// Call of the command, sessionID is optional.
func (m CSSSetMediaText) Call(c *Call) (*CSSSetMediaTextResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSSetMediaText", m)
	if err != nil {
		return nil, err
	}

	var res CSSSetMediaTextResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSSetRuleSelector Modifies the rule selector.
type CSSSetRuleSelector struct {
	// StyleSheetID ...
	StyleSheetID *CSSStyleSheetID `json:"styleSheetId"`

	// Range ...
	Range *CSSSourceRange `json:"range"`

	// Selector ...
	Selector string `json:"selector"`
}

// CSSSetRuleSelectorResult type
type CSSSetRuleSelectorResult struct {
	// SelectorList The resulting selector list after modification.
	SelectorList *CSSSelectorList `json:"selectorList"`
}

// Call of the command, sessionID is optional.
func (m CSSSetRuleSelector) Call(c *Call) (*CSSSetRuleSelectorResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSSetRuleSelector", m)
	if err != nil {
		return nil, err
	}

	var res CSSSetRuleSelectorResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSSetStyleSheetText Sets the new stylesheet text.
type CSSSetStyleSheetText struct {
	// StyleSheetID ...
	StyleSheetID *CSSStyleSheetID `json:"styleSheetId"`

	// Text ...
	Text string `json:"text"`
}

// CSSSetStyleSheetTextResult type
type CSSSetStyleSheetTextResult struct {
	// SourceMapURL URL of source map associated with script (if any).
	SourceMapURL string `json:"sourceMapURL,omitempty"`
}

// Call of the command, sessionID is optional.
func (m CSSSetStyleSheetText) Call(c *Call) (*CSSSetStyleSheetTextResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSSetStyleSheetText", m)
	if err != nil {
		return nil, err
	}

	var res CSSSetStyleSheetTextResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSSetStyleTexts Applies specified style edits one after another in the given order.
type CSSSetStyleTexts struct {
	// Edits ...
	Edits []*CSSStyleDeclarationEdit `json:"edits"`
}

// CSSSetStyleTextsResult type
type CSSSetStyleTextsResult struct {
	// Styles The resulting styles after modification.
	Styles []*CSSCSSStyle `json:"styles"`
}

// Call of the command, sessionID is optional.
func (m CSSSetStyleTexts) Call(c *Call) (*CSSSetStyleTextsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSSetStyleTexts", m)
	if err != nil {
		return nil, err
	}

	var res CSSSetStyleTextsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSStartRuleUsageTracking Enables the selector recording.
type CSSStartRuleUsageTracking struct {
}

// CSSStartRuleUsageTrackingResult type
type CSSStartRuleUsageTrackingResult struct {
}

// Call of the command, sessionID is optional.
func (m CSSStartRuleUsageTracking) Call(c *Call) (*CSSStartRuleUsageTrackingResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSStartRuleUsageTracking", m)
	if err != nil {
		return nil, err
	}

	var res CSSStartRuleUsageTrackingResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSStopRuleUsageTracking Stop tracking rule usage and return the list of rules that were used since last call to
// `takeCoverageDelta` (or since start of coverage instrumentation)
type CSSStopRuleUsageTracking struct {
}

// CSSStopRuleUsageTrackingResult type
type CSSStopRuleUsageTrackingResult struct {
	// RuleUsage ...
	RuleUsage []*CSSRuleUsage `json:"ruleUsage"`
}

// Call of the command, sessionID is optional.
func (m CSSStopRuleUsageTracking) Call(c *Call) (*CSSStopRuleUsageTrackingResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSStopRuleUsageTracking", m)
	if err != nil {
		return nil, err
	}

	var res CSSStopRuleUsageTrackingResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// CSSTakeCoverageDelta Obtain list of rules that became used since last call to this method (or since start of coverage
// instrumentation)
type CSSTakeCoverageDelta struct {
}

// CSSTakeCoverageDeltaResult type
type CSSTakeCoverageDeltaResult struct {
	// Coverage ...
	Coverage []*CSSRuleUsage `json:"coverage"`

	// Timestamp Monotonically increasing time, in seconds.
	Timestamp float64 `json:"timestamp"`
}

// Call of the command, sessionID is optional.
func (m CSSTakeCoverageDelta) Call(c *Call) (*CSSTakeCoverageDeltaResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "CSSTakeCoverageDelta", m)
	if err != nil {
		return nil, err
	}

	var res CSSTakeCoverageDeltaResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}