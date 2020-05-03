// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// DebuggerDebuggerContinueToLocationTargetCallFrames Enum of possible values
type DebuggerDebuggerContinueToLocationTargetCallFrames string

const (
	// DebuggerDebuggerContinueToLocationTargetCallFramesAny enum value
	DebuggerDebuggerContinueToLocationTargetCallFramesAny DebuggerDebuggerContinueToLocationTargetCallFrames = "any"

	// DebuggerDebuggerContinueToLocationTargetCallFramesCurrent enum value
	DebuggerDebuggerContinueToLocationTargetCallFramesCurrent DebuggerDebuggerContinueToLocationTargetCallFrames = "current"
)

// DebuggerContinueToLocation Continues execution until specific location is reached.
type DebuggerContinueToLocation struct {
	// Location Location to continue to.
	Location *DebuggerLocation `json:"location"`

	// TargetCallFrames ...
	TargetCallFrames DebuggerDebuggerContinueToLocationTargetCallFrames `json:"targetCallFrames,omitempty"`
}

// DebuggerContinueToLocationResult type
type DebuggerContinueToLocationResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerContinueToLocation) Call(c *Call) (*DebuggerContinueToLocationResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerContinueToLocation", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerContinueToLocationResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerDisable Disables debugger for given page.
type DebuggerDisable struct {
}

// DebuggerDisableResult type
type DebuggerDisableResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerDisable) Call(c *Call) (*DebuggerDisableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerDisable", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerDisableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerEnable Enables debugger for the given page. Clients should not assume that the debugging has been
// enabled until the result for this command is received.
type DebuggerEnable struct {
	// MaxScriptsCacheSize (experimental) The maximum size in bytes of collected scripts (not referenced by other heap objects)
	// the debugger can hold. Puts no limit if paramter is omitted.
	MaxScriptsCacheSize float64 `json:"maxScriptsCacheSize,omitempty"`
}

// DebuggerEnableResult type
type DebuggerEnableResult struct {
	// DebuggerID (experimental) Unique identifier of the debugger.
	DebuggerID *RuntimeUniqueDebuggerID `json:"debuggerId"`
}

// Call of the command, sessionID is optional.
func (m DebuggerEnable) Call(c *Call) (*DebuggerEnableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerEnable", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerEnableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerEvaluateOnCallFrame Evaluates expression on a given call frame.
type DebuggerEvaluateOnCallFrame struct {
	// CallFrameID Call frame identifier to evaluate on.
	CallFrameID *DebuggerCallFrameID `json:"callFrameId"`

	// Expression Expression to evaluate.
	Expression string `json:"expression"`

	// ObjectGroup String object group name to put result into (allows rapid releasing resulting object handles
	// using `releaseObjectGroup`).
	ObjectGroup string `json:"objectGroup,omitempty"`

	// IncludeCommandLineAPI Specifies whether command line API should be available to the evaluated expression, defaults
	// to false.
	IncludeCommandLineAPI bool `json:"includeCommandLineAPI,omitempty"`

	// Silent In silent mode exceptions thrown during evaluation are not reported and do not pause
	// execution. Overrides `setPauseOnException` state.
	Silent bool `json:"silent,omitempty"`

	// ReturnByValue Whether the result is expected to be a JSON object that should be sent by value.
	ReturnByValue bool `json:"returnByValue,omitempty"`

	// GeneratePreview (experimental) Whether preview should be generated for the result.
	GeneratePreview bool `json:"generatePreview,omitempty"`

	// ThrowOnSideEffect Whether to throw an exception if side effect cannot be ruled out during evaluation.
	ThrowOnSideEffect bool `json:"throwOnSideEffect,omitempty"`

	// Timeout (experimental) Terminate execution after timing out (number of milliseconds).
	Timeout *RuntimeTimeDelta `json:"timeout,omitempty"`
}

// DebuggerEvaluateOnCallFrameResult type
type DebuggerEvaluateOnCallFrameResult struct {
	// Result Object wrapper for the evaluation result.
	Result *RuntimeRemoteObject `json:"result"`

	// ExceptionDetails Exception details.
	ExceptionDetails *RuntimeExceptionDetails `json:"exceptionDetails,omitempty"`
}

// Call of the command, sessionID is optional.
func (m DebuggerEvaluateOnCallFrame) Call(c *Call) (*DebuggerEvaluateOnCallFrameResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerEvaluateOnCallFrame", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerEvaluateOnCallFrameResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerGetPossibleBreakpoints Returns possible locations for breakpoint. scriptId in start and end range locations should be
// the same.
type DebuggerGetPossibleBreakpoints struct {
	// Start Start of range to search possible breakpoint locations in.
	Start *DebuggerLocation `json:"start"`

	// End End of range to search possible breakpoint locations in (excluding). When not specified, end
	// of scripts is used as end of range.
	End *DebuggerLocation `json:"end,omitempty"`

	// RestrictToFunction Only consider locations which are in the same (non-nested) function as start.
	RestrictToFunction bool `json:"restrictToFunction,omitempty"`
}

// DebuggerGetPossibleBreakpointsResult type
type DebuggerGetPossibleBreakpointsResult struct {
	// Locations List of the possible breakpoint locations.
	Locations []*DebuggerBreakLocation `json:"locations"`
}

// Call of the command, sessionID is optional.
func (m DebuggerGetPossibleBreakpoints) Call(c *Call) (*DebuggerGetPossibleBreakpointsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerGetPossibleBreakpoints", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerGetPossibleBreakpointsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerGetScriptSource Returns source for the script with given id.
type DebuggerGetScriptSource struct {
	// ScriptID Id of the script to get source for.
	ScriptID *RuntimeScriptID `json:"scriptId"`
}

// DebuggerGetScriptSourceResult type
type DebuggerGetScriptSourceResult struct {
	// ScriptSource Script source (empty in case of Wasm bytecode).
	ScriptSource string `json:"scriptSource"`

	// Bytecode Wasm bytecode.
	Bytecode []byte `json:"bytecode,omitempty"`
}

// Call of the command, sessionID is optional.
func (m DebuggerGetScriptSource) Call(c *Call) (*DebuggerGetScriptSourceResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerGetScriptSource", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerGetScriptSourceResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerGetWasmBytecode (deprecated) This command is deprecated. Use getScriptSource instead.
type DebuggerGetWasmBytecode struct {
	// ScriptID Id of the Wasm script to get source for.
	ScriptID *RuntimeScriptID `json:"scriptId"`
}

// DebuggerGetWasmBytecodeResult type
type DebuggerGetWasmBytecodeResult struct {
	// Bytecode Script source.
	Bytecode []byte `json:"bytecode"`
}

// Call of the command, sessionID is optional.
func (m DebuggerGetWasmBytecode) Call(c *Call) (*DebuggerGetWasmBytecodeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerGetWasmBytecode", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerGetWasmBytecodeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerGetStackTrace (experimental) Returns stack trace with given `stackTraceId`.
type DebuggerGetStackTrace struct {
	// StackTraceID ...
	StackTraceID *RuntimeStackTraceID `json:"stackTraceId"`
}

// DebuggerGetStackTraceResult type
type DebuggerGetStackTraceResult struct {
	// StackTrace ...
	StackTrace *RuntimeStackTrace `json:"stackTrace"`
}

// Call of the command, sessionID is optional.
func (m DebuggerGetStackTrace) Call(c *Call) (*DebuggerGetStackTraceResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerGetStackTrace", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerGetStackTraceResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerPause Stops on the next JavaScript statement.
type DebuggerPause struct {
}

// DebuggerPauseResult type
type DebuggerPauseResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerPause) Call(c *Call) (*DebuggerPauseResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerPause", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerPauseResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerPauseOnAsyncCall (deprecated) (experimental) ...
type DebuggerPauseOnAsyncCall struct {
	// ParentStackTraceID Debugger will pause when async call with given stack trace is started.
	ParentStackTraceID *RuntimeStackTraceID `json:"parentStackTraceId"`
}

// DebuggerPauseOnAsyncCallResult type
type DebuggerPauseOnAsyncCallResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerPauseOnAsyncCall) Call(c *Call) (*DebuggerPauseOnAsyncCallResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerPauseOnAsyncCall", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerPauseOnAsyncCallResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerRemoveBreakpoint Removes JavaScript breakpoint.
type DebuggerRemoveBreakpoint struct {
	// BreakpointID ...
	BreakpointID *DebuggerBreakpointID `json:"breakpointId"`
}

// DebuggerRemoveBreakpointResult type
type DebuggerRemoveBreakpointResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerRemoveBreakpoint) Call(c *Call) (*DebuggerRemoveBreakpointResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerRemoveBreakpoint", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerRemoveBreakpointResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerRestartFrame Restarts particular call frame from the beginning.
type DebuggerRestartFrame struct {
	// CallFrameID Call frame identifier to evaluate on.
	CallFrameID *DebuggerCallFrameID `json:"callFrameId"`
}

// DebuggerRestartFrameResult type
type DebuggerRestartFrameResult struct {
	// CallFrames New stack trace.
	CallFrames []*DebuggerCallFrame `json:"callFrames"`

	// AsyncStackTrace Async stack trace, if any.
	AsyncStackTrace *RuntimeStackTrace `json:"asyncStackTrace,omitempty"`

	// AsyncStackTraceID (experimental) Async stack trace, if any.
	AsyncStackTraceID *RuntimeStackTraceID `json:"asyncStackTraceId,omitempty"`
}

// Call of the command, sessionID is optional.
func (m DebuggerRestartFrame) Call(c *Call) (*DebuggerRestartFrameResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerRestartFrame", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerRestartFrameResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerResume Resumes JavaScript execution.
type DebuggerResume struct {
}

// DebuggerResumeResult type
type DebuggerResumeResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerResume) Call(c *Call) (*DebuggerResumeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerResume", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerResumeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSearchInContent Searches for given string in script content.
type DebuggerSearchInContent struct {
	// ScriptID Id of the script to search in.
	ScriptID *RuntimeScriptID `json:"scriptId"`

	// Query String to search for.
	Query string `json:"query"`

	// CaseSensitive If true, search is case sensitive.
	CaseSensitive bool `json:"caseSensitive,omitempty"`

	// IsRegex If true, treats string parameter as regex.
	IsRegex bool `json:"isRegex,omitempty"`
}

// DebuggerSearchInContentResult type
type DebuggerSearchInContentResult struct {
	// Result List of search matches.
	Result []*DebuggerSearchMatch `json:"result"`
}

// Call of the command, sessionID is optional.
func (m DebuggerSearchInContent) Call(c *Call) (*DebuggerSearchInContentResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSearchInContent", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSearchInContentResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetAsyncCallStackDepth Enables or disables async call stacks tracking.
type DebuggerSetAsyncCallStackDepth struct {
	// MaxDepth Maximum depth of async call stacks. Setting to `0` will effectively disable collecting async
	// call stacks (default).
	MaxDepth int64 `json:"maxDepth"`
}

// DebuggerSetAsyncCallStackDepthResult type
type DebuggerSetAsyncCallStackDepthResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerSetAsyncCallStackDepth) Call(c *Call) (*DebuggerSetAsyncCallStackDepthResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetAsyncCallStackDepth", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetAsyncCallStackDepthResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetBlackboxPatterns (experimental) Replace previous blackbox patterns with passed ones. Forces backend to skip stepping/pausing in
// scripts with url matching one of the patterns. VM will try to leave blackboxed script by
// performing 'step in' several times, finally resorting to 'step out' if unsuccessful.
type DebuggerSetBlackboxPatterns struct {
	// Patterns Array of regexps that will be used to check script url for blackbox state.
	Patterns []string `json:"patterns"`
}

// DebuggerSetBlackboxPatternsResult type
type DebuggerSetBlackboxPatternsResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerSetBlackboxPatterns) Call(c *Call) (*DebuggerSetBlackboxPatternsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetBlackboxPatterns", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetBlackboxPatternsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetBlackboxedRanges (experimental) Makes backend skip steps in the script in blackboxed ranges. VM will try leave blacklisted
// scripts by performing 'step in' several times, finally resorting to 'step out' if unsuccessful.
// Positions array contains positions where blackbox state is changed. First interval isn't
// blackboxed. Array should be sorted.
type DebuggerSetBlackboxedRanges struct {
	// ScriptID Id of the script.
	ScriptID *RuntimeScriptID `json:"scriptId"`

	// Positions ...
	Positions []*DebuggerScriptPosition `json:"positions"`
}

// DebuggerSetBlackboxedRangesResult type
type DebuggerSetBlackboxedRangesResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerSetBlackboxedRanges) Call(c *Call) (*DebuggerSetBlackboxedRangesResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetBlackboxedRanges", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetBlackboxedRangesResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetBreakpoint Sets JavaScript breakpoint at a given location.
type DebuggerSetBreakpoint struct {
	// Location Location to set breakpoint in.
	Location *DebuggerLocation `json:"location"`

	// Condition Expression to use as a breakpoint condition. When specified, debugger will only stop on the
	// breakpoint if this expression evaluates to true.
	Condition string `json:"condition,omitempty"`
}

// DebuggerSetBreakpointResult type
type DebuggerSetBreakpointResult struct {
	// BreakpointID Id of the created breakpoint for further reference.
	BreakpointID *DebuggerBreakpointID `json:"breakpointId"`

	// ActualLocation Location this breakpoint resolved into.
	ActualLocation *DebuggerLocation `json:"actualLocation"`
}

// Call of the command, sessionID is optional.
func (m DebuggerSetBreakpoint) Call(c *Call) (*DebuggerSetBreakpointResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetBreakpoint", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetBreakpointResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerDebuggerSetInstrumentationBreakpointInstrumentation Enum of possible values
type DebuggerDebuggerSetInstrumentationBreakpointInstrumentation string

const (
	// DebuggerDebuggerSetInstrumentationBreakpointInstrumentationBeforeScriptExecution enum value
	DebuggerDebuggerSetInstrumentationBreakpointInstrumentationBeforeScriptExecution DebuggerDebuggerSetInstrumentationBreakpointInstrumentation = "beforeScriptExecution"

	// DebuggerDebuggerSetInstrumentationBreakpointInstrumentationBeforeScriptWithSourceMapExecution enum value
	DebuggerDebuggerSetInstrumentationBreakpointInstrumentationBeforeScriptWithSourceMapExecution DebuggerDebuggerSetInstrumentationBreakpointInstrumentation = "beforeScriptWithSourceMapExecution"
)

// DebuggerSetInstrumentationBreakpoint Sets instrumentation breakpoint.
type DebuggerSetInstrumentationBreakpoint struct {
	// Instrumentation Instrumentation name.
	Instrumentation DebuggerDebuggerSetInstrumentationBreakpointInstrumentation `json:"instrumentation"`
}

// DebuggerSetInstrumentationBreakpointResult type
type DebuggerSetInstrumentationBreakpointResult struct {
	// BreakpointID Id of the created breakpoint for further reference.
	BreakpointID *DebuggerBreakpointID `json:"breakpointId"`
}

// Call of the command, sessionID is optional.
func (m DebuggerSetInstrumentationBreakpoint) Call(c *Call) (*DebuggerSetInstrumentationBreakpointResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetInstrumentationBreakpoint", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetInstrumentationBreakpointResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetBreakpointByURL Sets JavaScript breakpoint at given location specified either by URL or URL regex. Once this
// command is issued, all existing parsed scripts will have breakpoints resolved and returned in
// `locations` property. Further matching script parsing will result in subsequent
// `breakpointResolved` events issued. This logical breakpoint will survive page reloads.
type DebuggerSetBreakpointByURL struct {
	// LineNumber Line number to set breakpoint at.
	LineNumber int64 `json:"lineNumber"`

	// URL URL of the resources to set breakpoint on.
	URL string `json:"url,omitempty"`

	// URLRegex Regex pattern for the URLs of the resources to set breakpoints on. Either `url` or
	// `urlRegex` must be specified.
	URLRegex string `json:"urlRegex,omitempty"`

	// ScriptHash Script hash of the resources to set breakpoint on.
	ScriptHash string `json:"scriptHash,omitempty"`

	// ColumnNumber Offset in the line to set breakpoint at.
	ColumnNumber int64 `json:"columnNumber,omitempty"`

	// Condition Expression to use as a breakpoint condition. When specified, debugger will only stop on the
	// breakpoint if this expression evaluates to true.
	Condition string `json:"condition,omitempty"`
}

// DebuggerSetBreakpointByURLResult type
type DebuggerSetBreakpointByURLResult struct {
	// BreakpointID Id of the created breakpoint for further reference.
	BreakpointID *DebuggerBreakpointID `json:"breakpointId"`

	// Locations List of the locations this breakpoint resolved into upon addition.
	Locations []*DebuggerLocation `json:"locations"`
}

// Call of the command, sessionID is optional.
func (m DebuggerSetBreakpointByURL) Call(c *Call) (*DebuggerSetBreakpointByURLResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetBreakpointByURL", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetBreakpointByURLResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetBreakpointOnFunctionCall (experimental) Sets JavaScript breakpoint before each call to the given function.
// If another function was created from the same source as a given one,
// calling it will also trigger the breakpoint.
type DebuggerSetBreakpointOnFunctionCall struct {
	// ObjectID Function object id.
	ObjectID *RuntimeRemoteObjectID `json:"objectId"`

	// Condition Expression to use as a breakpoint condition. When specified, debugger will
	// stop on the breakpoint if this expression evaluates to true.
	Condition string `json:"condition,omitempty"`
}

// DebuggerSetBreakpointOnFunctionCallResult type
type DebuggerSetBreakpointOnFunctionCallResult struct {
	// BreakpointID Id of the created breakpoint for further reference.
	BreakpointID *DebuggerBreakpointID `json:"breakpointId"`
}

// Call of the command, sessionID is optional.
func (m DebuggerSetBreakpointOnFunctionCall) Call(c *Call) (*DebuggerSetBreakpointOnFunctionCallResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetBreakpointOnFunctionCall", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetBreakpointOnFunctionCallResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetBreakpointsActive Activates / deactivates all breakpoints on the page.
type DebuggerSetBreakpointsActive struct {
	// Active New value for breakpoints active state.
	Active bool `json:"active"`
}

// DebuggerSetBreakpointsActiveResult type
type DebuggerSetBreakpointsActiveResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerSetBreakpointsActive) Call(c *Call) (*DebuggerSetBreakpointsActiveResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetBreakpointsActive", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetBreakpointsActiveResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerDebuggerSetPauseOnExceptionsState Enum of possible values
type DebuggerDebuggerSetPauseOnExceptionsState string

const (
	// DebuggerDebuggerSetPauseOnExceptionsStateNone enum value
	DebuggerDebuggerSetPauseOnExceptionsStateNone DebuggerDebuggerSetPauseOnExceptionsState = "none"

	// DebuggerDebuggerSetPauseOnExceptionsStateUncaught enum value
	DebuggerDebuggerSetPauseOnExceptionsStateUncaught DebuggerDebuggerSetPauseOnExceptionsState = "uncaught"

	// DebuggerDebuggerSetPauseOnExceptionsStateAll enum value
	DebuggerDebuggerSetPauseOnExceptionsStateAll DebuggerDebuggerSetPauseOnExceptionsState = "all"
)

// DebuggerSetPauseOnExceptions Defines pause on exceptions state. Can be set to stop on all exceptions, uncaught exceptions or
// no exceptions. Initial pause on exceptions state is `none`.
type DebuggerSetPauseOnExceptions struct {
	// State Pause on exceptions mode.
	State DebuggerDebuggerSetPauseOnExceptionsState `json:"state"`
}

// DebuggerSetPauseOnExceptionsResult type
type DebuggerSetPauseOnExceptionsResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerSetPauseOnExceptions) Call(c *Call) (*DebuggerSetPauseOnExceptionsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetPauseOnExceptions", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetPauseOnExceptionsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetReturnValue (experimental) Changes return value in top frame. Available only at return break position.
type DebuggerSetReturnValue struct {
	// NewValue New return value.
	NewValue *RuntimeCallArgument `json:"newValue"`
}

// DebuggerSetReturnValueResult type
type DebuggerSetReturnValueResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerSetReturnValue) Call(c *Call) (*DebuggerSetReturnValueResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetReturnValue", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetReturnValueResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetScriptSource Edits JavaScript source live.
type DebuggerSetScriptSource struct {
	// ScriptID Id of the script to edit.
	ScriptID *RuntimeScriptID `json:"scriptId"`

	// ScriptSource New content of the script.
	ScriptSource string `json:"scriptSource"`

	// DryRun If true the change will not actually be applied. Dry run may be used to get result
	// description without actually modifying the code.
	DryRun bool `json:"dryRun,omitempty"`
}

// DebuggerSetScriptSourceResult type
type DebuggerSetScriptSourceResult struct {
	// CallFrames New stack trace in case editing has happened while VM was stopped.
	CallFrames []*DebuggerCallFrame `json:"callFrames,omitempty"`

	// StackChanged Whether current call stack  was modified after applying the changes.
	StackChanged bool `json:"stackChanged,omitempty"`

	// AsyncStackTrace Async stack trace, if any.
	AsyncStackTrace *RuntimeStackTrace `json:"asyncStackTrace,omitempty"`

	// AsyncStackTraceID (experimental) Async stack trace, if any.
	AsyncStackTraceID *RuntimeStackTraceID `json:"asyncStackTraceId,omitempty"`

	// ExceptionDetails Exception details if any.
	ExceptionDetails *RuntimeExceptionDetails `json:"exceptionDetails,omitempty"`
}

// Call of the command, sessionID is optional.
func (m DebuggerSetScriptSource) Call(c *Call) (*DebuggerSetScriptSourceResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetScriptSource", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetScriptSourceResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetSkipAllPauses Makes page not interrupt on any pauses (breakpoint, exception, dom exception etc).
type DebuggerSetSkipAllPauses struct {
	// Skip New value for skip pauses state.
	Skip bool `json:"skip"`
}

// DebuggerSetSkipAllPausesResult type
type DebuggerSetSkipAllPausesResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerSetSkipAllPauses) Call(c *Call) (*DebuggerSetSkipAllPausesResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetSkipAllPauses", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetSkipAllPausesResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerSetVariableValue Changes value of variable in a callframe. Object-based scopes are not supported and must be
// mutated manually.
type DebuggerSetVariableValue struct {
	// ScopeNumber 0-based number of scope as was listed in scope chain. Only 'local', 'closure' and 'catch'
	// scope types are allowed. Other scopes could be manipulated manually.
	ScopeNumber int64 `json:"scopeNumber"`

	// VariableName Variable name.
	VariableName string `json:"variableName"`

	// NewValue New variable value.
	NewValue *RuntimeCallArgument `json:"newValue"`

	// CallFrameID Id of callframe that holds variable.
	CallFrameID *DebuggerCallFrameID `json:"callFrameId"`
}

// DebuggerSetVariableValueResult type
type DebuggerSetVariableValueResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerSetVariableValue) Call(c *Call) (*DebuggerSetVariableValueResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerSetVariableValue", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerSetVariableValueResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerStepInto Steps into the function call.
type DebuggerStepInto struct {
	// BreakOnAsyncCall (experimental) Debugger will pause on the execution of the first async task which was scheduled
	// before next pause.
	BreakOnAsyncCall bool `json:"breakOnAsyncCall,omitempty"`
}

// DebuggerStepIntoResult type
type DebuggerStepIntoResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerStepInto) Call(c *Call) (*DebuggerStepIntoResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerStepInto", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerStepIntoResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerStepOut Steps out of the function call.
type DebuggerStepOut struct {
}

// DebuggerStepOutResult type
type DebuggerStepOutResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerStepOut) Call(c *Call) (*DebuggerStepOutResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerStepOut", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerStepOutResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DebuggerStepOver Steps over the statement.
type DebuggerStepOver struct {
}

// DebuggerStepOverResult type
type DebuggerStepOverResult struct {
}

// Call of the command, sessionID is optional.
func (m DebuggerStepOver) Call(c *Call) (*DebuggerStepOverResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DebuggerStepOver", m)
	if err != nil {
		return nil, err
	}

	var res DebuggerStepOverResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}