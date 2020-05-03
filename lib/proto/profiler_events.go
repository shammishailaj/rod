// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// ProfilerConsoleProfileFinished ...
type ProfilerConsoleProfileFinished struct {
	// ID ...
	ID string `json:"id"`

	// Location Location of console.profileEnd().
	Location *DebuggerLocation `json:"location"`

	// Profile ...
	Profile *ProfilerProfile `json:"profile"`

	// Title Profile title passed as an argument to console.profile().
	Title string `json:"title,omitempty"`
}

// MethodName interface
func (evt ProfilerConsoleProfileFinished) MethodName() string {
	return "Profiler.consoleProfileFinished"
}

// Load json
func (evt ProfilerConsoleProfileFinished) Load(b []byte) *ProfilerConsoleProfileFinished {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// ProfilerConsoleProfileStarted Sent when new profile recording is started using console.profile() call.
type ProfilerConsoleProfileStarted struct {
	// ID ...
	ID string `json:"id"`

	// Location Location of console.profile().
	Location *DebuggerLocation `json:"location"`

	// Title Profile title passed as an argument to console.profile().
	Title string `json:"title,omitempty"`
}

// MethodName interface
func (evt ProfilerConsoleProfileStarted) MethodName() string {
	return "Profiler.consoleProfileStarted"
}

// Load json
func (evt ProfilerConsoleProfileStarted) Load(b []byte) *ProfilerConsoleProfileStarted {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// ProfilerPreciseCoverageDeltaUpdate (experimental) Reports coverage delta since the last poll (either from an event like this, or from
// `takePreciseCoverage` for the current isolate. May only be sent if precise code
// coverage has been started. This event can be trigged by the embedder to, for example,
// trigger collection of coverage data immediatelly at a certain point in time.
type ProfilerPreciseCoverageDeltaUpdate struct {
	// Timestamp Monotonically increasing time (in seconds) when the coverage update was taken in the backend.
	Timestamp float64 `json:"timestamp"`

	// Occassion Identifier for distinguishing coverage events.
	Occassion string `json:"occassion"`

	// Result Coverage data for the current isolate.
	Result []*ProfilerScriptCoverage `json:"result"`
}

// MethodName interface
func (evt ProfilerPreciseCoverageDeltaUpdate) MethodName() string {
	return "Profiler.preciseCoverageDeltaUpdate"
}

// Load json
func (evt ProfilerPreciseCoverageDeltaUpdate) Load(b []byte) *ProfilerPreciseCoverageDeltaUpdate {
	E(json.Unmarshal(b, &evt))
	return &evt
}