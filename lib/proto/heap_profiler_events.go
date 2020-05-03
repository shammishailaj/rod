// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// HeapProfilerAddHeapSnapshotChunk ...
type HeapProfilerAddHeapSnapshotChunk struct {
	// Chunk ...
	Chunk string `json:"chunk"`
}

// MethodName interface
func (evt HeapProfilerAddHeapSnapshotChunk) MethodName() string {
	return "HeapProfiler.addHeapSnapshotChunk"
}

// Load json
func (evt HeapProfilerAddHeapSnapshotChunk) Load(b []byte) *HeapProfilerAddHeapSnapshotChunk {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// HeapProfilerHeapStatsUpdate If heap objects tracking has been started then backend may send update for one or more fragments
type HeapProfilerHeapStatsUpdate struct {
	// StatsUpdate An array of triplets. Each triplet describes a fragment. The first integer is the fragment
	// index, the second integer is a total count of objects for the fragment, the third integer is
	// a total size of the objects for the fragment.
	StatsUpdate []int64 `json:"statsUpdate"`
}

// MethodName interface
func (evt HeapProfilerHeapStatsUpdate) MethodName() string {
	return "HeapProfiler.heapStatsUpdate"
}

// Load json
func (evt HeapProfilerHeapStatsUpdate) Load(b []byte) *HeapProfilerHeapStatsUpdate {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// HeapProfilerLastSeenObjectID If heap objects tracking has been started then backend regularly sends a current value for last
// seen object id and corresponding timestamp. If the were changes in the heap since last event
// then one or more heapStatsUpdate events will be sent before a new lastSeenObjectId event.
type HeapProfilerLastSeenObjectID struct {
	// LastSeenObjectID ...
	LastSeenObjectID int64 `json:"lastSeenObjectId"`

	// Timestamp ...
	Timestamp float64 `json:"timestamp"`
}

// MethodName interface
func (evt HeapProfilerLastSeenObjectID) MethodName() string {
	return "HeapProfiler.lastSeenObjectId"
}

// Load json
func (evt HeapProfilerLastSeenObjectID) Load(b []byte) *HeapProfilerLastSeenObjectID {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// HeapProfilerReportHeapSnapshotProgress ...
type HeapProfilerReportHeapSnapshotProgress struct {
	// Done ...
	Done int64 `json:"done"`

	// Total ...
	Total int64 `json:"total"`

	// Finished ...
	Finished bool `json:"finished,omitempty"`
}

// MethodName interface
func (evt HeapProfilerReportHeapSnapshotProgress) MethodName() string {
	return "HeapProfiler.reportHeapSnapshotProgress"
}

// Load json
func (evt HeapProfilerReportHeapSnapshotProgress) Load(b []byte) *HeapProfilerReportHeapSnapshotProgress {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// HeapProfilerResetProfiles ...
type HeapProfilerResetProfiles struct {
}

// MethodName interface
func (evt HeapProfilerResetProfiles) MethodName() string {
	return "HeapProfiler.resetProfiles"
}

// Load json
func (evt HeapProfilerResetProfiles) Load(b []byte) *HeapProfilerResetProfiles {
	E(json.Unmarshal(b, &evt))
	return &evt
}