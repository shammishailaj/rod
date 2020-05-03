// This file is generated by "./lib/proto/cmd/gen"

package proto

// TracingMemoryDumpConfig Configuration for memory dump. Used only when "memory-infra" category is enabled.
type TracingMemoryDumpConfig map[string]interface{}

// TracingTraceConfig ...
type TracingTraceConfig struct {
	// RecordMode Controls how the trace buffer stores data.
	RecordMode string `json:"recordMode,omitempty"`

	// EnableSampling Turns on JavaScript stack sampling.
	EnableSampling bool `json:"enableSampling,omitempty"`

	// EnableSystrace Turns on system tracing.
	EnableSystrace bool `json:"enableSystrace,omitempty"`

	// EnableArgumentFilter Turns on argument filter.
	EnableArgumentFilter bool `json:"enableArgumentFilter,omitempty"`

	// IncludedCategories Included category filters.
	IncludedCategories []string `json:"includedCategories,omitempty"`

	// ExcludedCategories Excluded category filters.
	ExcludedCategories []string `json:"excludedCategories,omitempty"`

	// SyntheticDelays Configuration to synthesize the delays in tracing.
	SyntheticDelays []string `json:"syntheticDelays,omitempty"`

	// MemoryDumpConfig Configuration for memory dump triggers. Used only when "memory-infra" category is enabled.
	MemoryDumpConfig *TracingMemoryDumpConfig `json:"memoryDumpConfig,omitempty"`
}

// TracingStreamFormat Data format of a trace. Can be either the legacy JSON format or the
// protocol buffer format. Note that the JSON format will be deprecated soon.
type TracingStreamFormat string

const (
	// TracingStreamFormatJSON enum value
	TracingStreamFormatJSON TracingStreamFormat = "json"

	// TracingStreamFormatProto enum value
	TracingStreamFormatProto TracingStreamFormat = "proto"
)

// TracingStreamCompression Compression type to use for traces returned via streams.
type TracingStreamCompression string

const (
	// TracingStreamCompressionNone enum value
	TracingStreamCompressionNone TracingStreamCompression = "none"

	// TracingStreamCompressionGzip enum value
	TracingStreamCompressionGzip TracingStreamCompression = "gzip"
)