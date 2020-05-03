// This file is generated by "./lib/proto/cmd/gen"

package proto

// HeadlessExperimentalScreenshotParams Encoding options for a screenshot.
type HeadlessExperimentalScreenshotParams struct {
	// Format Image compression format (defaults to png).
	Format string `json:"format,omitempty"`

	// Quality Compression quality from range [0..100] (jpeg only).
	Quality int64 `json:"quality,omitempty"`
}
