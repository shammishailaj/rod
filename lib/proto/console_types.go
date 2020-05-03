// This file is generated by "./lib/proto/cmd/gen"

package proto

// ConsoleConsoleMessage Console message.
type ConsoleConsoleMessage struct {
	// Source Message source.
	Source string `json:"source"`

	// Level Message severity.
	Level string `json:"level"`

	// Text Message text.
	Text string `json:"text"`

	// URL URL of the message origin.
	URL string `json:"url,omitempty"`

	// Line Line number in the resource that generated this message (1-based).
	Line int64 `json:"line,omitempty"`

	// Column Column number in the resource that generated this message (1-based).
	Column int64 `json:"column,omitempty"`
}