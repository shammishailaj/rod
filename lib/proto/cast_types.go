// This file is generated by "./lib/proto/cmd/gen"

package proto

// CastSink ...
type CastSink struct {
	// Name ...
	Name string `json:"name"`

	// ID ...
	ID string `json:"id"`

	// Session Text describing the current session. Present only if there is an active
	// session on the sink.
	Session string `json:"session,omitempty"`
}
