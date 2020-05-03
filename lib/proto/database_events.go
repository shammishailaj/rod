// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// DatabaseAddDatabase ...
type DatabaseAddDatabase struct {
	// Database ...
	Database *DatabaseDatabase `json:"database"`
}

// MethodName interface
func (evt DatabaseAddDatabase) MethodName() string {
	return "Database.addDatabase"
}

// Load json
func (evt DatabaseAddDatabase) Load(b []byte) *DatabaseAddDatabase {
	E(json.Unmarshal(b, &evt))
	return &evt
}
