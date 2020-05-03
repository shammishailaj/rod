// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// DatabaseDisable Disables database tracking, prevents database events from being sent to the client.
type DatabaseDisable struct {
}

// DatabaseDisableResult type
type DatabaseDisableResult struct {
}

// Call of the command, sessionID is optional.
func (m DatabaseDisable) Call(c *Call) (*DatabaseDisableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DatabaseDisable", m)
	if err != nil {
		return nil, err
	}

	var res DatabaseDisableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DatabaseEnable Enables database tracking, database events will now be delivered to the client.
type DatabaseEnable struct {
}

// DatabaseEnableResult type
type DatabaseEnableResult struct {
}

// Call of the command, sessionID is optional.
func (m DatabaseEnable) Call(c *Call) (*DatabaseEnableResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DatabaseEnable", m)
	if err != nil {
		return nil, err
	}

	var res DatabaseEnableResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DatabaseExecuteSQL ...
type DatabaseExecuteSQL struct {
	// DatabaseID ...
	DatabaseID *DatabaseDatabaseID `json:"databaseId"`

	// Query ...
	Query string `json:"query"`
}

// DatabaseExecuteSQLResult type
type DatabaseExecuteSQLResult struct {
	// ColumnNames ...
	ColumnNames []string `json:"columnNames,omitempty"`

	// Values ...
	Values []interface{} `json:"values,omitempty"`

	// SQLError ...
	SQLError *DatabaseError `json:"sqlError,omitempty"`
}

// Call of the command, sessionID is optional.
func (m DatabaseExecuteSQL) Call(c *Call) (*DatabaseExecuteSQLResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DatabaseExecuteSQL", m)
	if err != nil {
		return nil, err
	}

	var res DatabaseExecuteSQLResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// DatabaseGetDatabaseTableNames ...
type DatabaseGetDatabaseTableNames struct {
	// DatabaseID ...
	DatabaseID *DatabaseDatabaseID `json:"databaseId"`
}

// DatabaseGetDatabaseTableNamesResult type
type DatabaseGetDatabaseTableNamesResult struct {
	// TableNames ...
	TableNames []string `json:"tableNames"`
}

// Call of the command, sessionID is optional.
func (m DatabaseGetDatabaseTableNames) Call(c *Call) (*DatabaseGetDatabaseTableNamesResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "DatabaseGetDatabaseTableNames", m)
	if err != nil {
		return nil, err
	}

	var res DatabaseGetDatabaseTableNamesResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}
