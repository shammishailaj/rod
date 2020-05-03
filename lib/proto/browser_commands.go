// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// BrowserSetPermission (experimental) Set permission settings for given origin.
type BrowserSetPermission struct {
	// Origin Origin the permission applies to.
	Origin string `json:"origin"`

	// Permission Descriptor of permission to override.
	Permission *BrowserPermissionDescriptor `json:"permission"`

	// Setting Setting of the permission.
	Setting *BrowserPermissionSetting `json:"setting"`

	// BrowserContextID Context to override. When omitted, default browser context is used.
	BrowserContextID *BrowserBrowserContextID `json:"browserContextId,omitempty"`
}

// BrowserSetPermissionResult type
type BrowserSetPermissionResult struct {
}

// Call of the command, sessionID is optional.
func (m BrowserSetPermission) Call(c *Call) (*BrowserSetPermissionResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserSetPermission", m)
	if err != nil {
		return nil, err
	}

	var res BrowserSetPermissionResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserGrantPermissions (experimental) Grant specific permissions to the given origin and reject all others.
type BrowserGrantPermissions struct {
	// Origin ...
	Origin string `json:"origin"`

	// Permissions ...
	Permissions []*BrowserPermissionType `json:"permissions"`

	// BrowserContextID BrowserContext to override permissions. When omitted, default browser context is used.
	BrowserContextID *BrowserBrowserContextID `json:"browserContextId,omitempty"`
}

// BrowserGrantPermissionsResult type
type BrowserGrantPermissionsResult struct {
}

// Call of the command, sessionID is optional.
func (m BrowserGrantPermissions) Call(c *Call) (*BrowserGrantPermissionsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserGrantPermissions", m)
	if err != nil {
		return nil, err
	}

	var res BrowserGrantPermissionsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserResetPermissions (experimental) Reset all permission management for all origins.
type BrowserResetPermissions struct {
	// BrowserContextID BrowserContext to reset permissions. When omitted, default browser context is used.
	BrowserContextID *BrowserBrowserContextID `json:"browserContextId,omitempty"`
}

// BrowserResetPermissionsResult type
type BrowserResetPermissionsResult struct {
}

// Call of the command, sessionID is optional.
func (m BrowserResetPermissions) Call(c *Call) (*BrowserResetPermissionsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserResetPermissions", m)
	if err != nil {
		return nil, err
	}

	var res BrowserResetPermissionsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserClose Close browser gracefully.
type BrowserClose struct {
}

// BrowserCloseResult type
type BrowserCloseResult struct {
}

// Call of the command, sessionID is optional.
func (m BrowserClose) Call(c *Call) (*BrowserCloseResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserClose", m)
	if err != nil {
		return nil, err
	}

	var res BrowserCloseResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserCrash (experimental) Crashes browser on the main thread.
type BrowserCrash struct {
}

// BrowserCrashResult type
type BrowserCrashResult struct {
}

// Call of the command, sessionID is optional.
func (m BrowserCrash) Call(c *Call) (*BrowserCrashResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserCrash", m)
	if err != nil {
		return nil, err
	}

	var res BrowserCrashResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserCrashGpuProcess (experimental) Crashes GPU process.
type BrowserCrashGpuProcess struct {
}

// BrowserCrashGpuProcessResult type
type BrowserCrashGpuProcessResult struct {
}

// Call of the command, sessionID is optional.
func (m BrowserCrashGpuProcess) Call(c *Call) (*BrowserCrashGpuProcessResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserCrashGpuProcess", m)
	if err != nil {
		return nil, err
	}

	var res BrowserCrashGpuProcessResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserGetVersion Returns version information.
type BrowserGetVersion struct {
}

// BrowserGetVersionResult type
type BrowserGetVersionResult struct {
	// ProtocolVersion Protocol version.
	ProtocolVersion string `json:"protocolVersion"`

	// Product Product name.
	Product string `json:"product"`

	// Revision Product revision.
	Revision string `json:"revision"`

	// UserAgent User-Agent.
	UserAgent string `json:"userAgent"`

	// JsVersion V8 version.
	JsVersion string `json:"jsVersion"`
}

// Call of the command, sessionID is optional.
func (m BrowserGetVersion) Call(c *Call) (*BrowserGetVersionResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserGetVersion", m)
	if err != nil {
		return nil, err
	}

	var res BrowserGetVersionResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserGetBrowserCommandLine (experimental) Returns the command line switches for the browser process if, and only if
// --enable-automation is on the commandline.
type BrowserGetBrowserCommandLine struct {
}

// BrowserGetBrowserCommandLineResult type
type BrowserGetBrowserCommandLineResult struct {
	// Arguments Commandline parameters
	Arguments []string `json:"arguments"`
}

// Call of the command, sessionID is optional.
func (m BrowserGetBrowserCommandLine) Call(c *Call) (*BrowserGetBrowserCommandLineResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserGetBrowserCommandLine", m)
	if err != nil {
		return nil, err
	}

	var res BrowserGetBrowserCommandLineResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserGetHistograms (experimental) Get Chrome histograms.
type BrowserGetHistograms struct {
	// Query Requested substring in name. Only histograms which have query as a
	// substring in their name are extracted. An empty or absent query returns
	// all histograms.
	Query string `json:"query,omitempty"`

	// Delta If true, retrieve delta since last call.
	Delta bool `json:"delta,omitempty"`
}

// BrowserGetHistogramsResult type
type BrowserGetHistogramsResult struct {
	// Histograms Histograms.
	Histograms []*BrowserHistogram `json:"histograms"`
}

// Call of the command, sessionID is optional.
func (m BrowserGetHistograms) Call(c *Call) (*BrowserGetHistogramsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserGetHistograms", m)
	if err != nil {
		return nil, err
	}

	var res BrowserGetHistogramsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserGetHistogram (experimental) Get a Chrome histogram by name.
type BrowserGetHistogram struct {
	// Name Requested histogram name.
	Name string `json:"name"`

	// Delta If true, retrieve delta since last call.
	Delta bool `json:"delta,omitempty"`
}

// BrowserGetHistogramResult type
type BrowserGetHistogramResult struct {
	// Histogram Histogram.
	Histogram *BrowserHistogram `json:"histogram"`
}

// Call of the command, sessionID is optional.
func (m BrowserGetHistogram) Call(c *Call) (*BrowserGetHistogramResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserGetHistogram", m)
	if err != nil {
		return nil, err
	}

	var res BrowserGetHistogramResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserGetWindowBounds (experimental) Get position and size of the browser window.
type BrowserGetWindowBounds struct {
	// WindowID Browser window id.
	WindowID *BrowserWindowID `json:"windowId"`
}

// BrowserGetWindowBoundsResult type
type BrowserGetWindowBoundsResult struct {
	// Bounds Bounds information of the window. When window state is 'minimized', the restored window
	// position and size are returned.
	Bounds *BrowserBounds `json:"bounds"`
}

// Call of the command, sessionID is optional.
func (m BrowserGetWindowBounds) Call(c *Call) (*BrowserGetWindowBoundsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserGetWindowBounds", m)
	if err != nil {
		return nil, err
	}

	var res BrowserGetWindowBoundsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserGetWindowForTarget (experimental) Get the browser window that contains the devtools target.
type BrowserGetWindowForTarget struct {
	// TargetID Devtools agent host id. If called as a part of the session, associated targetId is used.
	TargetID *TargetTargetID `json:"targetId,omitempty"`
}

// BrowserGetWindowForTargetResult type
type BrowserGetWindowForTargetResult struct {
	// WindowID Browser window id.
	WindowID *BrowserWindowID `json:"windowId"`

	// Bounds Bounds information of the window. When window state is 'minimized', the restored window
	// position and size are returned.
	Bounds *BrowserBounds `json:"bounds"`
}

// Call of the command, sessionID is optional.
func (m BrowserGetWindowForTarget) Call(c *Call) (*BrowserGetWindowForTargetResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserGetWindowForTarget", m)
	if err != nil {
		return nil, err
	}

	var res BrowserGetWindowForTargetResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserSetWindowBounds (experimental) Set position and/or size of the browser window.
type BrowserSetWindowBounds struct {
	// WindowID Browser window id.
	WindowID *BrowserWindowID `json:"windowId"`

	// Bounds New window bounds. The 'minimized', 'maximized' and 'fullscreen' states cannot be combined
	// with 'left', 'top', 'width' or 'height'. Leaves unspecified fields unchanged.
	Bounds *BrowserBounds `json:"bounds"`
}

// BrowserSetWindowBoundsResult type
type BrowserSetWindowBoundsResult struct {
}

// Call of the command, sessionID is optional.
func (m BrowserSetWindowBounds) Call(c *Call) (*BrowserSetWindowBoundsResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserSetWindowBounds", m)
	if err != nil {
		return nil, err
	}

	var res BrowserSetWindowBoundsResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// BrowserSetDockTile (experimental) Set dock tile details, platform-specific.
type BrowserSetDockTile struct {
	// BadgeLabel ...
	BadgeLabel string `json:"badgeLabel,omitempty"`

	// Image Png encoded image.
	Image []byte `json:"image,omitempty"`
}

// BrowserSetDockTileResult type
type BrowserSetDockTileResult struct {
}

// Call of the command, sessionID is optional.
func (m BrowserSetDockTile) Call(c *Call) (*BrowserSetDockTileResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "BrowserSetDockTile", m)
	if err != nil {
		return nil, err
	}

	var res BrowserSetDockTileResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}
