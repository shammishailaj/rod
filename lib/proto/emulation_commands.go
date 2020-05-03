// This file is generated by "./lib/proto/cmd/gen"

package proto

import (
	"encoding/json"
)

// EmulationCanEmulate Tells whether emulation is supported.
type EmulationCanEmulate struct {
}

// EmulationCanEmulateResult type
type EmulationCanEmulateResult struct {
	// Result True if emulation is supported.
	Result bool `json:"result"`
}

// Call of the command, sessionID is optional.
func (m EmulationCanEmulate) Call(c *Call) (*EmulationCanEmulateResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationCanEmulate", m)
	if err != nil {
		return nil, err
	}

	var res EmulationCanEmulateResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationClearDeviceMetricsOverride Clears the overriden device metrics.
type EmulationClearDeviceMetricsOverride struct {
}

// EmulationClearDeviceMetricsOverrideResult type
type EmulationClearDeviceMetricsOverrideResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationClearDeviceMetricsOverride) Call(c *Call) (*EmulationClearDeviceMetricsOverrideResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationClearDeviceMetricsOverride", m)
	if err != nil {
		return nil, err
	}

	var res EmulationClearDeviceMetricsOverrideResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationClearGeolocationOverride Clears the overriden Geolocation Position and Error.
type EmulationClearGeolocationOverride struct {
}

// EmulationClearGeolocationOverrideResult type
type EmulationClearGeolocationOverrideResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationClearGeolocationOverride) Call(c *Call) (*EmulationClearGeolocationOverrideResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationClearGeolocationOverride", m)
	if err != nil {
		return nil, err
	}

	var res EmulationClearGeolocationOverrideResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationResetPageScaleFactor (experimental) Requests that page scale factor is reset to initial values.
type EmulationResetPageScaleFactor struct {
}

// EmulationResetPageScaleFactorResult type
type EmulationResetPageScaleFactorResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationResetPageScaleFactor) Call(c *Call) (*EmulationResetPageScaleFactorResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationResetPageScaleFactor", m)
	if err != nil {
		return nil, err
	}

	var res EmulationResetPageScaleFactorResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetFocusEmulationEnabled (experimental) Enables or disables simulating a focused and active page.
type EmulationSetFocusEmulationEnabled struct {
	// Enabled Whether to enable to disable focus emulation.
	Enabled bool `json:"enabled"`
}

// EmulationSetFocusEmulationEnabledResult type
type EmulationSetFocusEmulationEnabledResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetFocusEmulationEnabled) Call(c *Call) (*EmulationSetFocusEmulationEnabledResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetFocusEmulationEnabled", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetFocusEmulationEnabledResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetCPUThrottlingRate (experimental) Enables CPU throttling to emulate slow CPUs.
type EmulationSetCPUThrottlingRate struct {
	// Rate Throttling rate as a slowdown factor (1 is no throttle, 2 is 2x slowdown, etc).
	Rate float64 `json:"rate"`
}

// EmulationSetCPUThrottlingRateResult type
type EmulationSetCPUThrottlingRateResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetCPUThrottlingRate) Call(c *Call) (*EmulationSetCPUThrottlingRateResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetCPUThrottlingRate", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetCPUThrottlingRateResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetDefaultBackgroundColorOverride Sets or clears an override of the default background color of the frame. This override is used
// if the content does not specify one.
type EmulationSetDefaultBackgroundColorOverride struct {
	// Color RGBA of the default background color. If not specified, any existing override will be
	// cleared.
	Color *DOMRGBA `json:"color,omitempty"`
}

// EmulationSetDefaultBackgroundColorOverrideResult type
type EmulationSetDefaultBackgroundColorOverrideResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetDefaultBackgroundColorOverride) Call(c *Call) (*EmulationSetDefaultBackgroundColorOverrideResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetDefaultBackgroundColorOverride", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetDefaultBackgroundColorOverrideResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetDeviceMetricsOverride Overrides the values of device screen dimensions (window.screen.width, window.screen.height,
// window.innerWidth, window.innerHeight, and "device-width"/"device-height"-related CSS media
// query results).
type EmulationSetDeviceMetricsOverride struct {
	// Width Overriding width value in pixels (minimum 0, maximum 10000000). 0 disables the override.
	Width int64 `json:"width"`

	// Height Overriding height value in pixels (minimum 0, maximum 10000000). 0 disables the override.
	Height int64 `json:"height"`

	// DeviceScaleFactor Overriding device scale factor value. 0 disables the override.
	DeviceScaleFactor float64 `json:"deviceScaleFactor"`

	// Mobile Whether to emulate mobile device. This includes viewport meta tag, overlay scrollbars, text
	// autosizing and more.
	Mobile bool `json:"mobile"`

	// Scale (experimental) Scale to apply to resulting view image.
	Scale float64 `json:"scale,omitempty"`

	// ScreenWidth (experimental) Overriding screen width value in pixels (minimum 0, maximum 10000000).
	ScreenWidth int64 `json:"screenWidth,omitempty"`

	// ScreenHeight (experimental) Overriding screen height value in pixels (minimum 0, maximum 10000000).
	ScreenHeight int64 `json:"screenHeight,omitempty"`

	// PositionX (experimental) Overriding view X position on screen in pixels (minimum 0, maximum 10000000).
	PositionX int64 `json:"positionX,omitempty"`

	// PositionY (experimental) Overriding view Y position on screen in pixels (minimum 0, maximum 10000000).
	PositionY int64 `json:"positionY,omitempty"`

	// DontSetVisibleSize (experimental) Do not set visible view size, rely upon explicit setVisibleSize call.
	DontSetVisibleSize bool `json:"dontSetVisibleSize,omitempty"`

	// ScreenOrientation Screen orientation override.
	ScreenOrientation *EmulationScreenOrientation `json:"screenOrientation,omitempty"`

	// Viewport (experimental) If set, the visible area of the page will be overridden to this viewport. This viewport
	// change is not observed by the page, e.g. viewport-relative elements do not change positions.
	Viewport *PageViewport `json:"viewport,omitempty"`
}

// EmulationSetDeviceMetricsOverrideResult type
type EmulationSetDeviceMetricsOverrideResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetDeviceMetricsOverride) Call(c *Call) (*EmulationSetDeviceMetricsOverrideResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetDeviceMetricsOverride", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetDeviceMetricsOverrideResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetScrollbarsHidden (experimental) ...
type EmulationSetScrollbarsHidden struct {
	// Hidden Whether scrollbars should be always hidden.
	Hidden bool `json:"hidden"`
}

// EmulationSetScrollbarsHiddenResult type
type EmulationSetScrollbarsHiddenResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetScrollbarsHidden) Call(c *Call) (*EmulationSetScrollbarsHiddenResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetScrollbarsHidden", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetScrollbarsHiddenResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetDocumentCookieDisabled (experimental) ...
type EmulationSetDocumentCookieDisabled struct {
	// Disabled Whether document.coookie API should be disabled.
	Disabled bool `json:"disabled"`
}

// EmulationSetDocumentCookieDisabledResult type
type EmulationSetDocumentCookieDisabledResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetDocumentCookieDisabled) Call(c *Call) (*EmulationSetDocumentCookieDisabledResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetDocumentCookieDisabled", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetDocumentCookieDisabledResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationEmulationSetEmitTouchEventsForMouseConfiguration Enum of possible values
type EmulationEmulationSetEmitTouchEventsForMouseConfiguration string

const (
	// EmulationEmulationSetEmitTouchEventsForMouseConfigurationMobile enum value
	EmulationEmulationSetEmitTouchEventsForMouseConfigurationMobile EmulationEmulationSetEmitTouchEventsForMouseConfiguration = "mobile"

	// EmulationEmulationSetEmitTouchEventsForMouseConfigurationDesktop enum value
	EmulationEmulationSetEmitTouchEventsForMouseConfigurationDesktop EmulationEmulationSetEmitTouchEventsForMouseConfiguration = "desktop"
)

// EmulationSetEmitTouchEventsForMouse (experimental) ...
type EmulationSetEmitTouchEventsForMouse struct {
	// Enabled Whether touch emulation based on mouse input should be enabled.
	Enabled bool `json:"enabled"`

	// Configuration Touch/gesture events configuration. Default: current platform.
	Configuration EmulationEmulationSetEmitTouchEventsForMouseConfiguration `json:"configuration,omitempty"`
}

// EmulationSetEmitTouchEventsForMouseResult type
type EmulationSetEmitTouchEventsForMouseResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetEmitTouchEventsForMouse) Call(c *Call) (*EmulationSetEmitTouchEventsForMouseResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetEmitTouchEventsForMouse", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetEmitTouchEventsForMouseResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetEmulatedMedia Emulates the given media type or media feature for CSS media queries.
type EmulationSetEmulatedMedia struct {
	// Media Media type to emulate. Empty string disables the override.
	Media string `json:"media,omitempty"`

	// Features Media features to emulate.
	Features []*EmulationMediaFeature `json:"features,omitempty"`
}

// EmulationSetEmulatedMediaResult type
type EmulationSetEmulatedMediaResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetEmulatedMedia) Call(c *Call) (*EmulationSetEmulatedMediaResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetEmulatedMedia", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetEmulatedMediaResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetGeolocationOverride Overrides the Geolocation Position or Error. Omitting any of the parameters emulates position
// unavailable.
type EmulationSetGeolocationOverride struct {
	// Latitude Mock latitude
	Latitude float64 `json:"latitude,omitempty"`

	// Longitude Mock longitude
	Longitude float64 `json:"longitude,omitempty"`

	// Accuracy Mock accuracy
	Accuracy float64 `json:"accuracy,omitempty"`
}

// EmulationSetGeolocationOverrideResult type
type EmulationSetGeolocationOverrideResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetGeolocationOverride) Call(c *Call) (*EmulationSetGeolocationOverrideResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetGeolocationOverride", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetGeolocationOverrideResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetNavigatorOverrides (deprecated) (experimental) Overrides value returned by the javascript navigator object.
type EmulationSetNavigatorOverrides struct {
	// Platform The platform navigator.platform should return.
	Platform string `json:"platform"`
}

// EmulationSetNavigatorOverridesResult type
type EmulationSetNavigatorOverridesResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetNavigatorOverrides) Call(c *Call) (*EmulationSetNavigatorOverridesResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetNavigatorOverrides", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetNavigatorOverridesResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetPageScaleFactor (experimental) Sets a specified page scale factor.
type EmulationSetPageScaleFactor struct {
	// PageScaleFactor Page scale factor.
	PageScaleFactor float64 `json:"pageScaleFactor"`
}

// EmulationSetPageScaleFactorResult type
type EmulationSetPageScaleFactorResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetPageScaleFactor) Call(c *Call) (*EmulationSetPageScaleFactorResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetPageScaleFactor", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetPageScaleFactorResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetScriptExecutionDisabled Switches script execution in the page.
type EmulationSetScriptExecutionDisabled struct {
	// Value Whether script execution should be disabled in the page.
	Value bool `json:"value"`
}

// EmulationSetScriptExecutionDisabledResult type
type EmulationSetScriptExecutionDisabledResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetScriptExecutionDisabled) Call(c *Call) (*EmulationSetScriptExecutionDisabledResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetScriptExecutionDisabled", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetScriptExecutionDisabledResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetTouchEmulationEnabled Enables touch on platforms which do not support them.
type EmulationSetTouchEmulationEnabled struct {
	// Enabled Whether the touch event emulation should be enabled.
	Enabled bool `json:"enabled"`

	// MaxTouchPoints Maximum touch points supported. Defaults to one.
	MaxTouchPoints int64 `json:"maxTouchPoints,omitempty"`
}

// EmulationSetTouchEmulationEnabledResult type
type EmulationSetTouchEmulationEnabledResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetTouchEmulationEnabled) Call(c *Call) (*EmulationSetTouchEmulationEnabledResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetTouchEmulationEnabled", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetTouchEmulationEnabledResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetVirtualTimePolicy (experimental) Turns on virtual time for all frames (replacing real-time with a synthetic time source) and sets
// the current virtual time policy.  Note this supersedes any previous time budget.
type EmulationSetVirtualTimePolicy struct {
	// Policy ...
	Policy *EmulationVirtualTimePolicy `json:"policy"`

	// Budget If set, after this many virtual milliseconds have elapsed virtual time will be paused and a
	// virtualTimeBudgetExpired event is sent.
	Budget float64 `json:"budget,omitempty"`

	// MaxVirtualTimeTaskStarvationCount If set this specifies the maximum number of tasks that can be run before virtual is forced
	// forwards to prevent deadlock.
	MaxVirtualTimeTaskStarvationCount int64 `json:"maxVirtualTimeTaskStarvationCount,omitempty"`

	// WaitForNavigation If set the virtual time policy change should be deferred until any frame starts navigating.
	// Note any previous deferred policy change is superseded.
	WaitForNavigation bool `json:"waitForNavigation,omitempty"`

	// InitialVirtualTime If set, base::Time::Now will be overriden to initially return this value.
	InitialVirtualTime *NetworkTimeSinceEpoch `json:"initialVirtualTime,omitempty"`
}

// EmulationSetVirtualTimePolicyResult type
type EmulationSetVirtualTimePolicyResult struct {
	// VirtualTimeTicksBase Absolute timestamp at which virtual time was first enabled (up time in milliseconds).
	VirtualTimeTicksBase float64 `json:"virtualTimeTicksBase"`
}

// Call of the command, sessionID is optional.
func (m EmulationSetVirtualTimePolicy) Call(c *Call) (*EmulationSetVirtualTimePolicyResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetVirtualTimePolicy", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetVirtualTimePolicyResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetTimezoneOverride (experimental) Overrides default host system timezone with the specified one.
type EmulationSetTimezoneOverride struct {
	// TimezoneID The timezone identifier. If empty, disables the override and
	// restores default host system timezone.
	TimezoneID string `json:"timezoneId"`
}

// EmulationSetTimezoneOverrideResult type
type EmulationSetTimezoneOverrideResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetTimezoneOverride) Call(c *Call) (*EmulationSetTimezoneOverrideResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetTimezoneOverride", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetTimezoneOverrideResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetVisibleSize (deprecated) (experimental) Resizes the frame/viewport of the page. Note that this does not affect the frame's container
// (e.g. browser window). Can be used to produce screenshots of the specified size. Not supported
// on Android.
type EmulationSetVisibleSize struct {
	// Width Frame width (DIP).
	Width int64 `json:"width"`

	// Height Frame height (DIP).
	Height int64 `json:"height"`
}

// EmulationSetVisibleSizeResult type
type EmulationSetVisibleSizeResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetVisibleSize) Call(c *Call) (*EmulationSetVisibleSizeResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetVisibleSize", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetVisibleSizeResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// EmulationSetUserAgentOverride Allows overriding user agent with the given string.
type EmulationSetUserAgentOverride struct {
	// UserAgent User agent to use.
	UserAgent string `json:"userAgent"`

	// AcceptLanguage Browser langugage to emulate.
	AcceptLanguage string `json:"acceptLanguage,omitempty"`

	// Platform The platform navigator.platform should return.
	Platform string `json:"platform,omitempty"`
}

// EmulationSetUserAgentOverrideResult type
type EmulationSetUserAgentOverrideResult struct {
}

// Call of the command, sessionID is optional.
func (m EmulationSetUserAgentOverride) Call(c *Call) (*EmulationSetUserAgentOverrideResult, error) {
	bin, err := c.Client.Call(c.Context, c.SessionID, "EmulationSetUserAgentOverride", m)
	if err != nil {
		return nil, err
	}

	var res EmulationSetUserAgentOverrideResult
	err = json.Unmarshal(bin, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}
