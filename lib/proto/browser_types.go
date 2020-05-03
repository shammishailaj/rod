// This file is generated by "./lib/proto/cmd/gen"

package proto

// BrowserBrowserContextID (experimental) ...
type BrowserBrowserContextID string

// BrowserWindowID (experimental) ...
type BrowserWindowID int64

// BrowserWindowState (experimental) The state of the browser window.
type BrowserWindowState string

const (
	// BrowserWindowStateNormal enum value
	BrowserWindowStateNormal BrowserWindowState = "normal"

	// BrowserWindowStateMinimized enum value
	BrowserWindowStateMinimized BrowserWindowState = "minimized"

	// BrowserWindowStateMaximized enum value
	BrowserWindowStateMaximized BrowserWindowState = "maximized"

	// BrowserWindowStateFullscreen enum value
	BrowserWindowStateFullscreen BrowserWindowState = "fullscreen"
)

// BrowserBounds (experimental) Browser window bounds information
type BrowserBounds struct {
	// Left The offset from the left edge of the screen to the window in pixels.
	Left int64 `json:"left,omitempty"`

	// Top The offset from the top edge of the screen to the window in pixels.
	Top int64 `json:"top,omitempty"`

	// Width The window width in pixels.
	Width int64 `json:"width,omitempty"`

	// Height The window height in pixels.
	Height int64 `json:"height,omitempty"`

	// WindowState The window state. Default to normal.
	WindowState *BrowserWindowState `json:"windowState,omitempty"`
}

// BrowserPermissionType (experimental) ...
type BrowserPermissionType string

const (
	// BrowserPermissionTypeAccessibilityEvents enum value
	BrowserPermissionTypeAccessibilityEvents BrowserPermissionType = "accessibilityEvents"

	// BrowserPermissionTypeAudioCapture enum value
	BrowserPermissionTypeAudioCapture BrowserPermissionType = "audioCapture"

	// BrowserPermissionTypeBackgroundSync enum value
	BrowserPermissionTypeBackgroundSync BrowserPermissionType = "backgroundSync"

	// BrowserPermissionTypeBackgroundFetch enum value
	BrowserPermissionTypeBackgroundFetch BrowserPermissionType = "backgroundFetch"

	// BrowserPermissionTypeClipboardReadWrite enum value
	BrowserPermissionTypeClipboardReadWrite BrowserPermissionType = "clipboardReadWrite"

	// BrowserPermissionTypeClipboardSanitizedWrite enum value
	BrowserPermissionTypeClipboardSanitizedWrite BrowserPermissionType = "clipboardSanitizedWrite"

	// BrowserPermissionTypeDurableStorage enum value
	BrowserPermissionTypeDurableStorage BrowserPermissionType = "durableStorage"

	// BrowserPermissionTypeFlash enum value
	BrowserPermissionTypeFlash BrowserPermissionType = "flash"

	// BrowserPermissionTypeGeolocation enum value
	BrowserPermissionTypeGeolocation BrowserPermissionType = "geolocation"

	// BrowserPermissionTypeMidi enum value
	BrowserPermissionTypeMidi BrowserPermissionType = "midi"

	// BrowserPermissionTypeMidiSysex enum value
	BrowserPermissionTypeMidiSysex BrowserPermissionType = "midiSysex"

	// BrowserPermissionTypeNfc enum value
	BrowserPermissionTypeNfc BrowserPermissionType = "nfc"

	// BrowserPermissionTypeNotifications enum value
	BrowserPermissionTypeNotifications BrowserPermissionType = "notifications"

	// BrowserPermissionTypePaymentHandler enum value
	BrowserPermissionTypePaymentHandler BrowserPermissionType = "paymentHandler"

	// BrowserPermissionTypePeriodicBackgroundSync enum value
	BrowserPermissionTypePeriodicBackgroundSync BrowserPermissionType = "periodicBackgroundSync"

	// BrowserPermissionTypeProtectedMediaIdentifier enum value
	BrowserPermissionTypeProtectedMediaIdentifier BrowserPermissionType = "protectedMediaIdentifier"

	// BrowserPermissionTypeSensors enum value
	BrowserPermissionTypeSensors BrowserPermissionType = "sensors"

	// BrowserPermissionTypeVideoCapture enum value
	BrowserPermissionTypeVideoCapture BrowserPermissionType = "videoCapture"

	// BrowserPermissionTypeIdleDetection enum value
	BrowserPermissionTypeIdleDetection BrowserPermissionType = "idleDetection"

	// BrowserPermissionTypeWakeLockScreen enum value
	BrowserPermissionTypeWakeLockScreen BrowserPermissionType = "wakeLockScreen"

	// BrowserPermissionTypeWakeLockSystem enum value
	BrowserPermissionTypeWakeLockSystem BrowserPermissionType = "wakeLockSystem"
)

// BrowserPermissionSetting (experimental) ...
type BrowserPermissionSetting string

const (
	// BrowserPermissionSettingGranted enum value
	BrowserPermissionSettingGranted BrowserPermissionSetting = "granted"

	// BrowserPermissionSettingDenied enum value
	BrowserPermissionSettingDenied BrowserPermissionSetting = "denied"

	// BrowserPermissionSettingPrompt enum value
	BrowserPermissionSettingPrompt BrowserPermissionSetting = "prompt"
)

// BrowserPermissionDescriptor (experimental) Definition of PermissionDescriptor defined in the Permissions API:
// https://w3c.github.io/permissions/#dictdef-permissiondescriptor.
type BrowserPermissionDescriptor struct {
	// Name Name of permission.
	// See https://cs.chromium.org/chromium/src/third_party/blink/renderer/modules/permissions/permission_descriptor.idl for valid permission names.
	Name string `json:"name"`

	// Sysex For "midi" permission, may also specify sysex control.
	Sysex bool `json:"sysex,omitempty"`

	// UserVisibleOnly For "push" permission, may specify userVisibleOnly.
	// Note that userVisibleOnly = true is the only currently supported type.
	UserVisibleOnly bool `json:"userVisibleOnly,omitempty"`

	// Type For "wake-lock" permission, must specify type as either "screen" or "system".
	Type string `json:"type,omitempty"`

	// AllowWithoutSanitization For "clipboard" permission, may specify allowWithoutSanitization.
	AllowWithoutSanitization bool `json:"allowWithoutSanitization,omitempty"`
}

// BrowserBucket (experimental) Chrome histogram bucket.
type BrowserBucket struct {
	// Low Minimum value (inclusive).
	Low int64 `json:"low"`

	// High Maximum value (exclusive).
	High int64 `json:"high"`

	// Count Number of samples.
	Count int64 `json:"count"`
}

// BrowserHistogram (experimental) Chrome histogram.
type BrowserHistogram struct {
	// Name Name.
	Name string `json:"name"`

	// Sum Sum of sample values.
	Sum int64 `json:"sum"`

	// Count Total number of samples.
	Count int64 `json:"count"`

	// Buckets Buckets.
	Buckets []*BrowserBucket `json:"buckets"`
}
