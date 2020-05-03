// This file is generated by "./lib/proto/cmd/gen"

package proto

// NetworkResourceType Resource type as it was perceived by the rendering engine.
type NetworkResourceType string

const (
	// NetworkResourceTypeDocument enum value
	NetworkResourceTypeDocument NetworkResourceType = "Document"

	// NetworkResourceTypeStylesheet enum value
	NetworkResourceTypeStylesheet NetworkResourceType = "Stylesheet"

	// NetworkResourceTypeImage enum value
	NetworkResourceTypeImage NetworkResourceType = "Image"

	// NetworkResourceTypeMedia enum value
	NetworkResourceTypeMedia NetworkResourceType = "Media"

	// NetworkResourceTypeFont enum value
	NetworkResourceTypeFont NetworkResourceType = "Font"

	// NetworkResourceTypeScript enum value
	NetworkResourceTypeScript NetworkResourceType = "Script"

	// NetworkResourceTypeTextTrack enum value
	NetworkResourceTypeTextTrack NetworkResourceType = "TextTrack"

	// NetworkResourceTypeXHR enum value
	NetworkResourceTypeXHR NetworkResourceType = "XHR"

	// NetworkResourceTypeFetch enum value
	NetworkResourceTypeFetch NetworkResourceType = "Fetch"

	// NetworkResourceTypeEventSource enum value
	NetworkResourceTypeEventSource NetworkResourceType = "EventSource"

	// NetworkResourceTypeWebSocket enum value
	NetworkResourceTypeWebSocket NetworkResourceType = "WebSocket"

	// NetworkResourceTypeManifest enum value
	NetworkResourceTypeManifest NetworkResourceType = "Manifest"

	// NetworkResourceTypeSignedExchange enum value
	NetworkResourceTypeSignedExchange NetworkResourceType = "SignedExchange"

	// NetworkResourceTypePing enum value
	NetworkResourceTypePing NetworkResourceType = "Ping"

	// NetworkResourceTypeCSPViolationReport enum value
	NetworkResourceTypeCSPViolationReport NetworkResourceType = "CSPViolationReport"

	// NetworkResourceTypeOther enum value
	NetworkResourceTypeOther NetworkResourceType = "Other"
)

// NetworkLoaderID Unique loader identifier.
type NetworkLoaderID string

// NetworkRequestID Unique request identifier.
type NetworkRequestID string

// NetworkInterceptionID Unique intercepted request identifier.
type NetworkInterceptionID string

// NetworkErrorReason Network level fetch failure reason.
type NetworkErrorReason string

const (
	// NetworkErrorReasonFailed enum value
	NetworkErrorReasonFailed NetworkErrorReason = "Failed"

	// NetworkErrorReasonAborted enum value
	NetworkErrorReasonAborted NetworkErrorReason = "Aborted"

	// NetworkErrorReasonTimedOut enum value
	NetworkErrorReasonTimedOut NetworkErrorReason = "TimedOut"

	// NetworkErrorReasonAccessDenied enum value
	NetworkErrorReasonAccessDenied NetworkErrorReason = "AccessDenied"

	// NetworkErrorReasonConnectionClosed enum value
	NetworkErrorReasonConnectionClosed NetworkErrorReason = "ConnectionClosed"

	// NetworkErrorReasonConnectionReset enum value
	NetworkErrorReasonConnectionReset NetworkErrorReason = "ConnectionReset"

	// NetworkErrorReasonConnectionRefused enum value
	NetworkErrorReasonConnectionRefused NetworkErrorReason = "ConnectionRefused"

	// NetworkErrorReasonConnectionAborted enum value
	NetworkErrorReasonConnectionAborted NetworkErrorReason = "ConnectionAborted"

	// NetworkErrorReasonConnectionFailed enum value
	NetworkErrorReasonConnectionFailed NetworkErrorReason = "ConnectionFailed"

	// NetworkErrorReasonNameNotResolved enum value
	NetworkErrorReasonNameNotResolved NetworkErrorReason = "NameNotResolved"

	// NetworkErrorReasonInternetDisconnected enum value
	NetworkErrorReasonInternetDisconnected NetworkErrorReason = "InternetDisconnected"

	// NetworkErrorReasonAddressUnreachable enum value
	NetworkErrorReasonAddressUnreachable NetworkErrorReason = "AddressUnreachable"

	// NetworkErrorReasonBlockedByClient enum value
	NetworkErrorReasonBlockedByClient NetworkErrorReason = "BlockedByClient"

	// NetworkErrorReasonBlockedByResponse enum value
	NetworkErrorReasonBlockedByResponse NetworkErrorReason = "BlockedByResponse"
)

// NetworkTimeSinceEpoch UTC time in seconds, counted from January 1, 1970.
type NetworkTimeSinceEpoch float64

// NetworkMonotonicTime Monotonically increasing time in seconds since an arbitrary point in the past.
type NetworkMonotonicTime float64

// NetworkHeaders Request / response headers as keys / values of JSON object.
type NetworkHeaders map[string]interface{}

// NetworkConnectionType The underlying connection technology that the browser is supposedly using.
type NetworkConnectionType string

const (
	// NetworkConnectionTypeNone enum value
	NetworkConnectionTypeNone NetworkConnectionType = "none"

	// NetworkConnectionTypeCellular2g enum value
	NetworkConnectionTypeCellular2g NetworkConnectionType = "cellular2g"

	// NetworkConnectionTypeCellular3g enum value
	NetworkConnectionTypeCellular3g NetworkConnectionType = "cellular3g"

	// NetworkConnectionTypeCellular4g enum value
	NetworkConnectionTypeCellular4g NetworkConnectionType = "cellular4g"

	// NetworkConnectionTypeBluetooth enum value
	NetworkConnectionTypeBluetooth NetworkConnectionType = "bluetooth"

	// NetworkConnectionTypeEthernet enum value
	NetworkConnectionTypeEthernet NetworkConnectionType = "ethernet"

	// NetworkConnectionTypeWifi enum value
	NetworkConnectionTypeWifi NetworkConnectionType = "wifi"

	// NetworkConnectionTypeWimax enum value
	NetworkConnectionTypeWimax NetworkConnectionType = "wimax"

	// NetworkConnectionTypeOther enum value
	NetworkConnectionTypeOther NetworkConnectionType = "other"
)

// NetworkCookieSameSite Represents the cookie's 'SameSite' status:
// https://tools.ietf.org/html/draft-west-first-party-cookies
type NetworkCookieSameSite string

const (
	// NetworkCookieSameSiteStrict enum value
	NetworkCookieSameSiteStrict NetworkCookieSameSite = "Strict"

	// NetworkCookieSameSiteLax enum value
	NetworkCookieSameSiteLax NetworkCookieSameSite = "Lax"

	// NetworkCookieSameSiteNone enum value
	NetworkCookieSameSiteNone NetworkCookieSameSite = "None"
)

// NetworkCookiePriority (experimental) Represents the cookie's 'Priority' status:
// https://tools.ietf.org/html/draft-west-cookie-priority-00
type NetworkCookiePriority string

const (
	// NetworkCookiePriorityLow enum value
	NetworkCookiePriorityLow NetworkCookiePriority = "Low"

	// NetworkCookiePriorityMedium enum value
	NetworkCookiePriorityMedium NetworkCookiePriority = "Medium"

	// NetworkCookiePriorityHigh enum value
	NetworkCookiePriorityHigh NetworkCookiePriority = "High"
)

// NetworkResourceTiming Timing information for the request.
type NetworkResourceTiming struct {
	// RequestTime Timing's requestTime is a baseline in seconds, while the other numbers are ticks in
	// milliseconds relatively to this requestTime.
	RequestTime float64 `json:"requestTime"`

	// ProxyStart Started resolving proxy.
	ProxyStart float64 `json:"proxyStart"`

	// ProxyEnd Finished resolving proxy.
	ProxyEnd float64 `json:"proxyEnd"`

	// DNSStart Started DNS address resolve.
	DNSStart float64 `json:"dnsStart"`

	// DNSEnd Finished DNS address resolve.
	DNSEnd float64 `json:"dnsEnd"`

	// ConnectStart Started connecting to the remote host.
	ConnectStart float64 `json:"connectStart"`

	// ConnectEnd Connected to the remote host.
	ConnectEnd float64 `json:"connectEnd"`

	// SslStart Started SSL handshake.
	SslStart float64 `json:"sslStart"`

	// SslEnd Finished SSL handshake.
	SslEnd float64 `json:"sslEnd"`

	// WorkerStart (experimental) Started running ServiceWorker.
	WorkerStart float64 `json:"workerStart"`

	// WorkerReady (experimental) Finished Starting ServiceWorker.
	WorkerReady float64 `json:"workerReady"`

	// SendStart Started sending request.
	SendStart float64 `json:"sendStart"`

	// SendEnd Finished sending request.
	SendEnd float64 `json:"sendEnd"`

	// PushStart (experimental) Time the server started pushing request.
	PushStart float64 `json:"pushStart"`

	// PushEnd (experimental) Time the server finished pushing request.
	PushEnd float64 `json:"pushEnd"`

	// ReceiveHeadersEnd Finished receiving response headers.
	ReceiveHeadersEnd float64 `json:"receiveHeadersEnd"`
}

// NetworkResourcePriority Loading priority of a resource request.
type NetworkResourcePriority string

const (
	// NetworkResourcePriorityVeryLow enum value
	NetworkResourcePriorityVeryLow NetworkResourcePriority = "VeryLow"

	// NetworkResourcePriorityLow enum value
	NetworkResourcePriorityLow NetworkResourcePriority = "Low"

	// NetworkResourcePriorityMedium enum value
	NetworkResourcePriorityMedium NetworkResourcePriority = "Medium"

	// NetworkResourcePriorityHigh enum value
	NetworkResourcePriorityHigh NetworkResourcePriority = "High"

	// NetworkResourcePriorityVeryHigh enum value
	NetworkResourcePriorityVeryHigh NetworkResourcePriority = "VeryHigh"
)

// NetworkRequest HTTP request data.
type NetworkRequest struct {
	// URL Request URL (without fragment).
	URL string `json:"url"`

	// URLFragment Fragment of the requested URL starting with hash, if present.
	URLFragment string `json:"urlFragment,omitempty"`

	// Method HTTP request method.
	Method string `json:"method"`

	// Headers HTTP request headers.
	Headers *NetworkHeaders `json:"headers"`

	// PostData HTTP POST request data.
	PostData string `json:"postData,omitempty"`

	// HasPostData True when the request has POST data. Note that postData might still be omitted when this flag is true when the data is too long.
	HasPostData bool `json:"hasPostData,omitempty"`

	// MixedContentType The mixed content type of the request.
	MixedContentType *SecurityMixedContentType `json:"mixedContentType,omitempty"`

	// InitialPriority Priority of the resource request at the time request is sent.
	InitialPriority *NetworkResourcePriority `json:"initialPriority"`

	// ReferrerPolicy The referrer policy of the request, as defined in https://www.w3.org/TR/referrer-policy/
	ReferrerPolicy string `json:"referrerPolicy"`

	// IsLinkPreload Whether is loaded via link preload.
	IsLinkPreload bool `json:"isLinkPreload,omitempty"`
}

// NetworkSignedCertificateTimestamp Details of a signed certificate timestamp (SCT).
type NetworkSignedCertificateTimestamp struct {
	// Status Validation status.
	Status string `json:"status"`

	// Origin Origin.
	Origin string `json:"origin"`

	// LogDescription Log name / description.
	LogDescription string `json:"logDescription"`

	// LogID Log ID.
	LogID string `json:"logId"`

	// Timestamp Issuance date.
	Timestamp *NetworkTimeSinceEpoch `json:"timestamp"`

	// HashAlgorithm Hash algorithm.
	HashAlgorithm string `json:"hashAlgorithm"`

	// SignatureAlgorithm Signature algorithm.
	SignatureAlgorithm string `json:"signatureAlgorithm"`

	// SignatureData Signature data.
	SignatureData string `json:"signatureData"`
}

// NetworkSecurityDetails Security details about a request.
type NetworkSecurityDetails struct {
	// Protocol Protocol name (e.g. "TLS 1.2" or "QUIC").
	Protocol string `json:"protocol"`

	// KeyExchange Key Exchange used by the connection, or the empty string if not applicable.
	KeyExchange string `json:"keyExchange"`

	// KeyExchangeGroup (EC)DH group used by the connection, if applicable.
	KeyExchangeGroup string `json:"keyExchangeGroup,omitempty"`

	// Cipher Cipher name.
	Cipher string `json:"cipher"`

	// Mac TLS MAC. Note that AEAD ciphers do not have separate MACs.
	Mac string `json:"mac,omitempty"`

	// CertificateID Certificate ID value.
	CertificateID *SecurityCertificateID `json:"certificateId"`

	// SubjectName Certificate subject name.
	SubjectName string `json:"subjectName"`

	// SanList Subject Alternative Name (SAN) DNS names and IP addresses.
	SanList []string `json:"sanList"`

	// Issuer Name of the issuing CA.
	Issuer string `json:"issuer"`

	// ValidFrom Certificate valid from date.
	ValidFrom *NetworkTimeSinceEpoch `json:"validFrom"`

	// ValidTo Certificate valid to (expiration) date
	ValidTo *NetworkTimeSinceEpoch `json:"validTo"`

	// SignedCertificateTimestampList List of signed certificate timestamps (SCTs).
	SignedCertificateTimestampList []*NetworkSignedCertificateTimestamp `json:"signedCertificateTimestampList"`

	// CertificateTransparencyCompliance Whether the request complied with Certificate Transparency policy
	CertificateTransparencyCompliance *NetworkCertificateTransparencyCompliance `json:"certificateTransparencyCompliance"`
}

// NetworkCertificateTransparencyCompliance Whether the request complied with Certificate Transparency policy.
type NetworkCertificateTransparencyCompliance string

const (
	// NetworkCertificateTransparencyComplianceUnknown enum value
	NetworkCertificateTransparencyComplianceUnknown NetworkCertificateTransparencyCompliance = "unknown"

	// NetworkCertificateTransparencyComplianceNotCompliant enum value
	NetworkCertificateTransparencyComplianceNotCompliant NetworkCertificateTransparencyCompliance = "not-compliant"

	// NetworkCertificateTransparencyComplianceCompliant enum value
	NetworkCertificateTransparencyComplianceCompliant NetworkCertificateTransparencyCompliance = "compliant"
)

// NetworkBlockedReason The reason why request was blocked.
type NetworkBlockedReason string

const (
	// NetworkBlockedReasonOther enum value
	NetworkBlockedReasonOther NetworkBlockedReason = "other"

	// NetworkBlockedReasonCsp enum value
	NetworkBlockedReasonCsp NetworkBlockedReason = "csp"

	// NetworkBlockedReasonMixedContent enum value
	NetworkBlockedReasonMixedContent NetworkBlockedReason = "mixed-content"

	// NetworkBlockedReasonOrigin enum value
	NetworkBlockedReasonOrigin NetworkBlockedReason = "origin"

	// NetworkBlockedReasonInspector enum value
	NetworkBlockedReasonInspector NetworkBlockedReason = "inspector"

	// NetworkBlockedReasonSubresourceFilter enum value
	NetworkBlockedReasonSubresourceFilter NetworkBlockedReason = "subresource-filter"

	// NetworkBlockedReasonContentType enum value
	NetworkBlockedReasonContentType NetworkBlockedReason = "content-type"

	// NetworkBlockedReasonCollapsedByClient enum value
	NetworkBlockedReasonCollapsedByClient NetworkBlockedReason = "collapsed-by-client"
)

// NetworkResponse HTTP response data.
type NetworkResponse struct {
	// URL Response URL. This URL can be different from CachedResource.url in case of redirect.
	URL string `json:"url"`

	// Status HTTP response status code.
	Status int64 `json:"status"`

	// StatusText HTTP response status text.
	StatusText string `json:"statusText"`

	// Headers HTTP response headers.
	Headers *NetworkHeaders `json:"headers"`

	// HeadersText HTTP response headers text.
	HeadersText string `json:"headersText,omitempty"`

	// MIMEType Resource mimeType as determined by the browser.
	MIMEType string `json:"mimeType"`

	// RequestHeaders Refined HTTP request headers that were actually transmitted over the network.
	RequestHeaders *NetworkHeaders `json:"requestHeaders,omitempty"`

	// RequestHeadersText HTTP request headers text.
	RequestHeadersText string `json:"requestHeadersText,omitempty"`

	// ConnectionReused Specifies whether physical connection was actually reused for this request.
	ConnectionReused bool `json:"connectionReused"`

	// ConnectionID Physical connection id that was actually used for this request.
	ConnectionID float64 `json:"connectionId"`

	// RemoteIPAddress Remote IP address.
	RemoteIPAddress string `json:"remoteIPAddress,omitempty"`

	// RemotePort Remote port.
	RemotePort int64 `json:"remotePort,omitempty"`

	// FromDiskCache Specifies that the request was served from the disk cache.
	FromDiskCache bool `json:"fromDiskCache,omitempty"`

	// FromServiceWorker Specifies that the request was served from the ServiceWorker.
	FromServiceWorker bool `json:"fromServiceWorker,omitempty"`

	// FromPrefetchCache Specifies that the request was served from the prefetch cache.
	FromPrefetchCache bool `json:"fromPrefetchCache,omitempty"`

	// EncodedDataLength Total number of bytes received for this request so far.
	EncodedDataLength float64 `json:"encodedDataLength"`

	// Timing Timing information for the given request.
	Timing *NetworkResourceTiming `json:"timing,omitempty"`

	// Protocol Protocol used to fetch this request.
	Protocol string `json:"protocol,omitempty"`

	// SecurityState Security state of the request resource.
	SecurityState *SecuritySecurityState `json:"securityState"`

	// SecurityDetails Security details for the request.
	SecurityDetails *NetworkSecurityDetails `json:"securityDetails,omitempty"`
}

// NetworkWebSocketRequest WebSocket request data.
type NetworkWebSocketRequest struct {
	// Headers HTTP request headers.
	Headers *NetworkHeaders `json:"headers"`
}

// NetworkWebSocketResponse WebSocket response data.
type NetworkWebSocketResponse struct {
	// Status HTTP response status code.
	Status int64 `json:"status"`

	// StatusText HTTP response status text.
	StatusText string `json:"statusText"`

	// Headers HTTP response headers.
	Headers *NetworkHeaders `json:"headers"`

	// HeadersText HTTP response headers text.
	HeadersText string `json:"headersText,omitempty"`

	// RequestHeaders HTTP request headers.
	RequestHeaders *NetworkHeaders `json:"requestHeaders,omitempty"`

	// RequestHeadersText HTTP request headers text.
	RequestHeadersText string `json:"requestHeadersText,omitempty"`
}

// NetworkWebSocketFrame WebSocket message data. This represents an entire WebSocket message, not just a fragmented frame as the name suggests.
type NetworkWebSocketFrame struct {
	// Opcode WebSocket message opcode.
	Opcode float64 `json:"opcode"`

	// Mask WebSocket message mask.
	Mask bool `json:"mask"`

	// PayloadData WebSocket message payload data.
	// If the opcode is 1, this is a text message and payloadData is a UTF-8 string.
	// If the opcode isn't 1, then payloadData is a base64 encoded string representing binary data.
	PayloadData string `json:"payloadData"`
}

// NetworkCachedResource Information about the cached resource.
type NetworkCachedResource struct {
	// URL Resource URL. This is the url of the original network request.
	URL string `json:"url"`

	// Type Type of this resource.
	Type *NetworkResourceType `json:"type"`

	// Response Cached response data.
	Response *NetworkResponse `json:"response,omitempty"`

	// BodySize Cached response body size.
	BodySize float64 `json:"bodySize"`
}

// NetworkInitiator Information about the request initiator.
type NetworkInitiator struct {
	// Type Type of this initiator.
	Type string `json:"type"`

	// Stack Initiator JavaScript stack trace, set for Script only.
	Stack *RuntimeStackTrace `json:"stack,omitempty"`

	// URL Initiator URL, set for Parser type or for Script type (when script is importing module) or for SignedExchange type.
	URL string `json:"url,omitempty"`

	// LineNumber Initiator line number, set for Parser type or for Script type (when script is importing
	// module) (0-based).
	LineNumber float64 `json:"lineNumber,omitempty"`
}

// NetworkCookie Cookie object
type NetworkCookie struct {
	// Name Cookie name.
	Name string `json:"name"`

	// Value Cookie value.
	Value string `json:"value"`

	// Domain Cookie domain.
	Domain string `json:"domain"`

	// Path Cookie path.
	Path string `json:"path"`

	// Expires Cookie expiration date as the number of seconds since the UNIX epoch.
	Expires float64 `json:"expires"`

	// Size Cookie size.
	Size int64 `json:"size"`

	// HTTPOnly True if cookie is http-only.
	HTTPOnly bool `json:"httpOnly"`

	// Secure True if cookie is secure.
	Secure bool `json:"secure"`

	// Session True in case of session cookie.
	Session bool `json:"session"`

	// SameSite Cookie SameSite type.
	SameSite *NetworkCookieSameSite `json:"sameSite,omitempty"`

	// Priority (experimental) Cookie Priority
	Priority *NetworkCookiePriority `json:"priority"`
}

// NetworkSetCookieBlockedReason (experimental) Types of reasons why a cookie may not be stored from a response.
type NetworkSetCookieBlockedReason string

const (
	// NetworkSetCookieBlockedReasonSecureOnly enum value
	NetworkSetCookieBlockedReasonSecureOnly NetworkSetCookieBlockedReason = "SecureOnly"

	// NetworkSetCookieBlockedReasonSameSiteStrict enum value
	NetworkSetCookieBlockedReasonSameSiteStrict NetworkSetCookieBlockedReason = "SameSiteStrict"

	// NetworkSetCookieBlockedReasonSameSiteLax enum value
	NetworkSetCookieBlockedReasonSameSiteLax NetworkSetCookieBlockedReason = "SameSiteLax"

	// NetworkSetCookieBlockedReasonSameSiteUnspecifiedTreatedAsLax enum value
	NetworkSetCookieBlockedReasonSameSiteUnspecifiedTreatedAsLax NetworkSetCookieBlockedReason = "SameSiteUnspecifiedTreatedAsLax"

	// NetworkSetCookieBlockedReasonSameSiteNoneInsecure enum value
	NetworkSetCookieBlockedReasonSameSiteNoneInsecure NetworkSetCookieBlockedReason = "SameSiteNoneInsecure"

	// NetworkSetCookieBlockedReasonUserPreferences enum value
	NetworkSetCookieBlockedReasonUserPreferences NetworkSetCookieBlockedReason = "UserPreferences"

	// NetworkSetCookieBlockedReasonSyntaxError enum value
	NetworkSetCookieBlockedReasonSyntaxError NetworkSetCookieBlockedReason = "SyntaxError"

	// NetworkSetCookieBlockedReasonSchemeNotSupported enum value
	NetworkSetCookieBlockedReasonSchemeNotSupported NetworkSetCookieBlockedReason = "SchemeNotSupported"

	// NetworkSetCookieBlockedReasonOverwriteSecure enum value
	NetworkSetCookieBlockedReasonOverwriteSecure NetworkSetCookieBlockedReason = "OverwriteSecure"

	// NetworkSetCookieBlockedReasonInvalidDomain enum value
	NetworkSetCookieBlockedReasonInvalidDomain NetworkSetCookieBlockedReason = "InvalidDomain"

	// NetworkSetCookieBlockedReasonInvalidPrefix enum value
	NetworkSetCookieBlockedReasonInvalidPrefix NetworkSetCookieBlockedReason = "InvalidPrefix"

	// NetworkSetCookieBlockedReasonUnknownError enum value
	NetworkSetCookieBlockedReasonUnknownError NetworkSetCookieBlockedReason = "UnknownError"
)

// NetworkCookieBlockedReason (experimental) Types of reasons why a cookie may not be sent with a request.
type NetworkCookieBlockedReason string

const (
	// NetworkCookieBlockedReasonSecureOnly enum value
	NetworkCookieBlockedReasonSecureOnly NetworkCookieBlockedReason = "SecureOnly"

	// NetworkCookieBlockedReasonNotOnPath enum value
	NetworkCookieBlockedReasonNotOnPath NetworkCookieBlockedReason = "NotOnPath"

	// NetworkCookieBlockedReasonDomainMismatch enum value
	NetworkCookieBlockedReasonDomainMismatch NetworkCookieBlockedReason = "DomainMismatch"

	// NetworkCookieBlockedReasonSameSiteStrict enum value
	NetworkCookieBlockedReasonSameSiteStrict NetworkCookieBlockedReason = "SameSiteStrict"

	// NetworkCookieBlockedReasonSameSiteLax enum value
	NetworkCookieBlockedReasonSameSiteLax NetworkCookieBlockedReason = "SameSiteLax"

	// NetworkCookieBlockedReasonSameSiteUnspecifiedTreatedAsLax enum value
	NetworkCookieBlockedReasonSameSiteUnspecifiedTreatedAsLax NetworkCookieBlockedReason = "SameSiteUnspecifiedTreatedAsLax"

	// NetworkCookieBlockedReasonSameSiteNoneInsecure enum value
	NetworkCookieBlockedReasonSameSiteNoneInsecure NetworkCookieBlockedReason = "SameSiteNoneInsecure"

	// NetworkCookieBlockedReasonUserPreferences enum value
	NetworkCookieBlockedReasonUserPreferences NetworkCookieBlockedReason = "UserPreferences"

	// NetworkCookieBlockedReasonUnknownError enum value
	NetworkCookieBlockedReasonUnknownError NetworkCookieBlockedReason = "UnknownError"
)

// NetworkBlockedSetCookieWithReason (experimental) A cookie which was not stored from a response with the corresponding reason.
type NetworkBlockedSetCookieWithReason struct {
	// BlockedReasons The reason(s) this cookie was blocked.
	BlockedReasons []*NetworkSetCookieBlockedReason `json:"blockedReasons"`

	// CookieLine The string representing this individual cookie as it would appear in the header.
	// This is not the entire "cookie" or "set-cookie" header which could have multiple cookies.
	CookieLine string `json:"cookieLine"`

	// Cookie The cookie object which represents the cookie which was not stored. It is optional because
	// sometimes complete cookie information is not available, such as in the case of parsing
	// errors.
	Cookie *NetworkCookie `json:"cookie,omitempty"`
}

// NetworkBlockedCookieWithReason (experimental) A cookie with was not sent with a request with the corresponding reason.
type NetworkBlockedCookieWithReason struct {
	// BlockedReasons The reason(s) the cookie was blocked.
	BlockedReasons []*NetworkCookieBlockedReason `json:"blockedReasons"`

	// Cookie The cookie object representing the cookie which was not sent.
	Cookie *NetworkCookie `json:"cookie"`
}

// NetworkCookieParam Cookie parameter object
type NetworkCookieParam struct {
	// Name Cookie name.
	Name string `json:"name"`

	// Value Cookie value.
	Value string `json:"value"`

	// URL The request-URI to associate with the setting of the cookie. This value can affect the
	// default domain and path values of the created cookie.
	URL string `json:"url,omitempty"`

	// Domain Cookie domain.
	Domain string `json:"domain,omitempty"`

	// Path Cookie path.
	Path string `json:"path,omitempty"`

	// Secure True if cookie is secure.
	Secure bool `json:"secure,omitempty"`

	// HTTPOnly True if cookie is http-only.
	HTTPOnly bool `json:"httpOnly,omitempty"`

	// SameSite Cookie SameSite type.
	SameSite *NetworkCookieSameSite `json:"sameSite,omitempty"`

	// Expires Cookie expiration date, session cookie if not set
	Expires *NetworkTimeSinceEpoch `json:"expires,omitempty"`

	// Priority (experimental) Cookie Priority.
	Priority *NetworkCookiePriority `json:"priority,omitempty"`
}

// NetworkAuthChallenge (experimental) Authorization challenge for HTTP status code 401 or 407.
type NetworkAuthChallenge struct {
	// Source Source of the authentication challenge.
	Source string `json:"source,omitempty"`

	// Origin Origin of the challenger.
	Origin string `json:"origin"`

	// Scheme The authentication scheme used, such as basic or digest
	Scheme string `json:"scheme"`

	// Realm The realm of the challenge. May be empty.
	Realm string `json:"realm"`
}

// NetworkAuthChallengeResponse (experimental) Response to an AuthChallenge.
type NetworkAuthChallengeResponse struct {
	// Response The decision on what to do in response to the authorization challenge.  Default means
	// deferring to the default behavior of the net stack, which will likely either the Cancel
	// authentication or display a popup dialog box.
	Response string `json:"response"`

	// Username The username to provide, possibly empty. Should only be set if response is
	// ProvideCredentials.
	Username string `json:"username,omitempty"`

	// Password The password to provide, possibly empty. Should only be set if response is
	// ProvideCredentials.
	Password string `json:"password,omitempty"`
}

// NetworkInterceptionStage (experimental) Stages of the interception to begin intercepting. Request will intercept before the request is
// sent. Response will intercept after the response is received.
type NetworkInterceptionStage string

const (
	// NetworkInterceptionStageRequest enum value
	NetworkInterceptionStageRequest NetworkInterceptionStage = "Request"

	// NetworkInterceptionStageHeadersReceived enum value
	NetworkInterceptionStageHeadersReceived NetworkInterceptionStage = "HeadersReceived"
)

// NetworkRequestPattern (experimental) Request pattern for interception.
type NetworkRequestPattern struct {
	// URLPattern Wildcards ('*' -> zero or more, '?' -> exactly one) are allowed. Escape character is
	// backslash. Omitting is equivalent to "*".
	URLPattern string `json:"urlPattern,omitempty"`

	// ResourceType If set, only requests for matching resource types will be intercepted.
	ResourceType *NetworkResourceType `json:"resourceType,omitempty"`

	// InterceptionStage Stage at wich to begin intercepting requests. Default is Request.
	InterceptionStage *NetworkInterceptionStage `json:"interceptionStage,omitempty"`
}

// NetworkSignedExchangeSignature (experimental) Information about a signed exchange signature.
// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#rfc.section.3.1
type NetworkSignedExchangeSignature struct {
	// Label Signed exchange signature label.
	Label string `json:"label"`

	// Signature The hex string of signed exchange signature.
	Signature string `json:"signature"`

	// Integrity Signed exchange signature integrity.
	Integrity string `json:"integrity"`

	// CertURL Signed exchange signature cert Url.
	CertURL string `json:"certUrl,omitempty"`

	// CertSha256 The hex string of signed exchange signature cert sha256.
	CertSha256 string `json:"certSha256,omitempty"`

	// ValidityURL Signed exchange signature validity Url.
	ValidityURL string `json:"validityUrl"`

	// Date Signed exchange signature date.
	Date int64 `json:"date"`

	// Expires Signed exchange signature expires.
	Expires int64 `json:"expires"`

	// Certificates The encoded certificates.
	Certificates []string `json:"certificates,omitempty"`
}

// NetworkSignedExchangeHeader (experimental) Information about a signed exchange header.
// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#cbor-representation
type NetworkSignedExchangeHeader struct {
	// RequestURL Signed exchange request URL.
	RequestURL string `json:"requestUrl"`

	// ResponseCode Signed exchange response code.
	ResponseCode int64 `json:"responseCode"`

	// ResponseHeaders Signed exchange response headers.
	ResponseHeaders *NetworkHeaders `json:"responseHeaders"`

	// Signatures Signed exchange response signature.
	Signatures []*NetworkSignedExchangeSignature `json:"signatures"`

	// HeaderIntegrity Signed exchange header integrity hash in the form of "sha256-<base64-hash-value>".
	HeaderIntegrity string `json:"headerIntegrity"`
}

// NetworkSignedExchangeErrorField (experimental) Field type for a signed exchange related error.
type NetworkSignedExchangeErrorField string

const (
	// NetworkSignedExchangeErrorFieldSignatureSig enum value
	NetworkSignedExchangeErrorFieldSignatureSig NetworkSignedExchangeErrorField = "signatureSig"

	// NetworkSignedExchangeErrorFieldSignatureIntegrity enum value
	NetworkSignedExchangeErrorFieldSignatureIntegrity NetworkSignedExchangeErrorField = "signatureIntegrity"

	// NetworkSignedExchangeErrorFieldSignatureCertURL enum value
	NetworkSignedExchangeErrorFieldSignatureCertURL NetworkSignedExchangeErrorField = "signatureCertUrl"

	// NetworkSignedExchangeErrorFieldSignatureCertSha256 enum value
	NetworkSignedExchangeErrorFieldSignatureCertSha256 NetworkSignedExchangeErrorField = "signatureCertSha256"

	// NetworkSignedExchangeErrorFieldSignatureValidityURL enum value
	NetworkSignedExchangeErrorFieldSignatureValidityURL NetworkSignedExchangeErrorField = "signatureValidityUrl"

	// NetworkSignedExchangeErrorFieldSignatureTimestamps enum value
	NetworkSignedExchangeErrorFieldSignatureTimestamps NetworkSignedExchangeErrorField = "signatureTimestamps"
)

// NetworkSignedExchangeError (experimental) Information about a signed exchange response.
type NetworkSignedExchangeError struct {
	// Message Error message.
	Message string `json:"message"`

	// SignatureIndex The index of the signature which caused the error.
	SignatureIndex int64 `json:"signatureIndex,omitempty"`

	// ErrorField The field which caused the error.
	ErrorField *NetworkSignedExchangeErrorField `json:"errorField,omitempty"`
}

// NetworkSignedExchangeInfo (experimental) Information about a signed exchange response.
type NetworkSignedExchangeInfo struct {
	// OuterResponse The outer response of signed HTTP exchange which was received from network.
	OuterResponse *NetworkResponse `json:"outerResponse"`

	// Header Information about the signed exchange header.
	Header *NetworkSignedExchangeHeader `json:"header,omitempty"`

	// SecurityDetails Security details for the signed exchange header.
	SecurityDetails *NetworkSecurityDetails `json:"securityDetails,omitempty"`

	// Errors Errors occurred while handling the signed exchagne.
	Errors []*NetworkSignedExchangeError `json:"errors,omitempty"`
}