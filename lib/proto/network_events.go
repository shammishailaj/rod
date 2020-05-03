// This file is generated by "./lib/proto/cmd/gen"

package proto

import "encoding/json"

// NetworkDataReceived Fired when data chunk was received over the network.
type NetworkDataReceived struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// DataLength Data chunk length.
	DataLength int64 `json:"dataLength"`

	// EncodedDataLength Actual bytes received (might be less than dataLength for compressed encodings).
	EncodedDataLength int64 `json:"encodedDataLength"`
}

// MethodName interface
func (evt NetworkDataReceived) MethodName() string {
	return "Network.dataReceived"
}

// Load json
func (evt NetworkDataReceived) Load(b []byte) *NetworkDataReceived {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkEventSourceMessageReceived Fired when EventSource message is received.
type NetworkEventSourceMessageReceived struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// EventName Message type.
	EventName string `json:"eventName"`

	// EventID Message identifier.
	EventID string `json:"eventId"`

	// Data Message content.
	Data string `json:"data"`
}

// MethodName interface
func (evt NetworkEventSourceMessageReceived) MethodName() string {
	return "Network.eventSourceMessageReceived"
}

// Load json
func (evt NetworkEventSourceMessageReceived) Load(b []byte) *NetworkEventSourceMessageReceived {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkLoadingFailed Fired when HTTP request has failed to load.
type NetworkLoadingFailed struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// Type Resource type.
	Type *NetworkResourceType `json:"type"`

	// ErrorText User friendly error message.
	ErrorText string `json:"errorText"`

	// Canceled True if loading was canceled.
	Canceled bool `json:"canceled,omitempty"`

	// BlockedReason The reason why loading was blocked, if any.
	BlockedReason *NetworkBlockedReason `json:"blockedReason,omitempty"`
}

// MethodName interface
func (evt NetworkLoadingFailed) MethodName() string {
	return "Network.loadingFailed"
}

// Load json
func (evt NetworkLoadingFailed) Load(b []byte) *NetworkLoadingFailed {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkLoadingFinished Fired when HTTP request has finished loading.
type NetworkLoadingFinished struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// EncodedDataLength Total number of bytes received for this request.
	EncodedDataLength float64 `json:"encodedDataLength"`

	// ShouldReportCorbBlocking Set when 1) response was blocked by Cross-Origin Read Blocking and also
	// 2) this needs to be reported to the DevTools console.
	ShouldReportCorbBlocking bool `json:"shouldReportCorbBlocking,omitempty"`
}

// MethodName interface
func (evt NetworkLoadingFinished) MethodName() string {
	return "Network.loadingFinished"
}

// Load json
func (evt NetworkLoadingFinished) Load(b []byte) *NetworkLoadingFinished {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkRequestIntercepted (deprecated) (experimental) Details of an intercepted HTTP request, which must be either allowed, blocked, modified or
// mocked.
// Deprecated, use Fetch.requestPaused instead.
type NetworkRequestIntercepted struct {
	// InterceptionID Each request the page makes will have a unique id, however if any redirects are encountered
	// while processing that fetch, they will be reported with the same id as the original fetch.
	// Likewise if HTTP authentication is needed then the same fetch id will be used.
	InterceptionID *NetworkInterceptionID `json:"interceptionId"`

	// Request ...
	Request *NetworkRequest `json:"request"`

	// FrameID The id of the frame that initiated the request.
	FrameID *PageFrameID `json:"frameId"`

	// ResourceType How the requested resource will be used.
	ResourceType *NetworkResourceType `json:"resourceType"`

	// IsNavigationRequest Whether this is a navigation request, which can abort the navigation completely.
	IsNavigationRequest bool `json:"isNavigationRequest"`

	// IsDownload Set if the request is a navigation that will result in a download.
	// Only present after response is received from the server (i.e. HeadersReceived stage).
	IsDownload bool `json:"isDownload,omitempty"`

	// RedirectURL Redirect location, only sent if a redirect was intercepted.
	RedirectURL string `json:"redirectUrl,omitempty"`

	// AuthChallenge Details of the Authorization Challenge encountered. If this is set then
	// continueInterceptedRequest must contain an authChallengeResponse.
	AuthChallenge *NetworkAuthChallenge `json:"authChallenge,omitempty"`

	// ResponseErrorReason Response error if intercepted at response stage or if redirect occurred while intercepting
	// request.
	ResponseErrorReason *NetworkErrorReason `json:"responseErrorReason,omitempty"`

	// ResponseStatusCode Response code if intercepted at response stage or if redirect occurred while intercepting
	// request or auth retry occurred.
	ResponseStatusCode int64 `json:"responseStatusCode,omitempty"`

	// ResponseHeaders Response headers if intercepted at the response stage or if redirect occurred while
	// intercepting request or auth retry occurred.
	ResponseHeaders *NetworkHeaders `json:"responseHeaders,omitempty"`

	// RequestID If the intercepted request had a corresponding requestWillBeSent event fired for it, then
	// this requestId will be the same as the requestId present in the requestWillBeSent event.
	RequestID *NetworkRequestID `json:"requestId,omitempty"`
}

// MethodName interface
func (evt NetworkRequestIntercepted) MethodName() string {
	return "Network.requestIntercepted"
}

// Load json
func (evt NetworkRequestIntercepted) Load(b []byte) *NetworkRequestIntercepted {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkRequestServedFromCache Fired if request ended up loading from cache.
type NetworkRequestServedFromCache struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`
}

// MethodName interface
func (evt NetworkRequestServedFromCache) MethodName() string {
	return "Network.requestServedFromCache"
}

// Load json
func (evt NetworkRequestServedFromCache) Load(b []byte) *NetworkRequestServedFromCache {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkRequestWillBeSent Fired when page is about to send HTTP request.
type NetworkRequestWillBeSent struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// LoaderID Loader identifier. Empty string if the request is fetched from worker.
	LoaderID *NetworkLoaderID `json:"loaderId"`

	// DocumentURL URL of the document this request is loaded for.
	DocumentURL string `json:"documentURL"`

	// Request Request data.
	Request *NetworkRequest `json:"request"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// WallTime Timestamp.
	WallTime *NetworkTimeSinceEpoch `json:"wallTime"`

	// Initiator Request initiator.
	Initiator *NetworkInitiator `json:"initiator"`

	// RedirectResponse Redirect response data.
	RedirectResponse *NetworkResponse `json:"redirectResponse,omitempty"`

	// Type Type of this resource.
	Type *NetworkResourceType `json:"type,omitempty"`

	// FrameID Frame identifier.
	FrameID *PageFrameID `json:"frameId,omitempty"`

	// HasUserGesture Whether the request is initiated by a user gesture. Defaults to false.
	HasUserGesture bool `json:"hasUserGesture,omitempty"`
}

// MethodName interface
func (evt NetworkRequestWillBeSent) MethodName() string {
	return "Network.requestWillBeSent"
}

// Load json
func (evt NetworkRequestWillBeSent) Load(b []byte) *NetworkRequestWillBeSent {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkResourceChangedPriority (experimental) Fired when resource loading priority is changed
type NetworkResourceChangedPriority struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// NewPriority New priority
	NewPriority *NetworkResourcePriority `json:"newPriority"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`
}

// MethodName interface
func (evt NetworkResourceChangedPriority) MethodName() string {
	return "Network.resourceChangedPriority"
}

// Load json
func (evt NetworkResourceChangedPriority) Load(b []byte) *NetworkResourceChangedPriority {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkSignedExchangeReceived (experimental) Fired when a signed exchange was received over the network
type NetworkSignedExchangeReceived struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Info Information about the signed exchange response.
	Info *NetworkSignedExchangeInfo `json:"info"`
}

// MethodName interface
func (evt NetworkSignedExchangeReceived) MethodName() string {
	return "Network.signedExchangeReceived"
}

// Load json
func (evt NetworkSignedExchangeReceived) Load(b []byte) *NetworkSignedExchangeReceived {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkResponseReceived Fired when HTTP response is available.
type NetworkResponseReceived struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// LoaderID Loader identifier. Empty string if the request is fetched from worker.
	LoaderID *NetworkLoaderID `json:"loaderId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// Type Resource type.
	Type *NetworkResourceType `json:"type"`

	// Response Response data.
	Response *NetworkResponse `json:"response"`

	// FrameID Frame identifier.
	FrameID *PageFrameID `json:"frameId,omitempty"`
}

// MethodName interface
func (evt NetworkResponseReceived) MethodName() string {
	return "Network.responseReceived"
}

// Load json
func (evt NetworkResponseReceived) Load(b []byte) *NetworkResponseReceived {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkWebSocketClosed Fired when WebSocket is closed.
type NetworkWebSocketClosed struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`
}

// MethodName interface
func (evt NetworkWebSocketClosed) MethodName() string {
	return "Network.webSocketClosed"
}

// Load json
func (evt NetworkWebSocketClosed) Load(b []byte) *NetworkWebSocketClosed {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkWebSocketCreated Fired upon WebSocket creation.
type NetworkWebSocketCreated struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// URL WebSocket request URL.
	URL string `json:"url"`

	// Initiator Request initiator.
	Initiator *NetworkInitiator `json:"initiator,omitempty"`
}

// MethodName interface
func (evt NetworkWebSocketCreated) MethodName() string {
	return "Network.webSocketCreated"
}

// Load json
func (evt NetworkWebSocketCreated) Load(b []byte) *NetworkWebSocketCreated {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkWebSocketFrameError Fired when WebSocket message error occurs.
type NetworkWebSocketFrameError struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// ErrorMessage WebSocket error message.
	ErrorMessage string `json:"errorMessage"`
}

// MethodName interface
func (evt NetworkWebSocketFrameError) MethodName() string {
	return "Network.webSocketFrameError"
}

// Load json
func (evt NetworkWebSocketFrameError) Load(b []byte) *NetworkWebSocketFrameError {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkWebSocketFrameReceived Fired when WebSocket message is received.
type NetworkWebSocketFrameReceived struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// Response WebSocket response data.
	Response *NetworkWebSocketFrame `json:"response"`
}

// MethodName interface
func (evt NetworkWebSocketFrameReceived) MethodName() string {
	return "Network.webSocketFrameReceived"
}

// Load json
func (evt NetworkWebSocketFrameReceived) Load(b []byte) *NetworkWebSocketFrameReceived {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkWebSocketFrameSent Fired when WebSocket message is sent.
type NetworkWebSocketFrameSent struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// Response WebSocket response data.
	Response *NetworkWebSocketFrame `json:"response"`
}

// MethodName interface
func (evt NetworkWebSocketFrameSent) MethodName() string {
	return "Network.webSocketFrameSent"
}

// Load json
func (evt NetworkWebSocketFrameSent) Load(b []byte) *NetworkWebSocketFrameSent {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkWebSocketHandshakeResponseReceived Fired when WebSocket handshake response becomes available.
type NetworkWebSocketHandshakeResponseReceived struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// Response WebSocket response data.
	Response *NetworkWebSocketResponse `json:"response"`
}

// MethodName interface
func (evt NetworkWebSocketHandshakeResponseReceived) MethodName() string {
	return "Network.webSocketHandshakeResponseReceived"
}

// Load json
func (evt NetworkWebSocketHandshakeResponseReceived) Load(b []byte) *NetworkWebSocketHandshakeResponseReceived {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkWebSocketWillSendHandshakeRequest Fired when WebSocket is about to initiate handshake.
type NetworkWebSocketWillSendHandshakeRequest struct {
	// RequestID Request identifier.
	RequestID *NetworkRequestID `json:"requestId"`

	// Timestamp Timestamp.
	Timestamp *NetworkMonotonicTime `json:"timestamp"`

	// WallTime UTC Timestamp.
	WallTime *NetworkTimeSinceEpoch `json:"wallTime"`

	// Request WebSocket request data.
	Request *NetworkWebSocketRequest `json:"request"`
}

// MethodName interface
func (evt NetworkWebSocketWillSendHandshakeRequest) MethodName() string {
	return "Network.webSocketWillSendHandshakeRequest"
}

// Load json
func (evt NetworkWebSocketWillSendHandshakeRequest) Load(b []byte) *NetworkWebSocketWillSendHandshakeRequest {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkRequestWillBeSentExtraInfo (experimental) Fired when additional information about a requestWillBeSent event is available from the
// network stack. Not every requestWillBeSent event will have an additional
// requestWillBeSentExtraInfo fired for it, and there is no guarantee whether requestWillBeSent
// or requestWillBeSentExtraInfo will be fired first for the same request.
type NetworkRequestWillBeSentExtraInfo struct {
	// RequestID Request identifier. Used to match this information to an existing requestWillBeSent event.
	RequestID *NetworkRequestID `json:"requestId"`

	// BlockedCookies A list of cookies which will not be sent with this request along with corresponding reasons
	// for blocking.
	BlockedCookies []*NetworkBlockedCookieWithReason `json:"blockedCookies"`

	// Headers Raw request headers as they will be sent over the wire.
	Headers *NetworkHeaders `json:"headers"`
}

// MethodName interface
func (evt NetworkRequestWillBeSentExtraInfo) MethodName() string {
	return "Network.requestWillBeSentExtraInfo"
}

// Load json
func (evt NetworkRequestWillBeSentExtraInfo) Load(b []byte) *NetworkRequestWillBeSentExtraInfo {
	E(json.Unmarshal(b, &evt))
	return &evt
}

// NetworkResponseReceivedExtraInfo (experimental) Fired when additional information about a responseReceived event is available from the network
// stack. Not every responseReceived event will have an additional responseReceivedExtraInfo for
// it, and responseReceivedExtraInfo may be fired before or after responseReceived.
type NetworkResponseReceivedExtraInfo struct {
	// RequestID Request identifier. Used to match this information to another responseReceived event.
	RequestID *NetworkRequestID `json:"requestId"`

	// BlockedCookies A list of cookies which were not stored from the response along with the corresponding
	// reasons for blocking. The cookies here may not be valid due to syntax errors, which
	// are represented by the invalid cookie line string instead of a proper cookie.
	BlockedCookies []*NetworkBlockedSetCookieWithReason `json:"blockedCookies"`

	// Headers Raw response headers as they were received over the wire.
	Headers *NetworkHeaders `json:"headers"`

	// HeadersText Raw response header text as it was received over the wire. The raw text may not always be
	// available, such as in the case of HTTP/2 or QUIC.
	HeadersText string `json:"headersText,omitempty"`
}

// MethodName interface
func (evt NetworkResponseReceivedExtraInfo) MethodName() string {
	return "Network.responseReceivedExtraInfo"
}

// Load json
func (evt NetworkResponseReceivedExtraInfo) Load(b []byte) *NetworkResponseReceivedExtraInfo {
	E(json.Unmarshal(b, &evt))
	return &evt
}
