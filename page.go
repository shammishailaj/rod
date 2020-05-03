//go:generate go run ./lib/assets/generate

package rod

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ysmood/kit"
	"github.com/ysmood/rod/lib/assets"
	"github.com/ysmood/rod/lib/cdp"
	"github.com/ysmood/rod/lib/proto"
)

// Page represents the webpage
type Page struct {
	// these are the handler for ctx
	ctx           context.Context
	ctxCancel     func()
	timeoutCancel func()

	browser *Browser

	TargetID  *proto.TargetTargetID
	SessionID *proto.TargetSessionID
	FrameID   *proto.PageFrameID
	URL       string

	// devices
	Mouse    *Mouse
	Keyboard *Keyboard

	element             *Element                     // iframe only
	windowObjectID      *proto.RuntimeRemoteObjectID // used as the thisObject when eval js
	getDownloadFileLock *sync.Mutex
}

// IsIframe tells if it's iframe
func (p *Page) IsIframe() bool {
	return p.element != nil
}

// Root page of the iframe, if it's not a iframe returns itself
func (p *Page) Root() *Page {
	f := p

	for f.IsIframe() {
		f = f.element.page
	}

	return f
}

// CookiesE returns the page cookies. By default it will return the cookies for current page.
// The urls is the list of URLs for which applicable cookies will be fetched.
func (p *Page) CookiesE(urls []string) ([]*proto.NetworkCookie, error) {
	if len(urls) == 0 {
		info, err := proto.TargetGetTargetInfo{p.TargetID}.Call(p.Call())
		if err != nil {
			return nil, err
		}
		urls = []string{info.TargetInfo.URL}
	}

	res, err := proto.NetworkGetCookies{Urls: urls}.Call(p.Call())
	if err != nil {
		return nil, err
	}
	return res.Cookies, nil
}

// SetCookiesE of the page.
// Cookie format: https://chromedevtools.github.io/devtools-protocol/tot/Network#method-setCookie
func (p *Page) SetCookiesE(cookies []*proto.NetworkCookieParam) error {
	_, err := proto.NetworkSetCookies{cookies}.Call(p.Call())
	return err
}

// NavigateE doc is the same as the method Navigate
func (p *Page) NavigateE(url string) error {
	_, err := proto.PageNavigate{URL: url}.Call(p.Call())
	return err
}

func (p *Page) getWindowID() (*proto.BrowserWindowID, error) {
	res, err := proto.BrowserGetWindowForTarget{TargetID: p.TargetID}.Call(p.Call())
	if err != nil {
		return nil, err
	}
	return res.WindowID, err
}

// GetWindowE doc is the same as the method GetWindow
func (p *Page) GetWindowE() (*proto.BrowserBounds, error) {
	id, err := p.getWindowID()
	if err != nil {
		return nil, err
	}

	res, err := proto.BrowserGetWindowBounds{WindowID: id}.Call(p.Call())
	if err != nil {
		return nil, err
	}

	return res.Bounds, nil
}

// WindowE https://chromedevtools.github.io/devtools-protocol/tot/Browser#type-Bounds
func (p *Page) WindowE(bounds *proto.BrowserBounds) error {
	id, err := p.getWindowID()
	if err != nil {
		return err
	}

	_, err = proto.BrowserSetWindowBounds{id, bounds}.Call(p.Call())
	return err
}

// ViewportE doc is the same as the method Viewport
func (p *Page) ViewportE(params *proto.EmulationSetDeviceMetricsOverride) error {
	_, err := params.Call(p.Call())
	return err
}

// CloseE page
func (p *Page) CloseE() error {
	_, err := proto.PageClose{}.Call(p.Call())
	return err
}

// HandleDialogE doc is the same as the method HandleDialog
func (p *Page) HandleDialogE(accept bool, promptText string) func() error {
	wait := p.WaitEventE(Method(proto.PageJavascriptDialogOpening{}))

	return func() error {
		_, err := wait()
		if err != nil {
			return err
		}
		_, err = proto.PageHandleJavaScriptDialog{
			Accept:     accept,
			PromptText: promptText,
		}.Call(p.Call())
		return err
	}
}

// GetDownloadFileE how it works is to proxy the request, the dir is the dir to save the file.
func (p *Page) GetDownloadFileE(dir, pattern string) (func() (http.Header, []byte, error), error) {
	var fetchEnable *proto.FetchEnable
	if pattern != "" {
		fetchEnable = &proto.FetchEnable{
			Patterns: []*proto.FetchRequestPattern{
				{URLPattern: pattern},
			},
		}
	}

	// both Page.setDownloadBehavior and Fetch.enable will pollute the global status,
	// we have to prevent race condition here
	p.getDownloadFileLock.Lock()

	_, err := proto.PageSetDownloadBehavior{
		Behavior:     proto.PagePageSetDownloadBehaviorBehaviorAllow,
		DownloadPath: dir,
	}.Call(p.Call())
	if err != nil {
		return nil, err
	}

	_, err = fetchEnable.Call(p.Call())
	if err != nil {
		return nil, err
	}

	wait := p.WaitEventE(Method(proto.FetchRequestPaused{}))

	return func() (http.Header, []byte, error) {
		defer func() {
			defer p.getDownloadFileLock.Unlock()
			_, err := proto.FetchDisable{}.Call(p.Call())
			kit.E(err)
		}()

		msg, err := wait()
		if err != nil {
			return nil, nil, err
		}

		msgReq := proto.FetchRequestPaused{}.Load(msg.Params)
		req := kit.Req(msgReq.Request.URL).Context(p.ctx)

		for k, v := range *msgReq.Request.Headers {
			req.Header(k, v.(string))
		}

		res, err := req.Response()
		if err != nil {
			return nil, nil, err
		}

		body, err := req.Bytes()
		if err != nil {
			return nil, nil, err
		}

		headers := []*proto.FetchHeaderEntry{}
		for k, vs := range res.Header {
			for _, v := range vs {
				headers = append(headers, &proto.FetchHeaderEntry{k, v})
			}
		}

		_, err = proto.FetchFulfillRequest{
			RequestID:       msgReq.RequestID,
			ResponseCode:    int64(res.StatusCode),
			ResponseHeaders: headers,
			Body:            body,
		}.Call(p.Call())

		return res.Header, body, err
	}, err
}

// ScreenshotE options: https://chromedevtools.github.io/devtools-protocol/tot/Page#method-captureScreenshot
func (p *Page) ScreenshotE(req *proto.PageCaptureScreenshot) ([]byte, error) {
	res, err := req.Call(p.Call())
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// PDFE prints page as PDF
func (p *Page) PDFE(req *proto.PagePrintToPDF) ([]byte, error) {
	res, err := req.Call(p.Call())
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// WaitPageE doc is the same as the method WaitPage
func (p *Page) WaitPageE() func() (*Page, error) {
	var targetInfo *proto.TargetTargetInfo

	wait := p.browser.Context(p.ctx).WaitEventE(func(e *cdp.Event) bool {
		if e.Method == "Target.targetCreated" {
			targetInfo := proto.TargetTargetCreated{}.Load(e.Params).TargetInfo

			if targetInfo.OpenerID == p.TargetID {
				return true
			}
		}
		return false
	})

	return func() (*Page, error) {
		_, err := wait()
		if err != nil {
			return nil, err
		}
		return p.browser.Context(p.ctx).page(targetInfo.TargetID)
	}
}

// PauseE doc is the same as the method Pause
func (p *Page) PauseE() error {
	_, err := proto.DebuggerEnable{}.Call(p.Call())
	if err != nil {
		return err
	}
	_, err = proto.DebuggerPause{}.Call(p.Call())
	if err != nil {
		return err
	}
	wait := p.WaitEventE(Method(proto.DebuggerResumed{}))
	_, err = wait()
	return err
}

// WaitRequestIdleE returns a wait function that waits until no request for d duration.
// Use the includes and excludes regexp list to filter the requests by their url.
// Such as set n to 1 if there's a polling request.
func (p *Page) WaitRequestIdleE(d time.Duration, includes, excludes []string) func() error {
	s := p.browser.Event().Subscribe()

	return func() (err error) {
		if p.browser.trace {
			defer p.Overlay(0, 0, 300, 0, "waiting for request idle "+strings.Join(includes, " "))()
		}
		defer p.browser.Event().Unsubscribe(s)

		reqList := map[*proto.NetworkRequestID]kit.Nil{}
		timeout := time.NewTimer(d)

		for {
			select {
			case <-p.ctx.Done():
				return p.ctx.Err()
			case <-timeout.C:
				return
			case msg, ok := <-s.C:
				if !ok {
					return
				}

				e := msg.(*cdp.Event)
				switch e.Method {
				case "Network.requestWillBeSent":
					timeout.Stop()
					evt := proto.NetworkRequestWillBeSent{}.Load(e.Params)
					url := evt.Request.URL
					id := evt.RequestID
					if matchWithFilter(url, includes, excludes) {
						reqList[id] = kit.Nil{}
					}
				case "Network.loadingFinished",
					"Network.loadingFailed",
					"Network.responseReceived":
					evt := proto.NetworkLoadingFinished{}.Load(e.Params)
					delete(reqList, evt.RequestID)
					if len(reqList) == 0 {
						timeout.Reset(d)
					}
				}
			}
		}
	}
}

// WaitIdleE doc is the same as the method WaitIdle
func (p *Page) WaitIdleE(timeout time.Duration) (err error) {
	_, err = p.EvalE(true, nil, p.jsFn("waitIdle"), Array{timeout.Seconds()})
	return err
}

// WaitLoadE doc is the same as the method WaitLoad
func (p *Page) WaitLoadE() error {
	_, err := p.EvalE(true, nil, p.jsFn("waitLoad"), nil)
	return err
}

// WaitEventE doc is the same as the method WaitEvent
func (p *Page) WaitEventE(filter EventFilter) func() (*cdp.Event, error) {
	return p.browser.Context(p.ctx).WaitEventE(func(e *cdp.Event) bool {
		return e.SessionID == string(*p.SessionID) && filter(e)
	})
}

// AddScriptTagE to page. If url is empty, content will be used.
func (p *Page) AddScriptTagE(url, content string) error {
	hash := md5.Sum([]byte(url + content))
	id := hex.EncodeToString(hash[:])
	_, err := p.EvalE(true, nil, p.jsFn("addScriptTag"), Array{id, url, content})
	return err
}

// AddStyleTagE to page. If url is empty, content will be used.
func (p *Page) AddStyleTagE(url, content string) error {
	hash := md5.Sum([]byte(url + content))
	id := hex.EncodeToString(hash[:])
	_, err := p.EvalE(true, nil, p.jsFn("addStyleTag"), Array{id, url, content})
	return err
}

// EvalE thisID is the remote objectID that will be the this of the js function, if it's empty "window" will be used.
// Set the byValue to true to reduce memory occupation.
func (p *Page) EvalE(byValue bool, thisID *proto.RuntimeRemoteObjectID, js string, jsArgs Array) (*proto.RuntimeCallFunctionOnResult, error) {
	backoff := kit.BackoffSleeper(30*time.Millisecond, 3*time.Second, nil)
	objectID := thisID
	var err error
	var res *proto.RuntimeCallFunctionOnResult

	// js context will be invalid if a frame is reloaded
	err = kit.Retry(p.ctx, backoff, func() (bool, error) {
		if thisID == nil {
			if p.windowObjectID == nil {
				err := p.initJS()
				if err != nil {
					if isNilContextErr(err) {
						return false, nil
					}
					return true, err
				}
			}
			objectID = p.windowObjectID
		}

		args := []*proto.RuntimeCallArgument{}
		for _, p := range jsArgs {
			args = append(args, &proto.RuntimeCallArgument{Value: p})
		}

		res, err = proto.RuntimeCallFunctionOn{
			ObjectID:            objectID,
			AwaitPromise:        true,
			ReturnByValue:       byValue,
			FunctionDeclaration: SprintFnThis(js),
			Arguments:           args,
		}.Call(p.Call())

		if thisID == nil {
			if isNilContextErr(err) {
				_ = p.initJS()
				return false, nil
			}
		}

		return true, err
	})

	if err != nil {
		return nil, err
	}

	if res.ExceptionDetails != nil {
		return nil, &Error{nil, res.ExceptionDetails.Exception.Description, res}
	}

	return res, nil
}

// Sleeper returns the default sleeper for retry, it uses backoff and requestIdleCallback to wait
func (p *Page) Sleeper() kit.Sleeper {
	return kit.BackoffSleeper(100*time.Millisecond, time.Second, nil)
}

// ReleaseE doc is the same as the method Release
func (p *Page) ReleaseE(objectID *proto.RuntimeRemoteObjectID) error {
	_, err := proto.RuntimeReleaseObject{ObjectID: objectID}.Call(p.Call())
	return err
}

// Call parameters for proto
func (p *Page) Call() *proto.Call {
	return &proto.Call{p.ctx, p.browser.client, string(*p.SessionID)}
}

func (p *Page) initSession() error {
	obj, err := proto.TargetAttachToTarget{
		TargetID: p.TargetID,
		Flatten:  true, // if it's not set no response will return
	}.Call(p.Call())
	if err != nil {
		return err
	}
	p.SessionID = obj.SessionID

	_, err = proto.PageEnable{}.Call(p.Call())
	if err != nil {
		return err
	}

	_, err = proto.NetworkEnable{}.Call(p.Call())
	if err != nil {
		return err
	}

	res, err := proto.DOMGetDocument{}.Call(p.Call())
	if err != nil {
		return err
	}

	for _, child := range res.Root.Children {
		frameID := child.FrameID
		if frameID != nil {
			p.FrameID = frameID
		}
	}

	return nil
}

func (p *Page) initJS() error {
	scriptURL := "\n//# sourceURL=__rod_helper__"

	params := *&proto.RuntimeEvaluate{
		Expression: sprintFnApply(assets.Helper, Array{p.FrameID}) + scriptURL,
	}

	if p.IsIframe() {
		res, err := proto.PageCreateIsolatedWorld{
			FrameID: p.FrameID,
		}.Call(p.Call())
		if err != nil {
			return err
		}

		params.ContextID = res.ExecutionContextID
	}

	res, err := params.Call(p.Call())
	if err != nil {
		return err
	}

	p.windowObjectID = res.Result.ObjectID

	return nil
}

func (p *Page) jsFnPrefix() string {
	return "rod" + string(*p.FrameID) + "."
}

func (p *Page) jsFn(fnName string) string {
	return p.jsFnPrefix() + fnName
}
