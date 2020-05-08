package rod

import (
	"context"
	"sync"
	"time"

	"github.com/ysmood/kit"
	"github.com/ysmood/rod/lib/cdp"
	"github.com/ysmood/rod/lib/defaults"
	"github.com/ysmood/rod/lib/launcher"
	"github.com/ysmood/rod/lib/proto"
)

// Browser represents the browser
// It doesn't depends on file system, it should work with remote browser seamlessly.
// To check the env var you can use to quickly enable options from CLI, check here:
// https://pkg.go.dev/github.com/ysmood/rod/lib/defaults
type Browser struct {
	// these are the handler for ctx
	ctx           context.Context
	ctxCancel     func()
	timeoutCancel func()

	// BrowserContextID is the id for incognito window
	BrowserContextID *proto.BrowserBrowserContextID

	controlURL string
	slowmotion time.Duration      // slowdown user inputs
	trace      bool               // enable show auto tracing of user inputs
	remote     *launcher.Launcher // enable launch chrome remotely

	monitorServer *kit.ServerContext

	client *cdp.Client
	event  *kit.Observable // all the browser events from cdp client
}

// New creates a controller
func New() *Browser {
	b := &Browser{
		ctx:        context.Background(),
		client:     cdp.New(),
		controlURL: defaults.URL,
		trace:      defaults.Trace,
		slowmotion: defaults.Slow,
	}

	if defaults.Remote && b.controlURL == "" {
		b.controlURL = "ws://127.0.0.1:9222"
	}

	return b
}

// ControlURL set the url to remote control browser.
func (b *Browser) ControlURL(url string) *Browser {
	b.controlURL = url
	return b
}

// Slowmotion set the delay for each chrome control action
func (b *Browser) Slowmotion(delay time.Duration) *Browser {
	b.slowmotion = delay
	return b
}

// Trace enables/disables the visual tracing of the input actions on the page
func (b *Browser) Trace(enable bool) *Browser {
	b.trace = enable
	return b
}

// Client set the cdp client
func (b *Browser) Client(c *cdp.Client) *Browser {
	b.client = c
	return b
}

// Remote is the option to launch chrome remotely
func (b *Browser) Remote(l *launcher.Launcher) *Browser {
	b.remote = l
	return b
}

// DebugCDP enables/disables the log of all cdp interface traffic
func (b *Browser) DebugCDP(enable bool) *Browser {
	b.client.Debug(enable)
	return b
}

// ConnectE doc is the same as the method Connect
func (b *Browser) ConnectE() error {
	*b = *b.Context(b.ctx)

	if b.controlURL == "" {
		u, err := launcher.New().Context(b.ctx).LaunchE()
		if err != nil {
			return err
		}
		b.controlURL = u
	}

	if defaults.Remote {
		if b.remote == nil {
			b.remote = launcher.NewRemote(b.controlURL)
		}
		ws := cdp.NewDefaultWsClient(b.ctx, b.controlURL, b.remote.Header())
		b.client = cdp.New().Websocket(ws)
	}

	b.client.URL(b.controlURL).Context(b.ctx).Connect()

	b.monitorServer = b.ServeMonitor(defaults.Monitor)

	return b.initEvents()
}

// CloseE doc is the same as the method Close
func (b *Browser) CloseE() error {
	_, err := proto.BrowserClose{}.Call(b.Call())
	if err != nil {
		return err
	}

	if b.monitorServer != nil {
		return b.monitorServer.Listener.Close()
	}

	return nil
}

// IncognitoE creates a new incognito browser
func (b *Browser) IncognitoE() (*Browser, error) {
	res, err := proto.TargetCreateBrowserContext{}.Call(b.Call())
	if err != nil {
		return nil, err
	}

	incognito := *b
	incognito.BrowserContextID = res.BrowserContextID

	return &incognito, nil
}

// PageE doc is the same as the method Page
func (b *Browser) PageE(url string) (*Page, error) {
	if url == "" {
		url = "about:blank"
	}

	req := proto.TargetCreateTarget{
		URL: url,
	}

	if b.BrowserContextID != nil {
		req.BrowserContextID = b.BrowserContextID
	}

	target, err := req.Call(b.Call())
	if err != nil {
		return nil, err
	}

	return b.page(target.TargetID)
}

// PagesE doc is the same as the method Pages
func (b *Browser) PagesE() (Pages, error) {
	list, err := proto.TargetGetTargets{}.Call(b.Call())
	if err != nil {
		return nil, err
	}

	pageList := Pages{}
	for _, target := range list.TargetInfos {
		if target.Type != "page" {
			continue
		}

		page, err := b.page(target.TargetID)
		if err != nil {
			return nil, err
		}
		pageList = append(pageList, page)
	}

	return pageList, nil
}

// EventFilter to filter events
type EventFilter func(*cdp.Event) bool

// WaitEventE returns wait and cancel methods
func (b *Browser) WaitEventE(filter EventFilter) func() (*cdp.Event, error) {
	var event *cdp.Event
	var err error
	w := kit.All(func() {
		_, err = b.Event().Until(b.ctx, func(e kit.Event) bool {
			event = e.(*cdp.Event)
			return filter(event)
		})
	})

	return func() (*cdp.Event, error) {
		w()
		return event, err
	}
}

// Event returns the observable for browser events
func (b *Browser) Event() *kit.Observable {
	return b.event
}

// Call parameters for proto
func (b *Browser) Call() *proto.Call {
	return &proto.Call{b.ctx, b.client, ""}
}

func (b *Browser) page(targetID *proto.TargetTargetID) (*Page, error) {
	page := &Page{
		ctx:                 b.ctx,
		browser:             b,
		TargetID:            targetID,
		getDownloadFileLock: &sync.Mutex{},
	}

	page.Mouse = &Mouse{page: page}

	page.Keyboard = &Keyboard{page: page}

	return page, page.initSession()
}

func (b *Browser) initEvents() error {
	b.event = kit.NewObservable()

	go func() {
		for msg := range b.client.Event() {
			go b.event.Publish(msg)
		}
		b.event.UnsubscribeAll()
	}()

	_, err := proto.TargetSetDiscoverTargets{
		Discover: true,
	}.Call(b.Call())

	return err
}
