package rod_test

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ysmood/kit"
	"github.com/ysmood/rod"
	"github.com/ysmood/rod/lib/defaults"
	"github.com/ysmood/rod/lib/launcher"
	"github.com/ysmood/rod/lib/proto"
)

func (s *S) TestBrowserPages() {
	page := s.browser.Page(srcFile("fixtures/click.html"))
	defer page.Close()

	pages := s.browser.Pages()

	s.Len(pages, 3)
}

func (s *S) TestBrowserContext() {
	b := s.browser.Timeout(time.Minute).CancelTimeout().Cancel()
	err := b.CloseE()
	s.Error(err)
}

func (s *S) TestIncognito() {
	file := srcFile("fixtures/click.html")
	k := kit.RandString(8)

	b := s.browser.Incognito()
	page := b.Page(file)
	page.Eval(`k => localStorage[k] = 1`, k)

	s.Nil(s.page.Navigate(file).Eval(`k => localStorage[k]`, k).Value())
	s.EqualValues(1, page.Eval(`k => localStorage[k]`, k).Int())
}

func (s *S) TestBrowserWaitEvent() {
	wait := s.browser.WaitEvent("Page.frameNavigated")
	s.page.Navigate(srcFile("fixtures/click.html"))
	wait()
}

func (s *S) TestBrowserCall() {
	v, err := proto.BrowserGetVersion{}.Call(s.browser.Call())
	kit.E(err)

	s.Regexp("HeadlessChrome", v.Product)
}

func (s *S) TestMonitor() {
	b := rod.New().Connect()
	defer b.Close()
	p := b.Page(srcFile("fixtures/click.html")).WaitLoad()
	host := b.ServeMonitor("127.0.0.1:0").Listener.Addr().String()

	s.Contains(kit.Req("http://"+host).MustString(), string(*p.TargetID))
	s.Contains(kit.Req("http://"+host+"/page/"+string(*p.TargetID)).MustString(), p.TargetID)
	s.Greater(len(kit.Req("http://"+host+"/screenshot/"+string(*p.TargetID)).MustBytes()), 1000)
}

func (s *S) TestRemoteLaunch() {
	defaults.Remote = true
	defer func() { defaults.Remote = false }()

	srv := kit.MustServer("127.0.0.1:0")
	defer func() { _ = srv.Listener.Close() }()
	proxy := &launcher.Proxy{Log: func(s string) {}}
	srv.Engine.NoRoute(gin.WrapH(proxy))
	go func() { _ = srv.Do() }()

	host := "ws://" + srv.Listener.Addr().String()
	b := rod.New().ControlURL(host).Connect()
	defer b.Close()

	p := b.Page(srcFile("fixtures/click.html"))
	p.Element("button").Click()
	s.True(p.Has("[a=ok]"))
}

func (s *S) TestConcurrentOperations() {
	p := s.page.Navigate(srcFile("fixtures/click.html"))
	list := []int64{}

	kit.All(func() {
		list = append(list, p.Eval(`() => new Promise(r => setTimeout(r, 100, 2))`).Int())
	}, func() {
		list = append(list, p.Eval(`() => 1`).Int())
	})()

	s.Equal([]int64{1, 2}, list)
}

func (s *S) TestPromiseLeak() {
	/*
		Perform a slow action then navigate the page to another url,
		we can see the slow operation will still be executed.

		The unexpected part is that the promise will resolve to the next page's url.
	*/

	p := s.page.Navigate(srcFile("fixtures/click.html"))
	var out string

	kit.All(func() {
		out = p.Eval(`() => new Promise(r => setTimeout(() => r(location.href), 200))`).String()
	}, func() {
		kit.Sleep(0.1)
		p.Navigate(srcFile("fixtures/input.html"))
	})()

	s.Contains(out, "input.html")
}

func (s *S) TestObjectLeak() {
	/*
		Seems like it won't leak
	*/

	p := s.page.Navigate(srcFile("fixtures/click.html"))

	el := p.Element("button")
	p.Navigate(srcFile("fixtures/input.html")).WaitLoad()
	s.Panics(func() {
		el.Describe()
	})
}

// It's obvious that, the v8 will take more time to parse long function.
// For BenchmarkCache and BenchmarkNoCache, the difference is nearly 12% which is too much to ignore.
func BenchmarkCacheOff(b *testing.B) {
	p := rod.New().Connect().Page(srcFile("fixtures/click.html"))

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		p.Eval(`(time) => {
			// won't call this function, it's used to make the declaration longer
			function foo (id, left, top, width, height, msg) {
				var div = document.createElement('div')
				var msgDiv = document.createElement('div')
				div.id = id
				div.style = 'position: fixed; z-index:2147483647; border: 2px dashed red;'
					+ 'border-radius: 3px; box-shadow: #5f3232 0 0 3px; pointer-events: none;'
					+ 'box-sizing: border-box;'
					+ 'left:' + left + 'px;'
					+ 'top:' + top + 'px;'
					+ 'height:' + height + 'px;'
					+ 'width:' + width + 'px;'
		
				if (height === 0) {
					div.style.border = 'none'
				}
			
				msgDiv.style = 'position: absolute; color: #cc26d6; font-size: 12px; background: #ffffffeb;'
					+ 'box-shadow: #333 0 0 3px; padding: 2px 5px; border-radius: 3px; white-space: nowrap;'
					+ 'top:' + height + 'px; '
			
				msgDiv.innerHTML = msg
			
				div.appendChild(msgDiv)
				document.body.appendChild(div)
			}
			return time
		}`, time.Now().UnixNano())
	}
}

func BenchmarkCache(b *testing.B) {
	p := rod.New().Connect().Page(srcFile("fixtures/click.html"))

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		p.Eval(`(time) => {
			return time
		}`, time.Now().UnixNano())
	}
}
