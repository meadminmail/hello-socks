package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func main() {
	flagSocksServer := flag.String("socks-server", "socks5://test:test@127.0.0.1:8080", "addr of socks server like socks://user:pass@127.0.0.1:8000")
	flag.Parse()

	urlToFetch := "https://www.baidu.com"

	proxyURL, err := url.Parse(*flagSocksServer)

	if err != nil {
		fmt.Printf("invalid proxy server URL, 错误：%v", err)
		return
	}
	response, err := newClient(proxyURL).Get(urlToFetch)

	if err != nil {
		fmt.Printf("could not GET, 错误：%v, %s", err, urlToFetch)
		return
	}
	defer silentClose(response.Body)

	respBytes, err := httputil.DumpResponse(response, true)

	if err != nil {
		fmt.Printf("failed httputil.DumpResponse, 错误：%v", err)
		return
	}
	fmt.Println(string(respBytes))
}

func newClient(proxyURL *url.URL) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
	}
}

func silentClose(c io.Closer) {
	if c != nil {
		_ = c.Close()
	}
}
