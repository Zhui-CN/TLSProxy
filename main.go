package main

import (
	"bytes"
	"encoding/base64"
	"github.com/Zhui-CN/HTTPTLSClient"
	"github.com/Zhui-CN/HTTPTLSClient/proxy"
	"gopkg.in/elazarl/goproxy.v1"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var (
	proxyUser                = "admin"
	proxyPwd                 = "admin123"
	unauthorizedMsg          = []byte("407 Proxy Authentication Required")
	proxyAuthorizationHeader = "Proxy-Authorization"
)
var proxies = proxy.FuncToProxy(func(*http.Request) *url.URL {
	return nil
})

func BasicUnauthorized(req *http.Request, realm string) *http.Response {
	// TODO(elazar): verify realm is well formed
	return &http.Response{
		StatusCode: 407,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Request:    req,
		Header: http.Header{
			"Proxy-Authenticate": []string{"Basic realm=" + realm},
			"Proxy-Connection":   []string{"close"},
		},
		Body:          io.NopCloser(bytes.NewBuffer(unauthorizedMsg)),
		ContentLength: int64(len(unauthorizedMsg)),
	}
}

func proxyAuth(req *http.Request) bool {
	authHeader := strings.SplitN(req.Header.Get(proxyAuthorizationHeader), " ", 2)
	req.Header.Del(proxyAuthorizationHeader)
	if len(authHeader) != 2 || authHeader[0] != "Basic" {
		return false
	}
	userPassRaw, err := base64.StdEncoding.DecodeString(authHeader[1])
	if err != nil {
		return false
	}
	userPass := strings.SplitN(string(userPassRaw), ":", 2)
	if len(userPass) != 2 {
		return false
	}
	return userPass[0] == proxyUser && userPass[1] == proxyPwd
}

func BasicConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	if !proxyAuth(ctx.Req) {
		ctx.Resp = BasicUnauthorized(ctx.Req, "")
		return goproxy.RejectConnect, host
	}
	return goproxy.MitmConnect, host
}

func handle(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" && !proxyAuth(req) {
		return nil, BasicUnauthorized(req, "")
	}
	client := HTTPTLSClient.New(proxies, nil)
	defer client.CloseIdleConnections()
	req.RequestURI = ""
	req.URL.Host = req.Host
	resp, err := client.Do(req)
	if err != nil {
		return req, nil
	}
	return nil, resp
}

func main() {
	p := goproxy.NewProxyHttpServer()
	p.OnRequest().HandleConnectFunc(BasicConnect)
	p.OnRequest().DoFunc(handle)
	p.Verbose = true
	log.Fatal(http.ListenAndServe(":9001", p))
}
