package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/form3tech-oss/f1/v2/pkg/f1"
	"github.com/form3tech-oss/f1/v2/pkg/f1/testing"
)

const Host = "tunnel.com"

func main() {
	f1 := f1.New()
	f1.Add("tunnel_dig", RunTunnelDig)
	f1.Add("tunnel_go", RunTunnelGo)
	f1.Add("lookup_go", RunLookupGo)
	f1.Add("lookup_local_go", RunLookupLocalGo)
	f1.Execute()
}

func RunTunnelDig(t *testing.T) testing.RunFn {
	endpoint := PrepareEndpoint("dig")
	return func(t *testing.T) { MakeRequest(t, endpoint) }
}

func RunTunnelGo(t *testing.T) testing.RunFn {
	endpoint := PrepareEndpoint("go")
	return func(t *testing.T) { MakeRequest(t, endpoint) }
}

func RunLookupGo(t *testing.T) testing.RunFn {
	return func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := net.DefaultResolver.LookupHost(ctx, Host)
		t.Require().NoError(err)
	}
}

func RunLookupLocalGo(t *testing.T) testing.RunFn {
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("udp", "127.0.0.1:12400")
		},
	}
	return func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := resolver.LookupHost(ctx, Host)
		t.Require().NoError(err)
	}
}

func MakeRequest(t *testing.T, endpoint string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	t.Require().NoError(err)
	res, err := (&http.Client{}).Do(req)
	t.Require().NoError(err)
	defer res.Body.Close()
	t.Require().Equal(http.StatusOK, res.StatusCode)
}

func PrepareEndpoint(method string) string {
	return fmt.Sprintf("http://127.0.0.1:8888/resolve?name=tunnel.com&method=%s", method)
}
