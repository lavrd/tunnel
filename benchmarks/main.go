package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/form3tech-oss/f1/v2/pkg/f1"
	"github.com/form3tech-oss/f1/v2/pkg/f1/testing"
)

func main() {
	f1 := f1.New()
	f1.Add("tunnel_dig", runTunnelDig)
	f1.Add("tunnel_go", runTunnelGo)
	f1.Execute()
}

func runTunnelDig(t *testing.T) testing.RunFn {
	endpoint := prepareEndpoint("dig")
	return func(t *testing.T) {
		makeRequest(t, endpoint)
	}
}

func runTunnelGo(t *testing.T) testing.RunFn {
	endpoint := prepareEndpoint("go")
	return func(t *testing.T) {
		makeRequest(t, endpoint)
	}
}

func makeRequest(t *testing.T, endpoint string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		t.FailNow()
		return
	}
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		t.FailNow()
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.FailNow()
		return
	}
}

func prepareEndpoint(method string) string {
	return fmt.Sprintf("http://127.0.0.1:8888/resolve?name=cloudflare.com&method=%s", method)
}
