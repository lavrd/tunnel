package main

import (
	"context"
	"net/http"
	"time"

	"github.com/form3tech-oss/f1/v2/pkg/f1"
	"github.com/form3tech-oss/f1/v2/pkg/f1/testing"
)

func main() {
	f1.New().Add("tunnel", runTunnel).Execute()
}

func runTunnel(t *testing.T) testing.RunFn {
	return func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		endpoint := "http://127.0.0.1:8888/resolve?name=cloudflare.com"
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
	}
}
