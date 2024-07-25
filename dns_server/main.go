package main

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
)

func main() {
	logger := slog.Default()
	http.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			logger.Error("incorrect method", "method", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		query := r.URL.Query()
		name := query.Get("name")
		if name == "" {
			logger.Error("name to resolve is empty")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		method := query.Get("method")
		var buf []byte
		switch method {
		case "dig":
			output, err := exec.Command("dig", name).Output()
			if err != nil {
				logger.Error("failed to execute dig command", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			buf = output
		case "go":
			addresses, err := net.DefaultResolver.LookupHost(ctx, name)
			if err != nil {
				logger.Error("failed to lookup for a host", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			buf, err = json.Marshal(addresses)
			if err != nil {
				logger.Error("failed to marshal address after go lookup", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		default:
			logger.Error("method (how to resolve) is empty or incorrect", "method", method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(buf); err != nil {
			logger.Error("failed to write response", "error", err)
			return
		}
	})

	logger.Info("starting http server for dns resolving")
	if err := http.ListenAndServe("0.0.0.0:8888", nil); err != nil {
		logger.Error("failed to listen and serve", "error", err)
		return
	}
}
