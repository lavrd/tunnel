package main

import (
	"log/slog"
	"net/http"
	"os/exec"
)

func main() {
	logger := slog.Default()
	http.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			logger.Error("incorrect method", "method", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			logger.Error("name to resolve is empty")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Info("name requested to resolve", "name", name)
		output, err := exec.Command("dig", "@1.1.1.1", "+trace", name).Output()
		if err != nil {
			logger.Error("failed to execute dig command", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err = w.Write(output); err != nil {
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
