package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func check() string {
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{}, // Loopback only; never use environment proxies.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Get("http://127.0.0.1:3200/ready")
	if err != nil {
		return "unhealthy: request failed"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "unhealthy: HTTP status"
	}
	const maxBody = 4096
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(body) > maxBody || strings.TrimSpace(string(body)) != "ready" {
		return "unhealthy: readiness body"
	}
	return "healthy"
}

func main() {
	status := check()
	fmt.Println(status)
	if status != "healthy" {
		os.Exit(1)
	}
}
