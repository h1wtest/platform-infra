package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func check() string {
	// The official webhook Secret mounts tls.crt and tls.key, not a CA file.
	// Trust this local public certificate explicitly; never read its private key.
	// Reload on every probe invocation so certificate renewal is respected.
	certificate, err := os.ReadFile("/run/secrets/cnpg.io/webhook/tls.crt")
	if err != nil {
		return "unhealthy: webhook certificate unavailable"
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return "unhealthy: invalid webhook certificate"
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: "cnpg-webhook-service.cnpg-system.svc",
				MinVersion: tls.VersionTLS12,
			},
		}, // Loopback only; never use environment proxies.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Get("https://127.0.0.1:9443/readyz")
	if err != nil {
		return "unhealthy: verified webhook request failed"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "unhealthy: HTTP status"
	}
	const maxBody = 4096
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
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
