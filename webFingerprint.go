package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// run does the full work: parse args, fetch, limit body size, fingerprint, output JSON.
func webFingerprinting(target string) {

	if len(os.Args) > 1 && os.Args[1] != "" {
		target = os.Args[1]
	}

	// overall timeout so we don't hang forever
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// tuned HTTP client for speed + connection reuse
	httpClient := &http.Client{
		Timeout: 12 * time.Second, // per-request timeout
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// Accept most TLS certs (if you want stricter validation remove this)
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	// Build request with sensible headers
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		log.Fatalf("creating request: %v", err)
	}
	req.Header.Set("User-Agent", "wappalyzer-go/1.0 (+https://github.com/projectdiscovery/wappalyzergo)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip")

	// Execute request
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	// Limit how many bytes we read from the body to avoid huge downloads.
	// Wappalyzer typically needs the HTML head and some body; 1 MiB should be plenty.
	const bodyLimit = 1 << 20 // 1 MiB

	limited := io.LimitReader(resp.Body, bodyLimit)
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, limited); err != nil && err != io.EOF {
		log.Fatalf("reading response body: %v", err)
	}
	bodyBytes := buf.Bytes()

	// Create wappalyzer client
	wa, err := wappalyzer.New()
	if err != nil {
		log.Fatalf("creating wappalyzer client: %v", err)
	}

	// Fingerprint (fast, pure function)
	fps := wa.Fingerprint(resp.Header, bodyBytes)

	// Output JSON for easier downstream parsing; pretty-print for humans.
	out := map[string]interface{}{
		"target":       target,
		"status":       resp.StatusCode,
		"content_len":  len(bodyBytes),
		"fingerprints": fps,
		"fetched_at":   time.Now().UTC().Format(time.RFC3339),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Fatalf("encoding output: %v", err)
	}
}
