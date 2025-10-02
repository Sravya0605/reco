package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TechResult represents a technology detection result
type TechResult struct {
	Technology string
	Version    string
	Category   string
	Confidence string
	Evidence   string
}

// techDetector performs technology stack detection
func techDetector(domain string) ([]TechResult, error) {
	var results []TechResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	targetURL := fmt.Sprintf("https://%s", domain)

	// Get main page
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)
	headers := resp.Header

	// Technology detection patterns
	techPatterns := map[string]map[string]string{
		"Content Management Systems": {
			"WordPress":   "wp-content|wp-includes|wp-admin|wordpress",
			"Drupal":      "drupal|sites/default|sites/all",
			"Joomla":      "joomla|com_content|administrator",
			"Magento":     "magento|mage/js|skin/frontend",
			"PrestaShop":  "prestashop|ps_|prestashop_",
			"Shopify":     "shopify|cdn.shopify.com",
			"Squarespace": "squarespace|static1.squarespace.com",
			"Wix":         "wix.com|static.wixstatic.com",
		},
		"JavaScript Frameworks": {
			"React":       "react|_react|ReactDOM",
			"Angular":     "angular|ng-|angularjs",
			"Vue.js":      "vue.js|vue.min.js|__vue__",
			"jQuery":      "jquery|jQuery",
			"Bootstrap":   "bootstrap|btn-|col-md",
			"Backbone.js": "backbone|Backbone",
			"Ember.js":    "ember|Ember",
		},
		"Web Servers": {
			"Apache":     "apache",
			"Nginx":      "nginx",
			"IIS":        "iis|microsoft-iis",
			"LiteSpeed":  "litespeed",
			"Cloudflare": "cloudflare",
		},
		"Programming Languages": {
			"PHP":     "php|x-powered-by.*php",
			"ASP.NET": "asp.net|aspnet|__viewstate",
			"Java":    "jsessionid|java|jsp",
			"Python":  "django|flask|python",
			"Ruby":    "ruby|rails|x-powered-by.*ruby",
			"Node.js": "node.js|express|x-powered-by.*express",
		},
		"Analytics & Marketing": {
			"Google Analytics":   "google-analytics|gtag|ga\\.js",
			"Facebook Pixel":     "facebook|fbevents|connect.facebook.net",
			"Google Tag Manager": "googletagmanager|gtm.js",
			"Hotjar":             "hotjar|hj\\.js",
		},
		"CDN & Hosting": {
			"Cloudflare":   "cloudflare|cf-ray",
			"AWS":          "amazonaws|cloudfront",
			"Google Cloud": "googlecloud|gcp",
			"Azure":        "azure|azurewebsites",
		},
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for category, techs := range techPatterns {
			for tech, pattern := range techs {
				if matched, _ := regexp.MatchString("(?i)"+pattern, bodyStr); matched {
					confidence := "Medium"
					version := extractVersion(bodyStr, tech)
					if version != "" {
						confidence = "High"
					}
					mu.Lock()
					results = append(results, TechResult{
						Technology: tech,
						Version:    version,
						Category:   category,
						Confidence: confidence,
						Evidence:   "HTML Content",
					})
					mu.Unlock()
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		if server := headers.Get("Server"); server != "" {
			mu.Lock()
			results = append(results, TechResult{
				Technology: parseServerHeader(server),
				Version:    extractVersionFromServer(server),
				Category:   "Web Servers",
				Confidence: "High",
				Evidence:   fmt.Sprintf("Server: %s", server),
			})
			mu.Unlock()
		}

		if powered := headers.Get("X-Powered-By"); powered != "" {
			mu.Lock()
			results = append(results, TechResult{
				Technology: parsePoweredByHeader(powered),
				Version:    extractVersionFromPoweredBy(powered),
				Category:   "Programming Languages",
				Confidence: "High",
				Evidence:   fmt.Sprintf("X-Powered-By: %s", powered),
			})
			mu.Unlock()
		}

		revealingHeaders := map[string]string{
			"X-AspNet-Version":    "ASP.NET",
			"X-AspNetMvc-Version": "ASP.NET MVC",
			"X-Drupal-Cache":      "Drupal",
			"X-Generator":         "Unknown CMS",
		}

		for header, tech := range revealingHeaders {
			if value := headers.Get(header); value != "" {
				mu.Lock()
				results = append(results, TechResult{
					Technology: tech,
					Version:    value,
					Category:   "Framework",
					Confidence: "High",
					Evidence:   fmt.Sprintf("%s: %s", header, value),
				})
				mu.Unlock()
			}
		}

	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		checkTechEndpoints(domain, client, &results, &mu)
	}()

	wg.Wait()

	return removeDuplicateTech(results), nil
}

// extractVersion tries to extract version numbers from content
func extractVersion(content, tech string) string {
	versionPatterns := map[string]string{
		"WordPress": `(?i)wp.*version['"\s]*[:=]['"\s]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
		"jQuery":    `(?i)jquery[\s-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
		"Bootstrap": `(?i)bootstrap[\s-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
		"React":     `(?i)react['"\s]*[:\"]?['"\s]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
		"Angular":   `(?i)angular['"\s]*[:\"]?['"\s]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`,
	}

	if pattern, exists := versionPatterns[tech]; exists {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

// parseServerHeader parses the Server header to identify web server
func parseServerHeader(server string) string {
	s := strings.ToLower(server)
	switch {
	case strings.Contains(s, "apache"):
		return "Apache"
	case strings.Contains(s, "nginx"):
		return "Nginx"
	case strings.Contains(s, "iis"):
		return "IIS"
	case strings.Contains(s, "litespeed"):
		return "LiteSpeed"
	case strings.Contains(s, "cloudflare"):
		return "Cloudflare"
	default:
		return server
	}
}

// extractVersionFromServer extracts version number from Server header
func extractVersionFromServer(server string) string {
	re := regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	matches := re.FindStringSubmatch(server)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// parsePoweredByHeader parses X-Powered-By header
func parsePoweredByHeader(powered string) string {
	s := strings.ToLower(powered)
	switch {
	case strings.Contains(s, "php"):
		return "PHP"
	case strings.Contains(s, "asp"):
		return "ASP.NET"
	case strings.Contains(s, "express"):
		return "Node.js/Express"
	default:
		return powered
	}
}

// extractVersionFromPoweredBy extracts version from X-Powered-By header
func extractVersionFromPoweredBy(powered string) string {
	re := regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	matches := re.FindStringSubmatch(powered)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// checkTechEndpoints checks specific technology-related endpoints
func checkTechEndpoints(domain string, client *http.Client, results *[]TechResult, mu *sync.Mutex) {
	endpoints := map[string]string{
		"/wp-admin/":      "WordPress",
		"/administrator/": "Joomla",
		"/admin/":         "Generic CMS",
		"/phpmyadmin/":    "phpMyAdmin",
		"/webmail/":       "Webmail",
		"/.well-known/":   "Well-known URIs",
		"/api/":           "API Endpoint",
		"/graphql":        "GraphQL",
		"/swagger/":       "Swagger API",
		"/robots.txt":     "robots.txt",
		"/sitemap.xml":    "XML Sitemap",
	}

	for ep, tech := range endpoints {
		func(endpoint, technology string) {
			url := fmt.Sprintf("https://%s%s", domain, endpoint)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; TechDetector/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
				mu.Lock()
				*results = append(*results, TechResult{
					Technology: technology,
					Version:    "",
					Category:   "Endpoints",
					Confidence: "Medium",
					Evidence:   fmt.Sprintf("Endpoint %s returned %d", endpoint, resp.StatusCode),
				})
				mu.Unlock()
			}
		}(ep, tech)
	}
}

// removeDuplicateTech removes duplicate technology results
func removeDuplicateTech(results []TechResult) []TechResult {
	keys := make(map[string]bool)
	var unique []TechResult

	for _, r := range results {
		key := fmt.Sprintf("%s-%s-%s", r.Technology, r.Version, r.Category)
		if !keys[key] {
			keys[key] = true
			unique = append(unique, r)
		}
	}

	return unique
}

// FormatTechResults formats technology detection results for display
func FormatTechResults(results []TechResult) string {
	if len(results) == 0 {
		return "No technologies detected."
	}

	var out strings.Builder
	out.WriteString(fmt.Sprintf("Detected %d technologies:\n\n", len(results)))

	categoryGroups := make(map[string][]TechResult)
	for _, r := range results {
		categoryGroups[r.Category] = append(categoryGroups[r.Category], r)
	}

	for category, techs := range categoryGroups {
		out.WriteString(fmt.Sprintf("=== %s ===\n", strings.ToUpper(category)))
		for i, t := range techs {
			versionStr := ""
			if t.Version != "" {
				versionStr = " v" + t.Version
			}
			out.WriteString(fmt.Sprintf("%d. %s%s [%s confidence]\n", i+1, t.Technology, versionStr, t.Confidence))
			out.WriteString(fmt.Sprintf("   Evidence: %s\n", t.Evidence))
		}
		out.WriteString("\n")
	}

	return out.String()
}
