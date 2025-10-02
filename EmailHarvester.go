package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// EmailResult represents an email finding with source and type classification
type EmailResult struct {
	Email  string
	Source string
	Type   string // e.g., "Direct", "Website", "Technical"
}

// EmailHarvester scans for email addresses related to a domain from various sources
func emailHarvester(domain string) ([]EmailResult, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	emailRegex := regexp.MustCompile("[a-zA-Z0-9._%+-]+@" + regexp.QuoteMeta(domain))

	var results []EmailResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Scan main page
	wg.Add(1)
	go func() {
		defer wg.Done()
		emails := extractEmailsFromURL("https://"+domain, client, emailRegex)
		mu.Lock()
		for _, e := range emails {
			results = append(results, EmailResult{Email: e, Source: "Main Website", Type: "Direct"})
		}
		mu.Unlock()
	}()

	// Scan common pages
	commonPages := []string{
		"about", "contact", "contact-us", "support", "help", "team", "staff", "directory",
	}
	for _, page := range commonPages {
		page := page
		wg.Add(1)
		go func() {
			defer wg.Done()
			url := fmt.Sprintf("https://%s/%s", domain, page)
			emails := extractEmailsFromURL(url, client, emailRegex)
			mu.Lock()
			for _, e := range emails {
				results = append(results, EmailResult{Email: e, Source: "Page " + page, Type: "Website"})
			}
			mu.Unlock()
		}()
	}

	// Scan robots.txt and sitemap.xml files
	robotsURL := "https://" + domain + "/robots.txt"
	sitemapURL := "https://" + domain + "/sitemap.xml"

	wg.Add(1)
	go func() {
		defer wg.Done()
		emails := extractEmailsFromURL(robotsURL, client, emailRegex)
		mu.Lock()
		for _, e := range emails {
			results = append(results, EmailResult{Email: e, Source: "robots.txt", Type: "Technical"})
		}
		mu.Unlock()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		emails := extractEmailsFromURL(sitemapURL, client, emailRegex)
		mu.Lock()
		for _, e := range emails {
			results = append(results, EmailResult{Email: e, Source: "sitemap.xml", Type: "Technical"})
		}
		mu.Unlock()
	}()

	wg.Wait()

	// Remove duplicates
	results = removeDuplicateEmails(results)

	// Sort by type and email for better readibility
	sort.Slice(results, func(i, j int) bool {
		if results[i].Type == results[j].Type {
			return results[i].Email < results[j].Email
		}
		return results[i].Type < results[j].Type
	})

	return results, nil
}

// extractEmailsFromURL fetches content from url and extracts emails matching regex
func extractEmailsFromURL(url string, client *http.Client, regex *regexp.Regexp) []string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; EmailHarvester/1.0)")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	emails := regex.FindAllString(string(body), -1)
	return emails
}

// removeDuplicateEmails removes duplicate email findings
func removeDuplicateEmails(emails []EmailResult) []EmailResult {
	seen := make(map[string]bool)
	var unique []EmailResult
	for _, e := range emails {
		if !seen[e.Email] {
			seen[e.Email] = true
			unique = append(unique, e)
		}
	}
	return unique
}

// FormatEmailResults formats the email findings for display or output
func FormatEmailResults(results []EmailResult) string {
	if len(results) == 0 {
		return "No emails found."
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Found %d email addresses:\n\n", len(results)))

	groups := map[string][]EmailResult{}
	for _, e := range results {
		groups[e.Type] = append(groups[e.Type], e)
	}

	for t, group := range groups {
		builder.WriteString(fmt.Sprintf("=== %s Emails ===\n", strings.Title(t)))
		for i, e := range group {
			builder.WriteString(fmt.Sprintf("%d. %s (Source: %s)\n", i+1, e.Email, e.Source))
		}
		builder.WriteString("\n")
	}

	return builder.String()
}
