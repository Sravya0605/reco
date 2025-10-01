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

// EmailResult represents an email finding
type EmailResult struct {
	Email  string
	Source string
	Type   string
}

// EmailHarvester performs email harvesting from various sources
func emailHarvester(domain string) ([]EmailResult, error) {
	var results []EmailResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Email regex pattern
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@` + regexp.QuoteMeta(domain))

	// Check main website
	wg.Add(1)
	go func() {
		defer wg.Done()
		emails := extractEmailsFromURL(fmt.Sprintf("https://%s", domain), client, emailRegex)
		mu.Lock()
		for _, email := range emails {
			results = append(results, EmailResult{
				Email:  email,
				Source: "Main Website",
				Type:   "Direct",
			})
		}
		mu.Unlock()
	}()

	// Check common pages
	commonPages := []string{
		"contact", "about", "team", "staff", "directory",
		"contact-us", "about-us", "support", "help",
	}

	for _, page := range commonPages {
		wg.Add(1)
		go func(page string) {
			defer wg.Done()
			pageURL := fmt.Sprintf("https://%s/%s", domain, page)
			emails := extractEmailsFromURL(pageURL, client, emailRegex)
			mu.Lock()
			for _, email := range emails {
				results = append(results, EmailResult{
					Email:  email,
					Source: fmt.Sprintf("Page: %s", page),
					Type:   "Website",
				})
			}
			mu.Unlock()
		}(page)
	}

	// Check robots.txt and sitemap.xml
	wg.Add(1)
	go func() {
		defer wg.Done()
		robotsEmails := extractEmailsFromURL(fmt.Sprintf("https://%s/robots.txt", domain), client, emailRegex)
		sitemapEmails := extractEmailsFromURL(fmt.Sprintf("https://%s/sitemap.xml", domain), client, emailRegex)

		mu.Lock()
		for _, email := range robotsEmails {
			results = append(results, EmailResult{
				Email:  email,
				Source: "robots.txt",
				Type:   "Technical",
			})
		}
		for _, email := range sitemapEmails {
			results = append(results, EmailResult{
				Email:  email,
				Source: "sitemap.xml",
				Type:   "Technical",
			})
		}
		mu.Unlock()
	}()

	wg.Wait()

	// Remove duplicates and sort
	results = removeDuplicateEmails(results)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Email < results[j].Email
	})

	return results, nil
}

// extractEmailsFromURL extracts emails from a given URL
func extractEmailsFromURL(targetURL string, client *http.Client, emailRegex *regexp.Regexp) []string {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	return emailRegex.FindAllString(string(body), -1)
}

// removeDuplicateEmails removes duplicate email results
func removeDuplicateEmails(results []EmailResult) []EmailResult {
	keys := make(map[string]bool)
	var unique []EmailResult

	for _, result := range results {
		if !keys[result.Email] {
			keys[result.Email] = true
			unique = append(unique, result)
		}
	}

	return unique
}

// FormatEmailResults formats email results for display
func FormatEmailResults(results []EmailResult) string {
	if len(results) == 0 {
		return "No emails found for the domain."
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Found %d email addresses:\n\n", len(results)))

	// Group by type
	typeGroups := make(map[string][]EmailResult)
	for _, result := range results {
		typeGroups[result.Type] = append(typeGroups[result.Type], result)
	}

	for emailType, emails := range typeGroups {
		output.WriteString(fmt.Sprintf("=== %s EMAILS ===\n", strings.ToUpper(emailType)))
		for i, result := range emails {
			output.WriteString(fmt.Sprintf("%d. %s (Source: %s)\n", i+1, result.Email, result.Source))
		}
		output.WriteString("\n")
	}

	return output.String()
}
