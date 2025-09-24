package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var sites = map[string]map[string]string{
	"Instagram": {
		"url":   "https://instagram.com/%s",
		"error": "This account does not exist",
	},
	"Twitter": {
		"url":   "https://twitter.com/%s",
		"error": "This account doesn’t exist",
	},
	"Facebook": {
		"url":   "https://www.facebook.com/%s",
		"error": "This page isn't available",
	},
	"GitHub": {
		"url":   "https://github.com/%s",
		"error": "Not Found",
	},
	"Reddit": {
		"url":   "https://www.reddit.com/user/%s",
		"error": "Sorry, nobody on Reddit goes by that name",
	},
	"LinkedIn": {
		"url":   "https://www.linkedin.com/in/%s",
		"error": "Profile Not Found",
	},
	"Pinterest": {
		"url":   "https://www.pinterest.com/%s",
		"error": "This page isn't available",
	},
	"TikTok": {
		"url":   "https://www.tiktok.com/@%s",
		"error": "Couldn't find this account",
	},
	"YouTube": {
		"url":   "https://www.youtube.com/@%s",
		"error": "This page isn't available",
	},
}

func findUser(username string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	var wg sync.WaitGroup
	for site, data := range sites {
		wg.Add(1)

		// Run each site check in a separate goroutine
		go func(site string, data map[string]string) {
			defer wg.Done()

			url := fmt.Sprintf(data["url"], username)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode == 404 || strings.Contains(strings.ToLower(string(body)), strings.ToLower(data["error"])) {
				return
			}

			fmt.Printf("[+] %s: %s\n", site, url)
		}(site, data)
	}

	// Wait for all goroutines to finish
	wg.Wait()
}
