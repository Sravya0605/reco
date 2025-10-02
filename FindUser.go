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
	"Instagram":     {"url": "https://instagram.com/%s", "error": "This account does not exist"},
	"Twitter":       {"url": "https://twitter.com/%s", "error": "This account doesn’t exist"},
	"Facebook":      {"url": "https://www.facebook.com/%s", "error": "This page isn't available"},
	"GitHub":        {"url": "https://github.com/%s", "error": "Not Found"},
	"Reddit":        {"url": "https://www.reddit.com/user/%s", "error": "Sorry, nobody on Reddit goes by that name"},
	"LinkedIn":      {"url": "https://www.linkedin.com/in/%s", "error": "Profile Not Found"},
	"Pinterest":     {"url": "https://www.pinterest.com/%s", "error": "This page isn't available"},
	"TikTok":        {"url": "https://www.tiktok.com/@%s", "error": "Couldn't find this account"},
	"YouTube":       {"url": "https://www.youtube.com/@%s", "error": "This page isn't available"},
	"Twitch":        {"url": "https://www.twitch.tv/%s", "error": "Sorry. Unless you've got a time machine, this user doesn’t exist"},
	"Snapchat":      {"url": "https://www.snapchat.com/add/%s", "error": "Sorry, this username isn’t available"},
	"Discord":       {"url": "https://discord.com/users/%s", "error": "404 Not Found"},
	"Medium":        {"url": "https://medium.com/@%s", "error": "Page not found"},
	"StackOverflow": {"url": "https://stackoverflow.com/users/%s", "error": "Page Not Found"},
	"Spotify":       {"url": "https://open.spotify.com/user/%s", "error": "Page not found"},
	"DeviantArt":    {"url": "https://www.deviantart.com/%s", "error": "404 Not Found"},
	"Flickr":        {"url": "https://www.flickr.com/people/%s", "error": "Sorry, that page doesn’t exist"},
	"VK":            {"url": "https://vk.com/%s", "error": "Page not found"},
}

func findUser(username string) []string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for site, data := range sites {
		wg.Add(1)
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

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			if resp.StatusCode == 404 || strings.Contains(strings.ToLower(string(body)), strings.ToLower(data["error"])) {
				// User not found
				return
			}

			// If no error indications, assume user exists
			formatted := fmt.Sprintf("[+] %s: %s", site, url)

			mu.Lock()
			results = append(results, formatted)
			mu.Unlock()
		}(site, data)
	}

	wg.Wait()
	return results
}
