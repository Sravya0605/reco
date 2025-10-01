package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func vhost(domain string) ([]string, error) {
	file, err := os.Open("TextFiles/subdomains-top1million-5000.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)
	var mu sync.Mutex
	var foundHosts []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-sem }()

			fullHost := fmt.Sprintf("%s.%s", subdomain, domain)
			url := fmt.Sprintf("https://%s/", domain) // connect to IP or main domain

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}

			req.Host = fullHost // set Host header for virtual host testing
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 301 {
				mu.Lock()
				foundHosts = append(foundHosts, fullHost)
				mu.Unlock()
			}
		}(subdomain)
	}

	wg.Wait()

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return foundHosts, nil
}
