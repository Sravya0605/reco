package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func vhost(domain string) {
	file, err := os.Open("TextFiles/subdomains-top1million-5000.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

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
			url := fmt.Sprintf("https://%s/", domain) // connect to IP

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}

			req.Host = fullHost // set Host header for vhost
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 301 {
				fmt.Printf("[+] %s\n", fullHost)
			}
		}(subdomain)
	}

	wg.Wait()

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading file: %v\n", err)
	}
}
