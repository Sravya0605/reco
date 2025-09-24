package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func whoIs(domain string) {
	api := "73095bdaadefb536293530d4fa553408e0a5ee7c82edcc606da2d0f20f93f2b8"

	url := fmt.Sprintf("https://whoisjson.com/api/v1/whois?domain=%s", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "TOKEN="+api)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}

	// Pretty print the JSON
	pretty, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Failed to format JSON: %v", err)
	}

	fmt.Printf("Whois JSON Response for %s:\n%s\n", domain, string(pretty))
}
