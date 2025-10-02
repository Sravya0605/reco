package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

func whoIs(domain string) ([]string, error) {
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
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Filter out redacted entries recursively
	filtered := filterWhois(result)

	pretty, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format JSON: %w", err)
	}

	lines := strings.Split(string(pretty), "\n")
	return lines, nil
}

func filterWhois(data map[string]interface{}) map[string]interface{} {
	cleaned := make(map[string]interface{})

	for key, value := range data {
		switch v := value.(type) {
		case string:
			if v != "REDACTED FOR PRIVACY" {
				cleaned[key] = v
			}
		case []interface{}:
			var newArr []interface{}
			for _, elem := range v {
				if elemMap, ok := elem.(map[string]interface{}); ok {
					newArr = append(newArr, filterWhois(elemMap))
				} else {
					newArr = append(newArr, elem)
				}
			}
			cleaned[key] = newArr
		case map[string]interface{}:
			cleaned[key] = filterWhois(v)
		default:
			cleaned[key] = value
		}
	}

	return cleaned
}
