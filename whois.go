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
			// Skip strings that are redacted or contain RDDS query instructions
			if v == "REDACTED FOR PRIVACY" || strings.Contains(v, "Please query the RDDS service of the Registrar of Record") {
				continue
			}
			cleaned[key] = v
		case nil:
			// Skip null values
			continue
		case []interface{}:
			var newArr []interface{}
			for _, elem := range v {
				if elemMap, ok := elem.(map[string]interface{}); ok {
					filteredElem := filterWhois(elemMap)
					// Only include non-empty maps
					if len(filteredElem) > 0 {
						newArr = append(newArr, filteredElem)
					}
				} else if elem != nil {
					newArr = append(newArr, elem)
				}
			}
			if len(newArr) > 0 {
				cleaned[key] = newArr
			}
		case map[string]interface{}:
			filteredMap := filterWhois(v)
			// Only include non-empty maps
			if len(filteredMap) > 0 {
				cleaned[key] = filteredMap
			}
		default:
			cleaned[key] = value
		}
	}

	return cleaned
}
