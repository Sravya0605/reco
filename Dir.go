package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

func dir(domain string) []string {
	file, err := os.Open("TextFiles/common.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Timeout: 7 * time.Second,
	}

	var results []string
	var mu sync.Mutex
	sem := make(chan struct{}, 200) // concurrency limit 20
	var wg sync.WaitGroup

	ignoreStatuses := map[int]bool{
		301: true,
	}

	for _, line := range lines {
		wg.Add(1)
		sem <- struct{}{} // acquire slot

		go func(line string) {
			defer wg.Done()
			defer func() { <-sem }() // release slot

			// Skip invalid paths
			if strings.ContainsAny(line, " @!#$%^&*()[]{};:'\"\\|,<>?") && !strings.HasPrefix(line, ".") {
				return
			}

			url := fmt.Sprintf("https://%s/%s", domain, line)
			var resp *http.Response
			var err error

			// Retry logic - try up to 3 times with delay
			for i := 0; i < 3; i++ {
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0")

				resp, err = client.Do(req)
				if err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err != nil || resp == nil {
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			content := strings.ToLower(string(body))
			if ignoreStatuses[resp.StatusCode] || strings.Contains(content, "not found") {
				return
			}

			mu.Lock()
			results = append(results, fmt.Sprintf("[%d] %s", resp.StatusCode, line))
			mu.Unlock()

			// Add a small delay between requests to avoid flooding
			time.Sleep(50 * time.Millisecond)
		}(line)
	}

	wg.Wait()

	// Sort results alphabetically
	sort.Slice(results, func(i, j int) bool {
		return results[i] < results[j]
	})

	// Remove duplicates
	results = removeDuplicates(results)

	return results
}

func removeDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for _, e := range elements {
		if !encountered[e] {
			encountered[e] = true
			result = append(result, e)
		}
	}
	return result
}
