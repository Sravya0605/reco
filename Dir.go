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
		Timeout: 5 * time.Second,
	}

	var results []string
	var mu sync.Mutex
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

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

			ignore := map[int]bool{
				301: true,
			}

			content := strings.ToLower(string(body))
			if ignore[resp.StatusCode] || strings.Contains(content, "not found") {
				return
			}

			mu.Lock()
			results = append(results, fmt.Sprintf("[%d] %s", resp.StatusCode, line))
			mu.Unlock()
		}(line)
	}

	wg.Wait()

	// Sort results alphabetically
	sort.Slice(results, func(i, j int) bool {
		return results[i] < results[j]
	})

	return results
}
