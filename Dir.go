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

type Result struct {
	path       string
	StatusCode int
}

func dir(domain string) {
	file, err := os.Open("TextFiles/common.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var mu sync.Mutex

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

	var results []Result

	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	for _, line := range lines {
		wg.Add(1)
		sem <- struct{}{} // acquire slot
		go func(line string) {
			defer wg.Done()
			defer func() { <-sem }() // release slot

			url := fmt.Sprintf("https://%s/%s", domain, line)

			if strings.ContainsAny(line, " @!#$%^&*()[]{};:'\"\\|,<>?") && !strings.HasPrefix(line, ".") {
				return // skip this line
			}

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
			results = append(results, Result{
				path:       line,
				StatusCode: resp.StatusCode,
			})
			mu.Unlock()

		}(line)
	}

	wg.Wait() // wait for all goroutines to finish
	sort.Slice(results, func(i, j int) bool {
		return results[i].StatusCode < results[j].StatusCode
	})

	for _, r := range results {
		color := colorForStatus(r.StatusCode)
		reset := "\033[0m"
		fmt.Printf("%s[%d]%s %s\n", color, r.StatusCode, reset, r.path)
	}
}

func colorForStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "\033[32m" // green
	case code >= 300 && code < 400:
		return "\033[36m" // cyan
	case code >= 400 && code < 500:
		return "\033[33m" // yellow
	default:
		return "\033[31m" // red
	}
}
