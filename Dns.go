package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func Dns(domain string) ([]string, error) {
	file, err := os.Open("TextFiles/subdomains-top1million-5000.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	client := &dns.Client{Timeout: 2 * time.Second}
	var subs []string
	var mu sync.Mutex
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()

			query := fmt.Sprintf("%s.%s.", sub, domain)
			msg := new(dns.Msg)
			msg.SetQuestion(query, dns.TypeA)

			res, _, err := client.Exchange(msg, "8.8.8.8:53")
			if err == nil && res.Rcode == dns.RcodeSuccess && len(res.Answer) > 0 {
				mu.Lock()
				subs = append(subs, query[:len(query)-1]) // remove trailing dot
				mu.Unlock()
			}
		}(sub)
	}

	wg.Wait()
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subs, nil
}
