package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func Dns(domain string) {
	file, err := os.Open("TextFiles/subdomains-top1million-5000.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	var subs []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain == "" {
			continue
		}

		query := fmt.Sprintf("%s.%s.", subdomain, domain)

		msg := new(dns.Msg)
		msg.SetQuestion(query, dns.TypeA)

		res, _, err := client.Exchange(msg, "8.8.8.8:53")
		if err != nil {
			continue
		}

		if res.Rcode == dns.RcodeSuccess && len(res.Answer) > 0 {
			fmt.Printf("[+] %s.%s\n", subdomain, domain)
			subs = append(subs, fmt.Sprintf("%s.%s", subdomain, domain))
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	fmt.Printf("\nFound %d valid subdomains\n", len(subs))
}
