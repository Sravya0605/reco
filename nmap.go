package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

// Default timeout increased to 10 minutes per scan
const (
	defaultTimeout = 15 * time.Minute
)

// Global variable to hold sudo password when needed
var sudoPass []byte = nil

// RunNmapScans runs a set of nmap scans concurrently against the target.
// Requests sudo access if not running as root and useSudo is true.
// Does NOT save outputs to files - returns aggregated string output.
func RunNmapScans(target string, useSudo bool) (string, error) {
	if target == "" {
		return "", fmt.Errorf("target must be specified")
	}

	var outputBuilder strings.Builder

	isRoot := (os.Geteuid() == 0)

	if !isRoot && useSudo {
		fmt.Print("Sudo privileges are recommended for more accurate scans.\nEnter sudo password (will not echo): ")
		pass, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("failed to read sudo password: %w", err)
		}
		sudoPass = pass
		outputBuilder.WriteString("Sudo password acquired, scans will be run with sudo prefix.\n")
	} else if isRoot {
		outputBuilder.WriteString("Running with root privileges, sudo prefix not used.\n")
		useSudo = false
	} else {
		outputBuilder.WriteString("Running without root privileges and sudo disabled; scans may be limited.\n")
		useSudo = false
	}

	if _, err := exec.LookPath("nmap"); err != nil {
		return "", fmt.Errorf("nmap not found in PATH")
	}

	// Adding target to each command and tuning timings (-T4 aggressive for speed)
	commands := [][]string{
		{"-Pn", "-sS", "--top-ports", "1000", "-T4", target},                                        // fast top TCP ports
		{"-Pn", "-sV", "--top-ports", "1000", "--script", "default,safe", "-T4", target},            // service/version + safe scripts
		{"-Pn", "-p", "80,443", "--script", "http-enum,http-vuln*,ssl-enum-ciphers", "-T4", target}, // web focus
		{"-Pn", "-sU", "-p", "53,67,69,123,161,500,514,1900,3306,5432", "-T4", target},              // UDP selective
		{"-Pn", "-sS", "-p-", "--defeat-rst-ratelimit", "-T4", target},                              // full TCP ports faster than -T3
	}

	maxWorkers := pickMaxWorkers()
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	type jobResult struct {
		Index   int
		CmdLine string
		Output  string
		Err     error
	}
	results := make([]jobResult, len(commands))

	for i, args := range commands {
		wg.Add(1)
		go func(idx int, cargs []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := runWithTimeoutAndSudo(defaultTimeout, "nmap", cargs, useSudo, sudoPass)
			results[idx] = jobResult{
				Index:   idx,
				CmdLine: "nmap " + strings.Join(cargs, " "),
				Output:  out,
				Err:     err,
			}
		}(i, args)
	}
	wg.Wait()

	outputBuilder.WriteString("\n## Nmap Scan Results\n")
	outputBuilder.WriteString("| # | Command | Open Ports | Error | Preview |\n|---|---------|------------|-------|---------|\n")
	for i, r := range results {
		opens := extractOpenPorts(r.Output)
		opStr := "none"
		if len(opens) > 0 {
			opStr = strings.Join(opens, ", ")
		}

		lines := strings.Split(r.Output, "\n")
		limit := 8
		if len(lines) < limit {
			limit = len(lines)
		}
		preview := ""
		if len(lines) > 0 {
			preview = strings.ReplaceAll(strings.Join(lines[:limit], " "), "|", "\\|")
		}

		errMsg := ""
		if r.Err != nil {
			errMsg = r.Err.Error()
		}

		outputBuilder.WriteString(fmt.Sprintf("| %d | `%s` | %s | %s | %s |\n",
			i+1, r.CmdLine, opStr, errMsg, preview))
	}

	outputBuilder.WriteString("\n<details><summary>Full Nmap Outputs</summary>\n\n")
	for i, r := range results {
		outputBuilder.WriteString(fmt.Sprintf("### Scan #%d: `%s`\n", i+1, r.CmdLine))
		outputBuilder.WriteString("```\n")
		outputBuilder.WriteString(r.Output)
		outputBuilder.WriteString("\n```\n\n")
	}
	outputBuilder.WriteString("</details>\n")

	outputBuilder.WriteString("Tip: For best results, run the binary itself using sudo (e.g., sudo ./your_scanner).\n")

	return outputBuilder.String(), nil
}

// pickMaxWorkers picks the concurrency level.
// Default = min(defaultMaxWorkers, runtime.NumCPU()*4) unless overridden by MAX_CONC env var.
func pickMaxWorkers() int {
	// Allow higher default concurrency, up to all logical CPUs * 8
	guess := runtime.NumCPU() * 8
	if s := os.Getenv("MAX_CONC"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			return v
		}
	}
	if guess < 1 {
		guess = 1
	}
	return guess
}

// runWithTimeoutAndSudo runs prog with args under a context timeout.
// If useSudo is true, prefixes with sudo and writes sudoPass to stdin.
func runWithTimeoutAndSudo(timeout time.Duration, prog string, args []string, useSudo bool, sudoPass []byte) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	if useSudo {
		all := append([]string{"-S", prog}, args...)
		cmd = exec.CommandContext(ctx, "sudo", all...)
		if len(sudoPass) > 0 {
			cmd.Stdin = bytes.NewBuffer(append(sudoPass, '\n'))
		}
	} else {
		cmd = exec.CommandContext(ctx, prog, args...)
	}

	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("command timed out after %v", timeout)
	}
	return string(out), err
}

var openLineRe = regexp.MustCompile(`(?m)^(\d+)/(tcp|udp)\s+open\s+([^\s]+)`)

// extractOpenPorts finds lines like "22/tcp open ssh" and returns short strings like "22/tcp(ssh)".
func extractOpenPorts(output string) []string {
	matches := openLineRe.FindAllStringSubmatch(output, -1)
	var out []string
	for _, m := range matches {
		out = append(out, fmt.Sprintf("%s/%s(%s)", m[1], m[2], m[3]))
	}
	return out
}
