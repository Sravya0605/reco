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
	defaultTimeout    = 10 * time.Minute
	defaultMaxWorkers = 16
)

// Global variable to hold sudo password when needed
var sudoPass []byte = nil

// RunNmapScans runs a set of nmap scans concurrently against the target.
// Requests sudo access if not running as root and useSudo is true.
// Does NOT save outputs to files - returns aggregated string output.
func RunNmapScans(target string, useSudo bool) (string, error) {
	var outputBuilder strings.Builder

	outputBuilder.WriteString(fmt.Sprintf("RunNmapScans: target=%q\n", target))

	isRoot := (os.Geteuid() == 0)

	if !isRoot && useSudo {
		// Prompt for sudo password interactively
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
		useSudo = false // unnecessary when already root
	} else {
		outputBuilder.WriteString("Running without root privileges and sudo disabled; scans may be limited.\n")
		useSudo = false
	}

	// Ensure nmap executable is in PATH
	if _, err := exec.LookPath("nmap"); err != nil {
		return "", fmt.Errorf("nmap not found in PATH")
	}

	commands := [][]string{
		{"nmap", "-sS", "-T3", target},
		{"nmap", "-p-", "-sS", "-sV", "-O", "-T3", target},
		{"nmap", "-sU", "-p", "53,67,68,69,123,161,500,514,1900,3306,5432", target},
		{"nmap", "--top-ports", "200", "--script=default,safe", "-sV", "-T3", target},
		{"nmap", "-A", "-T3", target},
		{"nmap", "-sT", "-T3", target},
		{"nmap", "-sS", "-sV", "--version-intensity", "5", target},
		{"nmap", "-sn", target},
	}

	maxWorkers := pickMaxWorkers()
	outputBuilder.WriteString(fmt.Sprintf("Executing up to %d concurrent scans (configurable via MAX_CONC environment variable).\n\n", maxWorkers))

	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	type jobResult struct {
		Index   int
		CmdLine string
		Output  string
		Err     error
	}
	results := make([]jobResult, len(commands))

	for i, cmdVec := range commands {
		i := i
		cmdVec := cmdVec

		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			out, err := runWithTimeoutAndSudo(defaultTimeout, cmdVec[0], cmdVec[1:], useSudo, sudoPass)

			results[i] = jobResult{
				Index:   i,
				CmdLine: strings.Join(cmdVec, " "),
				Output:  out,
				Err:     err,
			}
		}()
	}
	wg.Wait()

	outputBuilder.WriteString("\n===== Beginner-friendly summary =====\n")
	for i := range results {
		r := results[i]
		outputBuilder.WriteString(fmt.Sprintf("\n--- Scan #%d ---\n", i+1))
		outputBuilder.WriteString(fmt.Sprintf("Command: %s\n", r.CmdLine))
		if r.Err != nil {
			outputBuilder.WriteString(fmt.Sprintf("Note: command returned error: %v\n", r.Err))
		}
		opens := extractOpenPorts(r.Output)
		if len(opens) > 0 {
			outputBuilder.WriteString(fmt.Sprintf("Open ports found (%d): %s\n", len(opens), strings.Join(opens, ", ")))
		} else {
			outputBuilder.WriteString("Open ports found: none (or host filtered/quiet).\n")
		}
		lines := strings.Split(r.Output, "\n")
		outputBuilder.WriteString("Preview (first 12 lines):\n")
		limit := 12
		if len(lines) < 12 {
			limit = len(lines)
		}
		for k := 0; k < limit; k++ {
			outputBuilder.WriteString(lines[k] + "\n")
		}
		if len(lines) > 12 {
			outputBuilder.WriteString("... (output truncated)\n")
		}
	}

	outputBuilder.WriteString("Tip: For best results, run the binary itself using sudo (e.g., sudo ./gonmap).\n")

	return outputBuilder.String(), nil
}

// -------------------- helpers --------------------

// pickMaxWorkers picks the concurrency level.
// Default = min(defaultMaxWorkers, runtime.NumCPU()*4) unless overridden by MAX_CONC env var.
func pickMaxWorkers() int {
	if s := os.Getenv("MAX_CONC"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			return v
		}
	}
	guess := runtime.NumCPU() * 4
	if guess > defaultMaxWorkers {
		guess = defaultMaxWorkers
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
