package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

// -------------------- Configuration --------------------

const (
	// default timeout per scan
	defaultTimeout = 3 * time.Minute
	// default maximum concurrency if not overridden by env MAX_CONC
	defaultMaxWorkers = 16
)

// -------------------- Public API --------------------

// RunNmapScans runs a set of nmap commands concurrently against a target,
// saves outputs temporarily, and returns a beginner-friendly aggregated summary.
func RunNmapScans(target string, useSudo bool) (string, error) {
	var outputBuilder strings.Builder

	outputBuilder.WriteString(fmt.Sprintf("RunNmapScans: target=%q, useSudo=%v\n", target, useSudo))
	if useSudo && os.Geteuid() == 0 {
		outputBuilder.WriteString("Already root — sudo prefix not required. Running without sudo prefix.\n")
		useSudo = false
	}

	// Prompt for sudo password once if needed
	var sudoPass []byte
	if useSudo {
		fmt.Print("Enter sudo password (will not echo): ")
		pass, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		sudoPass = pass
	}

	// Ensure nmap exists
	if _, err := exec.LookPath("nmap"); err != nil {
		return "", fmt.Errorf("nmap not found in PATH")
	}

	// create a single temp dir for outputs
	outDir, err := os.MkdirTemp("", "gonmap-output-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	outputBuilder.WriteString(fmt.Sprintf("Saving outputs to: %s\n\n", outDir))

	commands := [][]string{
		{"nmap", "-sS", "-T4", target},
		{"nmap", "-p-", "-sS", "-sV", "-O", "-T4", target},
		{"nmap", "-sU", "-p", "53,67,68,69,123,161,500,514,1900,3306,5432", target},
		{"nmap", "--top-ports", "200", "--script=default,safe", "-sV", "-T4", target},
		{"nmap", "-A", "-T4", target},
		{"nmap", "-sT", "-T4", target},
		{"nmap", "-sS", "-sV", "--version-intensity", "5", target},
		{"nmap", "-sn", target},
	}

	maxWorkers := pickMaxWorkers()
	outputBuilder.WriteString(fmt.Sprintf("Running up to %d scans concurrently (override with MAX_CONC env).\n\n", maxWorkers))

	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	type jobResult struct {
		Index   int
		CmdLine string
		Output  string
		Err     error
		File    string
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

			name := fmt.Sprintf("scan_%02d_%s", i+1, slugify(strings.Join(cmdVec, "_")))
			filename := filepath.Join(outDir, name+".txt")

			out, err := runWithTimeoutAndSudo(defaultTimeout, cmdVec[0], cmdVec[1:], useSudo, sudoPass)

			_ = os.WriteFile(filename, []byte(out), 0644)

			results[i] = jobResult{
				Index:   i,
				CmdLine: strings.Join(cmdVec, " "),
				Output:  out,
				Err:     err,
				File:    filename,
			}
		}()
	}
	wg.Wait()

	outputBuilder.WriteString("\n\n===== Beginner-friendly summary =====\n")
	for i := range results {
		r := results[i]
		outputBuilder.WriteString(fmt.Sprintf("\n--- Scan #%d ---\n", i+1))
		outputBuilder.WriteString(fmt.Sprintf("Command: %s\n", r.CmdLine))
		outputBuilder.WriteString(fmt.Sprintf("Saved output: %s\n", r.File))
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
			outputBuilder.WriteString(fmt.Sprintf("... (output truncated) full output in %s\n", r.File))
		}
	}
	outputBuilder.WriteString(fmt.Sprintf("\nAll outputs are in: %s\n", outDir))
	outputBuilder.WriteString("Tip: Run the binary itself with sudo (e.g., sudo ./gonmap) for better security.\n")

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

// slugify makes a safe filename tag from input string.
func slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ",", "_")
	re := regexp.MustCompile(`[^a-z0-9_\-]+`)
	s = re.ReplaceAllString(s, "")
	if len(s) > 40 {
		s = s[:40]
	}
	if s == "" {
		return "scan"
	}
	return s
}
