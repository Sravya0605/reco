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

// RunNmapScans runs a set of nmap commands against target with optional sudo.
// It runs scans concurrently (bounded by MAX_CONC), saves outputs to a temp dir,
// and prints a concise, beginner-friendly summary when finished.
func RunNmapScans(target string, useSudo bool) {
	fmt.Printf("RunNmapScans: target=%q, useSudo=%v\n", target, useSudo)
	if useSudo && os.Geteuid() == 0 {
		fmt.Println("Already root — sudo prefix not required. Running without sudo prefix.")
		useSudo = false
	}

	// Prompt for sudo password once if needed
	var sudoPass []byte
	if useSudo {
		fmt.Print("Enter sudo password (will not echo): ")
		pass, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Printf("failed to read password: %v\n", err)
			return
		}
		sudoPass = pass
	}

	// Ensure nmap exists
	if _, err := exec.LookPath("nmap"); err != nil {
		fmt.Println("nmap not found in PATH. Install nmap first.")
		return
	}

	// create a single temp dir for outputs
	outDir, err := os.MkdirTemp("", "gonmap-output-*")
	if err != nil {
		fmt.Printf("failed to create temp dir: %v\n", err)
		return
	}
	fmt.Printf("Saving outputs to: %s\n\n", outDir)

	// define the scans (concise, useful)
	commands := [][]string{
		{"nmap", "-sS", "-T4", target},                                                // SYN top1000
		{"nmap", "-p-", "-sS", "-sV", "-O", "-T4", target},                            // full TCP + service + OS
		{"nmap", "-sU", "-p", "53,67,68,69,123,161,500,514,1900,3306,5432", target},   // UDP common
		{"nmap", "--top-ports", "200", "--script=default,safe", "-sV", "-T4", target}, // top ports + safe NSE
		{"nmap", "-A", "-T4", target},                                                 // aggressive (noisy)
		{"nmap", "-sT", "-T4", target},                                                // connect scan fallback
		{"nmap", "-sS", "-sV", "--version-intensity", "5", target},                    // extra version probe
		{"nmap", "-sn", target},                                                       // ping sweep (CIDR recommended)
	}

	// concurrency: pick aggressive default but allow override
	maxWorkers := pickMaxWorkers()
	fmt.Printf("Running up to %d scans concurrently (override with MAX_CONC env).\n\n", maxWorkers)

	// create worker semaphore
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
	// run jobs
	for i, cmdVec := range commands {
		// capture loop vars
		i := i
		cmdVec := cmdVec

		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			// build name and file path
			name := fmt.Sprintf("scan_%02d_%s", i+1, slugify(strings.Join(cmdVec, "_")))
			filename := filepath.Join(outDir, name+".txt")

			// run with timeout
			out, err := runWithTimeoutAndSudo(defaultTimeout, cmdVec[0], cmdVec[1:], useSudo, sudoPass)

			// save output (best-effort)
			_ = os.WriteFile(filename, []byte(out), 0644)

			results[i] = jobResult{
				Index:   i,
				CmdLine: strings.Join(cmdVec, " "),
				Output:  out,
				Err:     err,
				File:    filename,
			}
			// small progress feedback for user
			if err != nil {
				fmt.Printf("[job %d] finished (error) — saved: %s\n", i+1, filename)
			} else {
				fmt.Printf("[job %d] finished — saved: %s\n", i+1, filename)
			}
		}()
	}

	// wait for all jobs
	wg.Wait()

	// print beginner-friendly summary in the original command order
	fmt.Println("\n\n===== Beginner-friendly summary =====")
	for i := range results {
		r := results[i]
		fmt.Printf("\n--- Scan #%d ---\n", i+1)
		fmt.Printf("Command: %s\n", r.CmdLine)
		fmt.Printf("Saved output: %s\n", r.File)
		if r.Err != nil {
			fmt.Printf("Note: command returned error: %v\n", r.Err)
		}
		opens := extractOpenPorts(r.Output)
		if len(opens) > 0 {
			fmt.Printf("Open ports found (%d): %s\n", len(opens), strings.Join(opens, ", "))
		} else {
			fmt.Println("Open ports found: none (or host filtered/quiet).")
		}
		// preview first 12 lines
		lines := strings.Split(r.Output, "\n")
		fmt.Println("Preview (first 12 lines):")
		for k := 0; k < len(lines) && k < 12; k++ {
			fmt.Println(lines[k])
		}
		if len(lines) > 12 {
			fmt.Printf("... (output truncated) full output in %s\n", r.File)
		}
	}
	fmt.Printf("\nAll outputs are in: %s\n", outDir)
	fmt.Println("Tip: Run the binary itself with sudo (e.g., sudo ./gonmap) for better security.")
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
// If useSudo is true it prefixes `sudo -S prog args...` and writes sudoPass to stdin.
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
	out := []string{}
	for _, m := range matches {
		out = append(out, fmt.Sprintf("%s/%s(%s)", m[1], m[2], m[3]))
	}
	return out
}

// slugify makes a short safe filename tag
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
