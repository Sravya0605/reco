package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CreateScanReport builds a markdown report from scanner outputs.
// - domain: the scanned domain
// - outputs: map of tool name -> full tool output (string)
// Returns: filepath written and the markdown contents, or error.
func CreateScanReport(domain string, outputs map[string]string) (string, string, error) {
	// sanitize domain for filename
	re := regexp.MustCompile(`[^a-zA-Z0-9\-_\.]`)
	safeDomain := re.ReplaceAllString(domain, "_")
	t := time.Now().UTC()
	ts := t.Format("2006-01-02_150405_UTC")

	dir := "reports"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("failed to create reports dir: %w", err)
	}

	filename := fmt.Sprintf("scan_%s_%s.md", safeDomain, ts)
	fp := filepath.Join(dir, filename)

	// Build executive summary heuristics
	var summaryLines []string
	var detailsBuilder strings.Builder

	summaryLines = append(summaryLines, fmt.Sprintf("- **Domain scanned:** `%s`", domain))
	summaryLines = append(summaryLines, fmt.Sprintf("- **Report generated (UTC):** %s", t.Format(time.RFC3339)))

	problemCount := 0

	// Sort tool names for stable order in report
	tools := make([]string, 0, len(outputs))
	for k := range outputs {
		tools = append(tools, k)
	}
	sort.Strings(tools)

	for _, tool := range tools {
		out := outputs[tool]
		preview := firstNLines(out, 8)
		lower := strings.ToLower(out)
		// detect obvious errors/timeouts
		if strings.Contains(lower, "error:") || strings.Contains(lower, "timeout") || strings.Contains(lower, "failed") || strings.Contains(lower, "context deadline") {
			problemCount++
			summaryLines = append(summaryLines, fmt.Sprintf("- [%s] **Issue detected** — check details.", tool))
		}

		// Positive quick findings heuristics
		if strings.Contains(lower, "host is up") || strings.Contains(lower, "open") || strings.Contains(lower, "200]") || strings.Contains(lower, "200 ") {
			summaryLines = append(summaryLines, fmt.Sprintf("- [%s] Positive result: reachable/open services or HTTP 200 responses.", tool))
		}

		// Build detail section for this tool
		detailsBuilder.WriteString("### " + tool + "\n\n")
		detailsBuilder.WriteString("```\n")
		detailsBuilder.WriteString(preview)
		if len(preview) < len(out) {
			detailsBuilder.WriteString("\n\n... (output truncated) ...")
		}
		detailsBuilder.WriteString("\n```\n\n")
	}

	// Executive summary header
	var md strings.Builder
	md.WriteString(fmt.Sprintf("# Scan Report — %s\n\n", domain))
	md.WriteString(fmt.Sprintf("> Generated: %s (UTC)\n\n", t.Format(time.RFC1123)))
	md.WriteString("## Executive summary\n\n")

	if problemCount == 0 {
		md.WriteString("- No obvious tool errors detected (check details below if uncertain).\n\n")
	} else {
		md.WriteString(fmt.Sprintf("- **%d** tool(s) reported errors/timeouts — see details below.\n\n", problemCount))
	}

	for _, l := range summaryLines {
		md.WriteString(l + "\n")
	}
	md.WriteString("\n---\n\n")

	// Quick Recommendations
	md.WriteString("## Quick Recommendations\n\n")
	md.WriteString("- If many scans timed out, increase HTTP/network timeouts or run the scanner from a different network.\n")
	md.WriteString("- Use a fast discovery step (masscan) followed by targeted nmap to avoid long full-port scans.\n")
	md.WriteString("- For DNS/whois failures, retry with alternative resolvers (8.8.8.8 / 1.1.1.1) and fallback whois providers.\n\n")
	md.WriteString("---\n\n")

	// Full details (each tool section)
	md.WriteString("## Tool outputs (preview)\n\n")
	md.WriteString(detailsBuilder.String())

	// Raw outputs under collapsible sections for easy GitHub rendering
	md.WriteString("---\n\n")
	md.WriteString("## Raw outputs (full)\n\n")
	for _, tool := range tools {
		out := outputs[tool]
		md.WriteString(fmt.Sprintf("<details>\n<summary>%s</summary>\n\n", tool))
		md.WriteString("```\n")
		md.WriteString(out)
		md.WriteString("\n```\n\n</details>\n\n")
	}

	// Write file
	content := md.String()
	if err := os.WriteFile(fp, []byte(content), 0o644); err != nil {
		return "", "", fmt.Errorf("failed to write report file: %w", err)
	}

	return fp, content, nil
}

// firstNLines returns up to n lines from s as a single string.
// It will trim leading/trailing whitespace.
func firstNLines(s string, n int) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(strings.Join(lines[:n], "\n"))
}
