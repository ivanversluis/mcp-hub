package nmapscan

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
)

type PortResult struct {
	Host    string `json:"host"`
	Port    string `json:"port"`
	State   string `json:"state"`
	Service string `json:"service"`
}

// allowedNmapFlags is a whitelist of safe nmap flags to prevent command injection.
var allowedNmapFlags = map[string]bool{
	"-sV": true, "-sS": true, "-sT": true, "-sU": true, "-sN": true,
	"-sF": true, "-sX": true, "-sA": true, "-sW": true, "-sM": true,
	"-sP": true, "-sn": true, "-Pn": true, "-PS": true, "-PA": true,
	"-PU": true, "-PE": true, "-PP": true, "-PM": true,
	"-O": true, "-A": true, "-T0": true, "-T1": true, "-T2": true,
	"-T3": true, "-T4": true, "-T5": true, "-F": true, "-r": true,
	"-v": true, "-vv": true, "-d": true, "-dd": true,
	"--open": true, "--top-ports": true, "--version-intensity": true,
}

// validTarget matches hostnames, IPs, CIDR ranges.
var validTarget = regexp.MustCompile(`^[a-zA-Z0-9._:/-]+$`)

func validateScanFlags(flags []string) error {
	for _, f := range flags {
		// Allow flags that start with - and are in the whitelist
		if strings.HasPrefix(f, "-") {
			// Strip value for flags like --top-ports (value is a separate arg)
			base := f
			if idx := strings.Index(f[1:], "="); idx >= 0 {
				base = f[:idx+1]
			}
			if !allowedNmapFlags[base] {
				return fmt.Errorf("disallowed nmap flag: %s", f)
			}
			continue
		}
		// Non-flag arguments in scan_type are numeric values for preceding flags (e.g. --top-ports 100)
		if matched := regexp.MustCompile(`^\d+$`).MatchString(f); !matched {
			return fmt.Errorf("invalid scan_type argument: %s", f)
		}
	}
	return nil
}

func validateTargets(targets string) error {
	for _, t := range strings.Fields(targets) {
		if !validTarget.MatchString(t) {
			return fmt.Errorf("invalid target: %s", t)
		}
	}
	return nil
}

func Run(ctx context.Context, targets, scanType string, format Format) (string, error) {
	if strings.TrimSpace(targets) == "" {
		return "", errors.New("targets are required")
	}
	if err := validateTargets(targets); err != nil {
		return "", err
	}
	if scanType == "" {
		scanType = "-sV"
	}

	scanFlags := strings.Fields(scanType)
	if err := validateScanFlags(scanFlags); err != nil {
		return "", err
	}

	args := []string{"-oG", "-"}
	args = append(args, scanFlags...)
	args = append(args, strings.Fields(targets)...)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nmap execution failed: %w: %s", err, string(out))
	}

	results := parseGrepableOutput(string(out))
	return render(results, format)
}

func parseGrepableOutput(raw string) []PortResult {
	lines := strings.Split(raw, "\n")
	var result []PortResult
	for _, line := range lines {
		if !strings.HasPrefix(line, "Host:") || !strings.Contains(line, "Ports:") {
			continue
		}
		parts := strings.SplitN(line, "Ports:", 2)
		host := strings.TrimSpace(strings.TrimPrefix(strings.Split(parts[0], "(")[0], "Host:"))
		ports := strings.Split(parts[1], ",")
		for _, p := range ports {
			fields := strings.Split(strings.TrimSpace(p), "/")
			if len(fields) < 5 {
				continue
			}
			result = append(result, PortResult{Host: host, Port: fields[0], State: fields[1], Service: fields[4]})
		}
	}
	return result
}

func render(results []PortResult, format Format) (string, error) {
	switch format {
	case FormatJSON:
		b, err := json.MarshalIndent(results, "", "  ")
		return string(b), err
	case FormatCSV:
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		_ = w.Write([]string{"host", "port", "state", "service"})
		for _, r := range results {
			_ = w.Write([]string{r.Host, r.Port, r.State, r.Service})
		}
		w.Flush()
		return buf.String(), w.Error()
	default:
		var b strings.Builder
		b.WriteString("HOST\tPORT\tSTATE\tSERVICE\n")
		for _, r := range results {
			b.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\n", r.Host, r.Port, r.State, r.Service))
		}
		if len(results) == 0 {
			b.WriteString("No open ports found.\n")
		}
		return b.String(), nil
	}
}
