package nmapscan

import (
	"strings"
	"testing"
)

func TestParseGrepableOutput(t *testing.T) {
	raw := "Host: 192.168.1.1 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///\n"
	results := parseGrepableOutput(raw)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Service != "ssh" {
		t.Fatalf("expected ssh service, got %s", results[0].Service)
	}
	if results[1].Service != "http" {
		t.Fatalf("expected http service, got %s", results[1].Service)
	}
}

func TestParseGrepableOutputMultiHost(t *testing.T) {
	raw := "Host: 10.0.0.1 (gw)\tPorts: 443/open/tcp//https///\nHost: 10.0.0.2 (srv)\tPorts: 22/open/tcp//ssh///\n"
	results := parseGrepableOutput(raw)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Host != "10.0.0.1" {
		t.Fatalf("expected host 10.0.0.1, got %s", results[0].Host)
	}
	if results[1].Host != "10.0.0.2" {
		t.Fatalf("expected host 10.0.0.2, got %s", results[1].Host)
	}
}

func TestRenderTable(t *testing.T) {
	out, err := render([]PortResult{{Host: "192.168.1.1", Port: "22", State: "open", Service: "ssh"}}, FormatTable)
	if err != nil {
		t.Fatalf("render returned error: %v", err)
	}
	if !strings.Contains(out, "HOST") || !strings.Contains(out, "192.168.1.1") {
		t.Fatalf("unexpected table output: %s", out)
	}
}

func TestRenderTableEmpty(t *testing.T) {
	out, err := render([]PortResult{}, FormatTable)
	if err != nil {
		t.Fatalf("render returned error: %v", err)
	}
	if !strings.Contains(out, "No open ports found") {
		t.Fatalf("expected empty message, got: %s", out)
	}
}

func TestRenderCSV(t *testing.T) {
	out, err := render([]PortResult{{Host: "127.0.0.1", Port: "443", State: "open", Service: "https"}}, FormatCSV)
	if err != nil {
		t.Fatalf("render returned error: %v", err)
	}
	if !strings.Contains(out, "127.0.0.1,443,open,https") {
		t.Fatalf("unexpected csv output: %s", out)
	}
	if !strings.Contains(out, "host,port,state,service") {
		t.Fatalf("missing csv header: %s", out)
	}
}

func TestRenderJSON(t *testing.T) {
	out, err := render([]PortResult{{Host: "10.0.0.1", Port: "80", State: "open", Service: "http"}}, FormatJSON)
	if err != nil {
		t.Fatalf("render returned error: %v", err)
	}
	if !strings.Contains(out, `"host": "10.0.0.1"`) {
		t.Fatalf("unexpected json output: %s", out)
	}
}

func TestValidateTargets(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"192.168.1.0/24", true},
		{"10.0.0.1", true},
		{"scanme.nmap.org", true},
		{"192.168.1.1 10.0.0.1", true},
		{"fe80::1", true},
		{"; rm -rf /", false},
		{"$(whoami)", false},
		{"`id`", false},
		{"host | cat /etc/passwd", false},
	}
	for _, tt := range tests {
		err := validateTargets(tt.input)
		if tt.valid && err != nil {
			t.Errorf("validateTargets(%q) unexpected error: %v", tt.input, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("validateTargets(%q) expected error, got nil", tt.input)
		}
	}
}

func TestValidateScanFlags(t *testing.T) {
	tests := []struct {
		input []string
		valid bool
	}{
		{[]string{"-sV"}, true},
		{[]string{"-sV", "-Pn"}, true},
		{[]string{"-T4", "-A"}, true},
		{[]string{"--top-ports", "100"}, true},
		{[]string{"--script=vuln"}, false},
		{[]string{"-oN", "/tmp/out"}, false},
		{[]string{"--interactive"}, false},
	}
	for _, tt := range tests {
		err := validateScanFlags(tt.input)
		if tt.valid && err != nil {
			t.Errorf("validateScanFlags(%v) unexpected error: %v", tt.input, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("validateScanFlags(%v) expected error, got nil", tt.input)
		}
	}
}

func TestRunEmptyTargets(t *testing.T) {
	_, err := Run(nil, "", "-sV", FormatTable)
	if err == nil {
		t.Fatal("expected error for empty targets")
	}
}

func TestRunInvalidTargets(t *testing.T) {
	_, err := Run(nil, "; whoami", "-sV", FormatTable)
	if err == nil {
		t.Fatal("expected error for malicious targets")
	}
}

func TestRunInvalidFlags(t *testing.T) {
	_, err := Run(nil, "192.168.1.1", "--script=exploit", FormatTable)
	if err == nil {
		t.Fatal("expected error for disallowed flags")
	}
}
