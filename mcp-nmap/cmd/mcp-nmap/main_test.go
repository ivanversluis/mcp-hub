package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestServeInitialize(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	var out bytes.Buffer
	err := serve(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result := resp.Result.(map[string]interface{})
	if result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("unexpected protocol version: %v", result["protocolVersion"])
	}
}

func TestServeToolsList(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n"
	var out bytes.Buffer
	err := serve(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	result := resp.Result.(map[string]interface{})
	tools := result["tools"].([]interface{})
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	tool := tools[0].(map[string]interface{})
	if tool["name"] != "nmap_scan" {
		t.Fatalf("unexpected tool name: %v", tool["name"])
	}
}

func TestServeInvalidJSON(t *testing.T) {
	input := "not json\n"
	var out bytes.Buffer
	err := serve(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected error response for invalid JSON")
	}
	if resp.Error.Code != -32700 {
		t.Fatalf("expected parse error code -32700, got %d", resp.Error.Code)
	}
}

func TestServeUnknownMethod(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":5,"method":"unknown/method","params":{}}` + "\n"
	var out bytes.Buffer
	err := serve(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Fatalf("expected method not found code -32601, got %d", resp.Error.Code)
	}
}

func TestServeToolCallValidation(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nmap_scan","arguments":{"targets":"; rm -rf /","scan_type":"-sV"}}}` + "\n"
	var out bytes.Buffer
	err := serve(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	result := resp.Result.(map[string]interface{})
	if result["isError"] != true {
		t.Fatal("expected isError=true for malicious target")
	}
}

func TestServeNotification(t *testing.T) {
	input := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}` + "\n"
	var out bytes.Buffer
	err := serve(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("serve error: %v", err)
	}
	// notifications produce no response
	if out.Len() != 0 {
		t.Fatalf("expected no output for notification, got: %s", out.String())
	}
}
