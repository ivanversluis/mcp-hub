package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"mcp-nmap/internal/nmapscan"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

func main() {
	if err := serve(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func serve(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = encoder.Encode(errorResponse(nil, -32700, fmt.Sprintf("invalid json: %v", err)))
			continue
		}

		resp := handleRequest(req)
		if resp != nil {
			if err := encoder.Encode(resp); err != nil {
				return fmt.Errorf("failed writing response: %w", err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}
	return nil
}

func handleRequest(req request) *response {
	id := decodeID(req.ID)

	switch req.Method {
	case "initialize":
		return &response{JSONRPC: "2.0", ID: id, Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]string{"name": "mcp-nmap", "version": "0.2.0"},
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
		}}
	case "tools/list":
		return &response{JSONRPC: "2.0", ID: id, Result: map[string]interface{}{
			"tools": []map[string]interface{}{toolSchema()},
		}}
	case "tools/call":
		res, err := callTool(req.Params)
		if err != nil {
			return errorResponse(id, -32000, err.Error())
		}
		return &response{JSONRPC: "2.0", ID: id, Result: res}
	case "notifications/initialized":
		return nil
	default:
		return errorResponse(id, -32601, "method not found")
	}
}

func callTool(raw json.RawMessage) (map[string]interface{}, error) {
	var p toolCallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Name != "nmap_scan" {
		return nil, errors.New("unsupported tool")
	}
	targets, _ := p.Arguments["targets"].(string)
	scanType, _ := p.Arguments["scan_type"].(string)
	fmtStr, _ := p.Arguments["output_format"].(string)
	if fmtStr == "" {
		fmtStr = string(nmapscan.FormatTable)
	}

	output, err := nmapscan.Run(context.Background(), targets, scanType, nmapscan.Format(fmtStr))
	if err != nil {
		return map[string]interface{}{"isError": true, "content": []map[string]string{{"type": "text", "text": err.Error()}}}, nil
	}
	return map[string]interface{}{"content": []map[string]string{{"type": "text", "text": output}}}, nil
}

func toolSchema() map[string]interface{} {
	return map[string]interface{}{
		"name":        "nmap_scan",
		"description": "Run nmap scan and return output in table, JSON, or CSV format.",
		"inputSchema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"targets":       map[string]string{"type": "string", "description": "Space-separated hosts/networks, e.g. 192.168.1.0/24"},
				"scan_type":     map[string]string{"type": "string", "description": "nmap flags like -sV -Pn", "default": "-sV"},
				"output_format": map[string]string{"type": "string", "description": "table | json | csv", "default": "table"},
			},
			"required": []string{"targets"},
		},
	}
}

func decodeID(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

func errorResponse(id interface{}, code int, message string) *response {
	return &response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}
