# mcp-nmap

MCP server for homelab network scanning using `nmap`, implemented locally with the Go standard library (no third-party runtime dependencies).

## Tool

| Tool | Purpose | Key Inputs | Output |
|---|---|---|---|
| `nmap_scan` | Scan hosts/subnets | `targets`, `scan_type`, `output_format` | `table`, `json`, or `csv` |

### Example MCP call arguments

```json
{
  "targets": "192.168.1.0/24",
  "scan_type": "-sV -Pn",
  "output_format": "json"
}
```

## Automation flows

- **n8n schedule**: trigger your AI agent on cron and call `nmap_scan` for routine checks.
- **Discord/OpenClaw action**: let Discord commands request on-demand scans against approved hosts.

## Build locally

```bash
go test ./...
go build -o mcp-nmap ./cmd/mcp-nmap
```

## Docker

```bash
docker build -t mcp-nmap:local .
```

> Runtime `nmap` package is intentionally deferred to a future iteration (Alpine `apk add nmap`).


## Dependency model

- Runtime code uses only Go standard library packages.
- No third-party Go modules are required for build/runtime.


## Move to new GitHub repository (`mcp-hub`)

If you want this project to publish from your new repo, push this code into `mcp-hub`. The CI uses `${{ github.repository }}` so image names automatically follow the repo (for example `ghcr.io/<owner>/mcp-hub`).

```bash
# in your local clone
git remote rename origin old-origin
git remote add origin git@github.com:<your-org-or-user>/mcp-hub.git
git push -u origin <branch-name>
```
