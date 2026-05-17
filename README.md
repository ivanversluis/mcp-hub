# mcp-nmap-python draft

This draft splits the original single free-form Nmap tool into task-shaped MCP tools with structured JSON output:

- `host_discovery`
- `service_scan`
- `port_scan`
- `os_detection`
- `udp_scan`
- `advanced_nmap_scan`

## Local stdio run

```bash
pip install .
mcp-nmap
```

## MCPO wrapper

```bash
mcpo --port 8000 --api-key "change-me" -- mcp-nmap
```

## Example Bruno / OpenAPI call

`POST /service_scan`

```json
{
  "targets": "192.168.1.10",
  "ports": "22,80,443",
  "timing": "T3",
  "skip_host_discovery": false,
  "version_light": true
}
```

## Container run

```bash
docker build -t mcp-nmap-python .
docker run --rm -p 8000:8000 mcp-nmap-python sh -lc 'mcpo --port 8000 --api-key change-me -- mcp-nmap'
```

## Notes

- XML is used as the machine-readable Nmap source of truth and normalized into JSON.
- `advanced_nmap_scan` uses an allowlist of flags instead of arbitrary raw shell input.
- `arp` discovery uses `-PR`; depending on your environment, low-level network scans may need extra container capabilities.
