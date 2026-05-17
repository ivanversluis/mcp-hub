from __future__ import annotations

import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import xmltodict
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mcp-nmap")

ALLOWED_TIMING = {"T0", "T1", "T2", "T3", "T4", "T5"}
ALLOWED_ADVANCED_FLAGS = {
    "-Pn",
    "-n",
    "-F",
    "-sV",
    "-O",
    "-sn",
    "-sU",
    "-PR",
    "--version-light",
    "--reason",
}
SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9_./,:\- ]+$")


def _validate_targets(targets: str) -> str:
    targets = targets.strip()
    if not targets:
        raise ValueError("targets is required")
    if len(targets) > 512:
        raise ValueError("targets too long")
    if not SAFE_TARGET_RE.match(targets):
        raise ValueError("targets contains unsupported characters")
    return targets


def _validate_ports(ports: Optional[str]) -> Optional[str]:
    if ports is None or ports == "":
        return None
    if not re.fullmatch(r"[0-9,\-]+", ports):
        raise ValueError("ports must contain only digits, commas, and dashes")
    return ports


def _run_nmap(args: List[str]) -> Dict[str, Any]:
    scan_id = str(uuid.uuid4())
    with tempfile.TemporaryDirectory() as tmpdir:
        xml_path = Path(tmpdir) / "scan.xml"
        cmd = ["nmap", *args, "-oX", str(xml_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if not xml_path.exists():
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "nmap did not produce XML output")

        xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
        parsed = xmltodict.parse(xml_text)
        result = _normalize(parsed)
        result["scan_id"] = scan_id
        result["resolved_command"] = cmd
        result["exit_code"] = proc.returncode
        result["stderr"] = proc.stderr.strip()
        result["stdout"] = proc.stdout.strip()
        result["raw_xml"] = xml_text
        return result


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize(doc: Dict[str, Any]) -> Dict[str, Any]:
    root = doc.get("nmaprun", {})
    hosts = []
    for host in _ensure_list(root.get("host")):
        addresses = _ensure_list(host.get("address"))
        hostnames_node = host.get("hostnames", {})
        hostname_entries = _ensure_list(hostnames_node.get("hostname")) if isinstance(hostnames_node, dict) else []
        ports_node = host.get("ports", {}) if isinstance(host.get("ports"), dict) else {}
        port_entries = _ensure_list(ports_node.get("port"))
        ports = []
        for p in port_entries:
            state = p.get("state", {}) if isinstance(p, dict) else {}
            service = p.get("service", {}) if isinstance(p, dict) else {}
            ports.append({
                "port": int(p.get("@portid", 0)) if str(p.get("@portid", "0")).isdigit() else p.get("@portid"),
                "protocol": p.get("@protocol"),
                "state": state.get("@state"),
                "reason": state.get("@reason"),
                "service": service.get("@name"),
                "product": service.get("@product"),
                "version": service.get("@version"),
                "extra_info": service.get("@extrainfo"),
            })

        os_node = host.get("os", {}) if isinstance(host.get("os"), dict) else {}
        os_matches = []
        for match in _ensure_list(os_node.get("osmatch")):
            os_matches.append({
                "name": match.get("@name"),
                "accuracy": match.get("@accuracy"),
            })

        hosts.append({
            "status": (host.get("status") or {}).get("@state") if isinstance(host.get("status"), dict) else None,
            "addresses": [{"addr": a.get("@addr"), "type": a.get("@addrtype")} for a in addresses if isinstance(a, dict)],
            "hostnames": [h.get("@name") for h in hostname_entries if isinstance(h, dict) and h.get("@name")],
            "ports": ports,
            "os_matches": os_matches,
        })

    stats = root.get("runstats", {}) if isinstance(root.get("runstats"), dict) else {}
    finished = stats.get("finished", {}) if isinstance(stats.get("finished"), dict) else {}
    hosts_stats = stats.get("hosts", {}) if isinstance(stats.get("hosts"), dict) else {}

    return {
        "scanner": root.get("@scanner"),
        "args": root.get("@args"),
        "start": root.get("@start"),
        "version": root.get("@version"),
        "hosts_up": hosts_stats.get("@up"),
        "hosts_down": hosts_stats.get("@down"),
        "hosts_total": hosts_stats.get("@total"),
        "finished_time": finished.get("@time"),
        "elapsed_seconds": finished.get("@elapsed"),
        "summary": finished.get("@summary"),
        "hosts": hosts,
    }


def _timing_flag(timing: str) -> str:
    if timing not in ALLOWED_TIMING:
        raise ValueError(f"timing must be one of {sorted(ALLOWED_TIMING)}")
    return f"-{timing}"


@mcp.tool()
def host_discovery(
    targets: str,
    timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = "T3",
    discovery_mode: Literal["auto", "arp", "skip_dns"] = "auto",
) -> Dict[str, Any]:
    """Find live hosts. Use arp on local LANs, or skip DNS to speed up scans."""
    args = ["-sn", _timing_flag(timing)]
    if discovery_mode == "arp":
        args.append("-PR")
    if discovery_mode == "skip_dns":
        args.append("-n")
    args.extend(_validate_targets(targets).split())
    return _run_nmap(args)


@mcp.tool()
def service_scan(
    targets: str,
    ports: Optional[str] = None,
    timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = "T3",
    skip_host_discovery: bool = False,
    version_light: bool = True,
) -> Dict[str, Any]:
    """Detect open TCP services and versions, suitable as the default homelab scan."""
    args = ["-sV", _timing_flag(timing)]
    if version_light:
        args.append("--version-light")
    if skip_host_discovery:
        args.append("-Pn")
    ports = _validate_ports(ports)
    if ports:
        args.extend(["-p", ports])
    args.extend(_validate_targets(targets).split())
    return _run_nmap(args)


@mcp.tool()
def port_scan(
    targets: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = 1000,
    timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = "T3",
    skip_host_discovery: bool = False,
) -> Dict[str, Any]:
    """Scan TCP ports by explicit list or top-ports profile."""
    args = [_timing_flag(timing)]
    if skip_host_discovery:
        args.append("-Pn")
    valid_ports = _validate_ports(ports)
    if valid_ports:
        args.extend(["-p", valid_ports])
    elif top_ports is not None:
        if top_ports < 1 or top_ports > 10000:
            raise ValueError("top_ports must be between 1 and 10000")
        args.extend(["--top-ports", str(top_ports)])
    else:
        args.append("-F")
    args.extend(_validate_targets(targets).split())
    return _run_nmap(args)


@mcp.tool()
def os_detection(
    targets: str,
    timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = "T3",
    skip_host_discovery: bool = False,
) -> Dict[str, Any]:
    """Attempt OS fingerprinting. Best results usually need at least one open and one closed TCP port."""
    args = ["-O", _timing_flag(timing)]
    if skip_host_discovery:
        args.append("-Pn")
    args.extend(_validate_targets(targets).split())
    return _run_nmap(args)


@mcp.tool()
def udp_scan(
    targets: str,
    ports: str,
    timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = "T3",
    skip_host_discovery: bool = False,
) -> Dict[str, Any]:
    """Scan selected UDP ports. Keep the port set small because UDP scans can be slow."""
    valid_ports = _validate_ports(ports)
    if not valid_ports:
        raise ValueError("ports is required for udp_scan")
    args = ["-sU", "-p", valid_ports, _timing_flag(timing)]
    if skip_host_discovery:
        args.append("-Pn")
    args.extend(_validate_targets(targets).split())
    return _run_nmap(args)


@mcp.tool()
def advanced_nmap_scan(
    targets: str,
    flags: List[str],
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
) -> Dict[str, Any]:
    """Advanced escape hatch with a small allowlist of safe-ish flags instead of arbitrary free-form commands."""
    if not flags:
        raise ValueError("flags is required")
    disallowed = [flag for flag in flags if flag not in ALLOWED_ADVANCED_FLAGS and not re.fullmatch(r"-T[0-5]", flag)]
    if disallowed:
        raise ValueError(f"unsupported flags: {', '.join(disallowed)}")
    args = list(flags)
    valid_ports = _validate_ports(ports)
    if valid_ports:
        args.extend(["-p", valid_ports])
    if top_ports is not None:
        if top_ports < 1 or top_ports > 10000:
            raise ValueError("top_ports must be between 1 and 10000")
        args.extend(["--top-ports", str(top_ports)])
    args.extend(_validate_targets(targets).split())
    return _run_nmap(args)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
