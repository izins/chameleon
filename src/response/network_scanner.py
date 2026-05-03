"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/response/network_scanner.py

Live network topology scanner — discovers all devices on the local
network via ARP, classifies them by type (router, server, workstation,
infrastructure), and exposes the topology for the SOC dashboard.

Device classification strategy:
  1. ARP scan to discover all live hosts + MAC addresses
  2. MAC OUI vendor lookup (Cisco = network device, etc.)
  3. Gateway detection (default route = router)
  4. Port probing (22/80/443 = server, 53 = DNS, etc.)
  5. Hostname resolution + pattern matching
  6. Merge with CMDB data from network_graph.py

The output feeds both:
  - The interactive topology visualization (frontend)
  - The ISO 27035 Phase 3 isolation overlay (red = isolated)
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from pydantic import BaseModel, Field

from src.config.settings import settings

logger = logging.getLogger(__name__)


# ── MAC OUI Vendor Database (common network vendors) ─────────────────
_MAC_VENDORS = {
    "00:1A:2B": "Cisco", "00:1B:54": "Cisco", "00:1C:58": "Cisco",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "00:15:5D": "Hyper-V", "08:00:27": "VirtualBox",
    "B4:96:91": "Intel", "3C:22:FB": "Apple", "DC:A6:32": "Raspberry Pi",
    "00:1E:67": "Intel", "00:25:90": "SuperMicro",
    "00:1A:A0": "Dell", "00:14:22": "Dell", "18:66:DA": "Dell",
    "00:17:A4": "HP", "00:1E:0B": "HP", "3C:D9:2B": "HP",
    "F0:1F:AF": "Dell", "00:0B:AB": "Cisco", "00:40:96": "Cisco",
    "00:03:BA": "Juniper", "00:05:85": "Juniper",
    "00:1B:17": "Palo Alto", "00:1C:06": "Aruba",
    "44:D9:E7": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "00:50:C2": "IEEE Registration", "02:42": "Docker",
}

_NETWORK_VENDORS = {"Cisco", "Juniper", "Palo Alto", "Aruba", "Ubiquiti"}

# ── Port → Service mapping for classification ────────────────────────
_SERVER_PORTS = {22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200}
_DNS_PORTS = {53}
_PRINTER_PORTS = {631, 9100}


# ── Data Models ──────────────────────────────────────────────────────

class NetworkDevice(BaseModel):
    """A discovered network device with classification metadata."""
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""

    # Classification
    device_type: str = "workstation"  # router, server, workstation, infrastructure, unknown
    device_role: str = ""            # web_server, core_router, dns_server, etc.
    criticality: int = 5            # 1-10
    business_impact: str = "medium"  # low, medium, high, critical

    # State
    is_gateway: bool = False
    is_local: bool = False
    is_isolated: bool = False
    isolation_reason: str = ""
    isolated_at: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)

    # Network position
    subnet: str = ""
    connections: List[str] = Field(default_factory=list)

    # Metadata
    last_seen: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )


class NetworkTopology(BaseModel):
    """Complete network topology for the SOC dashboard."""
    scan_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    scanned_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    local_ip: str = ""
    gateway_ip: str = ""
    total_devices: int = 0
    devices: List[NetworkDevice] = Field(default_factory=list)

    # Edges for graph visualization
    edges: List[Dict[str, str]] = Field(default_factory=list)

    # Isolation overlay
    isolated_devices: List[str] = Field(default_factory=list)
    active_incidents: List[Dict[str, Any]] = Field(default_factory=list)


# ── Network Scanner ──────────────────────────────────────────────────

class NetworkScanner:
    """Discovers and classifies devices on the local network.

    Combines ARP discovery, MAC vendor lookup, port probing,
    and hostname resolution to build a complete network topology.
    """

    def __init__(self) -> None:
        self._local_ip = self._get_local_ip()
        self._gateway_ip = self._get_default_gateway()
        self._topology: Optional[NetworkTopology] = None
        logger.info(
            "NetworkScanner ready — local=%s gateway=%s",
            self._local_ip, self._gateway_ip,
        )

    def scan(self, probe_ports: bool = False) -> NetworkTopology:
        """Run a full network scan and return the topology.

        Args:
            probe_ports: If True, probe common ports on each host.
                        Disabled by default for speed.

        Returns:
            NetworkTopology with all discovered and classified devices.
        """
        logger.info("Starting network scan...")

        # Step 1: ARP discovery
        arp_entries = self._get_arp_entries()
        logger.info("ARP discovery: %d entries found", len(arp_entries))

        # Step 2: Build devices
        devices: List[NetworkDevice] = []

        # Add local machine first
        local_device = NetworkDevice(
            ip=self._local_ip,
            hostname=socket.gethostname(),
            device_type="workstation",
            device_role="analyst_workstation",
            is_local=True,
            criticality=5,
            business_impact="medium",
        )
        devices.append(local_device)

        for ip, mac in arp_entries:
            device = self._classify_device(ip, mac, probe_ports)
            devices.append(device)

        # Step 3: Build edges (star topology from gateway + local connections)
        edges = self._build_edges(devices)

        # Step 4: Merge with CMDB data if available
        devices = self._merge_cmdb_data(devices)

        # Step 5: Apply isolation state from active incidents
        devices, isolated_ips, incidents = self._apply_isolation_overlay(devices)

        topology = NetworkTopology(
            local_ip=self._local_ip,
            gateway_ip=self._gateway_ip,
            total_devices=len(devices),
            devices=devices,
            edges=edges,
            isolated_devices=isolated_ips,
            active_incidents=incidents,
        )

        self._topology = topology
        self._persist(topology)

        logger.info(
            "Scan complete: %d devices, %d edges, %d isolated",
            len(devices), len(edges), len(isolated_ips),
        )
        return topology

    # ── ARP Discovery ────────────────────────────────────────────────

    def _get_arp_entries(self) -> List[Tuple[str, str]]:
        """Get ARP table entries (IP, MAC) pairs.

        Filters out multicast, broadcast, and incomplete entries.
        """
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(
                    "arp -a", shell=True, timeout=10,
                ).decode("cp1252", errors="ignore")
                pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17,})"
            else:
                output = subprocess.check_output(
                    "arp -a", shell=True, timeout=10,
                ).decode("utf-8", errors="ignore")
                pattern = r"(\d+\.\d+\.\d+\.\d+)\s+.*?([0-9a-fA-F:]{17,})"

            matches = re.findall(pattern, output)

            # Filter noise
            clean = []
            for ip, mac in matches:
                if (
                    not ip.startswith("224.")
                    and not ip.startswith("239.")
                    and not ip.startswith("255.")
                    and ip != "255.255.255.255"
                    and mac.lower() != "ff-ff-ff-ff-ff-ff"
                    and mac.lower() != "ff:ff:ff:ff:ff:ff"
                    and ip != self._local_ip
                ):
                    # Normalize MAC format
                    mac_normalized = mac.replace("-", ":").lower()
                    clean.append((ip, mac_normalized))

            return clean

        except Exception as exc:
            logger.warning("ARP scan failed: %s", exc)
            return []

    # ── Device Classification ────────────────────────────────────────

    def _classify_device(
        self, ip: str, mac: str, probe_ports: bool = False,
    ) -> NetworkDevice:
        """Classify a device by its MAC vendor, hostname, and ports."""
        device = NetworkDevice(ip=ip, mac=mac)

        # 1. MAC vendor lookup
        device.vendor = self._lookup_mac_vendor(mac)

        # 2. Gateway check
        if ip == self._gateway_ip:
            device.is_gateway = True
            device.device_type = "router"
            device.device_role = "default_gateway"
            device.criticality = 10
            device.business_impact = "critical"
            return device

        # 3. Hostname resolution
        device.hostname = self._resolve_hostname(ip)

        # 4. Network vendor → likely network device
        if device.vendor in _NETWORK_VENDORS:
            device.device_type = "infrastructure"
            device.device_role = "network_device"
            device.criticality = 8
            device.business_impact = "high"
            return device

        # 5. Hostname-based classification
        hostname_lower = device.hostname.lower()
        if any(kw in hostname_lower for kw in ("router", "switch", "fw", "firewall")):
            device.device_type = "infrastructure"
            device.device_role = hostname_lower.split(".")[0]
            device.criticality = 9
            device.business_impact = "critical"
        elif any(kw in hostname_lower for kw in ("srv", "server", "db", "sql", "web", "app", "api")):
            device.device_type = "server"
            device.device_role = hostname_lower.split(".")[0]
            device.criticality = 7
            device.business_impact = "high"
        elif any(kw in hostname_lower for kw in ("nas", "backup", "storage")):
            device.device_type = "server"
            device.device_role = "storage"
            device.criticality = 8
            device.business_impact = "high"
        elif any(kw in hostname_lower for kw in ("printer", "print")):
            device.device_type = "workstation"
            device.device_role = "printer"
            device.criticality = 2
            device.business_impact = "low"
        elif "vm" in hostname_lower or device.vendor in ("VMware", "Hyper-V", "VirtualBox"):
            device.device_type = "server"
            device.device_role = "virtual_machine"
            device.criticality = 6
            device.business_impact = "medium"

        # 6. Port probing (optional — slow)
        if probe_ports:
            device.open_ports = self._probe_ports(ip)
            if device.open_ports:
                server_hits = set(device.open_ports) & _SERVER_PORTS
                if server_hits:
                    device.device_type = "server"
                    if 80 in server_hits or 443 in server_hits:
                        device.device_role = "web_server"
                    elif 3306 in server_hits or 5432 in server_hits:
                        device.device_role = "database"
                        device.criticality = 9
                        device.business_impact = "critical"

        # 7. Subnet classification
        device.subnet = self._get_subnet(ip)

        return device

    def _lookup_mac_vendor(self, mac: str) -> str:
        """Lookup vendor from MAC OUI (first 3 octets)."""
        mac_upper = mac.upper().replace("-", ":")
        oui_3 = mac_upper[:8]  # XX:XX:XX
        oui_2 = mac_upper[:5]  # XX:XX (for Docker etc.)

        return _MAC_VENDORS.get(oui_3, _MAC_VENDORS.get(oui_2, ""))

    def _resolve_hostname(self, ip: str) -> str:
        """Reverse DNS lookup for hostname."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    def _probe_ports(self, ip: str, timeout: float = 0.3) -> List[int]:
        """Quick TCP connect scan on common ports."""
        open_ports = []
        for port in sorted(_SERVER_PORTS | _DNS_PORTS | _PRINTER_PORTS):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        return open_ports

    def _get_subnet(self, ip: str) -> str:
        """Extract /24 subnet from IP."""
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""

    # ── Network Helpers ──────────────────────────────────────────────

    def _get_local_ip(self) -> str:
        """Get the local machine's IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return socket.gethostbyname(socket.gethostname())

    def _get_default_gateway(self) -> str:
        """Detect the default gateway IP."""
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(
                    "ipconfig", shell=True, timeout=5,
                ).decode("cp1252", errors="ignore")
                # Match "Default Gateway" line
                gw_match = re.findall(
                    r"Default Gateway[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", output,
                )
                if gw_match:
                    return gw_match[0]
            else:
                output = subprocess.check_output(
                    "ip route | grep default", shell=True, timeout=5,
                ).decode("utf-8", errors="ignore")
                gw_match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
                if gw_match:
                    return gw_match.group(1)
        except Exception:
            pass
        return ""

    # ── Edge Building ────────────────────────────────────────────────

    def _build_edges(self, devices: List[NetworkDevice]) -> List[Dict[str, str]]:
        """Build network edges for visualization.

        Strategy: Gateway connects to all devices.
        Devices in the same subnet are also connected.
        """
        edges = []
        gateway_ip = self._gateway_ip or self._local_ip

        for device in devices:
            if device.ip == gateway_ip:
                continue
            # Everyone connects through the gateway
            edges.append({"source": gateway_ip, "target": device.ip})

            # Local machine connects to gateway
            if device.is_local and gateway_ip != device.ip:
                edges.append({"source": device.ip, "target": gateway_ip})

        return edges

    # ── CMDB Merge ───────────────────────────────────────────────────

    def _merge_cmdb_data(self, devices: List[NetworkDevice]) -> List[NetworkDevice]:
        """Merge discovered devices with CMDB data from network_graph.py."""
        try:
            from src.response.network_graph import _DEMO_ASSETS
            for device in devices:
                cmdb = _DEMO_ASSETS.get(device.ip)
                if cmdb:
                    device.device_role = cmdb.get("role", device.device_role)
                    device.device_type = cmdb.get("asset_type", device.device_type)
                    device.criticality = cmdb.get("criticality", device.criticality)
                    device.business_impact = cmdb.get("business_impact", device.business_impact)
                    logger.debug("CMDB merge for %s → role=%s", device.ip, device.device_role)
        except ImportError:
            pass
        return devices

    # ── Isolation Overlay ────────────────────────────────────────────

    def _apply_isolation_overlay(
        self, devices: List[NetworkDevice],
    ) -> Tuple[List[NetworkDevice], List[str], List[Dict]]:
        """Mark devices that are currently isolated from active incidents.

        Reads the ISO 27035 tracker records + isolation log to determine
        which devices are under containment.
        """
        isolated_ips: List[str] = []
        incidents: List[Dict] = []

        # Check ISO 27035 records for active containment
        iso_dir = Path(settings.demo_output_file).parent / "iso27035"
        if iso_dir.exists():
            for f in iso_dir.glob("iso_*.json"):
                try:
                    with open(f, "r", encoding="utf-8") as fh:
                        record = json.load(fh)

                    entity = record.get("entity_id", "")
                    status = record.get("overall_status", "")
                    severity = record.get("severity", "P4")
                    attack = record.get("attack_type", "")

                    # Check if Phase 3 (Response) containment was executed
                    phase3 = record.get("phases", {}).get("Phase 3: Response", {})
                    containment = phase3.get("sub_phases", {}).get("containment", {})

                    if containment.get("status") == "completed":
                        # Find matching device
                        for device in devices:
                            if device.ip == entity:
                                device.is_isolated = True
                                device.isolation_reason = f"{attack} ({severity})"
                                device.isolated_at = containment.get("completed_at", "")
                                isolated_ips.append(device.ip)

                        incidents.append({
                            "incident_id": record.get("incident_id", "")[:8],
                            "entity_id": entity,
                            "severity": severity,
                            "attack_type": attack,
                            "status": status,
                        })

                except Exception:
                    pass

        return devices, isolated_ips, incidents

    # ── Persistence ──────────────────────────────────────────────────

    def _persist(self, topology: NetworkTopology) -> None:
        """Save topology to disk for the SOC API."""
        try:
            output_dir = Path(settings.demo_output_file).parent / "network"
            output_dir.mkdir(parents=True, exist_ok=True)
            path = output_dir / "topology.json"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(topology.model_dump_json(indent=2))
            logger.info("Topology saved → %s", path)
        except Exception as exc:
            logger.warning("Failed to save topology: %s", exc)

    @property
    def topology(self) -> Optional[NetworkTopology]:
        """Get the last scan result."""
        return self._topology


# ── Standalone loader (for API use without re-scanning) ──────────────

def load_topology_from_disk() -> Optional[Dict]:
    """Load the persisted topology for the SOC API."""
    path = Path(settings.demo_output_file).parent / "network" / "topology.json"
    if path.exists():
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return None


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Discovers ALL devices on the local network via ARP.
# 2. Classifies each device (router, server, workstation, infrastructure).
# 3. Detects the default gateway and builds network edges.
# 4. Merges with CMDB data for enriched classification.
# 5. Applies isolation overlay from active ISO 27035 incidents.
# 6. Persists topology for SOC dashboard consumption.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="INFO")

    scanner = NetworkScanner()
    topo = scanner.scan(probe_ports=False)

    print(f"\n{'=' * 65}")
    print(f"NETWORK TOPOLOGY — {topo.total_devices} devices")
    print(f"Local: {topo.local_ip} | Gateway: {topo.gateway_ip}")
    print(f"{'=' * 65}")

    for d in topo.devices:
        iso_mark = " [ISOLATED]" if d.is_isolated else ""
        gw_mark = " (GATEWAY)" if d.is_gateway else ""
        local_mark = " (YOU)" if d.is_local else ""
        print(
            f"  {d.ip:18s} {d.device_type:14s} {d.device_role:18s} "
            f"crit={d.criticality:2d} {d.vendor:12s} {d.hostname:20s}"
            f"{iso_mark}{gw_mark}{local_mark}"
        )

    if topo.isolated_devices:
        print(f"\n  ISOLATED: {topo.isolated_devices}")
    print()
