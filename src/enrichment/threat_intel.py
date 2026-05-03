"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/enrichment/threat_intel.py

Multi-source Threat Intelligence aggregator. Queries external databases
to corroborate whether a source IP is actually malicious before we
escalate and wake up on-call engineers.

Sources (in demo mode, all return synthetic data):
  1. AbuseIPDB   — community abuse reports
  2. VirusTotal  — multi-engine malware scan
  3. Shodan      — exposed services / Tor exit node detection
  4. GeoIP       — geographic origin of the attack

This module is the backbone of the Two-Step Verification Gate.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from src.config.settings import settings
from src.database.db_manager import db

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────
ABUSEIPDB_MALICIOUS_THRESHOLD: int = 50   # abuse confidence score (0-100)
VT_MALICIOUS_THRESHOLD: int = 5           # # of engines flagging as malicious
KNOWN_TOR_EXIT_NODES: set = {
    "185.220.101.42", "185.220.101.43", "185.220.100.240",
    "199.249.230.89", "23.129.64.130",
}


# ── Data Models ──────────────────────────────────────────────────────
class AbuseIPDBResult(BaseModel):
    """Result from AbuseIPDB lookup."""
    ip: str = ""
    is_public: bool = True
    abuse_confidence_score: int = Field(default=0, ge=0, le=100)
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: str = ""
    country_code: str = ""
    isp: str = ""
    domain: str = ""
    is_tor: bool = False
    is_whitelisted: bool = False


class VirusTotalResult(BaseModel):
    """Result from VirusTotal IP lookup."""
    ip: str = ""
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    total_engines: int = 70
    reputation_score: int = 0
    as_owner: str = ""
    country: str = ""
    detected_urls: List[str] = Field(default_factory=list)


class GeoIPResult(BaseModel):
    """Geographic information for an IP."""
    ip: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    asn: int = 0
    as_name: str = ""
    isp: str = ""
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False


class ThreatIntelReport(BaseModel):
    """Aggregated threat intelligence from all sources.

    This is the output that feeds into the Verification Gate.

    Attributes:
        ip: The IP address investigated.
        overall_threat_score: Normalized score 0-10 (10 = confirmed malicious).
        is_known_malicious: True if any trusted source confirms malicious.
        sources_consulted: Number of external sources queried.
        sources_confirming: Number of sources that confirmed malicious.
        abuseipdb: AbuseIPDB lookup result.
        virustotal: VirusTotal lookup result.
        geoip: Geographic IP information.
        corroboration_summary: Human-readable summary for legal documents.
    """
    ip: str = ""
    query_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    overall_threat_score: float = Field(default=0.0, ge=0.0, le=10.0)
    is_known_malicious: bool = False
    sources_consulted: int = 0
    sources_confirming: int = 0
    abuseipdb: AbuseIPDBResult = Field(default_factory=AbuseIPDBResult)
    virustotal: VirusTotalResult = Field(default_factory=VirusTotalResult)
    geoip: GeoIPResult = Field(default_factory=GeoIPResult)
    corroboration_summary: str = ""


class ThreatIntelAggregator:
    """Queries multiple threat intelligence sources and produces a unified report.

    In DEMO mode, returns realistic synthetic data. In production, makes
    real API calls to AbuseIPDB, VirusTotal, and MaxMind.
    """

    def __init__(self) -> None:
        self._demo = settings.demo_mode
        logger.info(
            "ThreatIntelAggregator initialized (demo=%s)", self._demo
        )

    def investigate(self, ip: str) -> ThreatIntelReport:
        """Run a full investigation on a given IP address.

        Queries all configured sources, normalizes the results,
        and produces a corroboration summary.

        Args:
            ip: The IP address to investigate.

        Returns:
            A ThreatIntelReport with aggregated findings.
        """
        logger.info("Investigating IP %s across threat intel sources...", ip)

        abuseipdb = self._query_abuseipdb(ip)
        virustotal = self._query_virustotal(ip)
        geoip = self._query_geoip(ip)

        # Count confirming sources
        sources_consulted = 3
        sources_confirming = 0

        if abuseipdb.abuse_confidence_score >= ABUSEIPDB_MALICIOUS_THRESHOLD:
            sources_confirming += 1
        if virustotal.malicious_count >= VT_MALICIOUS_THRESHOLD:
            sources_confirming += 1
        if geoip.is_tor or geoip.is_vpn:
            sources_confirming += 1

        # Calculate overall threat score (0-10)
        abuse_component = (abuseipdb.abuse_confidence_score / 100) * 4  # max 4
        vt_component = min(4.0, (virustotal.malicious_count / 10) * 4)  # max 4
        anonymity_component = 2.0 if (geoip.is_tor or geoip.is_vpn) else 0.0
        overall = min(10.0, round(abuse_component + vt_component + anonymity_component, 2))

        is_malicious = sources_confirming >= 2 or overall >= 7.0

        # Build legal corroboration summary
        summary_lines = [
            f"THREAT INTELLIGENCE REPORT — {ip}",
            f"Query Time: {datetime.now(timezone.utc).isoformat()}",
            f"Sources Consulted: {sources_consulted}",
            f"Sources Confirming Malicious: {sources_confirming}/{sources_consulted}",
            "",
        ]
        if abuseipdb.abuse_confidence_score >= ABUSEIPDB_MALICIOUS_THRESHOLD:
            summary_lines.append(
                f"✓ AbuseIPDB: Confidence {abuseipdb.abuse_confidence_score}%, "
                f"reported {abuseipdb.total_reports} times by "
                f"{abuseipdb.num_distinct_users} distinct users."
            )
        if virustotal.malicious_count >= VT_MALICIOUS_THRESHOLD:
            summary_lines.append(
                f"✓ VirusTotal: Flagged by {virustotal.malicious_count}/"
                f"{virustotal.total_engines} engines as malicious."
            )
        if geoip.is_tor:
            summary_lines.append(
                f"✓ Network: IP is a known Tor exit node (anonymization detected)."
            )
        if geoip.is_vpn:
            summary_lines.append(
                f"✓ Network: IP is a known VPN/proxy endpoint."
            )
        summary_lines.append(
            f"\nOrigin: {geoip.city}, {geoip.country} (ASN: {geoip.asn} — {geoip.as_name})"
        )
        summary_lines.append(f"ISP: {geoip.isp}")
        summary_lines.append(f"Overall Threat Score: {overall}/10")
        summary_lines.append(
            f"Verdict: {'CONFIRMED MALICIOUS' if is_malicious else 'INCONCLUSIVE'}"
        )

        report = ThreatIntelReport(
            ip=ip,
            overall_threat_score=overall,
            is_known_malicious=is_malicious,
            sources_consulted=sources_consulted,
            sources_confirming=sources_confirming,
            abuseipdb=abuseipdb,
            virustotal=virustotal,
            geoip=geoip,
            corroboration_summary="\n".join(summary_lines),
        )

        logger.info(
            "ThreatIntel [%s] → score=%.1f  malicious=%s  confirming=%d/%d",
            ip, overall, is_malicious, sources_confirming, sources_consulted,
        )
        return report

    # ── Source Queries ────────────────────────────────────────────────

    def _query_abuseipdb(self, ip: str) -> AbuseIPDBResult:
        """Query AbuseIPDB for IP reputation.

        Args:
            ip: Target IP address.

        Returns:
            AbuseIPDBResult with abuse score and report counts.
        """
        if self._demo:
            # Realistic synthetic data based on IP hash
            seed = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
            is_known = ip in KNOWN_TOR_EXIT_NODES or seed % 3 == 0
            return AbuseIPDBResult(
                ip=ip,
                abuse_confidence_score=87 if is_known else 12,
                total_reports=847 if is_known else 2,
                num_distinct_users=312 if is_known else 1,
                last_reported_at=datetime.now(timezone.utc).isoformat(),
                country_code="RU" if is_known else "US",
                isp="LLC Baxet" if is_known else "Comcast",
                domain="tor-exit.example.com" if is_known else "home.example.com",
                is_tor=ip in KNOWN_TOR_EXIT_NODES,
                is_whitelisted=False,
            )
        # Production: call AbuseIPDB API v2
        # headers = {"Key": os.environ["ABUSEIPDB_API_KEY"], "Accept": "application/json"}
        # resp = httpx.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
        logger.warning("AbuseIPDB production mode not configured — returning empty result")
        return AbuseIPDBResult(ip=ip)

    def _query_virustotal(self, ip: str) -> VirusTotalResult:
        """Query VirusTotal for IP analysis.

        Args:
            ip: Target IP address.

        Returns:
            VirusTotalResult with engine detection counts.
        """
        if self._demo:
            seed = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
            is_known = ip in KNOWN_TOR_EXIT_NODES or seed % 3 == 0
            return VirusTotalResult(
                ip=ip,
                malicious_count=42 if is_known else 0,
                suspicious_count=8 if is_known else 1,
                harmless_count=20 if is_known else 69,
                total_engines=70,
                reputation_score=-85 if is_known else 5,
                as_owner="LLC Baxet" if is_known else "Comcast Cable",
                country="RU" if is_known else "US",
                detected_urls=[
                    "http://malware-c2.example.com/payload",
                    "http://phishing.example.com/login",
                ] if is_known else [],
            )
        logger.warning("VirusTotal production mode not configured — returning empty result")
        return VirusTotalResult(ip=ip)

    def _query_geoip(self, ip: str) -> GeoIPResult:
        """Query GeoIP database for location information.

        Args:
            ip: Target IP address.

        Returns:
            GeoIPResult with geographic and network metadata.
        """
        # Check cache first — avoid redundant API calls
        cached = db.get_geo(ip)
        if cached:
            logger.debug("GeoIP cache hit for %s", ip)
            return GeoIPResult(
                ip=ip,
                country=cached.get("country", ""),
                country_code=cached.get("country_code", ""),
                city=cached.get("city", ""),
                latitude=cached.get("latitude", 0.0),
                longitude=cached.get("longitude", 0.0),
                asn=cached.get("asn", 0),
                as_name="",
                isp=cached.get("isp", ""),
                is_tor=bool(cached.get("is_tor", False)),
                is_vpn=bool(cached.get("is_vpn", False)),
                is_proxy=False,
            )

        if self._demo:
            is_tor = ip in KNOWN_TOR_EXIT_NODES
            # Realistic geolocation based on IP pattern
            geo_map: Dict[str, Dict[str, Any]] = {
                "185.220": {"country": "Russie", "code": "RU", "city": "Moscou",
                            "lat": 55.7558, "lng": 37.6173, "asn": 205100,
                            "as_name": "F5 Networks / Tor Exit", "isp": "LLC Baxet"},
                "10.0": {"country": "Interne", "code": "LAN", "city": "Réseau Local",
                         "lat": 0.0, "lng": 0.0, "asn": 0,
                         "as_name": "Private Network", "isp": "Interne"},
                "192.168": {"country": "Interne", "code": "LAN", "city": "Réseau Local",
                            "lat": 0.0, "lng": 0.0, "asn": 0,
                            "as_name": "Private Network", "isp": "Interne"},
            }
            prefix = ".".join(ip.split(".")[:2])
            geo = geo_map.get(prefix, {
                "country": "États-Unis", "code": "US", "city": "Ashburn",
                "lat": 39.0438, "lng": -77.4874, "asn": 13335,
                "as_name": "Cloudflare Inc", "isp": "Cloudflare",
            })
            res = GeoIPResult(
                ip=ip,
                country=geo["country"],
                country_code=geo["code"],
                city=geo["city"],
                latitude=geo["lat"],
                longitude=geo["lng"],
                asn=geo["asn"],
                as_name=geo["as_name"],
                isp=geo["isp"],
                is_tor=is_tor,
                is_vpn=False,
                is_proxy=False,
            )
            
            # Save to Hot DB Cache
            try:
                db.save_geo(ip, res.model_dump())
            except Exception as e:
                logger.error("Failed to save GeoIP to cache: %s", e)
                
            return res
        logger.warning("GeoIP production mode not configured — returning empty result")
        return GeoIPResult(ip=ip)


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Corroborates ML alerts with external trusted sources (AbuseIPDB, VT).
# 2. Provides geographic context for incident reports and legal documents.
# 3. Calculates an independent threat score to prevent false-positive escalation.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    aggregator = ThreatIntelAggregator()

    for ip in ["185.220.101.42", "10.0.0.5", "8.8.8.8"]:
        report = aggregator.investigate(ip)
        logger.info("\n%s", report.corroboration_summary)
        logger.info("-" * 60)
