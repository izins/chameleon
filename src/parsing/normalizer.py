"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/parsing/normalizer.py

Maps any supported log format into a NormalizedEvent (ECS-aligned).
The normalizer detects whether an incoming raw line is syslog, MySQL,
firewall (UFW), or generic, and extracts structured fields accordingly.

Pipeline: raw line → DrainParser (template) → Normalizer (ECS) → NormalizedEvent
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from src.config.settings import EventAction, EventCategory
from src.parsing.drain_parser import DrainParser, DrainResult
from src.parsing.models import NormalizedEvent, RawLogEvent

logger = logging.getLogger(__name__)

# ── Compiled regex patterns ──────────────────────────────────────────
RE_SYSLOG = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[]+)\[(?P<pid>\d+)\]:\s+(?P<message>.+)$"
)
RE_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_USERNAME = re.compile(r"(?:for|user|by user)\s+(\S+)", re.IGNORECASE)
RE_UFW = re.compile(r"\[UFW\s+(?P<action>\S+)\].*SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)")
RE_MYSQL_QUERY = re.compile(r"Query\s+'(?P<query>.+?)'\s+executed\s+by\s+user\s+(?P<user>\S+)", re.IGNORECASE)
RE_SSH_FAILED = re.compile(r"Failed\s+password", re.IGNORECASE)
RE_SSH_ACCEPTED = re.compile(r"Accepted\s+(?:password|publickey)", re.IGNORECASE)
RE_SSH_DISCONNECT = re.compile(r"Disconnected\s+from", re.IGNORECASE)
RE_PRIV_ESCALATION = re.compile(r"(?:sudo|su|pkexec|privilege|escalat)", re.IGNORECASE)


class LogNormalizer:
    """Stateful normalizer using DrainParser + regex heuristics."""

    def __init__(self, drain_parser: Optional[DrainParser] = None) -> None:
        self._drain = drain_parser or DrainParser()
        logger.info("LogNormalizer ready (drain clusters=%d)", self._drain.cluster_count)

    def normalize(self, raw: RawLogEvent) -> NormalizedEvent:
        """Transform a RawLogEvent into a NormalizedEvent.

        Args:
            raw: The raw log event to normalise.

        Returns:
            A fully populated NormalizedEvent.

        Raises:
            ValueError: If the raw line is empty.
        """
        line = raw.raw_line.strip()
        if not line:
            raise ValueError("Cannot normalise an empty log line.")

        drain_result: DrainResult = self._drain.parse(line)
        category, action, source_ip, dest_ip, username, process_name, timestamp = (
            self._extract_fields(line)
        )
        if timestamp is None:
            timestamp = raw.ingestion_ts

        event = NormalizedEvent(
            timestamp=timestamp, source_ip=source_ip, dest_ip=dest_ip,
            event_category=category, event_action=action, username=username,
            process_name=process_name, log_original=raw.raw_line,
            template_id=drain_result.template_id, template_str=drain_result.template_str,
            host_name=raw.host_name, log_source=raw.log_source,
        ).compute_hash()
        logger.debug("Normalised → cat=%s act=%s src=%s user=%s tpl=%d",
                      event.event_category.value, event.event_action.value,
                      event.source_ip, event.username, event.template_id)
        return event

    def normalize_line(self, line: str, host: str = "unknown",
                       source: str = "unknown") -> NormalizedEvent:
        """Convenience wrapper: normalise a plain string directly.

        Args:
            line: Raw log line.
            host: Originating host name.
            source: Log stream identifier.

        Returns:
            A NormalizedEvent.
        """
        raw = RawLogEvent(raw_line=line, host_name=host, log_source=source)
        return self.normalize(raw)

    def _extract_fields(self, line: str) -> tuple[
        EventCategory, EventAction, str, str, str, str, Optional[datetime]
    ]:
        """Extract structured ECS fields from a raw log line using regex heuristics.

        Args:
            line: The raw log line.

        Returns:
            7-tuple: (category, action, source_ip, dest_ip, username, process_name, timestamp).
        """
        category, action = EventCategory.UNKNOWN, EventAction.UNKNOWN
        source_ip, dest_ip, username, process_name = "", "", "", ""
        timestamp: Optional[datetime] = None

        syslog_match = RE_SYSLOG.match(line)
        if syslog_match:
            process_name = syslog_match.group("process").strip()
            timestamp = self._parse_syslog_ts(syslog_match.group("ts"))
            message = syslog_match.group("message")
        else:
            message = line

        ips = RE_IPV4.findall(line)
        if len(ips) >= 1:
            source_ip = ips[0]
        if len(ips) >= 2:
            dest_ip = ips[1]

        user_match = RE_USERNAME.search(line)
        if user_match:
            username = user_match.group(1)

        # UFW firewall
        ufw_match = RE_UFW.search(line)
        if ufw_match:
            category = EventCategory.NETWORK
            ufw_action = ufw_match.group("action").upper()
            source_ip, dest_ip = ufw_match.group("src"), ufw_match.group("dst")
            action = (EventAction.CONNECTION_DENIED if ufw_action == "BLOCK"
                      else EventAction.CONNECTION_ACCEPTED if ufw_action == "ALLOW"
                      else EventAction.CONNECTION_ATTEMPT)
            return category, action, source_ip, dest_ip, username, process_name, timestamp

        # MySQL query
        mysql_match = RE_MYSQL_QUERY.search(line)
        if mysql_match:
            category, action = EventCategory.DATABASE, EventAction.QUERY_EXECUTE
            username = mysql_match.group("user")
            return category, action, source_ip, dest_ip, username, process_name, timestamp

        # SSH authentication
        if RE_SSH_FAILED.search(message):
            category, action = EventCategory.AUTHENTICATION, EventAction.LOGIN_FAILURE
        elif RE_SSH_ACCEPTED.search(message):
            category, action = EventCategory.AUTHENTICATION, EventAction.LOGIN_SUCCESS
        elif RE_SSH_DISCONNECT.search(message):
            category, action = EventCategory.AUTHENTICATION, EventAction.LOGOUT

        # Privilege escalation
        if RE_PRIV_ESCALATION.search(message):
            category, action = EventCategory.SYSTEM, EventAction.PRIVILEGE_CHANGE

        if category == EventCategory.UNKNOWN and process_name:
            category = EventCategory.PROCESS

        return category, action, source_ip, dest_ip, username, process_name, timestamp

    @staticmethod
    def _parse_syslog_ts(ts_str: str) -> Optional[datetime]:
        """Parse syslog timestamp (e.g. 'May  1 10:23:45') to UTC datetime.

        Args:
            ts_str: Syslog timestamp string.

        Returns:
            Timezone-aware datetime in UTC, or None on failure.
        """
        try:
            now = datetime.now(timezone.utc)
            parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(
                year=now.year, tzinfo=timezone.utc)
            return parsed
        except (ValueError, TypeError) as exc:
            logger.warning("Failed to parse syslog timestamp '%s': %s", ts_str, exc)
            return None


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Bridges raw text lines and structured ECS events.
# 2. Applies format-specific regex heuristics (syslog, UFW, MySQL, SSH).
# 3. Combines DrainParser template extraction with field extraction.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level="DEBUG")

    SAMPLE_LINES: list[str] = [
        "May  1 10:23:45 web01 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "May  1 10:23:46 web01 sshd[12346]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2",
        "May  1 10:25:00 db01 mysqld[5678]: Query 'SELECT * FROM users WHERE id=1 OR 1=1' executed by user webapp",
        "May  1 10:26:30 app01 kernel[0]: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.0.0.10 PROTO=TCP DPT=443",
        "May  1 10:27:00 web01 sudo[9999]: user admin ran command /bin/bash with privilege escalation",
    ]

    normalizer = LogNormalizer()
    logger.info("=" * 60)
    logger.info("NORMALIZER DEMO")
    logger.info("=" * 60)

    for line in SAMPLE_LINES:
        event = normalizer.normalize_line(line, host="demo-host", source="demo.log")
        logger.info("  cat=%-15s act=%-20s src=%-16s user=%-10s tpl=%d  hash=%s…",
                     event.event_category.value, event.event_action.value,
                     event.source_ip, event.username, event.template_id, event.event_hash[:16])

    logger.info("Normalizer demo complete ✓")
