"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/parsing/sessionizer.py

Transforms a stream of individual NormalizedEvents into LogSession
objects grouped by entity within sliding time windows.

WHY SESSIONS MATTER FOR ML:
  DeepLog expects an ordered sequence of template IDs from ONE entity.
  LogLizer expects a count vector of template IDs per session.
  XGBoost / IsolationForest expect a feature vector per session.

  Without sessionization, we would feed the models individual log lines
  with no temporal or entity context — they would be unable to detect
  patterns like "5 failed logins followed by a success followed by a
  lateral movement", because each event arrives in isolation.

THE PIPELINE:
  raw log → DrainParser → NormalizedEvent → Sessionizer → LogSession
                                                              ↓
                                                         [ML Models]
                                                     DeepLog reads template_sequence
                                                     LogLizer reads template_counts
                                                     XGBoost reads template_counts

ENTITY RESOLUTION:
  A single attacker (e.g. 192.168.1.100) may appear in:
    - auth.log     → "Failed password for root from 192.168.1.100"
    - kern.log     → "[UFW BLOCK] SRC=192.168.1.100"
    - mysql.log    → "Query executed by user root" (if correlated)
  The sessionizer groups ALL of these into one session keyed by
  source_ip=192.168.1.100, so the model sees the full attack sequence
  across log sources.
"""

from __future__ import annotations

import collections
import logging
import threading
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional

from src.parsing.models import LogSession, NormalizedEvent

# ── Logging ──────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────
DEFAULT_WINDOW_SECONDS: int = 300       # 5 minutes
DEFAULT_MAX_EVENTS: int = 200           # cap per session
DEFAULT_FLUSH_INTERVAL_SECONDS: int = 60  # periodic flush check


class EntityKeyStrategy(str, Enum):
    """How to extract the grouping key from a NormalizedEvent."""
    SOURCE_IP = "source_ip"
    USERNAME = "username"
    HOST = "host"
    COMPOSITE = "composite"   # source_ip + username combined


def _resolve_entity_key(
    event: NormalizedEvent,
    strategy: EntityKeyStrategy,
) -> Optional[str]:
    """
    Extract the entity key from an event based on the chosen strategy.

    Args:
        event: The normalized event.
        strategy: Which field(s) to use as the grouping key.

    Returns:
        The entity key string, or None if no usable key is found.
    """
    if strategy == EntityKeyStrategy.SOURCE_IP:
        return event.source_ip if event.source_ip else None

    if strategy == EntityKeyStrategy.USERNAME:
        return event.username if event.username else None

    if strategy == EntityKeyStrategy.HOST:
        return event.host_name if event.host_name != "unknown" else None

    if strategy == EntityKeyStrategy.COMPOSITE:
        # Combine IP + username for finer-grained sessions.
        # Example: "192.168.1.100|root" groups all activity by root
        # from that specific machine.
        parts = []
        if event.source_ip:
            parts.append(event.source_ip)
        if event.username:
            parts.append(event.username)
        return "|".join(parts) if parts else None

    return None


def _build_session(
    entity_id: str,
    entity_type: str,
    events: List[NormalizedEvent],
) -> LogSession:
    """
    Build a LogSession from a list of events belonging to one entity.

    This computes all the derived fields the ML models need:
      - template_sequence (chronologically ordered template IDs)
      - template_counts   (count vector for LogLizer / XGBoost)
      - event_hashes      (for traceability in the alert contract)
      - cross-source metadata (unique IPs, categories)

    Args:
        entity_id: The entity key value.
        entity_type: The entity dimension (ip/user/host/composite).
        events: List of NormalizedEvents, not necessarily sorted.

    Returns:
        A fully populated LogSession.
    """
    # Sort events chronologically — DeepLog needs temporal order
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    # Build the template sequence (DeepLog LSTM input)
    template_sequence = [e.template_id for e in sorted_events]

    # Build the count vector (LogLizer / XGBoost feature vector)
    counter: collections.Counter = collections.Counter(template_sequence)
    template_counts = dict(counter)

    # Collect event hashes for traceability
    event_hashes = [e.event_hash for e in sorted_events if e.event_hash]

    # Total suspicion from BaselineProfiler
    total_suspicion = sum(e.suspicion_delta for e in sorted_events)

    # Cross-source correlation: unique IPs and categories
    source_ips = sorted(set(e.source_ip for e in sorted_events if e.source_ip))
    dest_ips = sorted(set(e.dest_ip for e in sorted_events if e.dest_ip))
    categories = sorted(set(e.event_category.value for e in sorted_events))

    return LogSession(
        entity_type=entity_type,
        entity_id=entity_id,
        start_ts=sorted_events[0].timestamp,
        end_ts=sorted_events[-1].timestamp,
        event_count=len(sorted_events),
        template_sequence=template_sequence,
        total_suspicion=total_suspicion,
        template_counts=template_counts,
        event_hashes=event_hashes,
        source_ips=source_ips,
        dest_ips=dest_ips,
        categories=categories,
        events=sorted_events,
    )


# ── Active window buffer for one entity ──────────────────────────────
class _EntityBuffer:
    """Internal buffer holding events for one entity's active window."""

    __slots__ = ("events", "window_start")

    def __init__(self, first_event: NormalizedEvent) -> None:
        self.events: List[NormalizedEvent] = [first_event]
        self.window_start: datetime = first_event.timestamp

    def add(self, event: NormalizedEvent) -> None:
        """Append an event to this buffer."""
        self.events.append(event)

    @property
    def last_ts(self) -> datetime:
        """Timestamp of the most recent event."""
        return self.events[-1].timestamp


class LogSessionizer:
    """
    Stateful sliding-window sessionizer that groups NormalizedEvents
    by entity and emits LogSession objects when a window closes.

    A window closes when:
      1. A new event arrives that is outside the time window, OR
      2. The event count reaches max_events_per_session, OR
      3. flush_all() or flush_expired() is called explicitly.

    Thread-safe: uses a Lock for concurrent access.

    Args:
        window_seconds: Duration of the sliding window in seconds.
        max_events: Maximum events per session before forced close.
        entity_strategy: How to extract the grouping key from events.
    """

    def __init__(
        self,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        max_events: int = DEFAULT_MAX_EVENTS,
        entity_strategy: EntityKeyStrategy = EntityKeyStrategy.SOURCE_IP,
    ) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._max_events = max_events
        self._strategy = entity_strategy
        self._buffers: Dict[str, _EntityBuffer] = {}
        self._lock = threading.Lock()

        logger.info(
            "LogSessionizer initialised — window=%ds  max_events=%d  "
            "strategy=%s",
            window_seconds,
            max_events,
            entity_strategy.value,
        )

    def process_event(
        self, event: NormalizedEvent
    ) -> Optional[LogSession]:
        """
        Feed a NormalizedEvent into the sessionizer.

        If the event causes a window to close (time exceeded or max
        events reached), the completed LogSession is returned.
        Otherwise returns None (the event was buffered).

        Args:
            event: A NormalizedEvent to sessionize.

        Returns:
            A LogSession if a window was closed, else None.
        """
        entity_key = _resolve_entity_key(event, self._strategy)
        if entity_key is None:
            # Cannot determine entity — fall back to host_name
            entity_key = event.host_name
            if entity_key == "unknown":
                logger.debug("Event has no usable entity key, skipping")
                return None

        with self._lock:
            buf = self._buffers.get(entity_key)

            # ── No active window for this entity → start one ─────────
            if buf is None:
                self._buffers[entity_key] = _EntityBuffer(event)
                return None

            # ── Check if the window should close ─────────────────────
            time_exceeded = (event.timestamp - buf.window_start) > self._window
            count_exceeded = len(buf.events) >= self._max_events

            if time_exceeded or count_exceeded:
                # Build the completed session from buffered events
                completed = _build_session(
                    entity_id=entity_key,
                    entity_type=self._strategy.value,
                    events=buf.events,
                )

                # Start a fresh window with the new event
                self._buffers[entity_key] = _EntityBuffer(event)

                logger.debug(
                    "Session closed for entity=%s  events=%d  "
                    "templates=%s  categories=%s",
                    entity_key,
                    completed.event_count,
                    completed.template_sequence,
                    completed.categories,
                )
                return completed

            # ── Within window — just buffer it ───────────────────────
            buf.add(event)
            return None

    def flush_all(self) -> List[LogSession]:
        """
        Close ALL active windows and return the sessions.

        Call this at the end of a static-file ingestion to emit any
        remaining buffered events as sessions.

        Returns:
            List of LogSession objects for every active buffer.
        """
        sessions: List[LogSession] = []
        with self._lock:
            for entity_key, buf in self._buffers.items():
                if buf.events:
                    session = _build_session(
                        entity_id=entity_key,
                        entity_type=self._strategy.value,
                        events=buf.events,
                    )
                    sessions.append(session)
            self._buffers.clear()

        if sessions:
            logger.info("Flushed %d sessions (all buffers)", len(sessions))
        return sessions

    def flush_expired(self, now: Optional[datetime] = None) -> List[LogSession]:
        """
        Close only windows whose last event is older than the window.

        Call this periodically (e.g. every 60s) during live ingestion
        to emit idle sessions.

        Args:
            now: Current time (defaults to utcnow). Pass explicitly
                for deterministic testing.

        Returns:
            List of completed LogSession objects.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        sessions: List[LogSession] = []
        expired_keys: List[str] = []

        with self._lock:
            for entity_key, buf in self._buffers.items():
                if (now - buf.last_ts) > self._window:
                    session = _build_session(
                        entity_id=entity_key,
                        entity_type=self._strategy.value,
                        events=buf.events,
                    )
                    sessions.append(session)
                    expired_keys.append(entity_key)

            for key in expired_keys:
                del self._buffers[key]

        if sessions:
            logger.info("Flushed %d expired sessions", len(sessions))
        return sessions

    @property
    def active_entity_count(self) -> int:
        """Number of entities with active (open) windows."""
        with self._lock:
            return len(self._buffers)

    @property
    def total_buffered_events(self) -> int:
        """Total events buffered across all active windows."""
        with self._lock:
            return sum(len(buf.events) for buf in self._buffers.values())


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# ---------------------
# 1. Transforms atomic log events into entity-level sessions that ML
#    models (DeepLog, LogLizer, XGBoost) can actually consume.
# 2. Correlates events across log sources (auth + network + DB) by
#    grouping on entity keys (IP, user, host, or composite).
# 3. Produces template_sequence (for DeepLog LSTM) and template_counts
#    (for LogLizer / XGBoost feature vectors) in a single pass.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    logging.basicConfig(level="DEBUG")

    logger.info("=" * 70)
    logger.info("SESSIONIZER DEMO — multi-source correlation")
    logger.info("=" * 70)

    from src.parsing.normalizer import LogNormalizer

    normalizer = LogNormalizer()

    # ── Simulate logs from MULTIPLE sources for the SAME attacker ────
    # The IP 192.168.1.100 appears in auth.log, kern.log, and mysql.log.
    # The sessionizer must group them into ONE session.
    MULTI_SOURCE_LOGS: list[tuple[str, str]] = [
        # (log_line, log_source)
        ("May  1 10:23:45 web01 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2", "auth.log"),
        ("May  1 10:23:46 web01 sshd[12346]: Failed password for root from 192.168.1.100 port 22 ssh2", "auth.log"),
        ("May  1 10:23:47 web01 sshd[12347]: Failed password for root from 192.168.1.100 port 22 ssh2", "auth.log"),
        ("May  1 10:23:50 web01 kernel[0]: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP DPT=443", "kern.log"),
        ("May  1 10:24:01 web01 sshd[12348]: Accepted publickey for root from 192.168.1.100 port 22 ssh2", "auth.log"),
        # Different entity (10.0.0.55) — should be a SEPARATE session
        ("May  1 10:23:48 web01 sshd[12350]: Failed password for admin from 10.0.0.55 port 22 ssh2", "auth.log"),
        # Another log from the attacker
        ("May  1 10:24:30 db01 mysqld[5678]: Query 'DROP TABLE users' executed by user root", "mysql.log"),
    ]

    sessionizer = LogSessionizer(
        window_seconds=300,  # 5 minute window
        max_events=100,
        entity_strategy=EntityKeyStrategy.SOURCE_IP,
    )

    # Process each event
    for log_line, source in MULTI_SOURCE_LOGS:
        event = normalizer.normalize_line(log_line, host="demo", source=source)
        session = sessionizer.process_event(event)
        if session:
            logger.info("SESSION CLOSED mid-stream: %s", session.entity_id)

    # Flush remaining sessions
    sessions = sessionizer.flush_all()

    logger.info("-" * 70)
    logger.info("RESULTS: %d sessions produced", len(sessions))
    logger.info("-" * 70)

    for s in sessions:
        logger.info("")
        logger.info("  ENTITY:            %s (%s)", s.entity_id, s.entity_type)
        logger.info("  EVENT COUNT:       %d", s.event_count)
        logger.info("  TEMPLATE SEQUENCE: %s  ← DeepLog LSTM input", s.template_sequence)
        logger.info("  TEMPLATE COUNTS:   %s  ← LogLizer feature vector", s.template_counts)
        logger.info("  LOG SOURCES:       %s", sorted(set(e.log_source for e in s.events)))
        logger.info("  CATEGORIES:        %s  ← cross-source correlation", s.categories)
        logger.info("  SOURCE IPs:        %s", s.source_ips)
        logger.info("  DEST IPs:          %s", s.dest_ips)
        logger.info("  TIME SPAN:         %s → %s", s.start_ts, s.end_ts)
        logger.info("  EVENT HASHES:      [%d hashes for traceability]", len(s.event_hashes))

    logger.info("")
    logger.info("Sessionizer demo complete ✓")
