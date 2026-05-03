"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/parsing/baseline_profiler.py

Behavioral Analytics (UEBA) — scores every NormalizedEvent against
the entity's historical profile.

Five detection signals:
  1. Temporal Anomaly  — activity at hours never seen before for this entity.
  2. Novelty Anomaly   — a Drain3 template ID never seen for this entity.
  3. Frequency Anomaly  — event rate exceeds historical average.
  4. Destination Anomaly — connection to an IP never contacted before.
  5. Night Penalty       — base suspicion for off-hours activity (0h-5h UTC).

Runs in Phase 1, right after normalization, so that the LogSession
carries behavioral context before the ML models see it.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Set

from src.parsing.models import NormalizedEvent

logger = logging.getLogger(__name__)

# ── Scoring weights (tuneable) ───────────────────────────────────────
WEIGHT_NIGHT_BASE: float = 2.0     # Off-hours (0h-5h) base penalty
WEIGHT_NOVEL_HOUR: float = 3.0     # Hour never seen for this entity
WEIGHT_NOVEL_TEMPLATE: float = 4.0 # Template never seen for this entity
WEIGHT_NOVEL_DEST: float = 2.0     # Destination IP never seen before
WEIGHT_FREQ_SPIKE: float = 3.0     # Frequency exceeds 3× historical avg
BASELINE_MIN_EVENTS: int = 10      # Minimum events before novelty scoring
FREQ_WINDOW_SECONDS: float = 60.0  # Sliding window for frequency calc
FREQ_SPIKE_MULTIPLIER: float = 3.0 # How many times the avg = spike


class EntityProfile:
    """Historical behavior profile for a single entity (IP/User/Host).

    Attributes:
        known_templates: Set of Drain3 template IDs seen.
        active_hours: Set of hours (0-23) when activity was observed.
        known_destinations: Set of destination IPs contacted.
        event_count: Total events processed.
        event_timestamps: Recent timestamps for frequency calculation.
    """

    __slots__ = (
        "known_templates", "active_hours", "known_destinations",
        "event_count", "event_timestamps",
    )

    def __init__(self) -> None:
        self.known_templates: Set[int] = set()
        self.active_hours: Set[int] = set()
        self.known_destinations: Set[str] = set()
        self.event_count: int = 0
        self.event_timestamps: Deque[float] = deque(maxlen=500)

    @property
    def avg_events_per_minute(self) -> float:
        """Calculate average event rate over the frequency window."""
        if len(self.event_timestamps) < 2:
            return 0.0
        span = self.event_timestamps[-1] - self.event_timestamps[0]
        if span <= 0:
            return float(len(self.event_timestamps))
        return len(self.event_timestamps) / (span / 60.0)


class BaselineProfiler:
    """Scores NormalizedEvents based on historical entity behavior.

    This runs IN PHASE 1, right after normalization, so it can
    enrich the LogSession with behavioral suspicion before the
    ML models even see it.
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, EntityProfile] = {}
        logger.info("BaselineProfiler initialised (UEBA Mode — 5 signals)")

    def score(self, event: NormalizedEvent) -> NormalizedEvent:
        """Calculate suspicion_delta and update the entity's profile.

        Detection signals applied in order:
          1. Night penalty (0h-5h UTC base suspicion).
          2. Novel hour (hour never seen for THIS entity).
          3. Novel template (Drain3 ID never seen for THIS entity).
          4. Novel destination (dest_ip never contacted by THIS entity).
          5. Frequency spike (rate > 3× historical average).

        Args:
            event: The normalized event to score.

        Returns:
            The same event with suspicion_delta populated.
        """
        entity_key = event.source_ip or event.username or event.host_name
        if not entity_key or entity_key == "unknown":
            return event

        if entity_key not in self._profiles:
            self._profiles[entity_key] = EntityProfile()

        prof = self._profiles[entity_key]
        delta = 0.0
        hour = event.timestamp.hour
        now_mono = time.monotonic()

        # ── 1. Night penalty (off-hours base suspicion) ──────────────
        if 0 <= hour <= 5:
            delta += WEIGHT_NIGHT_BASE

        # ── 2. Novel hour (entity-specific, not hardcoded) ───────────
        if prof.event_count > BASELINE_MIN_EVENTS:
            if hour not in prof.active_hours:
                delta += WEIGHT_NOVEL_HOUR

        # ── 3. Novel template ────────────────────────────────────────
        if prof.event_count > BASELINE_MIN_EVENTS:
            if event.template_id not in prof.known_templates:
                delta += WEIGHT_NOVEL_TEMPLATE

        # ── 4. Novel destination ─────────────────────────────────────
        if event.dest_ip and prof.event_count > BASELINE_MIN_EVENTS:
            if event.dest_ip not in prof.known_destinations:
                delta += WEIGHT_NOVEL_DEST

        # ── 5. Frequency spike ───────────────────────────────────────
        if prof.event_count > BASELINE_MIN_EVENTS:
            avg = prof.avg_events_per_minute
            if avg > 0:
                # Count events in the last FREQ_WINDOW_SECONDS
                cutoff = now_mono - FREQ_WINDOW_SECONDS
                recent_count = sum(
                    1 for ts in prof.event_timestamps if ts > cutoff
                )
                current_rate = recent_count / (FREQ_WINDOW_SECONDS / 60.0)
                if current_rate > avg * FREQ_SPIKE_MULTIPLIER:
                    delta += WEIGHT_FREQ_SPIKE

        # ── Update profile (learn) ───────────────────────────────────
        prof.known_templates.add(event.template_id)
        prof.active_hours.add(hour)
        if event.dest_ip:
            prof.known_destinations.add(event.dest_ip)
        prof.event_count += 1
        prof.event_timestamps.append(now_mono)

        # ── Write score to event ─────────────────────────────────────
        event.suspicion_delta = delta

        if delta > 0:
            logger.debug(
                "Baseline suspicion for %s: +%.1f "
                "(tpl=%d hour=%d dest=%s freq=%.1f/min)",
                entity_key, delta, event.template_id, hour,
                event.dest_ip or "-", prof.avg_events_per_minute,
            )

        return event


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Detects "Low & Slow" attacks that use normal log syntax.
# 2. Five UEBA signals: temporal, novelty, destination, frequency, night.
# 3. Ensures the EntityTracker gets updated even if ML models say "Normal".
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os

    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    from src.config.settings import EventCategory

    profiler = BaselineProfiler()

    logger.info("=" * 60)
    logger.info("BASELINE PROFILER DEMO — 5 UEBA signals")
    logger.info("=" * 60)

    # Build a baseline (12 normal events during work hours)
    for i in range(12):
        ev = NormalizedEvent(
            log_original=f"normal log {i}",
            source_ip="10.0.0.1", dest_ip="10.0.0.5",
            template_id=1,
            timestamp=datetime(2024, 1, 1, 10, i, 0, tzinfo=timezone.utc),
        )
        profiler.score(ev)

    # Signal 1+2: Night activity at an unusual hour
    ev_night = NormalizedEvent(
        log_original="night login", source_ip="10.0.0.1",
        template_id=1,
        timestamp=datetime(2024, 1, 2, 3, 0, 0, tzinfo=timezone.utc),
    )
    profiler.score(ev_night)
    logger.info("Night + Novel hour → suspicion=%.1f", ev_night.suspicion_delta)

    # Signal 3: New template
    ev_novel = NormalizedEvent(
        log_original="never seen before", source_ip="10.0.0.1",
        template_id=99,
        timestamp=datetime(2024, 1, 2, 10, 0, 0, tzinfo=timezone.utc),
    )
    profiler.score(ev_novel)
    logger.info("Novel template → suspicion=%.1f", ev_novel.suspicion_delta)

    # Signal 4: New destination
    ev_dest = NormalizedEvent(
        log_original="new dest", source_ip="10.0.0.1",
        dest_ip="10.0.0.99", template_id=1,
        timestamp=datetime(2024, 1, 2, 10, 5, 0, tzinfo=timezone.utc),
    )
    profiler.score(ev_dest)
    logger.info("Novel destination → suspicion=%.1f", ev_dest.suspicion_delta)

    logger.info("BaselineProfiler demo complete ✓")
