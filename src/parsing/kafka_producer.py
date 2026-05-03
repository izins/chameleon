"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/parsing/kafka_producer.py

Transport layer for Phase 1.  Reads raw log lines (from a live file via
watchdog or from a static test file), normalises each line through the
LogNormalizer, and pushes NormalizedEvents to Kafka (or to a local JSON
file in demo mode).

Supports two ingestion modes:
  a) Live tail (watchdog FileSystemEventHandler) — for production.
  b) Static file read — for offline demo / hackathon.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import List, Optional

from src.config.settings import settings, configure_logging
from src.parsing.models import LogSession, NormalizedEvent
from src.parsing.normalizer import LogNormalizer
from src.parsing.sessionizer import LogSessionizer
from src.parsing.baseline_profiler import BaselineProfiler
from src.ml.ml_detector import MLDetector
from src.enrichment.enrichment_engine import EnrichmentEngine
from src.enrichment.verification_gate import VerificationGate, VerificationResult
from src.response.iso27035_tracker import get_iso_tracker, ISOPhase

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────
MAX_RETRIES: int = settings.kafka_max_retries
RETRY_BASE: float = settings.kafka_retry_base_seconds


def _exponential_backoff(attempt: int) -> float:
    """Calculate exponential back-off delay.

    Args:
        attempt: Zero-based retry attempt number.

    Returns:
        Delay in seconds (base * 2^attempt).
    """
    return RETRY_BASE * (2 ** attempt)


# ── Demo-mode file writer (replaces Kafka) ───────────────────────────
class DemoFileWriter:
    """Writes NormalizedEvents to a local JSON-lines file.

    Used as a drop-in replacement for KafkaProducer when AEGIS_DEMO_MODE=true.

    Args:
        output_path: File path to write JSON lines to.
    """

    def __init__(self, output_path: str) -> None:
        self._path = Path(output_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("DemoFileWriter → %s", self._path)

    def send(self, event: NormalizedEvent) -> None:
        """Append a single event as a JSON line.

        Args:
            event: The normalised event to persist.
        """
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(event.model_dump_json() + "\n")

    def send_batch(self, events: List[NormalizedEvent]) -> None:
        """Append multiple events as JSON lines.

        Args:
            events: List of normalised events.
        """
        with open(self._path, "a", encoding="utf-8") as fh:
            for event in events:
                fh.write(event.model_dump_json() + "\n")
        logger.info("DemoFileWriter flushed %d events", len(events))


# ── Kafka producer wrapper ───────────────────────────────────────────
class AegisKafkaProducer:
    """Sends NormalizedEvents to Kafka with exponential back-off.

    In demo mode, delegates to DemoFileWriter instead.

    Args:
        topic: Kafka topic to produce to.
        demo_mode: Override demo-mode flag (defaults to settings).
    """

    def __init__(self, topic: Optional[str] = None,
                 demo_mode: Optional[bool] = None) -> None:
        self._topic = topic or settings.kafka_topic_normalized
        self._demo = demo_mode if demo_mode is not None else settings.demo_mode
        self._producer = None
        self._demo_writer: Optional[DemoFileWriter] = None

        if self._demo:
            self._demo_writer = DemoFileWriter(settings.demo_output_file)
            logger.info("AegisKafkaProducer running in DEMO mode")
        else:
            self._connect_kafka()

    def _connect_kafka(self) -> None:
        """Establish Kafka connection with exponential back-off.

        Raises:
            ConnectionError: If all retry attempts are exhausted.
        """
        from kafka import KafkaProducer as _KP  # noqa: late import

        for attempt in range(MAX_RETRIES):
            try:
                self._producer = _KP(
                    bootstrap_servers=settings.kafka_bootstrap_servers.split(","),
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    acks="all",
                    retries=3,
                )
                logger.info("Kafka producer connected on attempt %d", attempt + 1)
                return
            except Exception as exc:
                delay = _exponential_backoff(attempt)
                logger.warning("Kafka connect attempt %d failed: %s — retrying in %.1fs",
                               attempt + 1, exc, delay)
                time.sleep(delay)

        raise ConnectionError(
            f"Failed to connect to Kafka after {MAX_RETRIES} attempts "
            f"(brokers={settings.kafka_bootstrap_servers})"
        )

    def send(self, event: NormalizedEvent) -> None:
        """Publish a single NormalizedEvent.

        Args:
            event: The normalised event.

        Raises:
            ConnectionError: If Kafka is unreachable and not in demo mode.
        """
        payload = event.model_dump(mode="json")
        if self._demo and self._demo_writer:
            self._demo_writer.send(event)
        elif self._producer:
            self._producer.send(self._topic, value=payload)
            self._producer.flush()
        else:
            raise ConnectionError("No Kafka producer and not in demo mode.")

    def send_batch(self, events: List[NormalizedEvent]) -> None:
        """Publish multiple NormalizedEvents.

        Args:
            events: List of normalised events.
        """
        if self._demo and self._demo_writer:
            self._demo_writer.send_batch(events)
        elif self._producer:
            for event in events:
                self._producer.send(self._topic, value=event.model_dump(mode="json"))
            self._producer.flush()
            logger.info("Kafka batch of %d events flushed", len(events))
        else:
            raise ConnectionError("No Kafka producer and not in demo mode.")

    def close(self) -> None:
        """Flush and close the producer."""
        if self._producer:
            self._producer.flush()
            self._producer.close()
            logger.info("Kafka producer closed")


# ── File ingestion engine ────────────────────────────────────────────
class LogIngestionEngine:
    """Reads log files, normalises events, groups them into sessions
    by entity, and publishes LogSession objects.

    The pipeline is:
        raw line → LogNormalizer → NormalizedEvent → LogSessionizer
                                                          ↓
                                                     LogSession
                                                          ↓
                                            Kafka / DemoFileWriter

    Args:
        normalizer: LogNormalizer instance.
        producer: AegisKafkaProducer instance.
        sessionizer: LogSessionizer instance (creates default if None).
        host_name: Default host name for ingested logs.
        log_source: Default log source identifier.
    """

    def __init__(
        self,
        normalizer: LogNormalizer,
        producer: AegisKafkaProducer,
        sessionizer: Optional[LogSessionizer] = None,
        host_name: str = "unknown",
        log_source: str = "unknown",
    ) -> None:
        self._normalizer = normalizer
        self._producer = producer
        self._sessionizer = sessionizer or LogSessionizer()
        self._profiler = BaselineProfiler()
        self._host = host_name
        self._source = log_source

        # ── Phase 1.5 + Phase 2: ML Detection → Enrichment ──────────
        self._ml_detector = MLDetector()
        self._enrichment = EnrichmentEngine()
        self._gate = VerificationGate()
        self._verdicts: List[VerificationResult] = []
        self._iso_tracker = get_iso_tracker()

    def ingest_static_file(self, file_path: str) -> List[LogSession]:
        """Read a static log file, normalise, sessionize, and publish.

        Each line is normalised into a NormalizedEvent, then fed to the
        sessionizer.  When a session window closes (time or count limit),
        the completed LogSession is published immediately.  At the end,
        all remaining open windows are flushed.

        Args:
            file_path: Path to the log file.

        Returns:
            List of LogSession objects produced.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        sessions: List[LogSession] = []

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event = self._normalizer.normalize_line(
                        stripped, host=self._host, source=self._source
                    )
                    # ── Behavioral Scoring (UEBA) ────────────────────
                    event = self._profiler.score(event)
                    
                    closed_session = self._sessionizer.process_event(event)
                    if closed_session:
                        self._publish_session(closed_session)
                        sessions.append(closed_session)
                        self._run_ml_pipeline(closed_session)
                except Exception as exc:
                    logger.warning("Skipping line %d: %s", line_no, exc)

        # Flush any remaining open windows
        remaining = self._sessionizer.flush_all()
        for session in remaining:
            self._publish_session(session)
            sessions.append(session)
            self._run_ml_pipeline(session)

        logger.info(
            "Ingested %d sessions from %s (total events: %d)",
            len(sessions),
            file_path,
            sum(s.event_count for s in sessions),
        )
        return sessions

    def _publish_session(self, session: LogSession) -> None:
        """Publish a single LogSession via the producer.

        Args:
            session: The completed session to publish.
        """
        payload = session.model_dump(mode="json")
        if self._producer._demo and self._producer._demo_writer:
            with open(self._producer._demo_writer._path, "a", encoding="utf-8") as fh:
                fh.write(session.model_dump_json() + "\n")
        elif self._producer._producer:
            self._producer._producer.send(self._producer._topic, value=payload)
            self._producer._producer.flush()

    def _run_ml_pipeline(self, session: LogSession) -> None:
        """Run Phase 1.5 → Phase 2 on a completed session.

        Pipeline: LogSession → MLDetector → ModelAlert → EnrichmentEngine
                  → VerificationGate → VerificationResult

        ISO 27035 phases are automatically tracked:
          Phase 1 (Detection): ML alert generation
          Phase 2 (Assessment): Enrichment + Verification Gate

        Args:
            session: The completed LogSession from the sessionizer.
        """
        try:
            alert = self._ml_detector.detect(session)
            if alert is None:
                return

            # ── ISO 27035 Phase 1: Detection & Reporting ───────────
            iso_record = self._iso_tracker.create_incident(alert.source_host)
            iso_id = iso_record.incident_id

            self._iso_tracker.start_phase(iso_id, ISOPhase.DETECTION, {
                "source": f"ML Pipeline ({alert.model_source})",
                "session_id": session.session_id[:8],
                "event_count": session.event_count,
                "confidence": alert.confidence,
                "attack_type": alert.attack_type,
            }, module="ml_detector.py")

            self._iso_tracker.complete_phase(iso_id, ISOPhase.DETECTION, {
                "alert_id": alert.alert_id[:8],
                "attack_type": alert.attack_type,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "model_source": alert.model_source,
            }, requirements_met=[
                "Monitor information security events from multiple sources",
                "Correlate events to identify potential incidents",
            ])

            # ── ISO 27035 Phase 2: Assessment & Decision ───────────
            self._iso_tracker.start_phase(iso_id, ISOPhase.ASSESSMENT, {
                "alert_id": alert.alert_id[:8],
                "enrichment_sources": ["MITRE", "CVE", "EntityTracker", "EPSS", "KEV"],
            }, module="enrichment_engine.py + verification_gate.py")

            enriched = self._enrichment.enrich(alert)
            verdict = self._gate.evaluate(enriched)
            self._verdicts.append(verdict)

            self._iso_tracker.complete_phase(iso_id, ISOPhase.ASSESSMENT, {
                "gate_verdict": verdict.verdict.value,
                "gate_score": verdict.gate_score,
                "should_isolate": verdict.should_isolate,
                "mitre_techniques": enriched.mitre_techniques,
                "max_cvss": enriched.max_cvss,
                "epss_score": enriched.epss_score,
                "is_kev": enriched.is_kev,
                "asset_type": enriched.asset_type,
                "business_impact": enriched.business_impact,
                "entity_cumulative_score": enriched.entity_cumulative_score,
            }, requirements_met=[
                "Classify the incident by type and severity",
                "Assess business impact (confidentiality, integrity, availability)",
                "Verify the incident is not a false positive",
            ])

            self._iso_tracker.update_summary(
                iso_id,
                severity=alert.severity,
                attack_type=alert.attack_type,
                risk_score=enriched.initial_risk_score,
                risk_label="HIGH" if enriched.initial_risk_score > 60 else "MEDIUM",
            )

            # Store ISO record ID on the verdict for Phase 3 consumption
            verdict._iso_incident_id = iso_id

            logger.info(
                "PIPELINE COMPLETE ▶ entity=%s  verdict=%s  score=%.1f  "
                "isolate=%s  notify=%s  iso=%s",
                session.entity_id,
                verdict.verdict.value,
                verdict.gate_score,
                verdict.should_isolate,
                verdict.should_notify_engineer,
                iso_id[:8],
            )
        except Exception as exc:
            logger.error(
                "ML pipeline error for session %s: %s",
                session.session_id[:8], exc,
            )

    @property
    def verdicts(self) -> List[VerificationResult]:
        """All VerificationResults produced during this ingestion run."""
        return list(self._verdicts)


    def ingest_live(self, file_path: str) -> None:
        """Tail a log file using watchdog and publish new lines.

        This blocks indefinitely. Use Ctrl+C or signal to stop.

        Args:
            file_path: Path to the log file to tail.

        Raises:
            FileNotFoundError: If the file does not exist.
            ImportError: If watchdog is not installed.
        """
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler, FileModifiedEvent
        except ImportError as exc:
            raise ImportError("watchdog is required for live mode: pip install watchdog") from exc

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        engine = self

        class _TailHandler(FileSystemEventHandler):
            def __init__(self) -> None:
                super().__init__()
                self._position = path.stat().st_size

            def on_modified(self, event: FileModifiedEvent) -> None:
                if Path(event.src_path).resolve() != path.resolve():
                    return
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(self._position)
                    new_lines = fh.readlines()
                    self._position = fh.tell()
                for raw_line in new_lines:
                    stripped = raw_line.strip()
                    if not stripped:
                        continue
                    try:
                        # ── FULL PIPELINE (same as static) ───────
                        ev = engine._normalizer.normalize_line(
                            stripped, host=engine._host,
                            source=engine._source,
                        )
                        ev = engine._profiler.score(ev)
                        closed = engine._sessionizer.process_event(ev)
                        if closed:
                            engine._publish_session(closed)
                            engine._run_ml_pipeline(closed)
                    except Exception as exc:
                        logger.warning("Live ingestion error: %s", exc)

        observer = Observer()
        observer.schedule(_TailHandler(), str(path.parent), recursive=False)
        observer.start()
        logger.info("Live tail started on %s — press Ctrl+C to stop", file_path)
        try:
            while True:
                # Periodic flush of idle sessions
                expired = self._sessionizer.flush_expired()
                for session in expired:
                    self._publish_session(session)
                    self._run_ml_pipeline(session)
                time.sleep(1)
        except KeyboardInterrupt:
            # Flush remaining sessions on shutdown
            remaining = self._sessionizer.flush_all()
            for session in remaining:
                self._publish_session(session)
                self._run_ml_pipeline(session)
            observer.stop()
        observer.join()
        self._producer.close()
        logger.info("Live tail stopped")


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Transport layer — moves normalised events to Kafka (or file).
# 2. Supports live tail (watchdog) and static file ingestion.
# 3. Handles Kafka connection errors with exponential back-off.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    configure_logging()

    # Create synthetic multi-source log file
    demo_log_dir = Path(settings.fixtures_dir)
    demo_log_dir.mkdir(parents=True, exist_ok=True)
    demo_log = demo_log_dir / "sample_multi.log"
    demo_log.write_text("\n".join([
        # Same attacker (192.168.1.100) across auth + network logs
        "May  1 10:23:45 web01 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "May  1 10:23:46 web01 sshd[12346]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "May  1 10:23:47 web01 sshd[12347]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "May  1 10:23:50 web01 kernel[0]: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP DPT=443",
        "May  1 10:24:01 web01 sshd[12348]: Accepted publickey for root from 192.168.1.100 port 22 ssh2",
        # Different entity
        "May  1 10:23:48 web01 sshd[12350]: Failed password for admin from 10.0.0.55 port 22 ssh2",
        # External scanner
        "May  1 10:26:30 app01 kernel[0]: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.0.0.10 PROTO=TCP DPT=443",
    ]), encoding="utf-8")

    normalizer = LogNormalizer()
    producer = AegisKafkaProducer(demo_mode=True)
    engine = LogIngestionEngine(
        normalizer, producer, host_name="demo-host", log_source="mixed.log"
    )

    logger.info("=" * 70)
    logger.info("KAFKA PRODUCER DEMO — Full Pipeline (Parse → ML → Enrich → Verify)")
    logger.info("=" * 70)

    sessions = engine.ingest_static_file(str(demo_log))
    for s in sessions:
        logger.info("")
        logger.info("  SESSION %s", s.session_id[:8])
        logger.info("    Entity:     %s (%s)", s.entity_id, s.entity_type)
        logger.info("    Events:     %d", s.event_count)
        logger.info("    Templates:  %s  ← DeepLog input", s.template_sequence)
        logger.info("    Counts:     %s  ← LogLizer features", s.template_counts)
        logger.info("    Categories: %s", s.categories)

    # ── Show ML / Enrichment verdicts ────────────────────────────────
    logger.info("")
    logger.info("=" * 70)
    logger.info("ML VERDICTS — %d alerts produced", len(engine.verdicts))
    logger.info("=" * 70)
    for v in engine.verdicts:
        logger.info("")
        logger.info("  VERDICT: %s  (score=%.1f/10)", v.verdict.value, v.gate_score)
        logger.info("  Entity:  %s", v.entity_id)
        logger.info("  Isolate: %s  Notify: %s  Review: %s",
                     v.should_isolate, v.should_notify_engineer,
                     v.requires_human_review)
        for sig in v.signals:
            marker = "✓" if sig.passed else "✗"
            logger.info("    %s %s: %.1f/%.1f — %s",
                         marker, sig.name, sig.score, sig.max_score, sig.detail)

    output = Path(settings.demo_output_file)
    if output.exists():
        logger.info("Demo output → %s (%d bytes)", output, output.stat().st_size)

    producer.close()
    logger.info("Full pipeline demo complete ✓")

