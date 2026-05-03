"""AEGIS — Phase 1 test suite (with sessionization tests)."""
from __future__ import annotations
import json, os
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

os.environ["AEGIS_DEMO_MODE"] = "true"

from src.config.settings import AttackType, EventAction, EventCategory, ModelSource, Severity, settings
from src.parsing.drain_parser import DrainParser, DrainResult
from src.parsing.kafka_producer import AegisKafkaProducer, DemoFileWriter, LogIngestionEngine
from src.parsing.models import ModelAlert, NormalizedEvent, RawLogEvent, LogSession
from src.parsing.normalizer import LogNormalizer
from src.parsing.sessionizer import LogSessionizer, EntityKeyStrategy

class TestSettings:
    def test_severity_enum_values(self): assert set(s.value for s in Severity) == {"P1","P2","P3","P4"}
    def test_attack_type_has_six(self): assert len(AttackType) == 6
    def test_model_source_has_five(self): assert len(ModelSource) == 5
    def test_demo_mode(self): assert os.environ.get("AEGIS_DEMO_MODE","").lower() == "true"
    def test_drain_defaults(self): assert settings.drain_sim_th == 0.4; assert settings.drain_depth == 4
    def test_event_category(self):
        assert set(e.value for e in EventCategory) == {"authentication","network","process","file","database","web","system","unknown"}
    def test_event_action(self):
        actions = {e.value for e in EventAction}
        assert "login_failure" in actions and "login_success" in actions

class TestRawLogEvent:
    def test_defaults(self):
        r = RawLogEvent(raw_line="test"); assert r.host_name == "unknown"; assert r.ingestion_ts.tzinfo is not None
    def test_empty_rejected(self):
        with pytest.raises(Exception): RawLogEvent(raw_line="")
    def test_naive_utc(self):
        r = RawLogEvent(raw_line="t", ingestion_ts=datetime(2024,1,1,12,0,0)); assert r.ingestion_ts.tzinfo is not None

class TestNormalizedEvent:
    def test_hash(self):
        e = NormalizedEvent(log_original="test").compute_hash(); assert len(e.event_hash)==64
    def test_deterministic(self):
        a = NormalizedEvent(log_original="x").compute_hash(); b = NormalizedEvent(log_original="x").compute_hash()
        assert a.event_hash == b.event_hash
    def test_different(self):
        a = NormalizedEvent(log_original="A").compute_hash(); b = NormalizedEvent(log_original="B").compute_hash()
        assert a.event_hash != b.event_hash
    def test_uuid_unique(self):
        assert NormalizedEvent(log_original="a").event_id != NormalizedEvent(log_original="b").event_id
    def test_roundtrip(self):
        e = NormalizedEvent(log_original="t", source_ip="1.2.3.4", event_category=EventCategory.NETWORK).compute_hash()
        r = NormalizedEvent(**json.loads(e.model_dump_json())); assert r.event_hash == e.event_hash

class TestModelAlert:
    def test_defaults(self): a = ModelAlert(); assert a.severity=="P4"
    def test_full(self):
        a = ModelAlert(severity="P1",attack_type="ssh_bruteforce",confidence=0.95,source_host="10.0.0.1",
                       affected_assets=["a","b"],event_hashes=["h"],model_source="DeepLog",
                       raw_sequence=[1,2],anomaly_score=-0.5,xgb_proba={"a":0.9})
        assert len(a.affected_assets)==2
    def test_bounds(self):
        with pytest.raises(Exception): ModelAlert(confidence=1.5)

class TestDrainParser:
    def test_basic(self):
        r = DrainParser().parse("Test line 12345"); assert isinstance(r, DrainResult); assert r.template_id >= 0
    def test_empty_raises(self):
        with pytest.raises(ValueError): DrainParser().parse("")
    def test_same_cluster(self):
        p = DrainParser()
        r1 = p.parse("Failed password for root from 1.1.1.1 port 22 ssh2")
        r2 = p.parse("Failed password for root from 2.2.2.2 port 22 ssh2")
        assert r1.template_id == r2.template_id

class TestLogNormalizer:
    @pytest.fixture
    def n(self): return LogNormalizer()
    def test_ssh_fail(self, n):
        e = n.normalize_line("May  1 10:23:45 web01 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2", host="web01")
        assert e.event_category == EventCategory.AUTHENTICATION
        assert e.event_action == EventAction.LOGIN_FAILURE
        assert e.source_ip == "192.168.1.100" and e.username == "root"
    def test_ssh_ok(self, n):
        e = n.normalize_line("May  1 10:24:01 web01 sshd[1]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2")
        assert e.event_action == EventAction.LOGIN_SUCCESS
    def test_ufw(self, n):
        e = n.normalize_line("May  1 10:26:30 app01 kernel[0]: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.0.0.10 PROTO=TCP DPT=443")
        assert e.event_category == EventCategory.NETWORK and e.source_ip == "45.33.32.156"
    def test_mysql(self, n):
        e = n.normalize_line("May  1 10:25:00 db01 mysqld[5678]: Query 'SELECT 1' executed by user webapp")
        assert e.event_category == EventCategory.DATABASE and e.username == "webapp"

class TestLogSession:
    def test_session_fields(self):
        s = LogSession(entity_id="1.1.1.1", template_sequence=[1,2,3], template_counts={"1":2,"2":1}, total_suspicion=5.0)
        assert s.entity_id == "1.1.1.1" and s.total_suspicion == 5.0

class TestBaselineProfiler:
    def test_temporal_anomaly(self):
        from src.parsing.baseline_profiler import BaselineProfiler
        bp = BaselineProfiler()
        # 3 AM is suspicious (night penalty)
        ts = datetime(2024, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
        ev = NormalizedEvent(log_original="test", source_ip="1.2.3.4", timestamp=ts)
        ev = bp.score(ev)
        assert ev.suspicion_delta >= 2.0

    def test_novelty_template(self):
        from src.parsing.baseline_profiler import BaselineProfiler
        bp = BaselineProfiler()
        # Fill baseline with 12 events
        for i in range(12):
            ev = NormalizedEvent(log_original="normal", source_ip="5.5.5.5", template_id=1)
            bp.score(ev)
        # New template should be suspicious
        ev_new = NormalizedEvent(log_original="weird", source_ip="5.5.5.5", template_id=99)
        ev_new = bp.score(ev_new)
        assert ev_new.suspicion_delta >= 4.0

    def test_novelty_destination(self):
        from src.parsing.baseline_profiler import BaselineProfiler
        bp = BaselineProfiler()
        # Build baseline with known destination
        for i in range(12):
            ev = NormalizedEvent(
                log_original="normal", source_ip="6.6.6.6",
                dest_ip="10.0.0.5", template_id=1,
            )
            bp.score(ev)
        # New destination should trigger
        ev_new = NormalizedEvent(
            log_original="new dest", source_ip="6.6.6.6",
            dest_ip="10.0.0.99", template_id=1,
        )
        ev_new = bp.score(ev_new)
        assert ev_new.suspicion_delta >= 2.0

    def test_novel_hour(self):
        from src.parsing.baseline_profiler import BaselineProfiler
        bp = BaselineProfiler()
        # Build baseline at hour 10 (12 events)
        for i in range(12):
            ev = NormalizedEvent(
                log_original="normal", source_ip="7.7.7.7", template_id=1,
                timestamp=datetime(2024, 1, 1, 10, i, 0, tzinfo=timezone.utc),
            )
            bp.score(ev)
        # Activity at hour 22 (never seen) — not a night hour, but novel
        ev_late = NormalizedEvent(
            log_original="late", source_ip="7.7.7.7", template_id=1,
            timestamp=datetime(2024, 1, 2, 22, 0, 0, tzinfo=timezone.utc),
        )
        ev_late = bp.score(ev_late)
        assert ev_late.suspicion_delta >= 3.0

    def test_no_suspicion_for_normal(self):
        from src.parsing.baseline_profiler import BaselineProfiler
        bp = BaselineProfiler()
        # Build baseline
        for i in range(12):
            ev = NormalizedEvent(
                log_original="normal", source_ip="8.8.8.8", template_id=1,
                dest_ip="10.0.0.5",
                timestamp=datetime(2024, 1, 1, 10, i, 0, tzinfo=timezone.utc),
            )
            bp.score(ev)
        # Same pattern should NOT trigger
        ev_same = NormalizedEvent(
            log_original="still normal", source_ip="8.8.8.8", template_id=1,
            dest_ip="10.0.0.5",
            timestamp=datetime(2024, 1, 2, 10, 5, 0, tzinfo=timezone.utc),
        )
        ev_same = bp.score(ev_same)
        assert ev_same.suspicion_delta == 0.0

class TestLogSessionizer:
    def test_groups_same_ip(self):
        sz = LogSessionizer(window_seconds=300, max_events=3)
        base = datetime.now(timezone.utc)
        e1 = NormalizedEvent(log_original="E1", source_ip="1.1.1.1", timestamp=base, template_id=10).compute_hash()
        e2 = NormalizedEvent(log_original="E2", source_ip="1.1.1.1", timestamp=base+timedelta(seconds=1), template_id=20).compute_hash()
        e3 = NormalizedEvent(log_original="E3", source_ip="1.1.1.1", timestamp=base+timedelta(seconds=2), template_id=30).compute_hash()
        assert sz.process_event(e1) is None
        assert sz.process_event(e2) is None
        assert sz.process_event(e3) is None  # 3 buffered, not yet closed
        # 4th event triggers close (buffer had 3 >= max_events)
        e4 = NormalizedEvent(log_original="E4", source_ip="1.1.1.1", timestamp=base+timedelta(seconds=3), template_id=40).compute_hash()
        session = sz.process_event(e4)
        assert session is not None
        assert session.entity_id == "1.1.1.1"
        assert session.template_sequence == [10, 20, 30]
        assert session.event_count == 3

    def test_separates_entities(self):
        sz = LogSessionizer(window_seconds=300, max_events=100)
        e1 = NormalizedEvent(log_original="A", source_ip="1.1.1.1", template_id=1).compute_hash()
        e2 = NormalizedEvent(log_original="B", source_ip="2.2.2.2", template_id=2).compute_hash()
        sz.process_event(e1); sz.process_event(e2)
        assert sz.active_entity_count == 2
        sessions = sz.flush_all()
        assert len(sessions) == 2
        ids = {s.entity_id for s in sessions}
        assert ids == {"1.1.1.1", "2.2.2.2"}

    def test_cross_source_correlation(self):
        """Events from auth.log and kern.log for same IP → one session."""
        norm = LogNormalizer()
        sz = LogSessionizer(window_seconds=300, max_events=100)
        lines = [
            "May  1 10:23:45 w1 sshd[1]: Failed password for root from 5.5.5.5 port 22 ssh2",
            "May  1 10:23:50 w1 kernel[0]: [UFW BLOCK] IN=eth0 OUT= SRC=5.5.5.5 DST=10.0.0.1 PROTO=TCP DPT=443",
        ]
        for l in lines:
            ev = norm.normalize_line(l, host="w1", source="mixed")
            sz.process_event(ev)
        sessions = sz.flush_all()
        assert len(sessions) == 1
        s = sessions[0]
        assert s.entity_id == "5.5.5.5"
        assert s.event_count == 2
        assert "authentication" in s.categories and "network" in s.categories
        assert len(s.template_sequence) == 2

    def test_template_counts(self):
        sz = LogSessionizer(window_seconds=300, max_events=100)
        base = datetime.now(timezone.utc)
        for i in range(3):
            e = NormalizedEvent(log_original=f"L{i}", source_ip="9.9.9.9", timestamp=base+timedelta(seconds=i), template_id=42).compute_hash()
            sz.process_event(e)
        sessions = sz.flush_all()
        assert sessions[0].template_counts.get(42) == 3

    def test_flush_expired(self):
        sz = LogSessionizer(window_seconds=1, max_events=100)
        e = NormalizedEvent(log_original="X", source_ip="7.7.7.7", timestamp=datetime(2020,1,1,tzinfo=timezone.utc)).compute_hash()
        sz.process_event(e)
        expired = sz.flush_expired(now=datetime.now(timezone.utc))
        assert len(expired) == 1

class TestIngestionEngine:
    def test_static_produces_sessions(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("\n".join([
            "May  1 10:23:45 w sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
            "May  1 10:23:46 w sshd[2]: Failed password for root from 1.2.3.4 port 22 ssh2",
            "May  1 10:26:30 w kernel[0]: [UFW BLOCK] IN=eth0 OUT= SRC=5.5.5.5 DST=6.6.6.6 PROTO=TCP DPT=443",
        ]), encoding="utf-8")
        n = LogNormalizer(); p = AegisKafkaProducer(demo_mode=True)
        eng = LogIngestionEngine(n, p, host_name="t", log_source="t.log")
        sessions = eng.ingest_static_file(str(log))
        assert len(sessions) >= 1
        assert all(isinstance(s, LogSession) for s in sessions)
        total_events = sum(s.event_count for s in sessions)
        assert total_events == 3

    def test_missing_file(self, tmp_path):
        n = LogNormalizer(); p = AegisKafkaProducer(demo_mode=True)
        with pytest.raises(FileNotFoundError):
            LogIngestionEngine(n, p).ingest_static_file(str(tmp_path / "nope.log"))

class TestDemoFileWriter:
    def test_write(self, tmp_path):
        w = DemoFileWriter(str(tmp_path / "o.jsonl"))
        w.send(NormalizedEvent(log_original="t").compute_hash())
        assert len((tmp_path / "o.jsonl").read_text().strip().split("\n")) == 1

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
