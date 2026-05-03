"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/config/settings.py

Central configuration for the entire AEGIS pipeline.  Every other module
imports its runtime knobs from here — Kafka brokers, topic names, Drain3
parameters, file paths, and feature flags.

The module uses ``pydantic-settings`` (Pydantic v2) so values are loaded
from environment variables **and** from an optional ``.env`` file.  No
hard-coded IPs, ports, or credentials exist anywhere else in the codebase.
"""

from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Logging setup ────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Project root (two levels up from this file) ─────────────────────
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent


# ── Enumerations ─────────────────────────────────────────────────────
class Severity(str, Enum):
    """Alert severity levels, ISO 22301-aligned."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class AttackType(str, Enum):
    """Known attack categories produced by the ML models."""

    SSH_BRUTEFORCE = "ssh_bruteforce"
    SQL_INJECTION = "sql_injection"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL = "data_exfil"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANOMALY_UNKNOWN = "anomaly_unknown"


class ModelSource(str, Enum):
    """ML model identifiers that may produce alerts."""

    DEEPLOG = "DeepLog"
    ISOLATION_FOREST = "IsolationForest"
    XGBOOST = "XGBoost"
    RULE_ENGINE = "RuleEngine"
    ENSEMBLE = "Ensemble"


class EventCategory(str, Enum):
    """ECS-style event categories for normalized logs."""

    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    DATABASE = "database"
    WEB = "web"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class EventAction(str, Enum):
    """ECS-style event actions for normalized logs."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    CONNECTION_ATTEMPT = "connection_attempt"
    CONNECTION_ACCEPTED = "connection_accepted"
    CONNECTION_DENIED = "connection_denied"
    PROCESS_START = "process_start"
    PROCESS_STOP = "process_stop"
    FILE_ACCESS = "file_access"
    FILE_MODIFY = "file_modify"
    QUERY_EXECUTE = "query_execute"
    PRIVILEGE_CHANGE = "privilege_change"
    UNKNOWN = "unknown"


# ── Main settings object ────────────────────────────────────────────
class AegisSettings(BaseSettings):
    """
    Single source of truth for every tuneable parameter in the AEGIS
    pipeline.  Values cascade: explicit env var → .env file → defaults.
    """

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Feature flags ────────────────────────────────────────────────
    demo_mode: bool = Field(
        default=False,
        description="When True, replace all external I/O with local stubs.",
    )
    dry_run: bool = Field(
        default=False,
        description="When True, isolation actions are logged but not executed.",
    )

    # ── Kafka ────────────────────────────────────────────────────────
    kafka_bootstrap_servers: str = Field(
        default="localhost:9092",
        description="Comma-separated Kafka broker list.",
    )
    kafka_topic_normalized: str = Field(
        default="normalized-events",
        description="Topic for normalised ECS events.",
    )
    kafka_topic_alerts: str = Field(
        default="model-alerts",
        description="Topic for ML-generated alerts.",
    )
    kafka_topic_enriched: str = Field(
        default="enriched-alerts",
        description="Topic for enriched alerts heading to Phase 3.",
    )
    kafka_consumer_group: str = Field(
        default="aegis-pipeline",
        description="Kafka consumer group ID.",
    )
    kafka_max_retries: int = Field(
        default=5,
        description="Maximum connection retry attempts.",
    )
    kafka_retry_base_seconds: float = Field(
        default=2.0,
        description="Base delay for exponential back-off (seconds).",
    )

    # ── Drain3 ───────────────────────────────────────────────────────
    drain_sim_th: float = Field(
        default=0.4,
        description="Drain3 similarity threshold for security logs.",
    )
    drain_depth: int = Field(
        default=4,
        description="Drain3 tree depth.",
    )
    drain_max_clusters: int = Field(
        default=1024,
        description="Maximum template clusters.",
    )

    # ── Paths ────────────────────────────────────────────────────────
    demo_output_file: str = Field(
        default=str(PROJECT_ROOT / "data" / "demo_normalized.json"),
        description="File path used as Kafka substitute in demo mode.",
    )
    demo_alert_file: str = Field(
        default=str(PROJECT_ROOT / "data" / "demo_alerts.json"),
        description="File path for demo alert data.",
    )
    fixtures_dir: str = Field(
        default=str(PROJECT_ROOT / "data" / "fixtures"),
        description="Directory containing synthetic fixtures.",
    )
    log_level: str = Field(
        default="INFO",
        description="Root logging level.",
    )

    # ── Elasticsearch ────────────────────────────────────────────────
    es_hosts: List[str] = Field(
        default=["http://localhost:9200"],
        description="Elasticsearch host list.",
    )

    # ── Blockchain / SQLite ──────────────────────────────────────────
    chain_db_path: str = Field(
        default=str(PROJECT_ROOT / "data" / "chain.db"),
        description="Path to the immutable blockchain SQLite DB.",
    )

    # ── NVD API ──────────────────────────────────────────────────────
    nvd_api_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD CVE API v2 base URL.",
    )
    nvd_cache_ttl_hours: int = Field(
        default=24,
        description="How long to cache NVD responses (hours).",
    )


# ── Module-level singleton ───────────────────────────────────────────
settings = AegisSettings()


def configure_logging() -> None:
    """
    Apply the global log level from settings to the root logger.

    Call this once at process startup so every ``logging.getLogger()``
    across the project inherits the configured level.
    """
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    logger.info(
        "AEGIS logging configured — level=%s  demo_mode=%s  dry_run=%s",
        settings.log_level,
        settings.demo_mode,
        settings.dry_run,
    )


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# ---------------------
# 1. Single source of truth — every tuneable knob lives here.
# 2. pydantic-settings validates types and loads from env / .env.
# 3. Enums prevent magic strings from leaking into business logic.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    configure_logging()
    logger.info("Settings dump ↓")
    for key, value in settings.model_dump().items():
        logger.info("  %-30s = %s", key, value)
    logger.info("PROJECT_ROOT = %s", PROJECT_ROOT)
    logger.info("All enums:")
    for enum_cls in (Severity, AttackType, ModelSource, EventCategory, EventAction):
        logger.info("  %s → %s", enum_cls.__name__, [e.value for e in enum_cls])
