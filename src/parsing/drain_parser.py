"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/parsing/drain_parser.py

Thin wrapper around the Drain3 log-clustering library.  Drain3 takes a
raw log line, strips variable parts (IPs, timestamps, PIDs …), and
returns a stable **template ID + template string**.  Those template IDs
become the vocabulary that DeepLog and other sequence models consume
downstream.

Configuration knobs (``sim_th``, ``depth``, ``max_clusters``) are pulled
from ``settings.py`` — they are tuned for security logs (``sim_th=0.4``
is deliberately low so that similar-but-distinct attack variants each
receive their own cluster).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from src.config.settings import settings

# ── Logging ──────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)


# ── Result container ─────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class DrainResult:
    """
    Immutable container for a single Drain3 parse result.

    Attributes:
        template_id: Cluster / template identifier assigned by Drain3.
        template_str: The generalised template string with ``<*>``
            placeholders where variable tokens appeared.
        change_type: Drain3 change indicator — ``"cluster_created"``,
            ``"cluster_template_changed"``, ``"none"``, etc.
    """

    template_id: int
    template_str: str
    change_type: str


class DrainParser:
    """
    Stateful Drain3 log parser.

    Maintains an in-memory cluster state.  Thread safety is guaranteed
    by Drain3 internally; however, if you need cross-process persistence
    you should configure a ``PersistenceHandler`` (out of scope for
    Phase 1).

    Args (constructor):
        sim_th: Similarity threshold (default from settings).
        depth: Parse-tree depth (default from settings).
        max_clusters: Maximum number of template clusters.
    """

    def __init__(
        self,
        sim_th: Optional[float] = None,
        depth: Optional[int] = None,
        max_clusters: Optional[int] = None,
    ) -> None:
        self._sim_th = sim_th if sim_th is not None else settings.drain_sim_th
        self._depth = depth if depth is not None else settings.drain_depth
        self._max_clusters = (
            max_clusters if max_clusters is not None else settings.drain_max_clusters
        )

        config = TemplateMinerConfig()
        config.drain_sim_th = self._sim_th
        config.drain_depth = self._depth
        config.drain_max_clusters = self._max_clusters
        # Mask known variable patterns so they collapse to <*>
        config.masking_instructions = []

        self._miner = TemplateMiner(config=config)

        logger.info(
            "DrainParser initialised — sim_th=%.2f  depth=%d  max_clusters=%d",
            self._sim_th,
            self._depth,
            self._max_clusters,
        )

    # ── Public API ───────────────────────────────────────────────────

    def parse(self, log_line: str) -> DrainResult:
        """
        Feed a single log line into Drain3 and return the parse result.

        Args:
            log_line: Raw log line (should be stripped of leading/trailing
                whitespace by the caller).

        Returns:
            A ``DrainResult`` containing the template ID, template
            string, and change-type indicator.

        Raises:
            ValueError: If *log_line* is empty or whitespace-only.
        """
        if not log_line or not log_line.strip():
            raise ValueError("Cannot parse an empty or whitespace-only log line.")

        result = self._miner.add_log_message(log_line)
        cluster = result.get("cluster_id", -1)
        template = result.get("template_mined", "")
        change = result.get("change_type", "none")

        # Drain3 may return the cluster_id as a string in some versions
        cluster_id = int(cluster) if cluster is not None else -1

        parsed = DrainResult(
            template_id=cluster_id,
            template_str=template,
            change_type=str(change),
        )
        logger.debug(
            "Parsed → cluster=%d  change=%s  template='%s'",
            parsed.template_id,
            parsed.change_type,
            parsed.template_str,
        )
        return parsed

    @property
    def cluster_count(self) -> int:
        """
        Return the current number of template clusters.

        Returns:
            Number of clusters tracked by the Drain3 miner.
        """
        return len(self._miner.drain.clusters)

    def get_all_templates(self) -> list[dict]:
        """
        Return a list of all current template clusters for inspection.

        Returns:
            List of dicts, each with keys ``cluster_id`` and ``template``.
        """
        return [
            {"cluster_id": c.cluster_id, "template": c.get_template()}
            for c in self._miner.drain.clusters
        ]


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# ---------------------
# 1. Wraps Drain3 behind a clean API so the rest of AEGIS never
#    touches Drain3 internals directly.
# 2. Configures Drain3 with security-log-optimal parameters from
#    settings.py (sim_th=0.4, depth=4).
# 3. Produces template IDs that feed the DeepLog sequence model
#    downstream.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level="DEBUG")

    # ── Synthetic security log lines ─────────────────────────────────
    SAMPLE_LINES: list[str] = [
        "May  1 10:23:45 web01 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "May  1 10:23:46 web01 sshd[12346]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "May  1 10:23:47 web01 sshd[12347]: Failed password for admin from 10.0.0.55 port 22 ssh2",
        "May  1 10:24:01 web01 sshd[12348]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2",
        "May  1 10:25:00 db01 mysqld[5678]: Query 'SELECT * FROM users WHERE id=1 OR 1=1' executed by user webapp",
        "May  1 10:25:01 db01 mysqld[5679]: Query 'SELECT * FROM orders WHERE id=42 OR 1=1' executed by user webapp",
        "May  1 10:26:30 app01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.0.0.10 PROTO=TCP DPT=443",
        "May  1 10:26:31 app01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.157 DST=10.0.0.10 PROTO=TCP DPT=80",
    ]

    parser = DrainParser()

    logger.info("=" * 60)
    logger.info("DRAIN3 PARSING DEMO")
    logger.info("=" * 60)

    for line in SAMPLE_LINES:
        result = parser.parse(line)
        logger.info(
            "  cluster=%d  change=%-25s  template='%s'",
            result.template_id,
            result.change_type,
            result.template_str,
        )

    logger.info("-" * 60)
    logger.info("Total clusters: %d", parser.cluster_count)
    for tpl in parser.get_all_templates():
        logger.info("  [%d] %s", tpl["cluster_id"], tpl["template"])
    logger.info("Drain parser demo complete ✓")
