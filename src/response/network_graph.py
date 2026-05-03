"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/response/network_graph.py

Builds an adjacency graph of the network from NetFlow data to
calculate propagation risk.

The graph answers: "If host X is compromised, how many high-value
assets can the attacker reach?"

In production: queries Elasticsearch NetFlow indices.
In demo mode: uses a synthetic network topology.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Set, Tuple

from src.config.settings import settings

logger = logging.getLogger(__name__)


# ── Asset criticality registry ───────────────────────────────────────
# In production, this comes from a CMDB or asset_registry.py
DEFAULT_CRITICALITY: int = 5
HIGH_VALUE_THRESHOLD: int = 7   # assets with criticality >= 7 are "high value"

_DEMO_ASSETS: Dict[str, Dict] = {
    "10.0.0.1":  {"role": "web_server",     "asset_type": "server",      "criticality": 6, "business_impact": "high",   "data_classification": "public",       "owner": "ops"},
    "10.0.0.5":  {"role": "app_server",     "asset_type": "server",      "criticality": 7, "business_impact": "high",   "data_classification": "internal",     "owner": "dev"},
    "10.0.0.10": {"role": "database",       "asset_type": "server",      "criticality": 9, "business_impact": "critical", "data_classification": "restricted",   "owner": "dba"},
    "10.0.0.20": {"role": "file_server",    "asset_type": "server",      "criticality": 8, "business_impact": "high",   "data_classification": "confidential", "owner": "ops"},
    "10.0.0.30": {"role": "monitoring",     "asset_type": "server",      "criticality": 4, "business_impact": "medium", "data_classification": "internal",     "owner": "ops"},
    "10.0.0.40": {"role": "jump_host",      "asset_type": "infrastructure","criticality": 7, "business_impact": "high",   "data_classification": "internal",     "owner": "sec"},
    "10.0.0.50": {"role": "backup_server",  "asset_type": "server",      "criticality": 8, "business_impact": "critical", "data_classification": "restricted",   "owner": "ops"},
    "192.168.1.10": {"role": "workstation", "asset_type": "workstation", "criticality": 3, "business_impact": "low",    "data_classification": "internal",     "owner": "hr"},
    "192.168.1.20": {"role": "workstation", "asset_type": "workstation", "criticality": 4, "business_impact": "medium", "data_classification": "confidential", "owner": "finance"},
    "10.0.0.254": {"role": "core_router",   "asset_type": "network",     "criticality": 10,"business_impact": "critical", "data_classification": "internal",     "owner": "neteng"},
}

# ── Demo network topology (adjacency list) ──────────────────────────
_DEMO_EDGES: List[Tuple[str, str]] = [
    ("10.0.0.1",  "10.0.0.5"),     # web → app
    ("10.0.0.1",  "10.0.0.30"),    # web → monitoring
    ("10.0.0.5",  "10.0.0.10"),    # app → database
    ("10.0.0.5",  "10.0.0.20"),    # app → file_server
    ("10.0.0.40", "10.0.0.5"),     # jump → app
    ("10.0.0.40", "10.0.0.10"),    # jump → database
    ("10.0.0.40", "10.0.0.50"),    # jump → backup
    ("10.0.0.20", "10.0.0.50"),    # file → backup
]


class NetworkGraph:
    """Adjacency graph of the network for propagation analysis.

    The graph is undirected — if A can reach B, B can reach A.

    Args:
        use_es: If True, query Elasticsearch for real NetFlow data.
    """

    def __init__(self, use_es: bool = False) -> None:
        self._adjacency: Dict[str, Set[str]] = {}
        self._assets: Dict[str, Dict] = dict(_DEMO_ASSETS)

        if use_es and not settings.demo_mode:
            self._load_from_elasticsearch()
        else:
            self._load_demo_topology()

        logger.info(
            "NetworkGraph ready — %d nodes, %d edges, %d high-value assets",
            len(self._adjacency),
            sum(len(v) for v in self._adjacency.values()) // 2,
            len(self.get_high_value_assets()),
        )

    def _load_demo_topology(self) -> None:
        """Build the graph from the demo edge list."""
        for src, dst in _DEMO_EDGES:
            self._add_edge(src, dst)

    def _load_from_elasticsearch(self) -> None:
        """Query ES NetFlow indices for real network topology.

        In production, this would query:
          GET /netflow-*/_search { aggs: { src_dst_pairs: ... } }
        """
        logger.info("ES NetFlow query not implemented — falling back to demo")
        self._load_demo_topology()

    def _add_edge(self, src: str, dst: str) -> None:
        """Add an undirected edge between two hosts."""
        self._adjacency.setdefault(src, set()).add(dst)
        self._adjacency.setdefault(dst, set()).add(src)

    def get_neighbors(self, host: str) -> Set[str]:
        """Get all hosts directly reachable from a given host.

        Args:
            host: The IP address.

        Returns:
            Set of neighbor IPs.
        """
        return self._adjacency.get(host, set())

    def get_reachable(self, host: str, max_depth: int = 3) -> Set[str]:
        """BFS to find all hosts reachable within max_depth hops.

        Args:
            host: The starting IP.
            max_depth: Maximum number of hops.

        Returns:
            Set of all reachable IPs (excluding the starting host).
        """
        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(host, 0)]

        while queue:
            current, depth = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            if depth < max_depth:
                for neighbor in self.get_neighbors(current):
                    if neighbor not in visited:
                        queue.append((neighbor, depth + 1))

        visited.discard(host)
        return visited

    def get_reachable_high_value(
        self, host: str, max_depth: int = 3,
    ) -> List[str]:
        """Find all high-value assets reachable from a compromised host.

        Args:
            host: The compromised host IP.
            max_depth: Maximum BFS depth.

        Returns:
            List of high-value asset IPs reachable from this host.
        """
        reachable = self.get_reachable(host, max_depth)
        return [
            ip for ip in reachable
            if self.get_asset_criticality(ip) >= HIGH_VALUE_THRESHOLD
        ]

    def get_asset_criticality(self, host: str) -> int:
        """Get the criticality score for a host.

        Args:
            host: The IP address.

        Returns:
            Criticality score (1-10). Returns DEFAULT_CRITICALITY if unknown.
        """
        asset = self._assets.get(host)
        return asset["criticality"] if asset else DEFAULT_CRITICALITY

    def get_asset_details(self, host: str) -> Dict:
        """Get the full context details of a host.

        Args:
            host: The IP address.

        Returns:
            Dictionary of asset attributes.
        """
        return self._assets.get(host, {
            "role": "unknown",
            "asset_type": "unknown",
            "criticality": DEFAULT_CRITICALITY,
            "business_impact": "unknown",
            "data_classification": "unknown",
            "owner": "unknown"
        })

    def get_high_value_assets(self) -> List[str]:
        """Get all high-value assets in the network.

        Returns:
            List of IPs with criticality >= HIGH_VALUE_THRESHOLD.
        """
        return [
            ip for ip, info in self._assets.items()
            if info["criticality"] >= HIGH_VALUE_THRESHOLD
        ]

    @property
    def node_count(self) -> int:
        """Number of nodes in the graph."""
        return len(self._adjacency)


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Calculates propagation_score: how many critical assets an attacker
#    can reach from the compromised host.
# 2. Feeds into the risk formula: score = cvss*0.4 + crit*0.3 + prop*0.3
# 3. In production, powered by Elasticsearch NetFlow data.
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os

    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    graph = NetworkGraph()

    logger.info("=" * 60)
    logger.info("NETWORK GRAPH DEMO — Propagation Analysis")
    logger.info("=" * 60)

    test_hosts = ["10.0.0.1", "10.0.0.40", "192.168.1.100"]
    for host in test_hosts:
        neighbors = graph.get_neighbors(host)
        reachable = graph.get_reachable(host)
        hv = graph.get_reachable_high_value(host)
        logger.info(
            "  %s → neighbors=%d  reachable=%d  high_value=%d  crit=%d",
            host, len(neighbors), len(reachable), len(hv),
            graph.get_asset_criticality(host),
        )
        if hv:
            logger.info("    HIGH-VALUE TARGETS: %s", hv)

    logger.info("NetworkGraph demo complete ✓")
