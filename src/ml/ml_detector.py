"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/ml/ml_detector.py

Phase 1.5 — ML Detection Bridge.

Takes a LogSession (output of Phase 1 / Sessionizer) and runs two
pre-trained models in sequence:

  1. LSTM Anomaly Detector
     - Input:  template_sequence (padded/truncated to SEQ_LEN=10)
     - Output: anomaly probability [0..1]
     - Purpose: Detects behavioural anomalies in the log sequence that
       rule-based systems miss (novel attack patterns, timing shifts).

  2. XGBoost Attack Classifier
     - Input:  same template_sequence as a flat feature vector
     - Output: multi-class attack label + per-class probabilities
     - Purpose: Classifies the type of attack for targeted response
       (bruteforce, malware_beacon, scan, data_exfiltration, normal).

Decision logic:
  - If LSTM says anomalous (prob ≥ threshold) OR XGBoost says non-normal
    → emit a ModelAlert with ensemble metadata.
  - The ModelAlert becomes the input for Phase 2 (EnrichmentEngine).
  - When both models agree, model_source="Ensemble" which gives higher
    weight in the VerificationGate's cross-model consensus check.

Model files are loaded from the ``fwdatest/`` directory (the same
weights produced by ``train_ia.py``).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import torch
import torch.nn as nn

from src.config.settings import settings, PROJECT_ROOT
from src.parsing.models import LogSession, ModelAlert

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────
SEQ_LEN: int = 10                   # Sequence length the models were trained on
LSTM_ANOMALY_THRESHOLD: float = 0.70  # LSTM probability ≥ this → anomalous
XGB_CONFIDENCE_FLOOR: float = 0.45    # Minimum XGB class probability to trust

# Model file paths (relative to project root)
LSTM_MODEL_PATH: Path = PROJECT_ROOT / "fwdatest" / "lstm_model.pth"
XGB_MODEL_PATH: Path = PROJECT_ROOT / "fwdatest" / "xgb_attack_model.json"

# XGBoost label mapping (must match train_ia.py)
XGB_LABEL_MAP: Dict[int, str] = {
    0: "normal",
    1: "ssh_bruteforce",
    2: "anomaly_unknown",       # malware_beacon → anomaly_unknown in AEGIS taxonomy
    3: "anomaly_unknown",       # scan → anomaly_unknown
    4: "data_exfil",
}

XGB_LABEL_NAMES: Dict[int, str] = {
    0: "normal",
    1: "bruteforce",
    2: "malware_beacon",
    3: "scan",
    4: "data_exfiltration",
}

# Severity mapping per attack class
SEVERITY_MAP: Dict[int, str] = {
    0: "P4",                    # normal — lowest severity
    1: "P3",                    # bruteforce
    2: "P2",                    # malware_beacon
    3: "P3",                    # scan
    4: "P1",                    # data_exfiltration — critical
}


# ── LSTM Architecture (must mirror train_ia.py exactly) ──────────────
class LSTMDetector(nn.Module):
    """LSTM-based anomaly detector.

    Architecture matches ``fwdatest/train_ia.py`` exactly so that the
    saved state_dict loads cleanly.

    Args:
        input_size: Feature dimension per timestep (1 = template ID).
        hidden_size: LSTM hidden units.
    """

    def __init__(self, input_size: int = 1, hidden_size: int = 64) -> None:
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=2,
            batch_first=True,
            dropout=0.2,
        )
        self.fc = nn.Sequential(
            nn.Linear(hidden_size, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: Tensor of shape (batch, seq_len, 1).

        Returns:
            Anomaly probability tensor of shape (batch,).
        """
        out, _ = self.lstm(x)
        out = out[:, -1, :]   # last timestep
        out = self.fc(out)
        return out.squeeze()


# ── Main ML Detector ─────────────────────────────────────────────────
class MLDetector:
    """Dual-model ML detector that bridges Phase 1 → Phase 2.

    Loads the pre-trained LSTM and XGBoost models, runs inference on
    each LogSession, and produces a ModelAlert when anomalous activity
    is detected.

    Usage::

        detector = MLDetector()
        alert = detector.detect(session)
        if alert:
            enriched = enrichment_engine.enrich(alert)
    """

    def __init__(self) -> None:
        self._lstm: Optional[LSTMDetector] = None
        self._xgb = None
        self._lstm_available = False
        self._xgb_available = False

        self._load_lstm()
        self._load_xgboost()

        logger.info(
            "MLDetector ready — LSTM=%s  XGBoost=%s",
            "loaded" if self._lstm_available else "UNAVAILABLE",
            "loaded" if self._xgb_available else "UNAVAILABLE",
        )

    # ── Model loading ────────────────────────────────────────────────

    def _load_lstm(self) -> None:
        """Load the LSTM model weights from disk."""
        if not LSTM_MODEL_PATH.exists():
            logger.warning("LSTM model not found at %s — LSTM detection disabled", LSTM_MODEL_PATH)
            return
        try:
            self._lstm = LSTMDetector()
            self._lstm.load_state_dict(
                torch.load(LSTM_MODEL_PATH, map_location="cpu", weights_only=True)
            )
            self._lstm.eval()
            self._lstm_available = True
            logger.info("LSTM model loaded from %s", LSTM_MODEL_PATH)
        except Exception as exc:
            logger.error("Failed to load LSTM model: %s", exc)
            self._lstm = None

    def _load_xgboost(self) -> None:
        """Load the XGBoost model from disk."""
        if not XGB_MODEL_PATH.exists():
            logger.warning("XGBoost model not found at %s — XGBoost detection disabled", XGB_MODEL_PATH)
            return
        try:
            from xgboost import XGBClassifier
            self._xgb = XGBClassifier()
            self._xgb.load_model(str(XGB_MODEL_PATH))
            self._xgb_available = True
            logger.info("XGBoost model loaded from %s", XGB_MODEL_PATH)
        except Exception as exc:
            logger.error("Failed to load XGBoost model: %s", exc)
            self._xgb = None

    # ── Sequence preparation ─────────────────────────────────────────

    @staticmethod
    def _prepare_sequence(template_sequence: List[int]) -> List[float]:
        """Pad or truncate a template sequence to SEQ_LEN.

        If the session has fewer than SEQ_LEN template IDs, the sequence
        is zero-padded on the left.  If longer, only the last SEQ_LEN
        elements are kept (most recent activity is most relevant).

        Args:
            template_sequence: Raw template ID sequence from LogSession.

        Returns:
            Float list of exactly SEQ_LEN elements.
        """
        seq = [float(t) for t in template_sequence]
        if len(seq) >= SEQ_LEN:
            return seq[-SEQ_LEN:]           # truncate: keep tail
        return [0.0] * (SEQ_LEN - len(seq)) + seq  # pad: prepend zeros

    # ── LSTM inference ───────────────────────────────────────────────

    def _run_lstm(self, sequence: List[float]) -> float:
        """Run LSTM inference on a prepared sequence.

        Args:
            sequence: Float list of length SEQ_LEN.

        Returns:
            Anomaly probability in [0, 1].
        """
        if not self._lstm_available or self._lstm is None:
            return 0.0
        tensor = torch.tensor([sequence], dtype=torch.float32).unsqueeze(-1)
        with torch.no_grad():
            prob = self._lstm(tensor).item()
        return prob

    # ── XGBoost inference ────────────────────────────────────────────

    def _run_xgboost(self, sequence: List[float]) -> tuple[int, Dict[str, float]]:
        """Run XGBoost inference on a prepared sequence.

        Args:
            sequence: Float list of length SEQ_LEN.

        Returns:
            Tuple of (predicted_class, probability_dict).
            probability_dict maps readable attack names to probabilities.
        """
        if not self._xgb_available or self._xgb is None:
            return 0, {"normal": 1.0}
        X = np.array([sequence])
        pred_class = int(self._xgb.predict(X)[0])
        pred_proba = self._xgb.predict_proba(X)[0]

        proba_dict: Dict[str, float] = {}
        for idx, prob in enumerate(pred_proba):
            label_name = XGB_LABEL_NAMES.get(idx, f"class_{idx}")
            proba_dict[label_name] = round(float(prob), 4)

        return pred_class, proba_dict

    # ── Main detection entry point ───────────────────────────────────

    def detect(self, session: LogSession) -> Optional[ModelAlert]:
        """Run dual-model detection on a LogSession.

        Decision matrix:
          - LSTM anomalous + XGBoost non-normal → ENSEMBLE alert (highest trust)
          - LSTM anomalous + XGBoost normal     → LSTM-only alert
          - LSTM normal    + XGBoost non-normal  → XGBoost-only alert
          - Both normal                          → None (no alert)

        Args:
            session: A complete LogSession from the Sessionizer.

        Returns:
            A ModelAlert if anomalous activity is detected, else None.
        """
        if not self._lstm_available and not self._xgb_available:
            logger.warning("No ML models available — skipping detection")
            return None

        # Prepare the input sequence
        sequence = self._prepare_sequence(session.template_sequence)

        # ── Run both models ──────────────────────────────────────────
        lstm_prob = self._run_lstm(sequence)
        xgb_class, xgb_proba = self._run_xgboost(sequence)

        lstm_anomalous = lstm_prob >= LSTM_ANOMALY_THRESHOLD
        
        xgb_anomalous = False
        xgb_top_prob = max(xgb_proba.values()) if xgb_proba else 0.0
        if xgb_class != 0 and xgb_top_prob >= XGB_CONFIDENCE_FLOOR:
            xgb_anomalous = True

        logger.debug(
            "ML detection for entity=%s — LSTM=%.3f(%s)  XGB=%s(%s)  seq=%s",
            session.entity_id,
            lstm_prob,
            "ANOMALY" if lstm_anomalous else "normal",
            XGB_LABEL_NAMES.get(xgb_class, "?"),
            "ANOMALY" if xgb_anomalous else "normal",
            session.template_sequence[:10],
        )

        # ── Decision: do we emit an alert? ───────────────────────────
        if not lstm_anomalous and not xgb_anomalous:
            return None     # Both models say normal → no alert

        # ── Determine model source and confidence ────────────────────
        if lstm_anomalous and xgb_anomalous:
            model_source = "Ensemble"
            # Ensemble confidence: weighted average (LSTM 40%, XGB 60%)
            xgb_top_prob = max(xgb_proba.values()) if xgb_proba else 0.5
            confidence = round(0.4 * lstm_prob + 0.6 * xgb_top_prob, 4)
        elif lstm_anomalous:
            model_source = "DeepLog"       # LSTM acts as DeepLog in AEGIS
            confidence = round(lstm_prob, 4)
        else:
            model_source = "XGBoost"
            xgb_top_prob = max(xgb_proba.values()) if xgb_proba else 0.5
            confidence = round(xgb_top_prob, 4)

        # ── Determine attack type ────────────────────────────────────
        if xgb_anomalous:
            attack_type = XGB_LABEL_MAP.get(xgb_class, "anomaly_unknown")
        else:
            attack_type = "anomaly_unknown"

        # ── Determine severity ───────────────────────────────────────
        if xgb_anomalous:
            severity = SEVERITY_MAP.get(xgb_class, "P4")
        else:
            # LSTM-only anomaly: severity based on probability
            severity = "P2" if lstm_prob >= 0.85 else "P3"

        # Boost severity if both models agree and suspicion is high
        if model_source == "Ensemble" and session.total_suspicion > 5.0:
            severity_upgrade = {"P4": "P3", "P3": "P2", "P2": "P1"}
            severity = severity_upgrade.get(severity, severity)

        # ── Build anomaly_score (IsolationForest convention: [-1, 0]) ─
        anomaly_score = round(-lstm_prob, 2)
        anomaly_score = max(-1.0, min(0.0, anomaly_score))

        # ── Affected assets (all destination IPs from the session) ───
        affected_assets = session.dest_ips if session.dest_ips else session.source_ips

        alert = ModelAlert(
            severity=severity,
            attack_type=attack_type,
            confidence=confidence,
            source_host=session.entity_id,
            affected_assets=affected_assets,
            event_hashes=session.event_hashes,
            model_source=model_source,
            raw_sequence=session.template_sequence,
            anomaly_score=anomaly_score,
            xgb_proba=xgb_proba,
        )

        logger.info(
            "ML ALERT ▶ entity=%s  attack=%s  severity=%s  confidence=%.2f  "
            "model=%s  lstm=%.3f  xgb=%s  suspicion=%.1f",
            session.entity_id,
            attack_type,
            severity,
            confidence,
            model_source,
            lstm_prob,
            XGB_LABEL_NAMES.get(xgb_class, "?"),
            session.total_suspicion,
        )
        return alert


# ═══════════════════════════════════════════════════════════════════════
# WHY THIS FILE EXISTS
# 1. Bridges Phase 1 (LogSession) → Phase 2 (ModelAlert) using the
#    pre-trained LSTM and XGBoost models from fwdatest/.
# 2. LSTM detects sequence anomalies; XGBoost classifies attack type.
# 3. Ensemble agreement (both models flag) triggers highest confidence
#    and sets model_source="Ensemble" for the VerificationGate's
#    cross-model consensus check.
# 4. Handles missing models gracefully (degrades to single-model).
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    os.environ.setdefault("AEGIS_DEMO_MODE", "true")
    logging.basicConfig(level="DEBUG")

    from datetime import datetime, timezone

    detector = MLDetector()

    logger.info("=" * 70)
    logger.info("ML DETECTOR DEMO — LSTM + XGBoost dual-model inference")
    logger.info("=" * 70)

    # Simulate a suspicious session (brute-force pattern)
    suspicious_session = LogSession(
        entity_id="192.168.1.100",
        entity_type="source_ip",
        start_ts=datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        end_ts=datetime(2024, 1, 1, 10, 5, 0, tzinfo=timezone.utc),
        event_count=10,
        template_sequence=[1, 1, 1, 1, 1, 1, 2, 3, 1, 4],  # repeated failures
        total_suspicion=8.0,
        template_counts={"1": 7, "2": 1, "3": 1, "4": 1},
        event_hashes=["aaa", "bbb", "ccc"],
        source_ips=["192.168.1.100"],
        dest_ips=["10.0.0.5"],
        categories=["authentication"],
    )

    alert = detector.detect(suspicious_session)
    if alert:
        logger.info("  Attack Type:  %s", alert.attack_type)
        logger.info("  Severity:     %s", alert.severity)
        logger.info("  Confidence:   %.2f", alert.confidence)
        logger.info("  Model Source: %s", alert.model_source)
        logger.info("  Anomaly:      %.2f", alert.anomaly_score)
        logger.info("  XGB Proba:    %s", alert.xgb_proba)
    else:
        logger.info("  No alert — both models say normal")

    # Simulate a normal session
    normal_session = LogSession(
        entity_id="10.0.0.1",
        entity_type="source_ip",
        start_ts=datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        end_ts=datetime(2024, 1, 1, 10, 5, 0, tzinfo=timezone.utc),
        event_count=5,
        template_sequence=[1, 2, 1, 2, 1],
        total_suspicion=0.0,
        template_counts={"1": 3, "2": 2},
        event_hashes=["ddd"],
        source_ips=["10.0.0.1"],
        dest_ips=["10.0.0.5"],
        categories=["network"],
    )

    alert2 = detector.detect(normal_session)
    if alert2:
        logger.info("  Normal session got alert: %s (conf=%.2f)", alert2.attack_type, alert2.confidence)
    else:
        logger.info("  Normal session → no alert ✓")

    logger.info("ML Detector demo complete ✓")
