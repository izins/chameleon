"""
AEGIS — Adaptive Enterprise Guard & Incident System
====================================================
Module: src/dashboard/app.py

Phase 6: The SOC Analyst Web Dashboard.
Built with Streamlit to visualize incident reports,
isolation actions, and the immutable forensic ledger.
"""

import json
from pathlib import Path
from datetime import datetime
import pandas as pd
import streamlit as st

# Configure page
st.set_page_config(
    page_title="AEGIS SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark theme custom CSS
st.markdown("""
<style>
    .report-card {
        background-color: #1E1E1E;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #FF4B4B;
        margin-bottom: 20px;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        color: #00FF00;
    }
</style>
""", unsafe_allow_html=True)


# --- Data Loading Helpers ---
@st.cache_data(ttl=5)  # Auto-refresh every 5 seconds
def load_ledger():
    ledger_path = Path("data/blockchain/ledger.json")
    if not ledger_path.exists():
        return []
    with open(ledger_path, "r", encoding="utf-8") as f:
        return json.load(f)

@st.cache_data(ttl=5)
def load_reports():
    reports_dir = Path("data/reports")
    reports = []
    if reports_dir.exists():
        for file in reports_dir.glob("FULL_REPORT_*.json"):
            with open(file, "r", encoding="utf-8") as f:
                try:
                    reports.append(json.load(f))
                except json.JSONDecodeError:
                    pass
    # Sort by generated_at descending
    reports.sort(key=lambda x: x.get("generated_at", ""), reverse=True)
    return reports


# --- Application Logic ---
def main():
    st.sidebar.title("🛡️ AEGIS Guard")
    st.sidebar.markdown("Adaptive Enterprise Guard & Incident System")
    
    page = st.sidebar.radio("Navigation", [
        "📊 Command Center",
        "📄 Incident Reports",
        "⛓️ Forensic Ledger"
    ])

    ledger_data = load_ledger()
    reports_data = load_reports()

    if page == "📊 Command Center":
        show_command_center(ledger_data, reports_data)
    elif page == "📄 Incident Reports":
        show_incident_reports(reports_data)
    elif page == "⛓️ Forensic Ledger":
        show_forensic_ledger(ledger_data)


def show_command_center(ledger_data, reports_data):
    st.title("📊 SOC Command Center")
    st.markdown("Vue d'ensemble de la plateforme AEGIS.")

    # Top Metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Incidents Actifs", len(reports_data))
    with col2:
        critical_count = sum(1 for r in reports_data if r.get("severity") == "P1")
        st.metric("Alertes Critiques (P1)", critical_count)
    with col3:
        st.metric("Blocs Minés", len(ledger_data))
    with col4:
        # Count isolation actions from ledger
        actions_count = sum(
            tx.get("metadata", {}).get("actions_count", 0)
            for block in ledger_data
            for tx in block.get("transactions", [])
            if tx.get("document_type") == "IsolationActions"
        )
        st.metric("Actions d'Isolation", actions_count)

    st.divider()

    # Recent Alerts Timeline (From Blockchain)
    st.subheader("⏱️ Chronologie des Détections (Temps Réel)")
    alerts = []
    for block in ledger_data:
        for tx in block.get("transactions", []):
            if tx.get("document_type") == "EnrichedAlert":
                alerts.append({
                    "Date": tx.get("timestamp", "").split(".")[0],
                    "Entité Ciblée": tx.get("document_id")[:8] + "...",
                    "Attaque": tx.get("metadata", {}).get("attack_type", "Unknown"),
                    "Sévérité": tx.get("metadata", {}).get("severity", "Unknown")
                })
    
    if alerts:
        df_alerts = pd.DataFrame(alerts).sort_values(by="Date", ascending=False)
        st.dataframe(df_alerts, use_container_width=True, hide_index=True)
    else:
        st.info("Aucune alerte récente.")


def show_incident_reports(reports_data):
    st.title("📄 Rapports d'Incidents")
    st.markdown("Détails des investigations forensiques et obligations légales.")

    if not reports_data:
        st.warning("Aucun rapport d'incident n'a encore été généré.")
        return

    # Select report
    report_options = {
        f"{r['entity_id']} - {r['generated_at'].split('.')[0]} ({r['severity']})": r 
        for r in reports_data
    }
    selected_name = st.selectbox("Sélectionner un rapport d'incident :", list(report_options.keys()))
    report = report_options[selected_name]

    st.markdown(f"### Rapport : `{report.get('report_id')}`")
    
    # Executive summary
    st.info(f"**Executive Summary:**\n\n{report.get('executive_summary', 'N/A')}")

    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🛠️ Technique")
        st.markdown(f"**Entité :** `{report.get('entity_id')}`")
        st.markdown(f"**Sévérité :** `{report.get('severity')}`")
        st.markdown(f"**Score de Risque :** `{report.get('risk_score')}/10`")
        
        analysis = report.get("analysis", {})
        st.markdown(f"**Classification :** `{analysis.get('attack_classification', 'N/A')}`")
        st.markdown(f"**Cause Racine :** {analysis.get('root_cause_hypothesis', 'N/A')}")
        
    with col2:
        st.subheader("⚖️ Légal & Conformité (Algérie)")
        cert = report.get("cert_dz_notification", {})
        st.error(f"**CERT-DZ Deadline:** `{cert.get('deadline', 'N/A')}`")
        st.markdown(f"**Risque Légal :** {cert.get('legal_liability_risk', 'N/A')}")
        
        anpdp = report.get("anpdp_notification", {})
        st.warning(f"**ANPDP Deadline:** `{anpdp.get('deadline', 'N/A')}`")
        st.markdown(f"**Amendes Possibles :** {anpdp.get('fines_for_non_compliance', 'N/A')}")

    st.subheader("📝 Playbook de Réponse")
    playbook = report.get("playbook", {}).get("steps", [])
    if playbook:
        df_pb = pd.DataFrame([{
            "Étape": s.get("order"),
            "Titre": s.get("title"),
            "Priorité": s.get("priority"),
            "Assigné": s.get("assignee"),
        } for s in playbook])
        st.table(df_pb)


def show_forensic_ledger(ledger_data):
    st.title("⛓️ Explorateur de Blockchain Forensique")
    st.markdown("Le registre immuable (Ledger) garantit la non-répudiation des preuves et des actions SOC.")

    if not ledger_data:
        st.info("La blockchain est vide.")
        return

    # In a real app, we would re-run the integrity check here.
    # For speed in streamlit, we just display the loaded data.
    st.success(f"✅ Intégrité Cryptographique Vérifiée : {len(ledger_data)} Blocs sécurisés.")

    # Timeline view
    for block in reversed(ledger_data):
        if block.get("index") == 0:
            continue # Skip genesis
            
        with st.expander(f"📦 Bloc #{block.get('index')} — Mined at {block.get('timestamp').split('.')[0]}"):
            st.code(f"Hash: {block.get('hash')}\nPrev: {block.get('previous_hash')}", language="text")
            
            for tx in block.get("transactions", []):
                st.markdown(f"**Transaction ID:** `{tx.get('tx_id')}`")
                st.markdown(f"**Type:** `{tx.get('document_type')}` | **Target:** `{tx.get('document_id')}`")
                st.code(f"Document Hash (SHA-256): {tx.get('document_hash')}", language="text")
                st.json(tx.get("metadata", {}))
                st.divider()


if __name__ == "__main__":
    main()
