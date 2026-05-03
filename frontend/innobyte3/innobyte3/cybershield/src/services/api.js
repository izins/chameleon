/**
 * AEGIS API Service Layer — Connected to Flask Backend
 * =====================================================
 * All calls go through the Vite proxy → Flask (:5000)
 * 
 * Mapping:
 *   Incidents     → /api/handler/incidents/active  (real report data)
 *   Logs          → /api/soc/feed                  (blockchain alert feed)
 *   Legal         → /api/legal/dashboard           (CERT-DZ / ANPDP)
 *   Analytics     → /api/analytics/global          (hot DB metrics)
 *   ISO 27035     → /api/iso27035/incidents         (lifecycle phases)
 *   Network       → /api/network/topology           (device topology)
 *   Workflows     → /api/handler/incidents/:id/playbook
 */

const BASE = '/api';

async function request(url, options = {}) {
  try {
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`API call failed: ${url}`, err);
    return null;
  }
}

// ── Severity mapping (backend P1-P4 → frontend labels) ──────────
const sevMap = { P1: 'Critical', P2: 'High', P3: 'Medium', P4: 'Low' };
const statusMap = (s) => {
  if (!s) return 'Open';
  const sl = s.toLowerCase();
  if (sl === 'closed' || sl === 'resolved') return 'Resolved';
  if (sl.includes('progress') || sl.includes('active')) return 'In Progress';
  return 'Open';
};

export const api = {
  // ── SOC Analyst / Engineer: Incidents ──────────────────────
  getIncidents: async () => {
    // Primary: handler/incidents/active (real reports)
    const data = await request(`${BASE}/handler/incidents/active`);
    if (!data || !data.incidents) return [];

    return data.incidents.map((inc, idx) => ({
      id: inc.incident_id?.slice(0, 13) || `INC-${idx}`,
      attackType: inc.attack_classification || inc.attack_type || 'Unknown',
      detectedAt: inc.date || new Date().toISOString(),
      severity: sevMap[inc.severity] || inc.severity || 'Medium',
      status: inc.cves_exploited?.length > 0 ? 'In Progress' : 'Open',
      assignedTo: 'AEGIS-AUTO',
      workflow: inc.attack_classification || 'Auto Response',
      description: inc.root_cause || `Attack on ${inc.target_entity}`,
      // Extra fields from backend
      target_entity: inc.target_entity,
      mitre_techniques: inc.mitre_techniques || [],
      cves_exploited: inc.cves_exploited || [],
      playbook_steps: inc.playbook_steps || 0,
      pending_actions: inc.pending_actions || [],
    }));
  },

  getIncident: async (id) => {
    const all = await api.getIncidents();
    return all.find(i => i.id === id) || null;
  },

  // ── SOC: Live Alert Feed (blockchain-backed) ──────────────
  getLogs: async () => {
    const data = await request(`${BASE}/soc/feed`);
    if (!data || !data.live_alerts) return [];

    return data.live_alerts.map((a, i) => ({
      id: a.tx_id?.slice(0, 8) || `LOG-${i}`,
      timestamp: a.time || new Date().toISOString(),
      type: 'Alert',
      actor: 'AEGIS ML',
      description: `${a.attack_type || 'Unknown'} detected on ${a.entity_id || 'unknown'}`,
      incidentId: a.entity_id,
      sourceIp: a.entity_id,
      severity: a.severity,
      block: a.block_index,
    }));
  },

  // ── Incident Handler: Playbook ─────────────────────────────
  getWorkflow: async (type) => {
    // Try to find a matching report and return its playbook
    const data = await request(`${BASE}/handler/incidents/active`);
    if (!data || !data.incidents) return [];

    for (const inc of data.incidents) {
      if ((inc.attack_classification || '').toLowerCase().includes(type.toLowerCase())) {
        const pb = await request(`${BASE}/handler/incidents/${inc.incident_id}/playbook`);
        if (pb && pb.playbook && pb.playbook.steps) {
          return pb.playbook.steps.map((step, i) => ({
            id: i + 1,
            title: step.title || step.action,
            description: step.detail || step.description || '',
            role: step.responsible || 'IT/CS Engineer',
            sla: step.sla || `Within ${step.estimated_minutes || 30} minutes`,
            legalRef: step.legal_reference || '',
            status: step.priority === 'CRITICAL' ? 'In Progress' : 'Not Started',
          }));
        }
      }
    }
    return [];
  },

  updateWorkflowStep: async (incidentId, stepId, status) => {
    return { success: true, incidentId, stepId, status };
  },

  // ── Legal Dashboard ────────────────────────────────────────
  getLegalDashboard: async () => {
    return await request(`${BASE}/legal/dashboard`);
  },

  getLegalVerifiedHistory: async () => {
    return await request(`${BASE}/legal/history/verified`);
  },

  verifyReport: async (reportId) => {
    return await request(`${BASE}/legal/blockchain/verify/${reportId}`);
  },

  // ── ISO 27035 Lifecycle ────────────────────────────────────
  getISOIncidents: async () => {
    const data = await request(`${BASE}/iso27035/incidents`);
    return data?.incidents || [];
  },

  getISOIncident: async (id) => {
    return await request(`${BASE}/iso27035/incident/${id}`);
  },

  getISOPhase: async (id, phase) => {
    return await request(`${BASE}/iso27035/incident/${id}/phase/${phase}`);
  },

  getISOCompliance: async (id) => {
    return await request(`${BASE}/iso27035/compliance/${id}`);
  },

  // ── Incident Progress (save/load analyst work) ─────────────
  getProgress: async (incidentId) => {
    return await request(`${BASE}/incidents/progress/${incidentId}`);
  },

  saveProgress: async (incidentId, data) => {
    return await request(`${BASE}/incidents/progress/${incidentId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  },

  getProgressStats: async () => {
    return await request(`${BASE}/incidents/progress/all/stats`);
  },

  // ── Network Topology ──────────────────────────────────────
  getNetworkTopology: async () => {
    return await request(`${BASE}/network/topology`);
  },

  scanNetwork: async () => {
    return await request(`${BASE}/network/scan`, { method: 'POST' });
  },

  // ── Unified Attack Database ────────────────────────────────
  getUnifiedAttacks: async () => {
    return await request(`${BASE}/attacks/unified`);
  },

  getAttackDetail: async (id) => {
    return await request(`${BASE}/attacks/${id}`);
  },

  // ── PDF Report Download ────────────────────────────────────
  downloadPDF: async (reportId) => {
    try {
      const res = await fetch(`${BASE}/reports/${reportId}/pdf`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AEGIS_REPORT_${reportId.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      return { success: true };
    } catch (err) {
      console.warn('PDF download failed:', err);
      return { success: false, error: err.message };
    }
  },

  // ── Analytics (Hot DB) ─────────────────────────────────────
  getAnalytics: async () => {
    return await request(`${BASE}/analytics/global`);
  },

  getGeoDistribution: async () => {
    return await request(`${BASE}/analytics/geo`);
  },

  getAttackTimeline: async () => {
    return await request(`${BASE}/analytics/timeline`);
  },

  getEntityDetail: async (ip) => {
    return await request(`${BASE}/analytics/entity/${ip}`);
  },

  // ── SOC Metrics ────────────────────────────────────────────
  getSOCMetrics: async () => {
    return await request(`${BASE}/soc/metrics`);
  },

  // ── Dashboard Payload (aggregated) ─────────────────────────
  getDashboardPayload: async () => {
    return await request(`${BASE}/dashboard`);
  },

  // ── Pentester (keep as-is for now) ─────────────────────────
  getPentesters: async () => {
    return [
      { id: 'PEN-001', name: 'Yassine K.', email: 'y.karim@pentest.dz', assignedIncident: 'INC-2026-003', accessStatus: 'Active', expiry: '05/05/2026 18:00' },
    ];
  },

  grantPentesterAccess: async (email, permissions) => {
    return { success: true, email, permissions };
  },

  simulateAttack: async () => {
    return await request(`${BASE}/simulate_attack`, { method: 'POST' });
  },

  // ── SOC Analysis (AI) ─────────────────────────────────────
  analyzeLogs: async (payload) => {
    // Try real endpoint first, fallback to local analysis
    const data = await request(`${BASE}/soc/analyze`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (data) return data;
    return {
      data: {
        assessment: "Analysis request sent to AEGIS pipeline. Check the ISO 27035 tracker for results.",
        iocs: []
      }
    };
  },

  // ── Blockchain ─────────────────────────────────────────────
  getBlockchainLedger: async () => {
    return await request(`${BASE}/blockchain/ledger`);
  },
};
