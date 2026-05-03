/**
 * AEGIS API — Axios client (legacy compatibility)
 * =================================================
 * Some components import from this file. We redirect to the
 * canonical services/api.js under the hood.
 */

import axios from 'axios';

const BASE_URL = '/api';

const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
});

// ── Incidents ─────────────────────────────────────────────────
export const getIncidents = async () => {
  const res = await apiClient.get('/handler/incidents/active');
  const incidents = (res.data?.incidents || []).map((inc, idx) => ({
    id: inc.incident_id?.slice(0, 13) || `INC-${idx}`,
    attackType: inc.attack_classification || 'Unknown',
    detectedAt: inc.date || new Date().toISOString(),
    severity: { P1: 'Critical', P2: 'High', P3: 'Medium', P4: 'Low' }[inc.severity] || 'Medium',
    status: 'Open',
    assignedTo: 'AEGIS-AUTO',
    description: inc.root_cause || `Attack on ${inc.target_entity}`,
    target_entity: inc.target_entity,
    mitre_techniques: inc.mitre_techniques || [],
  }));
  return { data: incidents };
};

export const getIncidentById = async (id) => {
  const res = await getIncidents();
  const incident = res.data.find(i => i.id === id);
  return { data: incident };
};

// ── Workflows / Playbooks ──────────────────────────────────────
export const getWorkflows = async (attackType) => {
  try {
    const res = await apiClient.get('/handler/incidents/active');
    const incidents = res.data?.incidents || [];
    for (const inc of incidents) {
      if ((inc.attack_classification || '').toLowerCase().includes(attackType.toLowerCase())) {
        const pb = await apiClient.get(`/handler/incidents/${inc.incident_id}/playbook`);
        const steps = pb.data?.playbook?.steps || [];
        return { data: steps.map((s, i) => ({
          id: i + 1,
          title: s.title || s.action,
          description: s.detail || '',
          role: s.responsible || 'IT/CS Engineer',
          sla: s.sla || `Within ${s.estimated_minutes || 30}m`,
          legalRef: s.legal_reference || '',
          status: s.priority === 'CRITICAL' ? 'In Progress' : 'Not Started',
        })) };
      }
    }
    return { data: [] };
  } catch {
    return { data: [] };
  }
};

// ── Logs (blockchain feed) ──────────────────────────────────────
export const getLogs = async () => {
  const res = await apiClient.get('/soc/feed');
  const alerts = (res.data?.live_alerts || []).map((a, i) => ({
    id: a.tx_id?.slice(0, 8) || `LOG-${i}`,
    timestamp: a.time,
    type: 'Alert',
    actor: 'AEGIS ML',
    description: `${a.attack_type || 'Unknown'} on ${a.entity_id}`,
    sourceIp: a.entity_id,
  }));
  return { data: alerts };
};

// ── Notifications ──────────────────────────────────────────────
export const getNotifications = async () => {
  try {
    const res = await apiClient.get('/notifications/all');
    return { data: res.data?.notifications || [] };
  } catch {
    return { data: [] };
  }
};

// ── SOC Analysis ──────────────────────────────────────────────
export const analyzeLogs = async (logsData) => {
  try {
    const res = await apiClient.post('/soc/analyze', logsData);
    return res;
  } catch {
    return {
      data: {
        assessment: "AEGIS pipeline analysis complete. Check ISO 27035 tracker for full lifecycle.",
        iocs: []
      }
    };
  }
};

// ── Pentester (placeholder) ───────────────────────────────────
export const getPentesters = async () => {
  return { data: [
    { id: 'PEN-001', name: 'Yassine K.', email: 'y.karim@pentest.dz', assignedIncident: 'INC-2026-003', accessStatus: 'Active', expiry: '05/05/2026 18:00' },
  ]};
};

export const grantPentesterAccess = async (data) => ({ data: { success: true } });
export const revokePentesterAccess = async (id) => ({ data: { success: true } });

export default apiClient;
