import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Check, ShieldAlert, Search, Wrench, FileText, RotateCcw,
  BookOpen, ChevronDown, ChevronUp, Bot, Lock, Save,
  CheckCircle2, AlertTriangle, Send, Zap, Target
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import { api } from '../../services/api';

/*
  ISO 27035 Phases — AI vs Human split:
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Phase 1-3 (Plan → Detect → Assess) = AI auto-completed ✅🔒
  Phase 4   (Respond & Eradicate)     = IT Team manual steps ✏️
  Phase 5-6 (Lessons Learned → Close) = Analyst must complete ✏️
*/

const ISO_PHASES = [
  {
    id: 1, code: 'ISO-27035-1', label: 'Plan & Prepare', icon: BookOpen,
    isAI: true, color: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/8',
    description: 'Establish incident response policy, roles, and communication plan.',
    playbook: [
      'Confirm IR policy version is current (review every 6 months)',
      'Verify CSIRT team roster and on-call contacts are up to date',
      'Ensure log sources (SIEM, EDR, firewall) are feeding correctly',
      'Confirm escalation matrix and legal/compliance contacts are accessible',
      'Validate secure communication channel (out-of-band) is operational',
    ],
  },
  {
    id: 2, code: 'ISO-27035-2', label: 'Detect & Report', icon: Search,
    isAI: true, color: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/8',
    description: 'Identify potential incidents through monitoring and user reports.',
    playbook: [
      'Ingest and triage raw log data from SIEM / EDR / network sensors',
      'Classify alert by source: automated detection, user report, or external tip',
      'Apply initial severity scoring: P1 Critical / P2 High / P3 Medium / P4 Low',
      'Extract IOCs: IPs, hashes, domains, user accounts, process names',
      'Open incident ticket and assign unique incident ID (INC-YYYYMMDD-XXX)',
      'Notify SOC lead within 15 min for P1/P2; 1 hour for P3/P4',
    ],
  },
  {
    id: 3, code: 'ISO-27035-3', label: 'Assess & Decide', icon: ShieldAlert,
    isAI: true, color: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/8',
    description: 'Evaluate incident scope, impact and decide on response path.',
    playbook: [
      'Determine affected assets: endpoints, servers, cloud resources, data stores',
      'Assess business impact: data confidentiality, integrity, availability',
      'Confirm whether incident is a false positive — document rationale',
      'Identify threat actor TTPs against MITRE ATT&CK framework',
      'Decide response path: contain immediately vs. monitor for attribution',
      'Trigger Loi 18-07 breach notification if personal data involved (72h clock)',
      'Escalate to management if financial, legal, or reputational risk identified',
    ],
  },
  {
    id: 4, code: 'ISO-27035-4', label: 'Respond & Eradicate', icon: Wrench,
    isAI: false, color: 'text-red-400', border: 'border-red-500/30', bg: 'bg-red-500/10',
    description: 'IT Team executes containment, eradication, and recovery — REQUIRES MANUAL VALIDATION.',
    playbook: [
      'CONTAIN: Isolate affected host(s) from network — preserve forensic state first',
      'CONTAIN: Block IOC IPs/domains at firewall, proxy, and DNS sinkholes',
      'CONTAIN: Disable or reset compromised credentials immediately',
      'ERADICATE: Remove malware, unauthorized accounts, and persistence mechanisms',
      'ERADICATE: Patch or mitigate exploited vulnerability (virtual patch if needed)',
      'RECOVER: Restore from last known-good backup — verify integrity before restore',
      'RECOVER: Re-image endpoints where rootkit or firmware compromise is suspected',
      'VERIFY: Confirm threat is eliminated before returning system to production',
    ],
  },
  {
    id: 5, code: 'ISO-27035-5', label: 'Lessons Learned', icon: RotateCcw,
    isAI: false, color: 'text-amber-400', border: 'border-amber-500/30', bg: 'bg-amber-500/10',
    description: 'Document findings and improve defenses — ANALYST MUST COMPLETE.',
    playbook: [
      'Conduct post-incident review within 5 business days of closure',
      'Complete full incident report: timeline, root cause, impact, response actions',
      'Identify detection gaps — update SIEM rules, signatures, and playbooks',
      'Review whether existing controls failed or were absent',
      'Update risk register and asset inventory based on findings',
      'Share sanitized threat intelligence with ISAC / trusted partners if applicable',
      'Archive all evidence per retention policy (minimum 1 year for ISO compliance)',
    ],
  },
  {
    id: 6, code: 'ISO-27035-6', label: 'Close & Report', icon: FileText,
    isAI: false, color: 'text-purple-400', border: 'border-purple-500/30', bg: 'bg-purple-500/10',
    description: 'Formally close the incident and report to stakeholders — ANALYST MUST COMPLETE.',
    playbook: [
      'Confirm all recovery actions are complete and verified',
      'Submit final incident report to CISO, legal, and compliance teams',
      'File regulatory notifications if required (Loi 18-07, Décret 20-05)',
      'Close incident ticket with root cause category and closure timestamp',
      'Update incident metrics dashboard (MTTD, MTTR, incident count)',
      'Brief executive stakeholders for P1/P2 incidents within 48h of closure',
    ],
  },
];

const AI_PHASES = ISO_PHASES.filter(p => p.isAI);
const HUMAN_PHASES = ISO_PHASES.filter(p => !p.isAI);

/* Kill chain badge colors */
const KC_COLORS = {
  'Reconnaissance': 'bg-blue-500/15 text-blue-400 border-blue-500/20',
  'Weaponization': 'bg-indigo-500/15 text-indigo-400 border-indigo-500/20',
  'Delivery': 'bg-violet-500/15 text-violet-400 border-violet-500/20',
  'Exploitation': 'bg-orange-500/15 text-orange-400 border-orange-500/20',
  'Installation': 'bg-red-500/15 text-red-400 border-red-500/20',
  'Command and Control': 'bg-pink-500/15 text-pink-400 border-pink-500/20',
  'Actions on Objectives': 'bg-red-600/15 text-red-500 border-red-600/20',
};

export const SOCAnalysis = () => {
  const { incidents, fetchIncidents, isLoadingIncidents } = useAppStore();
  const [openIncident, setOpenIncident] = useState(null);
  const [activePhase, setActivePhase] = useState({});
  const [completedSteps, setCompletedSteps] = useState({});
  const [notes, setNotes] = useState({});
  const [saving, setSaving] = useState({});
  const [saveStatus, setSaveStatus] = useState({});

  // Unified attack data for dynamic kill chain
  const [unifiedAttacks, setUnifiedAttacks] = useState([]);
  useEffect(() => {
    fetchIncidents();
    (async () => {
      try {
        const data = await api.getUnifiedAttacks();
        if (data?.attacks) setUnifiedAttacks(data.attacks);
      } catch {}
    })();
  }, [fetchIncidents]);

  // Map incident → attack data from unified DB
  const getAttackData = useCallback((incident) => {
    if (!incident) return null;
    // Try matching by entity_id or by report_id prefix
    return unifiedAttacks.find(a =>
      a.entity_id === incident.target_entity ||
      a.id === incident.id?.slice(0, 8)
    ) || null;
  }, [unifiedAttacks]);

  // Load saved progress when opening an incident
  const toggleIncident = async (id) => {
    if (openIncident === id) { setOpenIncident(null); return; }
    setOpenIncident(id);
    if (!activePhase[id]) setActivePhase(prev => ({ ...prev, [id]: 4 }));
    try {
      const resp = await api.getProgress(id);
      if (resp?.progress?.completed_steps) {
        setCompletedSteps(prev => ({ ...prev, ...resp.progress.completed_steps }));
      }
      if (resp?.progress?.notes) {
        setNotes(prev => ({ ...prev, [id]: resp.progress.notes }));
      }
    } catch {}
  };

  const toggleStep = (incidentId, phaseId, stepIdx) => {
    const key = `${incidentId}-${phaseId}-${stepIdx}`;
    setCompletedSteps(prev => ({ ...prev, [key]: !prev[key] }));
    setSaveStatus(prev => ({ ...prev, [incidentId]: null }));
  };

  // Submit progress to backend
  const submitProgress = useCallback(async (incidentId) => {
    setSaving(prev => ({ ...prev, [incidentId]: true }));
    try {
      const relevant = {};
      Object.entries(completedSteps).forEach(([key, val]) => {
        if (key.startsWith(incidentId)) relevant[key] = val;
      });
      await api.saveProgress(incidentId, {
        completed_steps: relevant,
        notes: notes[incidentId] || '',
        analyst: 'Ahmed B.',
      });
      setSaveStatus(prev => ({ ...prev, [incidentId]: 'success' }));
      setTimeout(() => setSaveStatus(prev => ({ ...prev, [incidentId]: null })), 3000);
    } catch {
      setSaveStatus(prev => ({ ...prev, [incidentId]: 'error' }));
    }
    setSaving(prev => ({ ...prev, [incidentId]: false }));
  }, [completedSteps, notes]);

  // Count completed human steps for an incident
  const getHumanProgress = (incidentId) => {
    let total = 0, done = 0;
    HUMAN_PHASES.forEach(phase => {
      phase.playbook.forEach((_, idx) => {
        total++;
        if (completedSteps[`${incidentId}-${phase.id}-${idx}`]) done++;
      });
    });
    return { total, done, pct: total > 0 ? Math.round((done / total) * 100) : 0 };
  };

  if (isLoadingIncidents && incidents.length === 0) {
    return (
      <div className="max-w-5xl mx-auto space-y-6">
        <h1 className="text-2xl font-bold text-white">Incident Response Playbook</h1>
        <div className="text-neutral-500 text-sm">Loading incidents from AEGIS backend...</div>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold text-white">Incident Response Playbook</h1>
      <p className="text-sm text-neutral-500">
        {incidents.length} incidents — AI handles Phases 1-3 (Detection → Assessment).
        Phase 4 (Eradication) is for IT Team. Phases 5-6 require your input.
      </p>

      {incidents.map((incident) => {
        const isOpen = openIncident === incident.id;
        const currentPhase = activePhase[incident.id] || 4;
        const phaseData = ISO_PHASES.find(p => p.id === currentPhase);
        const progress = getHumanProgress(incident.id);
        const attackData = getAttackData(incident);

        return (
          <div key={incident.id} className="bg-brand-bg-card border border-brand-border rounded-md">
            {/* INCIDENT HEADER */}
            <button onClick={() => toggleIncident(incident.id)} className="w-full p-4 flex justify-between items-center text-left">
              <div className="flex-1">
                <div className="flex items-center gap-3 flex-wrap">
                  <h2 className="text-white font-semibold">{incident.id}</h2>
                  <span className={`px-2 py-0.5 text-[10px] font-medium rounded-full ${
                    incident.severity === 'Critical' ? 'bg-red-500/15 text-red-400' :
                    incident.severity === 'High' ? 'bg-orange-500/15 text-orange-400' :
                    incident.severity === 'Medium' ? 'bg-yellow-500/15 text-yellow-400' :
                    'bg-emerald-500/15 text-emerald-400'
                  }`}>{incident.severity}</span>
                  {incident.target_entity && (
                    <span className="px-2 py-0.5 text-[10px] font-mono bg-brand-bg-surface border border-brand-border rounded text-neutral-400">
                      {incident.target_entity}
                    </span>
                  )}
                  {/* Dynamic kill chain from unified DB */}
                  {attackData?.kill_chain && (
                    <span className={`px-2 py-0.5 text-[10px] font-medium rounded-full border ${KC_COLORS[attackData.kill_chain] || 'bg-neutral-500/15 text-neutral-400 border-neutral-500/20'}`}>
                      ⛓ {attackData.kill_chain}
                    </span>
                  )}
                  {progress.done > 0 && (
                    <span className="px-2 py-0.5 text-[10px] bg-brand-primary/10 text-brand-primary border border-brand-primary/20 rounded-full">
                      {progress.pct}% complete
                    </span>
                  )}
                </div>
                <p className="text-xs text-neutral-400 mt-1">{incident.description || incident.attackType}</p>
              </div>
              {isOpen ? <ChevronUp /> : <ChevronDown />}
            </button>

            {/* EXPANDED CONTENT */}
            {isOpen && (
              <div className="border-t border-brand-border p-4 space-y-4">
                {/* ═══ DYNAMIC ATTACK INTEL FROM UNIFIED DB ═══ */}
                {attackData && (
                  <div className="bg-brand-bg-surface border border-brand-border rounded-xl p-4 space-y-3">
                    <h3 className="text-xs font-semibold text-brand-info uppercase tracking-wider flex items-center gap-2">
                      <Target size={13} /> Attack Intelligence — {attackData.attack_type}
                    </h3>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div>
                        <p className="text-[10px] text-neutral-500">Kill Chain</p>
                        <p className="text-xs text-white font-medium">{attackData.kill_chain || '—'}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-neutral-500">Risk Score</p>
                        <p className="text-xs text-red-400 font-bold">{attackData.risk_score?.toFixed(1)}/10</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-neutral-500">MITRE ATT&CK</p>
                        <p className="text-xs text-brand-primary font-mono">{(attackData.mitre || []).join(', ') || '—'}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-neutral-500">CVEs</p>
                        <p className="text-xs text-red-400 font-mono">{(attackData.cves || []).join(', ') || 'None'}</p>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <p className="text-[10px] text-neutral-500">Attack Vector</p>
                        <p className="text-xs text-neutral-300">{attackData.attack_vector || '—'}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-neutral-500">Root Cause</p>
                        <p className="text-xs text-neutral-300">{attackData.root_cause || '—'}</p>
                      </div>
                    </div>
                    {attackData.ioc_summary && (
                      <div>
                        <p className="text-[10px] text-neutral-500">IoC Summary</p>
                        <p className="text-xs text-neutral-400">{attackData.ioc_summary}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* ═══ AI-COMPLETED PHASES (1-3 only) — GREEN, LOCKED ═══ */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                    <Bot size={14} /> AEGIS AI — Phases 1→3 Auto-Completed (Detection → Assessment)
                  </h3>
                  <p className="text-[10px] text-neutral-600">Automated detection, classification, and impact assessment. Cannot be modified.</p>

                  <div className="grid grid-cols-3 gap-2">
                    {AI_PHASES.map(phase => {
                      const Icon = phase.icon;
                      return (
                        <div key={phase.id} className="bg-emerald-500/5 border border-emerald-500/15 rounded-lg p-3 cursor-not-allowed select-none">
                          <div className="flex items-center gap-2 mb-1">
                            <Lock size={10} className="text-emerald-500" />
                            <Icon size={12} className="text-emerald-400" />
                            <span className="text-[11px] font-semibold text-emerald-300">{phase.label}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <p className="text-[9px] text-emerald-600/70">{phase.playbook.length} steps</p>
                            <span className="text-[9px] text-emerald-500 flex items-center gap-1"><Check size={8} /> Done</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* ═══ HUMAN PHASES (4-6) — EDITABLE ═══ */}
                <div className="space-y-3 mt-4">
                  <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-2">
                    <AlertTriangle size={14} /> Manual Action Required — Phases 4, 5 & 6
                  </h3>
                  <p className="text-[10px] text-neutral-500">
                    Phase 4: IT Team eradication steps. Phases 5-6: analyst documentation. Click steps to mark as completed.
                  </p>

                  {/* Phase selector (human phases: 4, 5, 6) */}
                  <div className="flex gap-2 flex-wrap">
                    {HUMAN_PHASES.map(p => {
                      const Icon = p.icon;
                      const isActive = currentPhase === p.id;
                      return (
                        <button
                          key={p.id}
                          onClick={() => setActivePhase(prev => ({ ...prev, [incident.id]: p.id }))}
                          className={`flex items-center gap-2 px-4 py-2 text-xs rounded-lg border transition-all ${
                            isActive
                              ? `${p.bg} ${p.color} ${p.border} font-semibold`
                              : 'bg-brand-bg-surface text-neutral-400 border-brand-border hover:text-white'
                          }`}
                        >
                          <Icon size={13} />
                          {p.label}
                          {p.id === 4 && <span className="text-[9px] ml-1 opacity-60">IT Team</span>}
                        </button>
                      );
                    })}
                  </div>

                  {/* Phase description */}
                  {phaseData && !phaseData.isAI && (
                    <div className={`p-3 rounded-lg border ${phaseData.border} ${phaseData.bg}`}>
                      <p className={`text-xs font-medium ${phaseData.color}`}>{phaseData.code} — {phaseData.description}</p>
                    </div>
                  )}

                  {/* Editable steps */}
                  {phaseData && !phaseData.isAI && (
                    <div className="space-y-2">
                      {phaseData.playbook.map((step, idx) => {
                        const key = `${incident.id}-${currentPhase}-${idx}`;
                        const done = completedSteps[key];
                        return (
                          <div
                            key={idx}
                            onClick={() => toggleStep(incident.id, currentPhase, idx)}
                            className={`p-3 border rounded-lg cursor-pointer transition-all ${done
                              ? 'bg-brand-primary/10 border-brand-primary/25'
                              : 'bg-brand-bg-surface border-brand-border hover:border-neutral-600'
                            }`}
                          >
                            <div className="flex items-center gap-3">
                              <div className={`w-5 h-5 rounded border-2 flex items-center justify-center shrink-0 transition-all ${
                                done ? 'bg-brand-primary border-brand-primary' : 'border-neutral-600'
                              }`}>
                                {done && <Check size={12} className="text-black" />}
                              </div>
                              <p className={`text-sm ${done ? 'text-neutral-400 line-through' : 'text-white'}`}>
                                {step}
                              </p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* Notes */}
                  <div>
                    <label className="text-[10px] text-neutral-500 uppercase tracking-wider block mb-1">Analyst Notes</label>
                    <textarea
                      value={notes[incident.id] || ''}
                      onChange={e => setNotes(prev => ({ ...prev, [incident.id]: e.target.value }))}
                      placeholder="Add observations, findings, or recommendations..."
                      className="w-full h-20 bg-brand-bg-surface border border-brand-border rounded-lg p-3 text-sm text-white placeholder-neutral-600 focus:outline-none focus:border-brand-primary/50 resize-none"
                    />
                  </div>

                  {/* Progress bar + Submit */}
                  <div className="flex items-center gap-4 pt-2">
                    <div className="flex-1">
                      <div className="flex justify-between text-[10px] text-neutral-500 mb-1">
                        <span>Progress: {progress.done}/{progress.total} steps</span>
                        <span>{progress.pct}%</span>
                      </div>
                      <div className="h-2 bg-brand-bg-surface rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-brand-primary to-emerald-400 rounded-full transition-all duration-500"
                          style={{ width: `${progress.pct}%` }}
                        />
                      </div>
                    </div>
                    <button
                      onClick={() => submitProgress(incident.id)}
                      disabled={saving[incident.id]}
                      className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                        saveStatus[incident.id] === 'success'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-brand-primary text-black hover:bg-brand-secondary'
                      } disabled:opacity-50`}
                    >
                      {saving[incident.id] ? (
                        <><Save size={14} className="animate-spin" /> Saving...</>
                      ) : saveStatus[incident.id] === 'success' ? (
                        <><CheckCircle2 size={14} /> Saved ✓</>
                      ) : (
                        <><Send size={14} /> Submit Progress</>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};