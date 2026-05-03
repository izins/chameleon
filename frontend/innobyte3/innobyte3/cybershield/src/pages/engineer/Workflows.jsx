import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, ArrowRight, Check, Clock, Circle, Lock, Bot, BookOpen, Download } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import { api } from '../../services/api';

/* ═══ EXPANDED WORKFLOWS — 10 Attack Types + ISO 27035 Mapping ═══ */
const WORKFLOWS = {
  'Phishing': {
    iso: 'Phase 2→3→4', isoClause: 'ISO 27035-2 §7.2, §8.1', legalRef: 'Loi 18-07 Art. 12',
    steps: [
      { id: 1, title: 'Isolate Affected Users', description: 'Disconnect affected user endpoints from network immediately.', role: 'IT/CS Engineer', sla: 'Within 15 min', legalRef: 'ISO 27035 Phase 3 — Containment', status: 'Done' },
      { id: 2, title: 'Analyze Email Headers & URLs', description: 'Extract sender IP, envelope headers, embedded URLs, and attachment hashes.', role: 'SOC Analyst', sla: 'Within 30 min', legalRef: 'ISO 27035-2 §7.2 — Evidence Collection', status: 'In Progress' },
      { id: 3, title: 'Block IOCs at Perimeter', description: 'Add extracted domains, IPs, and hashes to firewall/proxy/DNS blocklists.', role: 'IT/CS Engineer', sla: 'Within 1 hour', legalRef: '', status: 'Not Started' },
      { id: 4, title: 'Reset Compromised Credentials', description: 'Force password reset for all users who clicked the phishing link.', role: 'IT/CS Engineer', sla: 'Within 2 hours', legalRef: 'Loi 18-07 Art. 12 — Obligation de sécurité', status: 'Not Started' },
      { id: 5, title: 'Notify Legal Team', description: 'If personal data involved, trigger CERT-DZ (24h) + ANPDP (72h) notification.', role: 'Juridical Team', sla: 'Within 24 hours', legalRef: 'Décret 20-05, Loi 18-07 Art. 15', status: 'Not Started' },
      { id: 6, title: 'User Awareness Training', description: 'Mandatory anti-phishing training for all affected + department users.', role: 'HR / CISO', sla: 'Within 48 hours', legalRef: 'ISO 27035-4 §9.1 — Lessons Learned', status: 'Not Started' },
    ]
  },
  'Ransomware': {
    iso: 'Phase 3→4→5', isoClause: 'ISO 27035-3 §8.2, §8.3', legalRef: 'Loi 18-07 Art. 38',
    steps: [
      { id: 1, title: 'Immediate Network Isolation', description: 'Sever all connections to affected segments — prevent lateral spread.', role: 'IT/CS Engineer', sla: 'Immediate', legalRef: 'ISO 27035 Phase 3 — Emergency Containment', status: 'Done' },
      { id: 2, title: 'Identify Ransomware Strain', description: 'Collect sample, check ID Ransomware, extract IOCs.', role: 'SOC Analyst', sla: 'Within 1 hour', legalRef: 'ISO 27035-2 §7.3 — Threat Classification', status: 'Done' },
      { id: 3, title: 'Preserve Forensic Evidence', description: 'Image affected drives, capture memory dumps, preserve encryption keys.', role: 'SOC Analyst', sla: 'Within 2 hours', legalRef: 'Loi 18-07 Art. 12 — Préservation des preuves', status: 'In Progress' },
      { id: 4, title: 'Notify CERT-DZ', description: 'Mandatory incident notification to national CERT within 24h.', role: 'Juridical Team', sla: 'Within 24 hours', legalRef: 'Décret 20-05 — Notification obligatoire', status: 'Not Started' },
      { id: 5, title: 'Restore from Clean Backups', description: 'Wipe infected machines, verify backup integrity, restore data.', role: 'IT/CS Engineer', sla: 'Within 48 hours', legalRef: '', status: 'Not Started' },
      { id: 6, title: 'Post-Incident Review', description: 'Document entry vector, timeline, and update IR playbook.', role: 'CISO', sla: 'Within 5 days', legalRef: 'ISO 27035-4 §9.1 — Lessons Learned', status: 'Not Started' },
    ]
  },
  'DDoS': {
    iso: 'Phase 3→4', isoClause: 'ISO 27035-3 §8.1', legalRef: 'Code Pénal Art. 394bis',
    steps: [
      { id: 1, title: 'Activate Anti-DDoS Mitigation', description: 'Route traffic through scrubbing center / CDN mitigation.', role: 'IT/CS Engineer', sla: 'Within 5 min', legalRef: 'ISO 27035 Phase 3 — Immediate Response', status: 'Done' },
      { id: 2, title: 'Analyze Attack Vectors', description: 'Identify type: SYN flood, UDP amplification, HTTP flood, slowloris.', role: 'SOC Analyst', sla: 'Within 30 min', legalRef: '', status: 'Done' },
      { id: 3, title: 'Implement Rate Limiting', description: 'Configure firewall rules, geo-blocking, and connection rate limits.', role: 'IT/CS Engineer', sla: 'Within 1 hour', legalRef: '', status: 'Done' },
      { id: 4, title: 'Document and Report', description: 'Log all attack metrics, report to ISP and authorities if needed.', role: 'SOC Analyst', sla: 'Within 24 hours', legalRef: 'Code Pénal Art. 394bis', status: 'Not Started' },
    ]
  },
  'Data Theft': {
    iso: 'Phase 2→3→4→5', isoClause: 'ISO 27035-2 §7.1, ISO 27035-4 §9', legalRef: 'Loi 18-07 Art. 15, 38',
    steps: [
      { id: 1, title: 'Identify Exfiltration Channel', description: 'Analyze DLP logs, DNS tunneling, HTTP uploads, USB activity.', role: 'SOC Analyst', sla: 'Within 30 min', legalRef: 'ISO 27035-2 §7.1 — Detection', status: 'Done' },
      { id: 2, title: 'Block Exfiltration Path', description: 'Terminate active connections, block destination IPs/domains.', role: 'IT/CS Engineer', sla: 'Within 15 min', legalRef: 'ISO 27035 Phase 3 — Containment', status: 'Done' },
      { id: 3, title: 'Assess Data Classification', description: 'Determine if personal/sensitive data (Loi 18-07 scope) was exposed.', role: 'Juridical Team', sla: 'Within 4 hours', legalRef: 'Loi 18-07 Art. 15 — Classification des données', status: 'In Progress' },
      { id: 4, title: 'Notify ANPDP if Personal Data', description: 'If personal data breach confirmed, notify within 72h.', role: 'Juridical Team', sla: 'Within 72 hours', legalRef: 'Loi 18-07 Art. 15 — Notification ANPDP', status: 'Not Started' },
      { id: 5, title: 'Forensic Investigation', description: 'Full chain of custody: who, what, when, how much data stolen.', role: 'SOC Analyst', sla: 'Within 5 days', legalRef: 'ISO 27035-4 §9 — Post-Incident Analysis', status: 'Not Started' },
    ]
  },
  'Privilege Escalation': {
    iso: 'Phase 3→4', isoClause: 'ISO 27035-3 §8.2', legalRef: 'Code Pénal Art. 394ter',
    steps: [
      { id: 1, title: 'Revoke Elevated Privileges', description: 'Immediately remove unauthorized elevated access.', role: 'IT/CS Engineer', sla: 'Immediate', legalRef: 'ISO 27035 Phase 3 — Containment', status: 'Done' },
      { id: 2, title: 'Patch CVE', description: 'Apply security patch for exploited vulnerability (kernel, sudo, etc.).', role: 'IT/CS Engineer', sla: 'Within 2 hours', legalRef: '', status: 'In Progress' },
      { id: 3, title: 'Credential Reset', description: 'Force rotation of all admin/root credentials on affected systems.', role: 'IT/CS Engineer', sla: 'Within 4 hours', legalRef: 'Loi 18-07 Art. 12', status: 'Not Started' },
      { id: 4, title: 'Audit Trail Review', description: 'Review sudo/su logs, check for persistence mechanisms.', role: 'SOC Analyst', sla: 'Within 8 hours', legalRef: 'ISO 27035-3 §8.2 — Eradication', status: 'Not Started' },
    ]
  },
  'Lateral Movement': {
    iso: 'Phase 3→4', isoClause: 'ISO 27035-3 §8.1, §8.3', legalRef: 'Code Pénal Art. 394bis',
    steps: [
      { id: 1, title: 'Network Segmentation', description: 'Isolate compromised subnet, implement micro-segmentation.', role: 'IT/CS Engineer', sla: 'Within 15 min', legalRef: 'ISO 27035 Phase 3', status: 'Done' },
      { id: 2, title: 'IOC Sweep Across Network', description: 'Hunt for attacker artifacts on all reachable hosts.', role: 'SOC Analyst', sla: 'Within 2 hours', legalRef: '', status: 'In Progress' },
      { id: 3, title: 'Disable Compromised Accounts', description: 'Lock all accounts used during lateral movement.', role: 'IT/CS Engineer', sla: 'Within 1 hour', legalRef: 'Loi 18-07 Art. 12', status: 'Not Started' },
      { id: 4, title: 'Deploy EDR Enhanced Rules', description: 'Push detection rules for observed TTPs to all endpoints.', role: 'SOC Analyst', sla: 'Within 4 hours', legalRef: 'ISO 27035-3 §8.3 — Recovery', status: 'Not Started' },
    ]
  },
  'Credential Attack': {
    iso: 'Phase 2→3→4', isoClause: 'ISO 27035-2 §7.2', legalRef: 'Code Pénal Art. 394bis',
    steps: [
      { id: 1, title: 'Lock Targeted Accounts', description: 'Immediately lock accounts showing brute-force attempts.', role: 'IT/CS Engineer', sla: 'Within 5 min', legalRef: '', status: 'Done' },
      { id: 2, title: 'Enforce MFA', description: 'Enable multi-factor authentication on all affected services.', role: 'IT/CS Engineer', sla: 'Within 2 hours', legalRef: 'Loi 18-07 Art. 12 — Mesures de sécurité', status: 'In Progress' },
      { id: 3, title: 'Credential Audit', description: 'Check for credential reuse, weak passwords, leaked credentials.', role: 'SOC Analyst', sla: 'Within 8 hours', legalRef: '', status: 'Not Started' },
      { id: 4, title: 'Block Source IPs', description: 'Add attacker IPs to permanent blocklist with geo-fencing.', role: 'IT/CS Engineer', sla: 'Within 1 hour', legalRef: 'Code Pénal Art. 394bis', status: 'Not Started' },
    ]
  },
  'Insider Threat': {
    iso: 'Phase 2→3→4→5→6', isoClause: 'ISO 27035-2 §7.1, ISO 27035-5 §10', legalRef: 'Loi 18-07 Art. 38, 46',
    steps: [
      { id: 1, title: 'Revoke All Access', description: 'Immediately suspend user account and revoke physical access.', role: 'HR / IT', sla: 'Immediate', legalRef: 'ISO 27035 Phase 3', status: 'Done' },
      { id: 2, title: 'Preserve Evidence', description: 'Image workstation, preserve email/chat logs, access logs.', role: 'SOC Analyst', sla: 'Within 2 hours', legalRef: 'Loi 18-07 Art. 12 — Préservation', status: 'In Progress' },
      { id: 3, title: 'Forensic Investigation', description: 'Full investigation: data accessed, copied, shared externally.', role: 'SOC Analyst', sla: 'Within 5 days', legalRef: 'ISO 27035-4 §9 — Analysis', status: 'Not Started' },
      { id: 4, title: 'Legal Action Assessment', description: 'Evaluate whether criminal referral is appropriate.', role: 'Juridical Team', sla: 'Within 10 days', legalRef: 'Loi 18-07 Art. 38, 46 — Sanctions pénales', status: 'Not Started' },
      { id: 5, title: 'Policy Review', description: 'Update access controls, least privilege, monitoring policies.', role: 'CISO', sla: 'Within 15 days', legalRef: 'ISO 27035-5 §10 — Improvement', status: 'Not Started' },
    ]
  },
  'Supply Chain Attack': {
    iso: 'Phase 1→2→3→4→5→6', isoClause: 'ISO 27035-1 §6, ISO 27035-5 §10', legalRef: 'Loi 18-07 Art. 44',
    steps: [
      { id: 1, title: 'Vendor Communication', description: 'Contact vendor/supplier to confirm compromise scope.', role: 'CISO', sla: 'Within 2 hours', legalRef: 'ISO 27035-1 §6 — Preparation', status: 'In Progress' },
      { id: 2, title: 'Isolate Vendor Components', description: 'Disable vendor VPN, API keys, remove compromised libraries.', role: 'IT/CS Engineer', sla: 'Within 4 hours', legalRef: 'Loi 18-07 Art. 44 — Transfert', status: 'Not Started' },
      { id: 3, title: 'Verify Update Integrity', description: 'Hash-check all recent vendor updates against known-good values.', role: 'SOC Analyst', sla: 'Within 8 hours', legalRef: '', status: 'Not Started' },
      { id: 4, title: 'Comprehensive Audit', description: 'Full audit of vendor access logs and data flows.', role: 'SOC Analyst', sla: 'Within 5 days', legalRef: 'ISO 27035-5 §10', status: 'Not Started' },
    ]
  },
  'Zero-Day Exploit': {
    iso: 'Phase 2→3→4→5', isoClause: 'ISO 27035-3 §8.2', legalRef: 'Décret 20-05',
    steps: [
      { id: 1, title: 'Virtual Patching', description: 'Deploy WAF/IPS rules to block exploitation pattern.', role: 'IT/CS Engineer', sla: 'Within 30 min', legalRef: 'ISO 27035 Phase 3 — Emergency', status: 'Done' },
      { id: 2, title: 'Vulnerability Analysis', description: 'Reverse-engineer exploit, determine affected software versions.', role: 'SOC Analyst', sla: 'Within 4 hours', legalRef: '', status: 'In Progress' },
      { id: 3, title: 'Share Threat Intel', description: 'Report to vendor, share IOCs with CERT-DZ and ISAC.', role: 'CISO', sla: 'Within 24 hours', legalRef: 'Décret 20-05 — Notification', status: 'Not Started' },
      { id: 4, title: 'Monitor for Re-exploitation', description: 'Enhanced monitoring on all instances of vulnerable software.', role: 'SOC Analyst', sla: 'Ongoing', legalRef: 'ISO 27035-4 §9 — Continuous Monitoring', status: 'Not Started' },
    ]
  },
};

export const Workflows = () => {
  const { incidents, fetchIncidents } = useAppStore();
  const [allWorkflows, setAllWorkflows] = useState(WORKFLOWS);
  const [types, setTypes] = useState(Object.keys(WORKFLOWS));
  const [selected, setSelected] = useState(Object.keys(WORKFLOWS)[0]);
  const [steps, setSteps] = useState([]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  // Merge live AEGIS playbooks from backend
  useEffect(() => {
    if (!incidents || incidents.length === 0) return;
    (async () => {
      const merged = { ...WORKFLOWS };
      for (const inc of incidents.slice(0, 5)) {
        try {
          const pbSteps = await api.getWorkflow(inc.attackType || 'unknown');
          if (pbSteps?.length > 0) {
            const label = `🤖 ${inc.attackType || 'Unknown'} [${inc.id}]`;
            merged[label] = { iso: 'AEGIS Auto', isoClause: 'AI-Generated', legalRef: 'AEGIS Pipeline', steps: pbSteps.map(s => ({ ...s, isAI: true })) };
          }
        } catch {}
      }
      setAllWorkflows(merged);
      setTypes(Object.keys(merged));
    })();
  }, [incidents]);

  useEffect(() => {
    const wf = allWorkflows[selected];
    setSteps(wf?.steps || []);
  }, [selected, allWorkflows]);

  const wfMeta = allWorkflows[selected] || {};

  return (
    <div className="flex h-[calc(100vh-8rem)] gap-5">
      {/* Sidebar */}
      <div className="w-72 shrink-0 bg-brand-bg-card border border-brand-border rounded-md flex flex-col overflow-hidden">
        <div className="p-4 border-b border-brand-border">
          <h3 className="text-[11px] uppercase tracking-wider text-neutral-500 font-semibold">Response Protocols</h3>
          <p className="text-[10px] text-neutral-600 mt-1">{types.length} attack types — ISO 27035 mapped</p>
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {types.map(type => (
            <button key={type} onClick={() => setSelected(type)}
              className={`w-full text-left px-3 py-2.5 rounded flex items-center justify-between transition-all text-sm ${
                selected === type ? 'bg-brand-primary/10 text-brand-primary border border-brand-primary/20' : 'text-neutral-400 hover:bg-white/[0.03] hover:text-white border border-transparent'
              }`}>
              <span className="font-medium truncate text-xs">{type}</span>
              {selected === type && <ArrowRight size={12} />}
            </button>
          ))}
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 bg-brand-bg-card border border-brand-border rounded-md overflow-hidden flex flex-col">
        <div className="p-5 border-b border-brand-border">
          <h2 className="text-lg font-semibold text-white">{selected} Response Protocol</h2>
          <div className="flex gap-3 mt-2">
            <span className="text-[10px] px-2 py-0.5 bg-brand-info/10 text-brand-info border border-brand-info/20 rounded font-mono">{wfMeta.iso || 'ISO 27035'}</span>
            <span className="text-[10px] px-2 py-0.5 bg-brand-bg-surface text-neutral-400 border border-brand-border rounded">{wfMeta.isoClause}</span>
            {wfMeta.legalRef && <span className="text-[10px] px-2 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded">{wfMeta.legalRef}</span>}
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {steps.length === 0 ? (
            <div className="text-sm text-neutral-500 py-8 text-center">No playbook steps.</div>
          ) : steps.map((step, idx) => {
            const isDone = step.status === 'Done';
            const isActive = step.status === 'In Progress';
            const isAI = step.isAI;
            return (
              <motion.div key={step.id || idx} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.06 }} className="flex gap-4">
                <div className="flex flex-col items-center">
                  <div className={`w-9 h-9 rounded-full flex items-center justify-center border-2 shrink-0 ${
                    isAI ? 'bg-emerald-500/15 border-emerald-500 text-emerald-400' :
                    isDone ? 'bg-emerald-500/10 border-emerald-500 text-emerald-500' :
                    isActive ? 'bg-yellow-500/10 border-yellow-500 text-yellow-500 animate-pulse' :
                    'bg-brand-bg-surface border-neutral-700 text-neutral-600'
                  }`}>
                    {isAI ? <Bot size={16} /> : isDone ? <Check size={16} /> : isActive ? <Clock size={16} /> : <Circle size={12} />}
                  </div>
                  {idx < steps.length - 1 && <div className={`w-0.5 flex-1 mt-1 ${isDone || isAI ? 'bg-emerald-500/30' : 'bg-neutral-800'}`} />}
                </div>
                <div className={`flex-1 pb-3 ${isAI ? '' : isDone ? 'opacity-70' : isActive ? '' : 'opacity-40'}`}>
                  <div className="flex items-center gap-2">
                    <h4 className={`font-medium text-sm ${isAI ? 'text-emerald-400' : isDone ? 'text-white' : isActive ? 'text-yellow-500' : 'text-neutral-400'}`}>
                      {idx + 1}. {step.title}
                    </h4>
                    {isAI && <span className="text-[9px] px-1.5 py-0.5 bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 rounded flex items-center gap-1"><Lock size={8} /> AEGIS AI</span>}
                  </div>
                  <p className="text-xs text-neutral-500 mt-1">{step.description}</p>
                  <div className="flex flex-wrap gap-2 mt-2">
                    <span className="text-[10px] bg-brand-bg-surface px-2 py-0.5 rounded border border-brand-border text-neutral-400">
                      <span className="text-brand-primary font-mono">{step.role}</span>
                    </span>
                    <span className="text-[10px] bg-brand-bg-surface px-2 py-0.5 rounded border border-brand-border text-brand-info">{step.sla}</span>
                    {step.legalRef && <span className="text-[10px] bg-brand-bg-surface px-2 py-0.5 rounded border border-brand-border text-amber-400">{step.legalRef}</span>}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
