import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Scale, CheckCircle2, AlertTriangle, Clock, Shield, FileText, ChevronDown, ExternalLink } from 'lucide-react';

const regulations = [
  { name: 'ISO 27035 — Incident Management', score: 94, status: 'Compliant', lastAudit: '2026-03-15', nextAudit: '2026-09-15', details: 'Full compliance with incident identification, reporting, assessment, response, and lessons learned phases. Minor gap in post-incident review documentation cadence.' },
  { name: 'Law 18-07 — Data Protection', score: 98, status: 'Compliant', lastAudit: '2026-04-01', nextAudit: '2026-10-01', details: 'Complete adherence to Algerian data protection requirements. Notification procedures tested and validated. Data processing agreements updated with all vendors.' },
  { name: 'ISO 27001 — Information Security', score: 91, status: 'Compliant', lastAudit: '2026-02-20', nextAudit: '2026-08-20', details: 'Information security management system certified. Risk assessment methodology current. Two observation items from last audit addressed and closed.' },
  { name: 'GDPR — EU Data Protection', score: 76, status: 'At Risk', lastAudit: '2026-04-28', nextAudit: '2026-07-28', details: 'Partial compliance for EU customer data handling. Data Processing Agreements need update for 3 sub-processors. Cookie consent mechanism requires revision.' },
  { name: 'PCI DSS — Payment Security', score: 88, status: 'Compliant', lastAudit: '2026-03-30', nextAudit: '2026-09-30', details: 'Payment card data handling procedures compliant. Network segmentation verified. Penetration testing schedule maintained quarterly.' },
  { name: 'Internal Security Policy', score: 100, status: 'Compliant', lastAudit: '2026-04-15', nextAudit: '2026-10-15', details: 'All internal security policies reviewed, updated, and acknowledged by staff. Training completion rate: 100%. Policy version control maintained.' },
];

const auditLog = [
  { event: 'ISO 27035 audit completed — Score: 94%', date: '2026-03-15', result: 'Pass' },
  { event: 'Law 18-07 compliance review', date: '2026-04-01', result: 'Pass' },
  { event: 'GDPR gap analysis initiated', date: '2026-04-10', result: 'In Progress' },
  { event: 'Internal policy annual review', date: '2026-04-15', result: 'Pass' },
  { event: 'PCI DSS quarterly assessment', date: '2026-03-30', result: 'Pass' },
  { event: 'GDPR sub-processor DPA review flagged', date: '2026-04-28', result: 'Action Required' },
];

const resultStyle = {
  Pass: 'text-emerald-400',
  'In Progress': 'text-amber-400',
  'Action Required': 'text-red-400',
};

export const LegalCompliance = () => {
  const [expanded, setExpanded] = useState(null);
  const overallScore = Math.round(regulations.reduce((a, r) => a + r.score, 0) / regulations.length);
  const compliant = regulations.filter(r => r.status === 'Compliant').length;
  const atRisk = regulations.filter(r => r.status === 'At Risk').length;

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300">
      <div className="flex items-center justify-between pb-6 border-b border-brand-border">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight flex items-center gap-2"><Scale size={20} className="text-brand-info" /> Compliance Hub</h1>
          <p className="text-xs text-neutral-500 mt-1">Regulatory compliance status and audit readiness.</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-5">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
          <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Overall Score</p>
          <p className={`text-2xl font-bold mt-1 ${overallScore >= 85 ? 'text-emerald-400' : 'text-amber-400'}`}>{overallScore}%</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
          <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Regulations Tracked</p>
          <p className="text-2xl font-bold text-white mt-1">{regulations.length}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
          <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Compliant</p>
          <p className="text-2xl font-bold text-emerald-400 mt-1 flex items-center gap-2"><CheckCircle2 size={18} /> {compliant}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
          <p className="text-[11px] text-neutral-500 uppercase tracking-wider">At Risk</p>
          <p className="text-2xl font-bold text-amber-400 mt-1 flex items-center gap-2"><AlertTriangle size={18} /> {atRisk}</p>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 pt-5 flex-1">
        {/* Regulations */}
        <div className="lg:col-span-8">
          <div className="bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden">
            <div className="px-5 py-3 border-b border-brand-border bg-brand-bg-surface">
              <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Regulatory Compliance</p>
            </div>
            <div className="divide-y divide-brand-border/50">
              {regulations.map((reg, i) => {
                const isAtRisk = reg.status === 'At Risk';
                const isOpen = expanded === i;
                return (
                  <motion.div key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.04 }}>
                    <div className="flex items-center gap-4 px-5 py-4 hover:bg-white/[0.015] transition-colors cursor-pointer" onClick={() => setExpanded(isOpen ? null : i)}>
                      <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${isAtRisk ? 'bg-amber-500/10 text-amber-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
                        {isAtRisk ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-white">{reg.name}</p>
                        <div className="flex items-center gap-3 mt-2">
                          <div className="flex-1 h-1.5 bg-brand-bg-surface rounded-full overflow-hidden max-w-xs">
                            <motion.div initial={{ width: 0 }} animate={{ width: `${reg.score}%` }} transition={{ duration: 1, delay: i * 0.1 }} className={`h-full rounded-full ${isAtRisk ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                          </div>
                          <span className={`text-xs font-medium ${isAtRisk ? 'text-amber-400' : 'text-emerald-400'}`}>{reg.score}%</span>
                        </div>
                      </div>
                      <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border shrink-0 ${isAtRisk ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'}`}>{reg.status}</span>
                      <ChevronDown size={16} className={`text-neutral-500 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
                    </div>
                    <AnimatePresence>
                      {isOpen && (
                        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                          <div className="px-5 pb-4 ml-[52px]">
                            <div className="bg-brand-bg-surface rounded-xl p-4 border border-brand-border/50 space-y-3 text-sm">
                              <p className="text-neutral-300 leading-relaxed">{reg.details}</p>
                              <div className="grid grid-cols-2 gap-3 pt-2">
                                <div><span className="text-neutral-500 text-xs">Last Audit:</span> <span className="text-white text-xs ml-1">{new Date(reg.lastAudit).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span></div>
                                <div><span className="text-neutral-500 text-xs">Next Audit:</span> <span className="text-white text-xs ml-1">{new Date(reg.nextAudit).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span></div>
                              </div>
                              {isAtRisk && <p className="text-amber-400 text-xs pt-1">⚠ Remediation plan required before next audit cycle.</p>}
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Audit Log */}
        <div className="lg:col-span-4">
          <div className="bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden h-full flex flex-col">
            <div className="px-5 py-3 border-b border-brand-border bg-brand-bg-surface flex items-center gap-2">
              <Clock size={14} className="text-brand-primary" />
              <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Audit Log</p>
            </div>
            <div className="divide-y divide-brand-border/50 flex-1 overflow-y-auto">
              {auditLog.map((entry, i) => (
                <motion.div key={i} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }} className="px-5 py-3.5 hover:bg-white/[0.015] transition-colors">
                  <p className="text-sm text-neutral-300 leading-snug">{entry.event}</p>
                  <div className="flex items-center justify-between mt-1.5">
                    <span className="text-[11px] text-neutral-500">{new Date(entry.date).toLocaleDateString()}</span>
                    <span className={`text-[11px] font-medium ${resultStyle[entry.result]}`}>{entry.result}</span>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
