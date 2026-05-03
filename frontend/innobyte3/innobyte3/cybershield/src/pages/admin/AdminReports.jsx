import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FileText, Download, Share2, Shield, CheckCircle2, AlertTriangle, Clock, ChevronDown, Printer, Eye } from 'lucide-react';

/* ═══ Mock Report Data ═══ */
const legalReports = [
  {
    id: 'LR-2026-001',
    title: 'Ransomware Incident Response Report',
    date: '2026-05-01',
    status: 'Final',
    severity: 'Critical',
    summary: 'Multiple file servers compromised with encrypted extensions. Immediate containment executed within 12 minutes. No data exfiltration confirmed. All affected systems restored from clean backups within 48 hours.',
    impact: 'High — Operational disruption for 6 hours. No customer data exposure confirmed.',
    actions: ['Network segments isolated immediately', 'Affected servers wiped and restored from backups', 'All credentials rotated organization-wide', 'Employee awareness training initiated', 'Authorities notified per Law 18-07 Article 22'],
  },
  {
    id: 'LR-2026-002',
    title: 'Phishing Campaign Analysis Report',
    date: '2026-04-28',
    status: 'Final',
    severity: 'Medium',
    summary: 'Spear phishing campaign targeted HR department with 23 malicious emails. 4 employees clicked the link. No credential compromise detected thanks to MFA enforcement.',
    impact: 'Low — No data breach. 4 endpoints quarantined and cleaned.',
    actions: ['Malicious domains blocked at firewall level', 'Affected endpoints isolated and scanned', 'Mandatory phishing awareness training deployed', 'Email gateway rules updated'],
  },
  {
    id: 'LR-2026-003',
    title: 'Data Breach Investigation Report',
    date: '2026-04-25',
    status: 'Under Review',
    severity: 'Critical',
    summary: 'Customer PII data found on dark web forum. Investigation confirmed the breach originated from a third-party vendor system, not internal infrastructure.',
    impact: 'High — Potential exposure of 1,200 customer records. Vendor notified and contract review initiated.',
    actions: ['Third-party vendor access revoked', 'Affected customers notified within 72 hours', 'Legal team engaged for regulatory compliance', 'Enhanced vendor risk assessment implemented'],
  },
];

const complianceItems = [
  { name: 'ISO 27035 Compliance', status: 'Compliant', progress: 94, lastAudit: '2026-03-15' },
  { name: 'Law 18-07 Adherence', status: 'Compliant', progress: 98, lastAudit: '2026-04-01' },
  { name: 'Data Protection Policy', status: 'Compliant', progress: 91, lastAudit: '2026-02-20' },
  { name: 'Incident Notification SLA', status: 'At Risk', progress: 76, lastAudit: '2026-04-28' },
  { name: 'Access Control Policy', status: 'Compliant', progress: 88, lastAudit: '2026-03-30' },
  { name: 'Audit Trail Integrity', status: 'Compliant', progress: 100, lastAudit: '2026-04-15' },
];

const sevStyles = {
  Critical: 'bg-red-500/10 text-red-400 border-red-500/20',
  Medium: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  Low: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
};

const statusBadge = {
  Final: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  'Under Review': 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  Draft: 'bg-neutral-500/10 text-neutral-400 border-neutral-500/20',
};

/* ═══ Report Detail Modal ═══ */
const ReportModal = ({ report, onClose }) => {
  if (!report) return null;
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        onClick={e => e.stopPropagation()}
        className="bg-brand-bg-card border border-brand-border rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col"
      >
        <div className="flex items-center justify-between p-5 border-b border-brand-border bg-brand-bg-surface shrink-0">
          <div>
            <h2 className="text-lg font-semibold text-white">{report.title}</h2>
            <p className="text-xs text-neutral-500 mt-1">{report.id} · {new Date(report.date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
          </div>
          <button onClick={onClose} className="text-neutral-400 hover:text-white transition-colors p-2 rounded-lg hover:bg-white/5">✕</button>
        </div>

        <div className="p-6 space-y-5 overflow-y-auto">
          <div className="flex gap-2">
            <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border ${sevStyles[report.severity]}`}>{report.severity}</span>
            <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border ${statusBadge[report.status]}`}>{report.status}</span>
          </div>

          <div>
            <h4 className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Executive Summary</h4>
            <p className="text-sm text-neutral-300 leading-relaxed bg-brand-bg-surface rounded-xl p-4 border border-brand-border/50">{report.summary}</p>
          </div>

          <div>
            <h4 className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Impact Assessment</h4>
            <p className="text-sm text-neutral-300 leading-relaxed bg-brand-bg-surface rounded-xl p-4 border border-brand-border/50">{report.impact}</p>
          </div>

          <div>
            <h4 className="text-xs text-neutral-500 uppercase tracking-wider mb-2">Actions Taken</h4>
            <div className="space-y-2">
              {report.actions.map((action, i) => (
                <div key={i} className="flex items-start gap-2.5 text-sm text-neutral-300">
                  <CheckCircle2 size={16} className="text-brand-primary shrink-0 mt-0.5" />
                  <span>{action}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Mock Export Actions */}
          <div className="flex gap-3 pt-2">
            <button className="flex-1 flex items-center justify-center gap-2 py-3 bg-brand-primary/10 text-brand-primary border border-brand-primary/20 rounded-xl text-sm font-medium hover:bg-brand-primary/20 transition-all">
              <Download size={16} /> Download PDF
            </button>
            <button className="flex-1 flex items-center justify-center gap-2 py-3 bg-brand-bg-surface text-neutral-300 border border-brand-border rounded-xl text-sm font-medium hover:bg-white/5 transition-all">
              <Share2 size={16} /> Share Report
            </button>
            <button className="flex items-center justify-center gap-2 px-4 py-3 bg-brand-bg-surface text-neutral-300 border border-brand-border rounded-xl text-sm font-medium hover:bg-white/5 transition-all">
              <Printer size={16} />
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};

/* ═══ MAIN COMPONENT ═══ */
export const AdminReports = () => {
  const [activeTab, setActiveTab] = useState('legal');
  const [selectedReport, setSelectedReport] = useState(null);
  const [expandedCompliance, setExpandedCompliance] = useState(null);

  const tabs = [
    { id: 'legal', label: 'Legal Reports', icon: FileText },
    { id: 'compliance', label: 'Compliance', icon: Shield },
  ];

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300">
      {/* Header */}
      <div className="flex items-center justify-between pb-6 border-b border-brand-border">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight flex items-center gap-2">
            <FileText size={20} className="text-brand-info" /> Reports
          </h1>
          <p className="text-xs text-neutral-500 mt-1">Legal documentation and compliance status.</p>
        </div>
        <div className="flex gap-2">
          <button className="flex items-center gap-2 px-4 py-2.5 bg-brand-primary/10 text-brand-primary border border-brand-primary/20 rounded-xl text-sm font-medium hover:bg-brand-primary/20 transition-all">
            <Download size={16} /> Export All
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 pt-5 border-b border-brand-border">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-5 py-3 text-sm font-medium border-b-2 transition-all -mb-[1px] ${activeTab === tab.id ? 'text-brand-primary border-brand-primary' : 'text-neutral-500 border-transparent hover:text-neutral-300'}`}
          >
            <tab.icon size={16} />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="pt-5 flex-1">
        <AnimatePresence mode="wait">
          {activeTab === 'legal' ? (
            <motion.div
              key="legal"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-4"
            >
              {/* Summary */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-2">
                <div className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
                  <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Total Reports</p>
                  <p className="text-2xl font-bold text-white mt-1">{legalReports.length}</p>
                </div>
                <div className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
                  <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Finalized</p>
                  <p className="text-2xl font-bold text-emerald-400 mt-1">{legalReports.filter(r => r.status === 'Final').length}</p>
                </div>
                <div className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
                  <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Under Review</p>
                  <p className="text-2xl font-bold text-amber-400 mt-1">{legalReports.filter(r => r.status === 'Under Review').length}</p>
                </div>
              </div>

              {/* Reports List */}
              <div className="bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden">
                <div className="px-5 py-3 border-b border-brand-border bg-brand-bg-surface">
                  <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Incident Reports</p>
                </div>
                <div className="divide-y divide-brand-border/50">
                  {legalReports.map((report, i) => (
                    <motion.div
                      key={report.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.05 }}
                      className="flex items-center gap-4 px-5 py-4 hover:bg-white/[0.015] transition-colors cursor-pointer group"
                      onClick={() => setSelectedReport(report)}
                    >
                      <div className="w-10 h-10 rounded-xl bg-brand-bg-surface border border-brand-border flex items-center justify-center shrink-0">
                        <FileText size={18} className="text-brand-info" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-white truncate group-hover:text-brand-primary transition-colors">{report.title}</p>
                        <div className="flex items-center gap-3 mt-1 text-xs text-neutral-500">
                          <span>{report.id}</span>
                          <span>·</span>
                          <span className="flex items-center gap-1"><Clock size={10} /> {new Date(report.date).toLocaleDateString()}</span>
                        </div>
                      </div>
                      <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border shrink-0 ${sevStyles[report.severity]}`}>
                        {report.severity}
                      </span>
                      <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border shrink-0 ${statusBadge[report.status]}`}>
                        {report.status}
                      </span>
                      <Eye size={16} className="text-neutral-600 group-hover:text-brand-primary shrink-0 transition-colors" />
                    </motion.div>
                  ))}
                </div>
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="compliance"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-4"
            >
              {/* Compliance Overview */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-2">
                <div className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
                  <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Overall Score</p>
                  <p className="text-2xl font-bold text-brand-primary mt-1">91%</p>
                </div>
                <div className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
                  <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Audit Ready</p>
                  <p className="text-2xl font-bold text-emerald-400 mt-1 flex items-center gap-2">
                    <CheckCircle2 size={20} /> Yes
                  </p>
                </div>
                <div className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
                  <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Policies at Risk</p>
                  <p className="text-2xl font-bold text-amber-400 mt-1">{complianceItems.filter(c => c.status === 'At Risk').length}</p>
                </div>
              </div>

              {/* Compliance Items */}
              <div className="bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden">
                <div className="px-5 py-3 border-b border-brand-border bg-brand-bg-surface">
                  <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Policy Adherence</p>
                </div>
                <div className="divide-y divide-brand-border/50">
                  {complianceItems.map((item, i) => {
                    const isAtRisk = item.status === 'At Risk';
                    const isExpanded = expandedCompliance === i;
                    return (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: i * 0.05 }}
                      >
                        <div
                          className="flex items-center gap-4 px-5 py-4 hover:bg-white/[0.015] transition-colors cursor-pointer"
                          onClick={() => setExpandedCompliance(isExpanded ? null : i)}
                        >
                          <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${isAtRisk ? 'bg-amber-500/10 text-amber-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
                            {isAtRisk ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-white">{item.name}</p>
                            <div className="flex items-center gap-3 mt-2">
                              <div className="flex-1 h-1.5 bg-brand-bg-surface rounded-full overflow-hidden">
                                <motion.div
                                  initial={{ width: 0 }}
                                  animate={{ width: `${item.progress}%` }}
                                  transition={{ duration: 1, delay: i * 0.1 }}
                                  className={`h-full rounded-full ${isAtRisk ? 'bg-amber-500' : 'bg-emerald-500'}`}
                                />
                              </div>
                              <span className={`text-xs font-medium ${isAtRisk ? 'text-amber-400' : 'text-emerald-400'}`}>{item.progress}%</span>
                            </div>
                          </div>
                          <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border shrink-0 ${isAtRisk ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'}`}>
                            {item.status}
                          </span>
                          <ChevronDown size={16} className={`text-neutral-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                        </div>
                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                              className="overflow-hidden"
                            >
                              <div className="px-5 pb-4 pl-18 ml-[52px]">
                                <div className="bg-brand-bg-surface rounded-xl p-4 border border-brand-border/50 text-sm text-neutral-400 space-y-2">
                                  <p><span className="text-neutral-500">Last Audit:</span> <span className="text-white">{new Date(item.lastAudit).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</span></p>
                                  <p><span className="text-neutral-500">Adherence:</span> <span className="text-white">{item.progress}% compliant</span></p>
                                  {isAtRisk && <p className="text-amber-400 text-xs">⚠ Action required — Review and update before next audit cycle.</p>}
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
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Report Modal */}
      <AnimatePresence>
        {selectedReport && <ReportModal report={selectedReport} onClose={() => setSelectedReport(null)} />}
      </AnimatePresence>
    </div>
  );
};
