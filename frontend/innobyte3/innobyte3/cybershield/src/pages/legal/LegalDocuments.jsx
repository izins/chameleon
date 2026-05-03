import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FileText, Download, Share2, Printer, Eye, Clock, CheckCircle2, X, Scale } from 'lucide-react';

const documents = [
  { id: 'DOC-001', title: 'Ransomware Incident Legal Report', type: 'Incident Report', date: '2026-05-01', status: 'Final', relatedIncident: 'INC-2026-002', content: 'Comprehensive legal analysis of ransomware incident affecting file servers. No customer data exposed. Containment achieved within 12 minutes. Regulatory notification not required per current assessment. All evidence preserved for potential forensic review.' },
  { id: 'DOC-002', title: 'Phishing Campaign Legal Assessment', type: 'Legal Assessment', date: '2026-04-28', status: 'Final', relatedIncident: 'INC-2026-001', content: 'Legal assessment of spear phishing campaign targeting HR. 4 employees interacted with malicious content. MFA prevented credential compromise. No data breach confirmed. Employee retraining documented as corrective measure.' },
  { id: 'DOC-003', title: 'Data Breach Notification Template', type: 'Notification', date: '2026-04-25', status: 'Draft', relatedIncident: 'INC-2026-003', content: 'Draft notification to affected customers regarding potential PII exposure from third-party vendor breach. Template includes required disclosures per Law 18-07 and recommended protective actions for affected individuals.' },
  { id: 'DOC-004', title: 'Q1 2026 Compliance Summary', type: 'Compliance Report', date: '2026-04-01', status: 'Final', relatedIncident: null, content: 'Quarterly compliance summary covering ISO 27035 adherence, incident response metrics, policy updates, and audit readiness assessment. Overall compliance score: 94%. Two minor findings addressed.' },
  { id: 'DOC-005', title: 'Insider Threat Investigation Brief', type: 'Investigation', date: '2026-04-28', status: 'Under Review', relatedIncident: 'INC-2026-006', content: 'Preliminary legal brief on insider threat investigation. Employee data access patterns analyzed. Legal hold placed on relevant communications and file access logs. HR coordination initiated for formal review process.' },
  { id: 'DOC-006', title: 'Device Loss Incident Closure', type: 'Incident Report', date: '2026-04-21', status: 'Final', relatedIncident: 'INC-2026-004', content: 'Final report on lost device incident. Remote wipe confirmed successful. No sensitive data exposure. Insurance claim filed. Updated device handling policy distributed to sales team.' },
];

const typeStyles = {
  'Incident Report': 'bg-red-500/10 text-red-400 border-red-500/20',
  'Legal Assessment': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  'Notification': 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  'Compliance Report': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  'Investigation': 'bg-purple-500/10 text-purple-400 border-purple-500/20',
};

const statusBadge = {
  Final: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  'Under Review': 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  Draft: 'bg-neutral-500/10 text-neutral-400 border-neutral-500/20',
};

const DocModal = ({ doc, onClose }) => {
  if (!doc) return null;
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onClick={onClose}>
      <motion.div initial={{ opacity: 0, scale: 0.95, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.95 }} onClick={e => e.stopPropagation()} className="bg-brand-bg-card border border-brand-border rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between p-5 border-b border-brand-border bg-brand-bg-surface">
          <h2 className="text-lg font-semibold text-white">{doc.title}</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-white p-2 rounded-lg hover:bg-white/5"><X size={18} /></button>
        </div>
        <div className="p-6 space-y-4">
          <div className="flex gap-2 flex-wrap">
            <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border ${typeStyles[doc.type]}`}>{doc.type}</span>
            <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border ${statusBadge[doc.status]}`}>{doc.status}</span>
            {doc.relatedIncident && <span className="px-2.5 py-1 text-[11px] font-medium rounded-full border bg-brand-bg-surface text-neutral-300 border-brand-border">{doc.relatedIncident}</span>}
          </div>
          <div className="bg-brand-bg-surface rounded-xl p-4 border border-brand-border/50">
            <p className="text-sm text-neutral-300 leading-relaxed">{doc.content}</p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-brand-bg-surface rounded-lg p-3 border border-brand-border/50">
              <p className="text-[11px] text-neutral-500 uppercase tracking-wider mb-1">Document ID</p>
              <p className="text-sm text-white font-medium">{doc.id}</p>
            </div>
            <div className="bg-brand-bg-surface rounded-lg p-3 border border-brand-border/50">
              <p className="text-[11px] text-neutral-500 uppercase tracking-wider mb-1">Date</p>
              <p className="text-sm text-white font-medium">{new Date(doc.date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button className="flex-1 flex items-center justify-center gap-2 py-3 bg-brand-primary/10 text-brand-primary border border-brand-primary/20 rounded-xl text-sm font-medium hover:bg-brand-primary/20 transition-all"><Download size={16} /> Download PDF</button>
            <button className="flex-1 flex items-center justify-center gap-2 py-3 bg-brand-bg-surface text-neutral-300 border border-brand-border rounded-xl text-sm font-medium hover:bg-white/5 transition-all"><Share2 size={16} /> Share</button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};

export const LegalDocuments = () => {
  const [selectedDoc, setSelectedDoc] = useState(null);
  const [filterType, setFilterType] = useState('All');
  const types = ['All', ...new Set(documents.map(d => d.type))];
  const filtered = documents.filter(d => filterType === 'All' || d.type === filterType);

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300">
      <div className="flex items-center justify-between pb-6 border-b border-brand-border">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight flex items-center gap-2"><FileText size={20} className="text-brand-info" /> Legal Documents</h1>
          <p className="text-xs text-neutral-500 mt-1">All legal reports, assessments, and compliance documentation.</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2.5 bg-brand-primary/10 text-brand-primary border border-brand-primary/20 rounded-xl text-sm font-medium hover:bg-brand-primary/20 transition-all"><Download size={16} /> Export All</button>
      </div>

      {/* Filter */}
      <div className="flex gap-2 pt-5 flex-wrap">
        {types.map(t => (
          <button key={t} onClick={() => setFilterType(t)} className={`px-4 py-2 text-xs font-medium rounded-lg border transition-all ${filterType === t ? 'bg-brand-primary/10 border-brand-primary/20 text-brand-primary' : 'bg-brand-bg-card border-brand-border text-neutral-400 hover:text-white'}`}>{t}</button>
        ))}
      </div>

      {/* Documents List */}
      <div className="mt-4 bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden flex-1">
        <div className="divide-y divide-brand-border/50">
          {filtered.map((doc, i) => (
            <motion.div key={doc.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.04 }} className="flex items-center gap-4 px-5 py-4 hover:bg-white/[0.015] transition-colors cursor-pointer group" onClick={() => setSelectedDoc(doc)}>
              <div className="w-10 h-10 rounded-xl bg-brand-bg-surface border border-brand-border flex items-center justify-center shrink-0">
                <FileText size={18} className="text-brand-info" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white truncate group-hover:text-brand-primary transition-colors">{doc.title}</p>
                <div className="flex items-center gap-3 mt-1 text-xs text-neutral-500">
                  <span>{doc.id}</span><span>·</span>
                  <span className="flex items-center gap-1"><Clock size={10} /> {new Date(doc.date).toLocaleDateString()}</span>
                  {doc.relatedIncident && <><span>·</span><span>{doc.relatedIncident}</span></>}
                </div>
              </div>
              <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border shrink-0 hidden sm:inline-block ${typeStyles[doc.type]}`}>{doc.type}</span>
              <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border shrink-0 ${statusBadge[doc.status]}`}>{doc.status}</span>
              <Eye size={16} className="text-neutral-600 group-hover:text-brand-primary shrink-0 transition-colors" />
            </motion.div>
          ))}
        </div>
      </div>

      <AnimatePresence>
        {selectedDoc && <DocModal doc={selectedDoc} onClose={() => setSelectedDoc(null)} />}
      </AnimatePresence>
    </div>
  );
};
