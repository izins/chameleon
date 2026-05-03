import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FileText, AlertTriangle, Shield, Clock, CheckCircle2, ChevronRight, X, ArrowRight, ArrowLeft, Download, Printer, Scale, Lock, BookOpen, ExternalLink } from 'lucide-react';
import { api } from '../../services/api';

const sevStyle = {
  Critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', dot: 'bg-red-500' },
  High: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', dot: 'bg-orange-500' },
  Medium: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20', dot: 'bg-amber-500' },
  Low: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20', dot: 'bg-emerald-500' },
};

/* ═══ Regulatory Detail Modal ═══ */
const IncidentModal = ({ attack, law, onClose }) => {
  const [tab, setTab] = useState('summary');
  const [downloading, setDownloading] = useState(false);
  if (!attack) return null;

  const ps = sevStyle[attack.severity_label] || sevStyle.Medium;
  const cert = attack.cert_dz || {};
  const anpdp = attack.anpdp || {};
  const impact = attack.impact || {};
  const loi = law?.loi_18_07 || {};
  const decret = law?.decret_20_05 || {};
  const anpdpLaw = law?.anpdp || {};
  const penal = law?.code_penal_cyber || {};

  const handlePDF = async () => {
    setDownloading(true);
    await api.downloadPDF(attack.report_id);
    setDownloading(false);
  };

  const tabs = [
    { id: 'summary', label: 'Résumé' },
    { id: 'forensic', label: 'Analyse' },
    { id: 'certdz', label: 'CERT-DZ' },
    { id: 'anpdp', label: 'ANPDP' },
    { id: 'law', label: 'Loi 18-07' },
    { id: 'blockchain', label: 'Blockchain' },
  ];

  const Section = ({ title, children }) => (
    <div className="bg-brand-bg-surface rounded-xl p-4 border border-brand-border/50">
      <p className="text-[11px] text-neutral-500 uppercase tracking-wider mb-2">{title}</p>
      {children}
    </div>
  );

  const Field = ({ label, value, mono, accent }) => (
    <div className="flex justify-between items-start py-1.5 border-b border-brand-border/20 last:border-0">
      <span className="text-xs text-neutral-500 shrink-0 w-40">{label}</span>
      <span className={`text-xs text-right ${mono ? 'font-mono' : ''} ${accent || 'text-neutral-300'}`}>{value || '—'}</span>
    </div>
  );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onClick={onClose}>
      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} onClick={e => e.stopPropagation()} className="bg-brand-bg-card border border-brand-border rounded-2xl w-full max-w-4xl shadow-2xl overflow-hidden max-h-[92vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-brand-border bg-brand-bg-surface shrink-0">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Scale size={18} className="text-brand-info" />
              {attack.id} — {attack.attack_type}
            </h2>
            <div className="flex gap-2 mt-1">
              <span className={`px-2 py-0.5 text-[10px] font-medium rounded-full border ${ps.bg} ${ps.text} ${ps.border}`}>{attack.severity_label}</span>
              <span className="px-2 py-0.5 text-[10px] font-mono text-neutral-400 bg-brand-bg-surface border border-brand-border rounded">{attack.entity_id}</span>
              {attack.blockchain_verified && <span className="px-2 py-0.5 text-[10px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-full">⛓ Verified</span>}
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={handlePDF} disabled={downloading} className="flex items-center gap-1.5 px-3 py-2 bg-brand-primary/10 border border-brand-primary/20 rounded-lg text-xs text-brand-primary hover:bg-brand-primary/20 transition-all disabled:opacity-50">
              <Download size={14} /> {downloading ? 'Generating...' : 'PDF Report'}
            </button>
            <button onClick={onClose} className="text-neutral-400 hover:text-white p-2 rounded-lg hover:bg-white/5"><X size={18} /></button>
          </div>
        </div>

        {/* Tab Bar */}
        <div className="flex gap-1 px-5 py-2 border-b border-brand-border/50 bg-brand-bg-surface/50 shrink-0 overflow-x-auto">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all whitespace-nowrap ${tab === t.id ? 'bg-brand-primary/10 text-brand-primary border border-brand-primary/20' : 'text-neutral-400 hover:text-white'}`}>{t.label}</button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {tab === 'summary' && (<>
            <Section title="Executive Summary">
              <p className="text-sm text-neutral-300 leading-relaxed">{attack.executive_summary || 'No summary available.'}</p>
            </Section>
            <div className="grid grid-cols-2 gap-3">
              <Section title="Risk Assessment">
                <Field label="Risk Score" value={`${attack.risk_score?.toFixed(2)} / 10`} accent="text-red-400" />
                <Field label="Risk Label" value={attack.risk_label} />
                <Field label="Kill Chain" value={attack.kill_chain} />
                <Field label="Dwell Time" value={attack.dwell_time} />
              </Section>
              <Section title="CIA Impact">
                <Field label="Confidentiality" value={`${impact.confidentiality}/10`} />
                <Field label="Integrity" value={`${impact.integrity}/10`} />
                <Field label="Availability" value={`${impact.availability}/10`} />
                <Field label="Overall" value={`${impact.overall}/10`} accent="text-brand-primary" />
              </Section>
            </div>
            <Section title="Applicable Regulations">
              {(attack.regulations || []).map((reg, i) => (
                <div key={i} className="flex items-start gap-2 py-1.5 border-b border-brand-border/20 last:border-0">
                  <span className="text-[10px] px-1.5 py-0.5 bg-brand-info/10 text-brand-info rounded font-mono shrink-0">{reg.reg_id}</span>
                  <div className="flex-1">
                    <p className="text-xs text-white">{reg.name}</p>
                    <p className="text-[10px] text-neutral-500">Deadline: {reg.deadline_hours}h — Penalty: {reg.penalty?.slice(0, 80)}</p>
                  </div>
                </div>
              ))}
            </Section>
          </>)}

          {tab === 'forensic' && (<>
            <Section title="Forensic Analysis">
              <Field label="Classification" value={attack.attack_type} accent="text-white font-semibold" />
              <Field label="Attack Vector" value={attack.attack_vector} />
              <Field label="Root Cause" value={attack.root_cause} />
              <Field label="MITRE Techniques" value={(attack.mitre || []).join(', ')} mono accent="text-brand-primary" />
              <Field label="CVEs Exploited" value={(attack.cves || []).join(', ')} mono accent="text-red-400" />
              <Field label="Lateral Risk" value={attack.lateral_risk} />
              <Field label="Data at Risk" value={attack.data_at_risk} />
              <Field label="IoC Summary" value={attack.ioc_summary} />
            </Section>
            <Section title="Investigation Steps">
              {(attack.investigation_steps || []).map((s, i) => (
                <div key={i} className="flex gap-2 py-1 text-xs text-neutral-300"><span className="text-brand-primary font-bold">{i+1}.</span>{s}</div>
              ))}
            </Section>
            <Section title="Recommendations">
              {(attack.recommendations || []).map((r, i) => (
                <div key={i} className="flex gap-2 py-1 text-xs text-neutral-300"><CheckCircle2 size={12} className="text-emerald-400 shrink-0 mt-0.5" />{r}</div>
              ))}
            </Section>
          </>)}

          {tab === 'certdz' && (<>
            <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4">
              <h3 className="text-sm font-semibold text-red-400 flex items-center gap-2 mb-1"><AlertTriangle size={16} /> Notification CERT-DZ Obligatoire</h3>
              <p className="text-xs text-neutral-400">{decret.full_title || 'Décret exécutif n° 20-05'}</p>
              <p className="text-lg font-bold text-red-400 mt-2">Délai: {decret.notification_deadline_hours || 24}h — Reste: {cert.hours_remaining}h</p>
            </div>
            <Section title="Détails de la Notification">
              <Field label="Deadline" value={cert.deadline} accent="text-red-400" />
              <Field label="Référence légale" value={cert.regulatory_reference} />
              <Field label="Nature de l'incident" value={cert.nature_of_breach} />
              <Field label="IP Source" value={cert.source_ip} mono />
              <Field label="Systèmes affectés" value={cert.affected_systems} />
              <Field label="Mesures de confinement" value={cert.containment_measures} />
              <Field label="Impact" value={cert.impact_assessment} />
              <Field label="Préservation des preuves" value={cert.evidence_preservation} />
              <Field label="Risque légal org." value={cert.legal_liability_risk} accent="text-orange-400" />
              <Field label="Pénalité attaquant" value={cert.penalties_for_attacker} accent="text-red-400" />
            </Section>
            <Section title="Champs Requis (Décret 20-05)">
              {(decret.required_fields || []).map((f, i) => (
                <div key={i} className="flex items-center gap-2 py-1 text-xs text-neutral-300"><CheckCircle2 size={12} className="text-brand-primary" />{f}</div>
              ))}
            </Section>
          </>)}

          {tab === 'anpdp' && (<>
            <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4">
              <h3 className="text-sm font-semibold text-amber-400 flex items-center gap-2 mb-1"><Lock size={16} /> Notification ANPDP — Loi 18-07</h3>
              <p className="text-xs text-neutral-400">{anpdpLaw.name}</p>
              <p className="text-lg font-bold text-amber-400 mt-2">Délai: {anpdpLaw.notification_deadline_hours || 72}h — Reste: {anpdp.hours_remaining}h</p>
            </div>
            <Section title="Détails de la Notification">
              <Field label="Deadline" value={anpdp.deadline} accent="text-amber-400" />
              <Field label="Référence légale" value={anpdp.regulatory_reference} />
              <Field label="Nature" value={anpdp.nature_of_breach} />
              <Field label="Catégories de données" value={anpdp.affected_data_categories} />
              <Field label="Personnes concernées" value={anpdp.estimated_persons_affected} accent="text-white font-semibold" />
              <Field label="Conséquences probables" value={anpdp.likely_consequences} />
              <Field label="Risque perte données" value={anpdp.data_loss_risk} />
              <Field label="Amendes non-conformité" value={anpdp.fines_for_non_compliance} accent="text-red-400" />
            </Section>
            <Section title="Champs Requis ANPDP">
              {(anpdpLaw.required_fields || []).map((f, i) => (
                <div key={i} className="flex items-center gap-2 py-1 text-xs text-neutral-300"><CheckCircle2 size={12} className="text-amber-400" />{f}</div>
              ))}
            </Section>
          </>)}

          {tab === 'law' && (<>
            <Section title={loi.name || 'Loi n° 18-07'}>
              <p className="text-xs text-neutral-400 mb-3">{loi.full_title}</p>
              <p className="text-xs text-red-400 font-semibold mb-3">Sanctions maximales: {loi.max_prison} prison + {loi.max_fine} amende</p>
              {Object.entries(loi.key_articles || {}).map(([key, art]) => (
                <div key={key} className="py-2 border-b border-brand-border/20 last:border-0">
                  <p className="text-xs font-semibold text-brand-info">{key.replace('art_', 'Article ')} — {art.title}</p>
                  <p className="text-xs text-neutral-400 mt-1 leading-relaxed">{art.text}</p>
                </div>
              ))}
            </Section>
            <Section title="Code Pénal — Infractions Informatiques">
              {Object.entries(penal).map(([key, text]) => (
                <div key={key} className="py-1.5 border-b border-brand-border/20 last:border-0">
                  <p className="text-xs"><span className="text-brand-info font-mono">{key.replace('art_', 'Art. ')}</span> — <span className="text-neutral-300">{text}</span></p>
                </div>
              ))}
            </Section>
          </>)}

          {tab === 'blockchain' && (<>
            <Section title="Vérification Blockchain">
              {attack.blockchain_verified ? (
                <>
                  <Field label="Block Index" value={`#${attack.blockchain?.block_index}`} mono accent="text-brand-primary" />
                  <Field label="Block Hash" value={attack.blockchain?.block_hash} mono />
                  <Field label="Transaction ID" value={attack.blockchain?.tx_id} mono />
                  <Field label="Document Hash" value={attack.blockchain?.document_hash?.slice(0, 32) + '...'} mono />
                  <Field label="Anchored At" value={attack.blockchain?.anchored_at} />
                  <div className="mt-3 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                    <p className="text-xs text-emerald-400 font-semibold">✓ Preuve immuable vérifiée sur la chaîne AEGIS</p>
                    <p className="text-[10px] text-neutral-500 mt-1">Ce rapport est ancré de manière irréversible sur le registre blockchain. Conforme à la Loi 18-07 Art. 12 (obligation de préservation des preuves).</p>
                  </div>
                </>
              ) : (
                <p className="text-xs text-neutral-500">Aucune ancre blockchain trouvée pour ce rapport.</p>
              )}
            </Section>
          </>)}
        </div>
      </motion.div>
    </motion.div>
  );
};

/* ═══ MAIN COMPONENT ═══ */
export const LegalDashboard = () => {
  const [attacks, setAttacks] = useState([]);
  const [law, setLaw] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [filterSev, setFilterSev] = useState('All');

  useEffect(() => {
    (async () => {
      const data = await api.getUnifiedAttacks();
      if (data?.attacks) {
        setAttacks(data.attacks);
        setLaw(data.algerian_law || null);
      }
      setLoading(false);
    })();
  }, []);

  const filtered = attacks.filter(a => filterSev === 'All' || a.severity_label === filterSev);

  const stats = {
    total: attacks.length,
    critical: attacks.filter(a => a.severity === 'P1').length,
    certPending: attacks.filter(a => (a.cert_dz?.hours_remaining || 0) > 0).length,
    bcVerified: attacks.filter(a => a.blockchain_verified).length,
  };

  if (loading) return <div className="flex items-center justify-center h-64 text-neutral-500">Loading unified attack database...</div>;

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300">
      <div className="flex items-center justify-between pb-5 border-b border-brand-border">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight flex items-center gap-2"><Scale size={20} className="text-brand-info" /> Legal Compliance Dashboard</h1>
          <p className="text-xs text-neutral-500 mt-1">{attacks.length} incidents from unified database — Loi 18-07 & Décret 20-05 compliance</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-5">
        {[
          { label: 'Total Incidents', value: stats.total, accent: 'text-brand-info' },
          { label: 'Critical (P1)', value: stats.critical, accent: 'text-red-400' },
          { label: 'CERT-DZ Pending', value: stats.certPending, accent: 'text-amber-400' },
          { label: '⛓ Blockchain Verified', value: stats.bcVerified, accent: 'text-emerald-400' },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
            <p className="text-[11px] text-neutral-500 uppercase tracking-wider">{s.label}</p>
            <p className={`text-2xl font-bold mt-1 ${s.accent}`}>{s.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Severity Filter */}
      <div className="flex gap-2 pt-4">
        {['All', 'Critical', 'High', 'Medium', 'Low'].map(s => (
          <button key={s} onClick={() => setFilterSev(s)} className={`px-4 py-2 text-xs font-medium rounded-lg border transition-all ${filterSev === s ? 'bg-brand-primary/10 border-brand-primary/20 text-brand-primary' : 'bg-brand-bg-card border-brand-border text-neutral-400 hover:text-white'}`}>{s}</button>
        ))}
      </div>

      {/* Incidents Table */}
      <div className="mt-4 bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden flex-1">
        <div className="px-5 py-3 border-b border-brand-border bg-brand-bg-surface grid grid-cols-12 gap-3 text-[11px] text-neutral-500 uppercase tracking-wider font-semibold">
          <span className="col-span-1">ID</span>
          <span className="col-span-2">Attack Type</span>
          <span className="col-span-2">Entity</span>
          <span className="col-span-1">Risk</span>
          <span className="col-span-1">Severity</span>
          <span className="col-span-2">CERT-DZ</span>
          <span className="col-span-2">ANPDP</span>
          <span className="col-span-1">⛓</span>
        </div>
        <div className="divide-y divide-brand-border/50 max-h-[50vh] overflow-y-auto">
          {filtered.map((a, i) => {
            const ps = sevStyle[a.severity_label] || sevStyle.Medium;
            return (
              <motion.div key={a.id + i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }} className="grid grid-cols-12 gap-3 items-center px-5 py-3 hover:bg-white/[0.015] cursor-pointer group" onClick={() => setSelectedAttack(a)}>
                <span className="col-span-1 text-xs font-mono text-neutral-400">{a.id}</span>
                <span className="col-span-2 text-sm text-white font-medium truncate">{a.attack_type}</span>
                <span className="col-span-2 text-xs font-mono text-neutral-500 truncate">{a.entity_id}</span>
                <span className="col-span-1 text-xs font-semibold text-red-400">{a.risk_score?.toFixed(1)}</span>
                <span className="col-span-1"><span className={`px-2 py-0.5 text-[10px] font-medium rounded-full border ${ps.bg} ${ps.text} ${ps.border}`}>{a.severity_label}</span></span>
                <span className="col-span-2 text-[10px] text-neutral-500">{a.cert_dz?.hours_remaining > 0 ? <span className="text-amber-400">{a.cert_dz.hours_remaining}h left</span> : <span className="text-emerald-400">Notified</span>}</span>
                <span className="col-span-2 text-[10px] text-neutral-500">{a.anpdp?.hours_remaining > 0 ? <span className="text-amber-400">{a.anpdp.hours_remaining}h left</span> : <span className="text-emerald-400">Notified</span>}</span>
                <span className="col-span-1">{a.blockchain_verified ? <span className="text-emerald-400 text-xs">✓</span> : <span className="text-neutral-600 text-xs">—</span>}</span>
              </motion.div>
            );
          })}
        </div>
      </div>

      <AnimatePresence>
        {selectedAttack && <IncidentModal attack={selectedAttack} law={law} onClose={() => setSelectedAttack(null)} />}
      </AnimatePresence>
    </div>
  );
};
