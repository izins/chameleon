import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowLeft, CheckCircle, Circle, Clock, Terminal, Lock, ShieldAlert } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import { api } from '../../services/api';

/* Static fallback — only used when backend has no playbook */
const FALLBACK_STEPS = [
  { id: 1, title: 'Isolate Affected Users', description: 'Disconnect affected user endpoints from the network.', role: 'IT/CS Engineer', sla: 'Within 15 minutes', legalRef: 'ISO 27035 Phase 3', status: 'Done' },
  { id: 2, title: 'Analyze Email Headers', description: 'Extract sender IP, domain, and malicious URLs.', role: 'SOC Analyst', sla: 'Within 30 minutes', legalRef: '', status: 'In Progress' },
  { id: 3, title: 'Block Malicious Domains', description: 'Add extracted IOCs to firewall blocklist.', role: 'IT/CS Engineer', sla: 'Within 1 hour', legalRef: '', status: 'Not Started' },
];

export const IncidentDetail = () => {
  const { id } = useParams();
  const { incidents } = useAppStore();
  const incident = incidents.find(i => i.id === id);

  const [steps, setSteps] = useState([]);

  useEffect(() => {
    // Fetch live playbook from backend, fallback to static
    (async () => {
      const attackType = incident?.attackType || 'unknown';
      const liveSteps = await api.getWorkflow(attackType);
      if (liveSteps && liveSteps.length > 0) {
        setSteps(liveSteps);
      } else {
        setSteps(FALLBACK_STEPS.map(s => ({ ...s })));
      }
    })();
  }, [incident]);

  const toggleStep = (idx) => {
    setSteps(prev => prev.map((s, i) => i === idx ? { ...s, status: s.status === 'Done' ? 'Not Started' : 'Done' } : s));
  };

  const done = steps.filter(s => s.status === 'Done').length;
  const progress = steps.length ? Math.round((done / steps.length) * 100) : 0;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3">
        <Link to="/engineer/incidents" className="p-2 rounded-md bg-brand-bg-card border border-brand-border hover:border-brand-border-bright transition-colors">
          <ArrowLeft size={18} className="text-neutral-400" />
        </Link>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-white">{incident?.attackType || 'Incident'}</h1>
            <span className="px-2 py-0.5 text-[11px] font-bold rounded bg-red-500/10 text-red-500">{incident?.severity || 'High'}</span>
          </div>
          <p className="text-neutral-500 text-sm font-mono mt-0.5">{id}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-brand-bg-card border border-brand-border rounded-md p-6">
          <div className="flex justify-between items-end mb-6">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-2"><Terminal size={18} className="text-brand-primary" /> Execution Workflow</h2>
              <p className="text-sm text-neutral-500 mt-1">ISO 27035 aligned response procedure</p>
            </div>
            <div className="text-right">
              <span className="text-2xl font-bold text-white">{progress}%</span>
              <p className="text-[11px] text-neutral-600 uppercase tracking-wider">Complete</p>
            </div>
          </div>

          <div className="w-full h-1.5 bg-brand-bg-elevated rounded-full mb-8 overflow-hidden">
            <motion.div animate={{ width: `${progress}%` }} className="h-full bg-brand-primary rounded-full" transition={{ duration: 0.5 }} />
          </div>

          <div className="space-y-4">
            {steps.map((step, idx) => {
              const isDone = step.status === 'Done';
              const isActive = step.status === 'In Progress';
              return (
                <motion.div key={step.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.06 }}
                  onClick={() => toggleStep(idx)}
                  className={`p-4 rounded-md border cursor-pointer transition-all ${isDone ? 'border-brand-primary/20 bg-brand-primary/[0.03]' : 'border-brand-border bg-brand-bg-surface hover:border-brand-border-bright'}`}>
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5">
                      {isDone ? <CheckCircle size={20} className="text-brand-primary" /> : isActive ? <Clock size={20} className="text-yellow-500" /> : <Circle size={18} className="text-neutral-600" />}
                    </div>
                    <div className="flex-1">
                      <div className="flex justify-between items-start">
                        <h4 className={`font-medium ${isDone ? 'text-neutral-400 line-through' : 'text-white'}`}>{step.title}</h4>
                        <span className={`text-[11px] px-2 py-0.5 rounded font-medium ${isDone ? 'bg-brand-primary/10 text-brand-primary' : 'bg-brand-bg-elevated text-neutral-500'}`}>
                          {isDone ? 'Done' : 'Mark Done'}
                        </span>
                      </div>
                      <p className="text-sm text-neutral-500 mt-1">{step.description}</p>
                      <div className="flex gap-2 mt-2 flex-wrap">
                        <span className="text-[11px] bg-brand-bg-elevated px-2 py-0.5 rounded text-neutral-400 border border-brand-border">Role: <span className="text-brand-primary font-mono">{step.role}</span></span>
                        <span className="text-[11px] bg-brand-bg-elevated px-2 py-0.5 rounded text-neutral-400 border border-brand-border">SLA: <span className="text-brand-info">{step.sla}</span></span>
                        {step.legalRef && <span className="text-[11px] bg-brand-bg-elevated px-2 py-0.5 rounded text-neutral-300 border border-brand-border">⚖️ {step.legalRef}</span>}
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>

        <div className="space-y-5">
          <div className="bg-brand-bg-card border border-brand-border rounded-md p-5">
            <h3 className="text-white font-semibold mb-4 flex items-center gap-2 text-sm"><Lock size={16} className="text-brand-info" /> Incident Details</h3>
            <dl className="space-y-3 text-sm">
              {[['Status', incident?.status], ['Type', incident?.attackType], ['Assigned', incident?.assignedTo], ['Detected', incident?.detectedAt]].map(([k, v]) => (
                <div key={k} className="flex justify-between"><dt className="text-neutral-500">{k}</dt><dd className="text-white font-medium">{v || 'N/A'}</dd></div>
              ))}
            </dl>
          </div>

          <div className="bg-brand-bg-card border border-brand-border rounded-md p-5">
            <h3 className="text-white font-semibold mb-3 flex items-center gap-2 text-sm"><ShieldAlert size={16} className="text-orange-500" /> Actions</h3>
            <p className="text-sm text-neutral-500 mb-4">{incident?.description || 'Review and respond to this incident.'}</p>
            <Link to="/engineer/pentester-access" className="block w-full py-2.5 bg-brand-bg-elevated border border-brand-border text-brand-primary rounded-md font-medium hover:bg-brand-primary/10 transition-colors text-center text-sm">
              Grant Pentester Access
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
