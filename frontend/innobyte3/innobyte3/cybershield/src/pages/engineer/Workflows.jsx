import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, ArrowRight, Check, Clock, Circle, Lock, Bot, BookOpen, Download } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import { api } from '../../services/api';

/* ═══ DYNAMIC WORKFLOWS (100% Backend Driven) ═══ */
const WORKFLOWS = {};

export const Workflows = () => {
  const { incidents, fetchIncidents } = useAppStore();
  const [allWorkflows, setAllWorkflows] = useState({});
  const [types, setTypes] = useState([]);
  const [selected, setSelected] = useState(null);
  const [steps, setSteps] = useState([]);

  const refreshWorkflows = useCallback(async () => {
    fetchIncidents();
    const data = await api.getIncidents();
    if (!data || data.length === 0) return;

    const merged = { ...WORKFLOWS };
    // Take the 5 most recent incidents to show in playbooks
    for (const inc of data.slice(0, 5)) {
      try {
        const pbSteps = await api.getWorkflow(inc.attackType || 'unknown');
        if (pbSteps?.length > 0) {
          const label = `🤖 ${inc.attackType || 'Unknown'} [${inc.id}]`;
          merged[label] = {
            iso: 'AEGIS Auto',
            isoClause: 'AI-Generated',
            legalRef: 'AEGIS Pipeline',
            steps: pbSteps.map(s => ({ ...s, isAI: true }))
          };
        }
      } catch { }
    }
    setAllWorkflows(merged);
    setTypes(Object.keys(merged));
    
    // Auto-select the first AI playbook if nothing is selected
    if (!selected && Object.keys(merged).length > 0) {
      setSelected(Object.keys(merged)[0]);
    }
  }, [fetchIncidents, selected]);

  useEffect(() => {
    refreshWorkflows();
    const interval = setInterval(refreshWorkflows, 10000);
    return () => clearInterval(interval);
  }, [refreshWorkflows]);

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
              className={`w-full text-left px-3 py-2.5 rounded flex items-center justify-between transition-all text-sm ${selected === type ? 'bg-brand-primary/10 text-brand-primary border border-brand-primary/20' : 'text-neutral-400 hover:bg-white/[0.03] hover:text-white border border-transparent'
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
                  <div className={`w-9 h-9 rounded-full flex items-center justify-center border-2 shrink-0 ${isAI ? 'bg-emerald-500/15 border-emerald-500 text-emerald-400' :
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
