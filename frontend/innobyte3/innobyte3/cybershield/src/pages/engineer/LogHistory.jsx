import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Search, History, GitCommit, User } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';

const typeColor = {
  Phishing: 'text-purple-400',
  Ransomware: 'text-red-500',
  DDoS: 'text-yellow-500',
  Malware: 'text-orange-500',
  'Insider Threat': 'text-pink-400',
  'Data Breach': 'text-red-400',
  'Credential Leak': 'text-blue-400',
  'Lost Device': 'text-neutral-400',
  'privilege_escalation': 'text-red-500',
  'ssh_bruteforce': 'text-orange-500',
  'anomaly_unknown': 'text-yellow-400',
  'Privilege Elevation Attack': 'text-red-500',
};

export const LogHistory = () => {
  const { logs, fetchLogs, incidents, fetchIncidents, isLoadingLogs } = useAppStore();
  const [search, setSearch] = useState('');

  useEffect(() => {
    fetchLogs();
    fetchIncidents();
  }, [fetchLogs, fetchIncidents]);

  // Merge logs from blockchain feed + incidents for a comprehensive history
  const allEntries = [
    ...logs.map(l => ({
      id: l.id,
      description: l.description || l.action,
      attackType: l.type || 'Alert',
      assignedTo: l.actor || 'AEGIS',
      detectedAt: l.timestamp,
      status: 'Logged',
      sourceIp: l.sourceIp,
      severity: l.severity,
      _source: 'blockchain',
    })),
    ...incidents.map(i => ({
      id: i.id,
      description: i.description || i.attackType,
      attackType: i.attackType,
      assignedTo: i.assignedTo,
      detectedAt: i.detectedAt,
      status: i.status,
      sourceIp: i.target_entity,
      severity: i.severity,
      _source: 'report',
    })),
  ];

  const filtered = allEntries
    .filter(i =>
      !search ||
      (i.description || '').toLowerCase().includes(search.toLowerCase()) ||
      (i.assignedTo || '').toLowerCase().includes(search.toLowerCase()) ||
      (i.id || '').toLowerCase().includes(search.toLowerCase())
    );

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <History size={22} className="text-brand-primary" /> Incident History
          </h1>
          <p className="text-neutral-500 text-sm mt-0.5">
            {allEntries.length} events — Immutable blockchain-backed log • Law 18-07 Compliant
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-600" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search incident…"
              className="bg-brand-bg-card border border-brand-border rounded-md pl-9 pr-4 py-2 text-sm text-white focus:border-brand-primary/50 outline-none w-48"
            />
          </div>
        </div>
      </div>

      <div className="bg-brand-bg-card border border-brand-border rounded-md p-6">
        {isLoadingLogs && allEntries.length === 0 ? (
          <div className="text-sm text-neutral-500 py-8 text-center">Loading history from AEGIS backend...</div>
        ) : (
          <div className="relative border-l border-brand-border ml-3 space-y-6">
            {filtered.map((incident, idx) => (
              <motion.div
                key={`${incident.id}-${idx}`}
                initial={{ opacity: 0, x: -16 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.04 }}
                className="relative pl-8"
              >
                <div className="absolute -left-[13px] top-1.5 w-[26px] h-[26px] bg-brand-bg-deep border border-brand-border rounded-full flex items-center justify-center">
                  <GitCommit
                    size={12}
                    className={typeColor[incident.attackType] || 'text-neutral-500'}
                  />
                </div>

                <div className="bg-brand-bg-surface border border-brand-border/50 rounded-md p-4 hover:border-brand-border-bright transition-colors">
                  <div className="flex justify-between items-start mb-1.5">
                    <p className="text-sm text-white font-medium">
                      {incident.description}
                    </p>
                    <span className="text-[11px] text-neutral-600 font-mono shrink-0 ml-4">
                      {incident.detectedAt}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-xs text-neutral-500 flex-wrap">
                    <span className="flex items-center gap-1">
                      <User size={12} />
                      {incident.assignedTo}
                    </span>

                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${typeColor[incident.attackType] || 'text-neutral-500'
                        } bg-white/[0.03]`}
                    >
                      {incident.attackType}
                    </span>

                    <span className="font-mono text-neutral-600">
                      {incident.id}
                    </span>

                    {incident.sourceIp && (
                      <span className="font-mono text-brand-primary text-[10px]">
                        {incident.sourceIp}
                      </span>
                    )}

                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                      incident._source === 'blockchain' ? 'text-blue-400 bg-blue-500/10' : 'text-neutral-400'
                    }`}>
                      {incident._source === 'blockchain' ? '⛓ Blockchain' : incident.status}
                    </span>
                  </div>
                </div>
              </motion.div>
            ))}

            {filtered.length === 0 && (
              <p className="pl-8 text-neutral-600 text-sm py-4">
                No incidents found.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
export default LogHistory;