import React, { useEffect, useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link2, Shield, Hash, Clock, ChevronRight, CheckCircle2, XCircle, Layers, FileText, AlertTriangle, Copy, Check, ArrowRight } from 'lucide-react';
import { api } from '../../services/api';

const SEV_DOT = { P1: '#ff4057', P2: '#f97316', P3: '#f59e0b', P4: '#00e87b' };
const DOC_COLORS = {
  IncidentReport: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20' },
  EnrichedAlert: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20' },
  SystemEvent: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20' },
  Unknown: { bg: 'bg-neutral-500/10', text: 'text-neutral-400', border: 'border-neutral-500/20' },
};

/* Copy hash button */
const CopyHash = ({ hash }) => {
  const [copied, setCopied] = useState(false);
  const short = hash ? `${hash.slice(0, 8)}…${hash.slice(-8)}` : '—';
  const handleCopy = () => {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button onClick={handleCopy} className="flex items-center gap-1 font-mono text-[10px] text-neutral-400 hover:text-white transition-colors group" title={hash}>
      <span>{short}</span>
      {copied ? <Check size={10} className="text-emerald-400" /> : <Copy size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />}
    </button>
  );
};

/* ═══ Workflow Node (n8n style) ═══ */
const WorkflowNode = ({ block, isSelected, onClick }) => {
  const isGenesis = block.index === 0;
  const isEven = block.index % 2 === 0;
  const prevIsEven = (block.index - 1) % 2 === 0;

  const mainType = Object.keys(block.document_types || {})[0] || 'SystemEvent';
  const docStyle = DOC_COLORS[mainType] || DOC_COLORS.Unknown;
  const mainSev = Object.keys(block.severities || {})[0];

  const xOffset = isEven ? '-translate-x-8' : 'translate-x-8';

  return (
    <div className="flex flex-col items-center group/node relative">
      {!isGenesis && (
        <div className="w-24 h-10 shrink-0 relative overflow-visible">
          <svg className="absolute inset-0 w-full h-full overflow-visible" viewBox="0 0 96 40" preserveAspectRatio="none">
            <path
              d={prevIsEven
                ? "M 16 0 C 16 20, 80 20, 80 40"
                : "M 80 0 C 80 20, 16 20, 16 40"}
              fill="none"
              stroke={isSelected ? "#00e87b" : "rgba(0, 232, 123, 0.3)"}
              strokeWidth="2.5"
              strokeDasharray={isSelected ? "none" : "4 4"}
              className="transition-colors duration-300"
            />
            {isSelected && (
              <circle r="3" fill="#00e87b" className="opacity-100 drop-shadow-[0_0_6px_#00e87b]">
                <animateMotion dur="1s" repeatCount="indefinite" path={prevIsEven ? "M 16 0 C 16 20, 80 20, 80 40" : "M 80 0 C 80 20, 16 20, 16 40"} />
              </circle>
            )}
          </svg>
        </div>
      )}
      <motion.div
        layout
        onClick={() => onClick(block)}
        className={`relative cursor-pointer w-[240px] rounded-lg border transition-all duration-300 shrink-0 transform ${xOffset} ${isSelected
            ? 'bg-[#1e232b] border-brand-primary shadow-[0_0_20px_rgba(0,232,123,0.15)] ring-1 ring-brand-primary/50 z-10 scale-[1.02]'
            : 'bg-[#11141a] border-brand-border/60 hover:border-brand-primary/50 hover:bg-[#161b22] hover:shadow-[0_4px_15px_rgba(0,0,0,0.4)] z-0'
          } backdrop-blur-sm`}
      >
        {/* Node Header */}
        <div className="flex items-center gap-3 p-3 border-b border-brand-border/40">
          <div className={`w-8 h-8 rounded shrink-0 ${isGenesis ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : `${docStyle.bg} ${docStyle.text} ${docStyle.border}`} border flex items-center justify-center shadow-inner`}>
            {isGenesis ? <Shield size={14} /> : <Layers size={14} />}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[12px] font-bold text-white flex items-center justify-between">
              <span>Block #{block.index}</span>
              {mainSev && <span className="w-1.5 h-1.5 rounded-full shadow-[0_0_5px_currentColor]" style={{ backgroundColor: SEV_DOT[mainSev] || '#888', color: SEV_DOT[mainSev] || '#888' }} />}
            </div>
            <div className="text-[10px] text-neutral-400 flex items-center gap-1.5 mt-0.5">
              <Clock size={10} className="opacity-70" />
              {new Date(block.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </div>
          </div>
        </div>

        {/* Node Body */}
        <div className="px-3 py-2.5 bg-black/30 rounded-b-lg flex items-center justify-between">
          <div className="flex items-center gap-2 text-[10px] text-neutral-400">
            <Hash size={11} className="opacity-60" />
            <span className="font-mono bg-black/40 px-1.5 py-0.5 rounded border border-white/5">{block.hash?.slice(0, 8)}…</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-neutral-500">TX:</span>
            <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${docStyle.bg} ${docStyle.text} ${docStyle.border} border shadow-sm`}>
              {block.tx_count}
            </span>
          </div>
        </div>

        {/* Connector dots */}
        {!isGenesis && (
          <div className="absolute -top-1.5 left-1/2 w-3 h-3 bg-[#11141a] border border-brand-border rounded-full -translate-x-1/2 flex items-center justify-center z-10 shadow-sm">
            <div className="w-1.5 h-1.5 bg-neutral-500 rounded-full" />
          </div>
        )}
        <div className="absolute -bottom-1.5 left-1/2 w-3 h-3 bg-[#11141a] border border-brand-border rounded-full -translate-x-1/2 flex items-center justify-center z-10 shadow-sm">
          <div className="w-1.5 h-1.5 bg-brand-primary/80 rounded-full shadow-[0_0_5px_rgba(0,232,123,0.5)]" />
        </div>
      </motion.div>
    </div>
  );
};

/* ═══ MAIN PAGE ═══ */
export const BlockchainExplorer = () => {
  const [ledger, setLedger] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedBlock, setSelectedBlock] = useState(null);

  const fetchLedger = async () => {
    try {
      const data = await api.getBlockchainLedger();
      if (data) {
        setLedger(data);
        // Auto-select genesis block if nothing is selected
        if (data.blocks?.length > 0 && !selectedBlock) setSelectedBlock(data.blocks[0]);
      }
    } catch { } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLedger();
    const interval = setInterval(fetchLedger, 5000); // Auto-poll every 5s for live updates
    return () => clearInterval(interval);
  }, []);

  const blocks = ledger?.blocks || [];

  const stats = useMemo(() => {
    if (!ledger) return {};
    const allSevs = {};
    const allTypes = {};
    blocks.forEach(b => {
      Object.entries(b.severities || {}).forEach(([k, v]) => { allSevs[k] = (allSevs[k] || 0) + v; });
      Object.entries(b.document_types || {}).forEach(([k, v]) => { allTypes[k] = (allTypes[k] || 0) + v; });
    });
    return { severities: allSevs, docTypes: allTypes };
  }, [ledger, blocks]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-neutral-500 flex items-center gap-2"><Link2 size={16} className="animate-spin" /> Loading blockchain ledger…</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 font-sans text-neutral-300">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-brand-primary/10 flex items-center justify-center">
              <Link2 size={20} className="text-brand-primary" />
            </div>
            Blockchain Explorer
          </h1>
          <p className="text-neutral-500 text-sm mt-1 ml-[52px]">AEGIS Immutable Evidence Ledger — {blocks.length} blocks, {ledger?.total_transactions || 0} transactions</p>
        </div>
        
        <button 
          onClick={() => { setLoading(true); fetchLedger(); }}
          className="flex items-center gap-2 px-4 py-2 bg-[#11141a] border border-brand-border/60 rounded-lg text-sm text-neutral-300 hover:text-white hover:border-brand-primary/50 hover:bg-[#161b22] transition-all"
        >
          <Clock size={14} className={loading ? "animate-spin text-brand-primary" : "text-brand-primary"} />
          {loading ? "Syncing..." : "Live Sync (5s)"}
        </button>
      </div>

      {/* Main Layout: Chain Viz + Block Detail */}
      <div className="flex gap-5">
        {/* Chain Visualization — n8n workflow style */}
        <div className="flex-1 flex flex-col h-[600px]">
          <div className="flex items-center gap-2 mb-3">
            <Layers size={14} className="text-brand-primary" />
            <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">Blockchain Workflow Pipeline</span>
            <span className="ml-auto text-[10px] text-neutral-600 font-medium">Genesis → Latest</span>
          </div>

          <div
            className="flex-1 bg-[#090b10] border border-brand-border rounded-xl py-8 overflow-y-auto overflow-x-hidden relative shadow-inner custom-scrollbar"
            style={{
              backgroundImage: 'radial-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px)',
              backgroundSize: '24px 24px',
              backgroundPosition: '0 0'
            }}
          >
            <div className="flex flex-col items-center">
              {blocks.map((block) => (
                <WorkflowNode
                  key={block.index}
                  block={block}
                  isSelected={selectedBlock?.index === block.index}
                  onClick={setSelectedBlock}
                />
              ))}
            </div>
          </div>
        </div>

        {/* Block Detail Panel */}
        <div className="w-96 shrink-0">
          <div className="bg-brand-bg-card border border-brand-border rounded-xl overflow-hidden sticky top-4">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-brand-border bg-brand-bg-surface">
              <Hash size={13} className="text-brand-primary" />
              <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">Block Details</span>
            </div>

            {selectedBlock ? (
              <div className="p-4 space-y-4 max-h-[600px] overflow-y-auto">
                {/* Block Header */}
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-brand-primary/10 flex items-center justify-center">
                    <Layers size={20} className="text-brand-primary" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white">Block #{selectedBlock.index}</h3>
                    <p className="text-[10px] text-neutral-500">{new Date(selectedBlock.timestamp).toLocaleString()}</p>
                  </div>
                </div>

                {/* Hash Details */}
                <div className="bg-brand-bg-surface rounded-lg p-3 space-y-2 border border-brand-border/50">
                  <div>
                    <p className="text-[9px] text-neutral-500 uppercase tracking-wider mb-0.5">Block Hash</p>
                    <div className="flex items-center gap-1">
                      <Hash size={9} className="text-brand-primary shrink-0" />
                      <CopyHash hash={selectedBlock.hash} />
                    </div>
                  </div>
                  <div>
                    <p className="text-[9px] text-neutral-500 uppercase tracking-wider mb-0.5">Previous Hash</p>
                    <div className="flex items-center gap-1">
                      <ArrowRight size={9} className="text-neutral-600 shrink-0" />
                      <CopyHash hash={selectedBlock.previous_hash} />
                    </div>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-neutral-500">Nonce</span>
                    <span className="text-white font-mono">{selectedBlock.nonce}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-neutral-500">Transactions</span>
                    <span className="text-white font-bold">{selectedBlock.tx_count}</span>
                  </div>
                </div>

                {/* Severity Distribution */}
                {Object.keys(selectedBlock.severities || {}).length > 0 && (
                  <div>
                    <p className="text-[9px] text-neutral-500 uppercase tracking-wider mb-1.5 font-semibold">Severity Distribution</p>
                    <div className="flex gap-2">
                      {Object.entries(selectedBlock.severities).map(([sev, count]) => (
                        <div key={sev} className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-brand-bg-surface border border-brand-border/50">
                          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: SEV_DOT[sev] || '#888' }} />
                          <span className="text-[10px] text-neutral-300 font-medium">{sev}: {count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Transactions */}
                <div>
                  <p className="text-[9px] text-neutral-500 uppercase tracking-wider mb-1.5 font-semibold">Transactions</p>
                  <div className="space-y-2">
                    {(selectedBlock.transactions || []).map((tx, i) => {
                      const docStyle = DOC_COLORS[tx.document_type] || DOC_COLORS.Unknown;
                      const meta = tx.metadata || {};
                      return (
                        <div key={tx.tx_id || i} className="bg-brand-bg-surface rounded-lg p-3 border border-brand-border/50 space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded ${docStyle.bg} ${docStyle.text} ${docStyle.border} border`}>
                              {tx.document_type}
                            </span>
                            {meta.severity && (
                              <span className="flex items-center gap-1 text-[10px]">
                                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: SEV_DOT[meta.severity] || '#888' }} />
                                <span className="text-neutral-400">{meta.severity}</span>
                              </span>
                            )}
                          </div>
                          <div className="text-[10px] text-neutral-500 font-mono">
                            TX: {(tx.tx_id || '').slice(0, 16)}…
                          </div>
                          {meta.entity_id && (
                            <div className="text-[10px] text-neutral-400">
                              <span className="text-neutral-500">Entity:</span> <span className="text-white font-medium">{meta.entity_id}</span>
                            </div>
                          )}
                          {meta.attack_classification && (
                            <div className="text-[10px] text-neutral-400">
                              <span className="text-neutral-500">Attack:</span> <span className="text-red-400">{meta.attack_classification}</span>
                            </div>
                          )}
                          {meta.risk_score && (
                            <div className="text-[10px] text-neutral-400">
                              <span className="text-neutral-500">Risk:</span> <span className="text-orange-400 font-bold">{meta.risk_score}/10</span>
                            </div>
                          )}
                          <div className="text-[9px] text-neutral-600 font-mono">
                            Doc Hash: {(tx.document_hash || '').slice(0, 20)}…
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Entities */}
                {selectedBlock.entities?.length > 0 && (
                  <div>
                    <p className="text-[9px] text-neutral-500 uppercase tracking-wider mb-1.5 font-semibold">Affected Entities</p>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedBlock.entities.map(e => (
                        <span key={e} className="px-2 py-1 text-[10px] font-mono bg-brand-bg-surface border border-brand-border/50 rounded-md text-neutral-300">{e}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-8 text-center space-y-2">
                <Layers size={28} className="text-neutral-700 mx-auto" />
                <p className="text-xs text-neutral-600">Select a block from the chain to inspect its transactions and hashes.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default BlockchainExplorer;
