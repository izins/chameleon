import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Network, Server, Monitor, Shield, Wifi, AlertTriangle,
  RefreshCcw, Lock, Unlock, ChevronDown, Eye, X, Activity,
  HardDrive, Database, Globe, Router, Play, Square, FileText, Download
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import { api } from '../../services/api';

/* ── Device icons by type ── */
const DEVICE_ICONS = {
  server: Server,
  workstation: Monitor,
  firewall: Shield,
  switch: Network,
  router: Router,
  gateway: Globe,
  database: Database,
  storage: HardDrive,
  default: Monitor,
};

/* ── Device role → subnet label ── */
const ROLE_LABELS = {
  analyst_workstation: 'SOC Analyst',
  siem_server: 'SIEM',
  firewall: 'Firewall',
  domain_controller: 'Domain Controller',
  file_server: 'File Server',
  web_server: 'Web Server',
  db_server: 'Database',
  email_gateway: 'Email Gateway',
  '': 'Endpoint',
};

/* ── Severity mapping ── */
const SEV_CONFIG = {
  P1: { color: '#ff4057', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30', label: 'Critical' },
  P2: { color: '#f97316', bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30', label: 'High' },
  P3: { color: '#f59e0b', bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30', label: 'Medium' },
  P4: { color: '#00e87b', bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', label: 'Low' },
};

/* ── Layout: Arrange devices in a radial topology ── */
function computeLayout(devices, edges, width, height) {
  if (!devices || devices.length === 0) return { nodes: [], links: [] };
  
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) * 0.32;

  // Find gateway or local device as center
  const centerIdx = devices.findIndex(d => d.is_gateway || d.is_local);
  const center = centerIdx >= 0 ? centerIdx : 0;

  const nodes = devices.map((d, i) => {
    if (i === center) {
      return { ...d, x: cx, y: cy, isCenter: true };
    }
    // Distribute others in a circle
    const others = devices.length - 1;
    const idx = i > center ? i - 1 : i;
    const angle = (2 * Math.PI * idx) / others - Math.PI / 2;
    return {
      ...d,
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
      isCenter: false,
    };
  });

  const links = edges.map(e => ({
    source: nodes.find(n => n.ip === e.source),
    target: nodes.find(n => n.ip === e.target),
  })).filter(l => l.source && l.target);

  return { nodes, links };
}

/* ── Device Node Component ── */
const DeviceNode = ({ device, isSelected, isIsolatedByAttack, onClick, activeIncident }) => {
  const Icon = DEVICE_ICONS[device.device_type] || DEVICE_ICONS.default;
  const role = ROLE_LABELS[device.device_role] || device.device_role || 'Endpoint';
  const isIsolated = device.is_isolated || isIsolatedByAttack;

  // Visual state
  let ringColor = '#1a1a1a';
  let glowColor = 'transparent';
  let statusDot = '#00e87b'; // healthy green

  if (isIsolated) {
    ringColor = '#ff4057';
    glowColor = 'rgba(255,64,87,0.15)';
    statusDot = '#ff4057';
  } else if (device.isCenter) {
    ringColor = '#00e87b';
    glowColor = 'rgba(0,232,123,0.08)';
  } else if (isSelected) {
    ringColor = '#38bdf8';
    glowColor = 'rgba(56,189,248,0.1)';
  }

  return (
    <g
      onClick={() => onClick(device)}
      style={{ cursor: 'pointer' }}
    >
      {/* Glow ring */}
      <circle
        cx={device.x} cy={device.y} r={38}
        fill={glowColor}
        stroke={ringColor}
        strokeWidth={isIsolated ? 2 : isSelected ? 1.5 : 0.5}
        strokeDasharray={isIsolated ? '6 3' : undefined}
        opacity={0.8}
      >
        {isIsolated && (
          <animate attributeName="stroke-dashoffset" values="0;-18" dur="1.5s" repeatCount="indefinite" />
        )}
      </circle>

      {/* Main circle */}
      <circle
        cx={device.x} cy={device.y} r={26}
        fill={isIsolated ? 'rgba(255,64,87,0.08)' : '#0d1117'}
        stroke={isIsolated ? '#ff4057' : isSelected ? '#38bdf8' : '#2a2a2a'}
        strokeWidth={1.5}
      />

      {/* Icon placeholder — foreignObject for React icons */}
      <foreignObject x={device.x - 11} y={device.y - 11} width={22} height={22}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%' }}>
          <Icon
            size={16}
            color={isIsolated ? '#ff4057' : device.isCenter ? '#00e87b' : '#9ca3af'}
          />
        </div>
      </foreignObject>

      {/* Status dot */}
      <circle cx={device.x + 20} cy={device.y - 20} r={4} fill={statusDot}>
        {isIsolated && (
          <animate attributeName="opacity" values="1;0.3;1" dur="1s" repeatCount="indefinite" />
        )}
      </circle>

      {/* IP label */}
      <text
        x={device.x} y={device.y + 42}
        textAnchor="middle" fontSize="9" fill="#9ca3af"
        fontFamily="ui-monospace, monospace" fontWeight="500"
      >
        {device.ip}
      </text>

      {/* Role label */}
      <text
        x={device.x} y={device.y + 54}
        textAnchor="middle" fontSize="8" fill="#4b5563"
        fontFamily="system-ui"
      >
        {device.hostname || role}
      </text>

      {/* Isolation badge */}
      {isIsolated && (
        <g>
          <rect x={device.x - 28} y={device.y - 42} width={56} height={16} rx={8}
            fill="rgba(255,64,87,0.15)" stroke="#ff4057" strokeWidth={0.5} />
          <text x={device.x} y={device.y - 31} textAnchor="middle" fontSize="8"
            fill="#ff4057" fontWeight="700" fontFamily="system-ui">ISOLATED</text>
        </g>
      )}
    </g>
  );
};

/* ════════════════════════════════════════════════════════════════ */
/* ══ MAIN COMPONENT ═══════════════════════════════════════════ */
/* ════════════════════════════════════════════════════════════════ */

export const NetworkTopology = () => {
  const { topology, fetchTopology, isLoadingTopology, incidents, fetchIncidents, addNotification } = useAppStore();
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [dims, setDims] = useState({ w: 800, h: 500 });
  const containerRef = useRef(null);

  // ── Simulation State ──
  const [simRunning, setSimRunning] = useState(false);
  const [simLogs, setSimLogs] = useState([]);
  const [simPhase, setSimPhase] = useState(null);
  const [simStats, setSimStats] = useState({ total: 0, phase: '', risk: 0 });
  const [simIsolated, setSimIsolated] = useState(new Set());
  const [simReport, setSimReport] = useState(null);
  const [simComplete, setSimComplete] = useState(false);
  const logEndRef = useRef(null);
  const eventSourceRef = useRef(null);

  const startSimulation = useCallback(() => {
    setSimRunning(true);
    setSimLogs([]);
    setSimPhase(null);
    setSimStats({ total: 0, phase: '', risk: 0 });
    setSimIsolated(new Set());
    setSimReport(null);
    setSimComplete(false);

    const es = new EventSource('/api/simulation/start');
    eventSourceRef.current = es;

    addNotification({
      id: `sim-start-${Date.now()}`,
      unread: true,
      severity: 'critical',
      timestamp: new Date().toISOString(),
      title: '🚨 Live Simulation Started',
      message: 'AEGIS active defenses are engaged. Monitoring network topology for lateral movement and anomalies.',
    });

    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      switch (data.type) {
        case 'log':
          setSimLogs(prev => {
            const next = [...prev, data];
            return next.length > 300 ? next.slice(-300) : next;
          });
          setSimStats(prev => ({ ...prev, total: data.num }));
          break;
        case 'phase':
          setSimPhase(data);
          setSimStats(prev => ({ ...prev, phase: data.phase }));
          break;
        case 'enrichment':
          setSimStats(prev => ({ ...prev, risk: data.risk_score }));
          setSimLogs(prev => [...prev, { ...data, type: 'enrichment', severity: 'INFO', raw: data.message, timestamp: new Date().toTimeString().slice(0, 8) }]);
          break;
        case 'isolation':
          setSimIsolated(prev => new Set([...prev, data.device_ip]));
          setSimLogs(prev => [...prev, { ...data, type: 'isolation', severity: 'CRITICAL', raw: data.message, timestamp: new Date().toTimeString().slice(0, 8) }]);
          addNotification({
            id: `iso-${Date.now()}-${Math.random()}`,
            unread: true,
            severity: 'warning',
            timestamp: new Date().toISOString(),
            title: '🔒 Endpoint Isolated',
            message: `AEGIS automatically isolated device ${data.device_ip} from the network to prevent lateral movement.`,
          });
          break;
        case 'dlp_block':
          setSimLogs(prev => [...prev, { ...data, severity: 'CRITICAL', raw: data.message, timestamp: new Date().toTimeString().slice(0, 8) }]);
          break;
        case 'report':
          setSimReport(data);
          setSimLogs(prev => [...prev, { severity: 'INFO', raw: data.message, timestamp: new Date().toTimeString().slice(0, 8) }]);
          break;
        case 'legal':
          setSimLogs(prev => [...prev, { severity: 'INFO', raw: data.message, timestamp: new Date().toTimeString().slice(0, 8) }]);
          break;
        case 'complete':
          setSimComplete(true);
          setSimRunning(false);
          setSimLogs(prev => [...prev, { severity: 'INFO', raw: data.message, timestamp: new Date().toTimeString().slice(0, 8) }]);
          addNotification({
            id: `sim-end-${Date.now()}`,
            unread: true,
            severity: 'info',
            timestamp: new Date().toISOString(),
            title: '✅ Simulation Concluded',
            message: 'Attack vector successfully neutralized. Immutable forensic evidence has been sealed in the blockchain.',
          });
          es.close();
          break;
      }
    };
    es.onerror = () => { setSimRunning(false); es.close(); };
  }, []);

  const stopSimulation = useCallback(() => {
    if (eventSourceRef.current) eventSourceRef.current.close();
    setSimRunning(false);
  }, []);

  // Auto-scroll logs
  useEffect(() => {
    if (logEndRef.current) logEndRef.current.scrollIntoView({ behavior: 'smooth' });
  }, [simLogs.length]);

  useEffect(() => {
    fetchTopology();
    fetchIncidents();
  }, [fetchTopology, fetchIncidents]);

  // Responsive sizing
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(([e]) => {
      setDims({
        w: e.contentRect.width,
        h: Math.max(450, e.contentRect.height),
      });
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Merge real topology + demo architecture for richer visualization
  const enrichedTopology = useMemo(() => {
    if (!topology) return null;
    
    // Use real topology devices + enrich with demo architecture
    const demoDevices = [
      { ip: '10.0.0.1', hostname: 'FW-EDGE-01', device_type: 'firewall', device_role: 'firewall', criticality: 10, business_impact: 'critical', is_gateway: true, is_local: false, is_isolated: false, subnet: '10.0.0.0/24', open_ports: [443, 80] },
      { ip: '10.0.0.10', hostname: 'SIEM-AEGIS', device_type: 'server', device_role: 'siem_server', criticality: 9, business_impact: 'critical', is_gateway: false, is_local: false, is_isolated: false, subnet: '10.0.0.0/24', open_ports: [5000, 5173] },
      { ip: '10.0.0.20', hostname: 'DC-01', device_type: 'server', device_role: 'domain_controller', criticality: 10, business_impact: 'critical', is_gateway: false, is_local: false, is_isolated: false, subnet: '10.0.0.0/24', open_ports: [389, 636] },
      { ip: '10.0.0.30', hostname: 'FS-FIN-01', device_type: 'storage', device_role: 'file_server', criticality: 8, business_impact: 'high', is_gateway: false, is_local: false, is_isolated: false, subnet: '10.0.0.0/24', open_ports: [445] },
      { ip: '10.0.0.40', hostname: 'WS-HR-042', device_type: 'workstation', device_role: 'analyst_workstation', criticality: 5, business_impact: 'medium', is_gateway: false, is_local: false, is_isolated: false, subnet: '10.0.0.0/24', open_ports: [] },
      { ip: '10.0.0.50', hostname: 'MAIL-GW', device_type: 'server', device_role: 'email_gateway', criticality: 7, business_impact: 'high', is_gateway: false, is_local: false, is_isolated: false, subnet: '10.0.0.0/24', open_ports: [25, 587] },
      { ip: '10.0.0.60', hostname: 'DB-PROD-01', device_type: 'database', device_role: 'db_server', criticality: 9, business_impact: 'critical', is_gateway: false, is_local: false, is_isolated: false, subnet: '10.0.0.0/24', open_ports: [5432] },
      { ip: '10.0.0.70', hostname: 'WEB-PORTAL', device_type: 'server', device_role: 'web_server', criticality: 6, business_impact: 'medium', is_gateway: false, is_local: false, is_isolated: false, subnet: '10.0.0.0/24', open_ports: [443, 8080] },
    ];

    const demoEdges = [
      { source: '10.0.0.1', target: '10.0.0.10' },
      { source: '10.0.0.1', target: '10.0.0.50' },
      { source: '10.0.0.1', target: '10.0.0.70' },
      { source: '10.0.0.10', target: '10.0.0.20' },
      { source: '10.0.0.10', target: '10.0.0.40' },
      { source: '10.0.0.20', target: '10.0.0.30' },
      { source: '10.0.0.20', target: '10.0.0.60' },
      { source: '10.0.0.50', target: '10.0.0.40' },
    ];

    // Combine: prefer real devices, add demo ones
    const realIps = new Set((topology.devices || []).map(d => d.ip));
    const allDevices = [
      ...demoDevices.filter(d => !realIps.has(d.ip)),
      ...(topology.devices || []),
    ];

    const allEdges = [...demoEdges, ...(topology.edges || [])];
    const incidents = topology.active_incidents || [];

    return { devices: allDevices, edges: allEdges, incidents, isolated_devices: topology.isolated_devices || [] };
  }, [topology]);

  // Compute layout
  const { nodes, links } = useMemo(() => {
    if (!enrichedTopology) return { nodes: [], links: [] };
    return computeLayout(enrichedTopology.devices, enrichedTopology.edges, dims.w, dims.h);
  }, [enrichedTopology, dims]);

  // Load REAL attacks from unified database
  const [unifiedAttacks, setUnifiedAttacks] = useState([]);
  useEffect(() => {
    (async () => {
      try {
        const data = await api.getUnifiedAttacks();
        if (data?.attacks) setUnifiedAttacks(data.attacks);
      } catch {}
    })();
  }, []);

  // Merge real unified attacks as "incidents" for the topology view
  const allIncidents = useMemo(() => {
    const fromTopo = enrichedTopology?.incidents || [];
    const fromUnified = unifiedAttacks.map(a => ({
      incident_id: a.report_id || a.id,
      entity_id: a.entity_id,
      severity: a.severity,
      attack_type: a.attack_type,
      risk_score: a.risk_score,
      mitre: (a.mitre || []).join(', '),
      cves: (a.cves || []).join(', '),
      kill_chain: a.kill_chain,
      status: 'active',
    }));
    // Deduplicate by entity_id
    const seen = new Set();
    return [...fromUnified, ...fromTopo].filter(inc => {
      const key = `${inc.entity_id}-${inc.attack_type}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [enrichedTopology, unifiedAttacks]);

  // Combine real isolation with simulation isolation
  const isolatedIpsForAttack = useMemo(() => {
    const ips = new Set([...simIsolated]);
    if (!selectedIncident) return ips;
    const inc = allIncidents.find(i => i.incident_id === selectedIncident);
    if (inc?.entity_id) ips.add(inc.entity_id);
    (enrichedTopology?.isolated_devices || []).forEach(d => ips.add(d));
    return ips;
  }, [selectedIncident, allIncidents, enrichedTopology, simIsolated]);

  const handleRefresh = async () => {
    await api.scanNetwork();
    fetchTopology();
  };

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300 gap-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight flex items-center gap-2">
            <Network size={20} className="text-brand-primary" /> Network Topology
          </h1>
          <p className="text-xs text-neutral-500 mt-1">
            Internal system architecture — {nodes.length} devices mapped
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Incident Filter */}
          <div className="relative">
            <select
              value={selectedIncident || ''}
              onChange={(e) => setSelectedIncident(e.target.value || null)}
              className="appearance-none bg-brand-bg-card border border-brand-border rounded-lg px-4 py-2 pr-8 text-xs text-neutral-300 focus:outline-none focus:border-brand-primary/50 cursor-pointer"
            >
              <option value="">All Devices (Normal)</option>
              {allIncidents.map((inc) => {
                const sev = SEV_CONFIG[inc.severity] || SEV_CONFIG.P3;
                return (
                  <option key={inc.incident_id} value={inc.incident_id}>
                    🔴 {inc.attack_type} — {inc.entity_id} ({sev.label})
                  </option>
                );
              })}
            </select>
            <ChevronDown size={12} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-neutral-500 pointer-events-none" />
          </div>
          <button
            onClick={handleRefresh}
            className="flex items-center gap-1.5 px-3 py-2 text-xs bg-brand-bg-card border border-brand-border rounded-lg text-neutral-400 hover:text-white hover:border-brand-primary/30 transition-all"
          >
            <RefreshCcw size={12} /> Rescan
          </button>
          {/* Simulation Button */}
          {simRunning ? (
            <button onClick={stopSimulation} className="flex items-center gap-1.5 px-4 py-2 text-xs bg-red-500/15 border border-red-500/30 rounded-lg text-red-400 font-semibold animate-pulse">
              <Square size={12} /> Stop Simulation
            </button>
          ) : (
            <button onClick={startSimulation} className="flex items-center gap-1.5 px-4 py-2 text-xs bg-red-500/10 border border-red-500/25 rounded-lg text-red-400 hover:bg-red-500/20 font-semibold transition-all">
              <Play size={12} /> 🔴 Start Simulation
            </button>
          )}
        </div>
      </div>

      {/* Main Layout: Topology + Sidebar */}
      <div className="flex-1 flex gap-5 min-h-0">
        {/* Topology Canvas */}
        <div
          ref={containerRef}
          className="flex-1 bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden relative"
          style={{ background: 'radial-gradient(ellipse at center, #0d1117 0%, #080a0f 100%)' }}
        >
          {/* Grid overlay */}
          <svg width="100%" height="100%" style={{ position: 'absolute', inset: 0, opacity: 0.04 }}>
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#fff" strokeWidth="0.5" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />
          </svg>

          {isLoadingTopology ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-sm text-neutral-500 flex items-center gap-2">
                <RefreshCcw size={14} className="animate-spin" /> Loading topology from AEGIS...
              </div>
            </div>
          ) : (
            <svg width={dims.w} height={dims.h} viewBox={`0 0 ${dims.w} ${dims.h}`} style={{ display: 'block' }}>
              {/* Edges / connections */}
              {links.map((link, i) => {
                const isAttackPath = selectedIncident && (
                  isolatedIpsForAttack.has(link.source.ip) || isolatedIpsForAttack.has(link.target.ip)
                );
                return (
                  <line
                    key={`edge-${i}`}
                    x1={link.source.x} y1={link.source.y}
                    x2={link.target.x} y2={link.target.y}
                    stroke={isAttackPath ? '#ff4057' : '#1f2937'}
                    strokeWidth={isAttackPath ? 1.5 : 0.8}
                    strokeDasharray={isAttackPath ? '6 4' : undefined}
                    opacity={isAttackPath ? 0.7 : 0.5}
                  >
                    {isAttackPath && (
                      <animate attributeName="stroke-dashoffset" values="0;-20" dur="1.5s" repeatCount="indefinite" />
                    )}
                  </line>
                );
              })}

              {/* Device Nodes */}
              {nodes.map((device, i) => (
                <DeviceNode
                  key={device.ip}
                  device={device}
                  isSelected={selectedDevice?.ip === device.ip}
                  isIsolatedByAttack={isolatedIpsForAttack.has(device.ip)}
                  onClick={setSelectedDevice}
                  activeIncident={selectedIncident}
                />
              ))}

              {/* Attack path label */}
              {selectedIncident && (
                <g>
                  <rect x={10} y={dims.h - 35} width={260} height={25} rx={6}
                    fill="rgba(255,64,87,0.08)" stroke="#ff4057" strokeWidth={0.5} />
                  <text x={20} y={dims.h - 18} fontSize="10" fill="#ff4057" fontWeight="600" fontFamily="system-ui">
                    ⚠ Viewing isolation state for: {allIncidents.find(i => i.incident_id === selectedIncident)?.attack_type || selectedIncident}
                  </text>
                </g>
              )}
            </svg>
          )}

          {/* Legend */}
          <div className="absolute bottom-3 right-3 flex items-center gap-4 bg-black/50 backdrop-blur-sm rounded-lg px-3 py-2 border border-white/5">
            {[
              { color: '#00e87b', label: 'Healthy' },
              { color: '#ff4057', label: 'Isolated' },
              { color: '#38bdf8', label: 'Selected' },
              { color: '#f59e0b', label: 'Warning' },
            ].map(l => (
              <span key={l.label} className="flex items-center gap-1.5 text-[10px] text-neutral-500">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: l.color }} />{l.label}
              </span>
            ))}
          </div>
        </div>

        {/* Right Sidebar: Device Details + Incident List */}
        <div className="w-80 shrink-0 flex flex-col gap-4">
          {/* Sim Phase Indicator */}
          {(simRunning || simComplete) && (
            <div className={`bg-brand-bg-card border rounded-xl p-3 space-y-2 ${simRunning ? 'border-red-500/30' : 'border-emerald-500/30'}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white flex items-center gap-2">
                  {simRunning ? <><span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" /> Live Simulation</> : <><span className="w-2 h-2 rounded-full bg-emerald-500" /> Simulation Complete</>}
                </span>
                <span className="text-[10px] font-mono text-neutral-500">{simStats.total}/200 logs</span>
              </div>
              {simPhase && <p className="text-[10px] text-neutral-400">Phase {simPhase.phase_num}/5: <span className="text-white font-medium">{simPhase.phase}</span> — {simPhase.mitre}</p>}
              <div className="h-1.5 bg-brand-bg-surface rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-red-500 to-orange-500 rounded-full transition-all duration-300" style={{ width: `${(simStats.total / 200) * 100}%` }} />
              </div>
              {simStats.risk > 0 && <p className="text-[10px] text-red-400">Risk Score: <span className="font-bold">{simStats.risk}/10</span></p>}
              {simIsolated.size > 0 && <p className="text-[10px] text-red-400">🔒 Isolated: {[...simIsolated].join(', ')}</p>}
              {simReport && (
                <div className="flex gap-2 pt-1">
                  <a href={`/api/reports/${simReport.report_id}/pdf`} target="_blank" rel="noreferrer" className="flex items-center gap-1 px-2 py-1 text-[10px] bg-brand-primary/10 text-brand-primary border border-brand-primary/20 rounded font-medium hover:bg-brand-primary/20">
                    <Download size={10} /> Attack PDF
                  </a>
                  <a href="/legal" className="flex items-center gap-1 px-2 py-1 text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/20 rounded font-medium hover:bg-purple-500/20">
                    <FileText size={10} /> Legal Report
                  </a>
                </div>
              )}
            </div>
          )}

          {/* Device Details */}
          <div className="bg-brand-bg-card border border-brand-border rounded-xl overflow-hidden flex-1">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-brand-border bg-brand-bg-surface">
              <Eye size={13} className="text-brand-primary" />
              <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">Device Inspector</span>
            </div>
            {selectedDevice ? (() => {
              const isIso = selectedDevice.is_isolated || isolatedIpsForAttack.has(selectedDevice.ip);
              const DevIcon = DEVICE_ICONS[selectedDevice.device_type] || DEVICE_ICONS.default;
              // Find any linked attacks for this device
              const linkedAttacks = allIncidents.filter(inc => inc.entity_id === selectedDevice.ip);
              return (
                <div className="p-4 space-y-4">
                  {/* Header with icon */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${isIso ? 'bg-red-500/10' : 'bg-brand-primary/10'}`}>
                        <DevIcon size={18} className={isIso ? 'text-red-400' : 'text-brand-primary'} />
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{selectedDevice.hostname || selectedDevice.ip}</h3>
                        <p className="text-[10px] text-neutral-500 font-mono">{selectedDevice.ip}</p>
                      </div>
                    </div>
                    <button onClick={() => setSelectedDevice(null)} className="text-neutral-500 hover:text-white transition-colors"><X size={14} /></button>
                  </div>

                  {/* Device Properties */}
                  <div className="space-y-2">
                    {[
                      { label: 'IP Address', value: selectedDevice.ip },
                      { label: 'Hostname', value: selectedDevice.hostname || '—' },
                      { label: 'MAC', value: selectedDevice.mac || 'N/A' },
                      { label: 'Type', value: selectedDevice.device_type || '—' },
                      { label: 'Role', value: ROLE_LABELS[selectedDevice.device_role] || selectedDevice.device_role || '—' },
                      { label: 'Subnet', value: selectedDevice.subnet || 'Local' },
                      { label: 'Criticality', value: `${selectedDevice.criticality || 0}/10` },
                      { label: 'Business Impact', value: selectedDevice.business_impact || '—' },
                      { label: 'Open Ports', value: (selectedDevice.open_ports || []).join(', ') || 'None scanned' },
                    ].map(row => (
                      <div key={row.label} className="flex items-center justify-between text-xs">
                        <span className="text-neutral-500">{row.label}</span>
                        <span className="text-neutral-300 font-mono text-right max-w-[140px] truncate">{row.value}</span>
                      </div>
                    ))}
                  </div>

                  {/* Status Badge */}
                  <div className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border ${
                    isIso
                      ? 'bg-red-500/10 border-red-500/20 text-red-400'
                      : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                  }`}>
                    {isIso ? (
                      <>
                        <Lock size={13} />
                        <div>
                          <span className="text-xs font-semibold block">ISOLATED</span>
                          <span className="text-[10px] opacity-70">{selectedDevice.isolation_reason || 'Threat containment active'}</span>
                        </div>
                      </>
                    ) : (
                      <>
                        <Unlock size={13} />
                        <div>
                          <span className="text-xs font-semibold block">Online</span>
                          <span className="text-[10px] opacity-70">Normal operations</span>
                        </div>
                      </>
                    )}
                  </div>

                  {/* Linked Attacks */}
                  {linkedAttacks.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-[10px] text-neutral-500 uppercase tracking-wider font-semibold">Linked Attacks</p>
                      {linkedAttacks.slice(0, 3).map((atk, i) => {
                        const sev = SEV_CONFIG[atk.severity] || SEV_CONFIG.P3;
                        return (
                          <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-brand-bg-surface border border-brand-border/50 text-xs">
                            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: sev.color }} />
                            <span className="text-white truncate flex-1">{atk.attack_type}</span>
                            <span className={`text-[9px] font-bold ${sev.text}`}>{sev.label}</span>
                          </div>
                        );
                      })}
                      {linkedAttacks.length > 3 && (
                        <p className="text-[10px] text-neutral-600 pl-1">+{linkedAttacks.length - 3} more</p>
                      )}
                    </div>
                  )}
                </div>
              );
            })() : (
              <div className="p-6 text-center space-y-2">
                <Monitor size={24} className="text-neutral-700 mx-auto" />
                <p className="text-xs text-neutral-600">Click a device node on the topology to inspect it.</p>
              </div>
            )}
          </div>

          {/* Active Incidents */}
          <div className="bg-brand-bg-card border border-brand-border rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-brand-border bg-brand-bg-surface">
              <AlertTriangle size={13} className="text-red-400" />
              <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">Active Incidents</span>
              <span className="ml-auto text-[10px] text-neutral-500">{allIncidents.length}</span>
            </div>
            <div className="divide-y divide-brand-border/50 max-h-40 overflow-y-auto">
              {allIncidents.slice(0, 10).map(inc => {
                const sev = SEV_CONFIG[inc.severity] || SEV_CONFIG.P3;
                return (
                  <button key={inc.incident_id} onClick={() => setSelectedIncident(selectedIncident === inc.incident_id ? null : inc.incident_id)} className="w-full text-left px-4 py-2 hover:bg-white/[0.02] text-xs">
                    <div className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: sev.color }} />
                      <span className="text-white truncate flex-1">{inc.attack_type}</span>
                      <span className={`text-[9px] font-bold ${sev.text}`}>{sev.label}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* ═══ LIVE LOG CONSOLE — visible during/after simulation ═══ */}
      {(simLogs.length > 0) && (
        <div className="bg-[#0a0a0a] border border-brand-border rounded-xl overflow-hidden" style={{ maxHeight: 220 }}>
          <div className="flex items-center justify-between px-4 py-2 border-b border-brand-border bg-[#111]">
            <span className="text-xs font-semibold text-emerald-400 font-mono flex items-center gap-2">
              <Activity size={12} className={simRunning ? 'animate-pulse' : ''} /> AEGIS RAW LOG CONSOLE — {simStats.total} events
            </span>
            <div className="flex items-center gap-3 text-[10px] font-mono">
              {simPhase && <span className="text-amber-400">{simPhase.phase} ({simPhase.mitre})</span>}
              {simIsolated.size > 0 && <span className="text-red-400 font-bold">🔒 {simIsolated.size} isolated</span>}
            </div>
          </div>
          <div className="overflow-y-auto font-mono text-[11px] leading-relaxed px-3 py-2" style={{ maxHeight: 180 }}>
            {simLogs.slice(-100).map((log, i) => {
              const sevColor = log.severity === 'CRITICAL' ? 'text-red-400' : log.severity === 'HIGH' ? 'text-orange-400' : log.severity === 'MEDIUM' ? 'text-yellow-400' : log.severity === 'INFO' ? 'text-emerald-400' : 'text-neutral-500';
              const bgColor = log.type === 'isolation' ? 'bg-red-500/8' : log.type === 'enrichment' ? 'bg-emerald-500/5' : '';
              return (
                <div key={i} className={`flex gap-2 py-0.5 ${bgColor}`}>
                  <span className="text-neutral-600 shrink-0">{log.timestamp || ''}</span>
                  <span className={`shrink-0 w-16 ${sevColor}`}>[{log.severity || 'LOG'}]</span>
                  <span className="text-neutral-300">{log.raw}</span>
                </div>
              );
            })}
            <div ref={logEndRef} />
          </div>
        </div>
      )}
    </div>
  );
};

export default NetworkTopology;
