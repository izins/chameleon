import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Server, Wifi, Shield, HardDrive, Cpu, Globe, Activity, CheckCircle2, AlertTriangle, Clock } from 'lucide-react';

/* ═══ Mock System Data ═══ */
const systems = [
  { name: 'Main Firewall', type: 'Network', status: 'Operational', uptime: '99.97%', icon: Shield, lastCheck: '2 min ago' },
  { name: 'IDS/IPS Engine', type: 'Security', status: 'Operational', uptime: '99.94%', icon: Activity, lastCheck: '1 min ago' },
  { name: 'Email Gateway', type: 'Communication', status: 'Operational', uptime: '99.89%', icon: Globe, lastCheck: '5 min ago' },
  { name: 'VPN Gateway', type: 'Network', status: 'Degraded', uptime: '97.2%', icon: Wifi, lastCheck: '3 min ago' },
  { name: 'Backup Server', type: 'Storage', status: 'Operational', uptime: '100%', icon: HardDrive, lastCheck: '10 min ago' },
  { name: 'Authentication Server', type: 'Identity', status: 'Operational', uptime: '99.99%', icon: Shield, lastCheck: '1 min ago' },
  { name: 'Web Application Firewall', type: 'Security', status: 'Operational', uptime: '99.91%', icon: Globe, lastCheck: '4 min ago' },
  { name: 'Database Cluster', type: 'Storage', status: 'Operational', uptime: '99.95%', icon: Server, lastCheck: '2 min ago' },
  { name: 'Load Balancer', type: 'Network', status: 'Maintenance', uptime: '95.1%', icon: Cpu, lastCheck: '30 min ago' },
];

const statusConfig = {
  Operational: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', dot: 'bg-emerald-500' },
  Degraded: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', dot: 'bg-amber-500' },
  Maintenance: { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', dot: 'bg-blue-500' },
  Down: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', dot: 'bg-red-500' },
};

const recentActivity = [
  { text: 'Firewall rule set updated successfully', time: '3 min ago', type: 'success' },
  { text: 'VPN latency spike detected — monitoring', time: '8 min ago', type: 'warning' },
  { text: 'Backup completed — 2.4TB archived', time: '15 min ago', type: 'success' },
  { text: 'Load balancer entering scheduled maintenance', time: '30 min ago', type: 'info' },
  { text: 'SSL certificate auto-renewal triggered', time: '1 hour ago', type: 'success' },
  { text: 'IDS signature database updated (v4.2.1)', time: '2 hours ago', type: 'success' },
];

const activityColors = {
  success: 'text-emerald-400',
  warning: 'text-amber-400',
  info: 'text-blue-400',
};

export const AdminOverview = () => {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const operational = systems.filter(s => s.status === 'Operational').length;
  const degraded = systems.filter(s => s.status === 'Degraded').length;
  const maintenance = systems.filter(s => s.status === 'Maintenance').length;

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300">
      {/* Header */}
      <div className="flex items-center justify-between pb-6 border-b border-brand-border">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight flex items-center gap-2">
            <Activity size={20} className="text-brand-info" /> System Overview
          </h1>
          <p className="text-xs text-neutral-500 mt-1">Infrastructure health and system status.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium border border-brand-border bg-brand-bg-surface rounded-lg">
            <Clock size={12} className="text-neutral-500" />
            {currentTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-5">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
          <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Total Systems</p>
          <p className="text-2xl font-bold text-white mt-1">{systems.length}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
          <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Operational</p>
          <p className="text-2xl font-bold text-emerald-400 mt-1 flex items-center gap-2"><CheckCircle2 size={18} /> {operational}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
          <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Degraded</p>
          <p className="text-2xl font-bold text-amber-400 mt-1 flex items-center gap-2"><AlertTriangle size={18} /> {degraded}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="bg-brand-bg-card border border-brand-border rounded-xl p-4">
          <p className="text-[11px] text-neutral-500 uppercase tracking-wider">Maintenance</p>
          <p className="text-2xl font-bold text-blue-400 mt-1 flex items-center gap-2"><Clock size={18} /> {maintenance}</p>
        </motion.div>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 pt-5 flex-1">
        {/* Systems Grid */}
        <div className="lg:col-span-8">
          <div className="bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden">
            <div className="px-5 py-3 border-b border-brand-border bg-brand-bg-surface flex items-center justify-between">
              <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Infrastructure Status</p>
              <span className="text-xs text-neutral-500">{systems.length} systems monitored</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-px bg-brand-border/30">
              {systems.map((sys, i) => {
                const config = statusConfig[sys.status];
                return (
                  <motion.div
                    key={sys.name}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.04 }}
                    className="bg-brand-bg-card p-4 hover:bg-white/[0.015] transition-colors"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${config.bg} ${config.color}`}>
                        <sys.icon size={18} />
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${config.dot} ${sys.status === 'Operational' ? 'animate-pulse' : ''}`} />
                        <span className={`text-[11px] font-medium ${config.color}`}>{sys.status}</span>
                      </div>
                    </div>
                    <p className="text-sm font-medium text-white">{sys.name}</p>
                    <div className="flex items-center justify-between mt-2">
                      <span className="text-[11px] text-neutral-500">{sys.type}</span>
                      <span className="text-[11px] text-neutral-500">↑ {sys.uptime}</span>
                    </div>
                    <p className="text-[10px] text-neutral-600 mt-1 flex items-center gap-1">
                      <Clock size={9} /> Checked {sys.lastCheck}
                    </p>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Activity Feed */}
        <div className="lg:col-span-4">
          <div className="bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden h-full flex flex-col">
            <div className="px-5 py-3 border-b border-brand-border bg-brand-bg-surface flex items-center gap-2">
              <Activity size={14} className="text-brand-primary" />
              <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Recent Activity</p>
            </div>
            <div className="divide-y divide-brand-border/50 flex-1 overflow-y-auto">
              {recentActivity.map((act, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="px-5 py-3.5 hover:bg-white/[0.015] transition-colors"
                >
                  <p className="text-sm text-neutral-300 leading-snug">{act.text}</p>
                  <p className={`text-[11px] mt-1 ${activityColors[act.type]}`}>{act.time}</p>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Overall Health Bar */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="mt-5 bg-brand-bg-card border border-brand-border rounded-2xl p-5"
      >
        <div className="flex items-center justify-between mb-3">
          <p className="text-sm font-semibold text-white">Overall Infrastructure Health</p>
          <span className="text-sm font-bold text-emerald-400">{Math.round((operational / systems.length) * 100)}%</span>
        </div>
        <div className="h-3 bg-brand-bg-surface rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${(operational / systems.length) * 100}%` }}
            transition={{ duration: 1.5, ease: 'easeOut' }}
            className="h-full bg-gradient-to-r from-emerald-500 to-brand-primary rounded-full"
          />
        </div>
      </motion.div>
    </div>
  );
};
