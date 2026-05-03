import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bell, Search, Filter, X, Eye, Clock, ShieldCheck, ShieldAlert, ShieldX, ChevronDown } from 'lucide-react';

/* ═══ Mock Notifications ═══ */
const allNotifications = [
  { id: 1, title: 'Malware Attempt Blocked', severity: 'Critical', status: 'Blocked', desc: 'Ransomware attack automatically neutralized on File Server 3. Anti-malware engine detected encrypted payload.', time: '2026-05-02T08:15:00', category: 'Malware' },
  { id: 2, title: 'Phishing Campaign Detected', severity: 'Medium', status: 'In Progress', desc: 'Suspicious emails targeting HR department identified. 12 emails quarantined.', time: '2026-05-02T07:30:00', category: 'Phishing' },
  { id: 3, title: 'Firewall Rules Updated', severity: 'Low', status: 'Resolved', desc: 'Monthly firewall policy refresh completed. All rules validated and deployed.', time: '2026-05-02T05:00:00', category: 'System' },
  { id: 4, title: 'Unauthorized Access Attempt', severity: 'Critical', status: 'Blocked', desc: 'Brute-force login attempt on admin portal from IP 185.220.101.xx blocked after 50 attempts.', time: '2026-05-01T22:45:00', category: 'Access' },
  { id: 5, title: 'SSL Certificate Renewed', severity: 'Low', status: 'Resolved', desc: 'All production SSL certificates renewed for the next 12 months successfully.', time: '2026-05-01T14:30:00', category: 'System' },
  { id: 6, title: 'DDoS Attack Mitigated', severity: 'Critical', status: 'Resolved', desc: 'Volumetric DDoS attack on public API gateway mitigated. Traffic scrubbing activated.', time: '2026-05-01T11:20:00', category: 'DDoS' },
  { id: 7, title: 'Data Exfiltration Alert', severity: 'Critical', status: 'In Progress', desc: 'Large outbound data transfer detected from internal financial database server.', time: '2026-04-30T16:00:00', category: 'Data Breach' },
  { id: 8, title: 'Endpoint Security Update', severity: 'Low', status: 'Resolved', desc: 'All endpoints updated with latest security patches and signature definitions.', time: '2026-04-30T10:00:00', category: 'System' },
  { id: 9, title: 'Credential Leak Discovered', severity: 'Medium', status: 'In Progress', desc: 'Admin credentials found in public GitHub repository. Password reset initiated.', time: '2026-04-29T09:15:00', category: 'Access' },
  { id: 10, title: 'VPN Configuration Change', severity: 'Low', status: 'Resolved', desc: 'VPN gateway configuration updated to enforce stronger encryption protocols.', time: '2026-04-28T15:30:00', category: 'System' },
  { id: 11, title: 'Insider Threat Activity', severity: 'Medium', status: 'In Progress', desc: 'Unusual file access pattern detected from employee workstation in finance dept.', time: '2026-04-28T11:00:00', category: 'Access' },
  { id: 12, title: 'Compliance Audit Scheduled', severity: 'Low', status: 'Resolved', desc: 'Annual ISO 27035 compliance audit scheduled for next quarter.', time: '2026-04-27T08:00:00', category: 'System' },
];

const sevConfig = {
  Critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', dot: 'bg-red-500', icon: ShieldX },
  Medium: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20', dot: 'bg-amber-500', icon: ShieldAlert },
  Low: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20', dot: 'bg-emerald-500', icon: ShieldCheck },
};

const statusStyles = {
  Blocked: 'text-red-400 bg-red-500/10 border-red-500/20',
  'In Progress': 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  Resolved: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
};

const fadeUp = { hidden: { opacity: 0, y: 16 }, show: { opacity: 1, y: 0 } };

/* ═══ Detail Modal ═══ */
const DetailModal = ({ notification, onClose }) => {
  if (!notification) return null;
  const sev = sevConfig[notification.severity];
  const SevIcon = sev.icon;
  const dt = new Date(notification.time);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        onClick={e => e.stopPropagation()}
        className="bg-brand-bg-card border border-brand-border rounded-2xl w-full max-w-lg mx-4 shadow-2xl overflow-hidden"
      >
        <div className="flex items-center justify-between p-5 border-b border-brand-border bg-brand-bg-surface">
          <h2 className="text-lg font-semibold text-white">Event Details</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-white/5">
            <X size={18} />
          </button>
        </div>

        <div className="p-6 space-y-5">
          <div className="flex items-start gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${sev.bg} ${sev.text}`}>
              <SevIcon size={24} />
            </div>
            <div className="flex-1">
              <h3 className="text-white font-semibold text-lg">{notification.title}</h3>
              <div className="flex items-center gap-2 mt-1">
                <span className={`px-2.5 py-0.5 text-[11px] font-medium rounded-full border ${sev.bg} ${sev.text} ${sev.border}`}>
                  {notification.severity}
                </span>
                <span className={`px-2.5 py-0.5 text-[11px] font-medium rounded-full border ${statusStyles[notification.status]}`}>
                  {notification.status}
                </span>
              </div>
            </div>
          </div>

          <div className="bg-brand-bg-surface rounded-xl p-4 border border-brand-border/50">
            <p className="text-sm text-neutral-300 leading-relaxed">{notification.desc}</p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="bg-brand-bg-surface rounded-lg p-3 border border-brand-border/50">
              <p className="text-[11px] text-neutral-500 uppercase tracking-wider mb-1">Category</p>
              <p className="text-sm text-white font-medium">{notification.category}</p>
            </div>
            <div className="bg-brand-bg-surface rounded-lg p-3 border border-brand-border/50">
              <p className="text-[11px] text-neutral-500 uppercase tracking-wider mb-1">Detected At</p>
              <p className="text-sm text-white font-medium">{dt.toLocaleDateString()} {dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-full py-3 bg-brand-primary/10 text-brand-primary border border-brand-primary/20 rounded-xl text-sm font-medium hover:bg-brand-primary/20 transition-all"
          >
            Close
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
};

/* ═══ MAIN COMPONENT ═══ */
export const AdminNotifications = () => {
  const [notifications] = useState(allNotifications);
  const [search, setSearch] = useState('');
  const [filterSev, setFilterSev] = useState('All');
  const [filterStatus, setFilterStatus] = useState('All');
  const [selectedNotif, setSelectedNotif] = useState(null);
  const [showFilters, setShowFilters] = useState(false);

  const filtered = notifications.filter(n => {
    const matchSearch = n.title.toLowerCase().includes(search.toLowerCase()) || n.desc.toLowerCase().includes(search.toLowerCase());
    const matchSev = filterSev === 'All' || n.severity === filterSev;
    const matchStatus = filterStatus === 'All' || n.status === filterStatus;
    return matchSearch && matchSev && matchStatus;
  });

  const counts = {
    total: notifications.length,
    critical: notifications.filter(n => n.severity === 'Critical').length,
    inProgress: notifications.filter(n => n.status === 'In Progress').length,
    resolved: notifications.filter(n => n.status === 'Resolved').length,
  };

  const formatTime = (isoStr) => {
    const dt = new Date(isoStr);
    const now = new Date();
    const diff = now - dt;
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    if (hours < 1) return 'Just now';
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return dt.toLocaleDateString();
  };

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300">
      {/* Header */}
      <div className="flex items-center justify-between pb-6 border-b border-brand-border">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight flex items-center gap-2">
            <Bell size={20} className="text-brand-info" /> Notifications
          </h1>
          <p className="text-xs text-neutral-500 mt-1">Security events and alerts overview.</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-5">
        {[
          { label: 'Total Events', value: counts.total, accent: 'text-brand-info' },
          { label: 'Critical', value: counts.critical, accent: 'text-red-400' },
          { label: 'In Progress', value: counts.inProgress, accent: 'text-amber-400' },
          { label: 'Resolved', value: counts.resolved, accent: 'text-emerald-400' },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="bg-brand-bg-card border border-brand-border rounded-xl p-4"
          >
            <p className="text-[11px] text-neutral-500 uppercase tracking-wider">{s.label}</p>
            <p className={`text-2xl font-bold mt-1 ${s.accent}`}>{s.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Search & Filters */}
      <div className="flex items-center gap-3 pt-5">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search events..."
            className="w-full bg-brand-bg-card border border-brand-border rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-neutral-600 focus:outline-none focus:border-brand-primary/50 transition-colors"
          />
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-2 px-4 py-2.5 border rounded-xl text-sm transition-all ${showFilters ? 'bg-brand-primary/10 border-brand-primary/20 text-brand-primary' : 'bg-brand-bg-card border-brand-border text-neutral-400 hover:text-white'}`}
        >
          <Filter size={16} /> Filters
          <ChevronDown size={14} className={`transition-transform ${showFilters ? 'rotate-180' : ''}`} />
        </button>
      </div>

      {/* Filter pills */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="flex flex-wrap gap-4 pt-4">
              <div>
                <p className="text-[11px] text-neutral-500 uppercase tracking-wider mb-2">Severity</p>
                <div className="flex gap-2">
                  {['All', 'Critical', 'Medium', 'Low'].map(s => (
                    <button
                      key={s}
                      onClick={() => setFilterSev(s)}
                      className={`px-3 py-1.5 text-xs rounded-lg border transition-all ${filterSev === s ? 'bg-brand-primary/10 border-brand-primary/20 text-brand-primary' : 'bg-brand-bg-card border-brand-border text-neutral-400 hover:text-white'}`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-[11px] text-neutral-500 uppercase tracking-wider mb-2">Status</p>
                <div className="flex gap-2">
                  {['All', 'Blocked', 'In Progress', 'Resolved'].map(s => (
                    <button
                      key={s}
                      onClick={() => setFilterStatus(s)}
                      className={`px-3 py-1.5 text-xs rounded-lg border transition-all ${filterStatus === s ? 'bg-brand-primary/10 border-brand-primary/20 text-brand-primary' : 'bg-brand-bg-card border-brand-border text-neutral-400 hover:text-white'}`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Notifications List */}
      <div className="mt-5 bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden flex-1">
        <div className="divide-y divide-brand-border/50">
          {filtered.length === 0 ? (
            <div className="p-12 text-center">
              <Bell size={32} className="text-neutral-600 mx-auto mb-3" />
              <p className="text-neutral-500 text-sm">No events match your filters.</p>
            </div>
          ) : (
            filtered.map((n, i) => {
              const sev = sevConfig[n.severity];
              const SevIcon = sev.icon;
              return (
                <motion.div
                  key={n.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03 }}
                  className="flex items-center gap-4 px-5 py-4 hover:bg-white/[0.015] transition-colors cursor-pointer group"
                  onClick={() => setSelectedNotif(n)}
                >
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${sev.bg} ${sev.text}`}>
                    <SevIcon size={18} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate group-hover:text-brand-primary transition-colors">{n.title}</p>
                    <p className="text-xs text-neutral-500 mt-0.5 truncate">{n.desc}</p>
                  </div>
                  <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border shrink-0 hidden sm:inline-block ${sev.bg} ${sev.text} ${sev.border}`}>
                    {n.severity}
                  </span>
                  <span className={`px-2.5 py-1 text-[11px] font-medium rounded-full border shrink-0 hidden md:inline-block ${statusStyles[n.status]}`}>
                    {n.status}
                  </span>
                  <span className="text-[11px] text-neutral-600 shrink-0 w-16 text-right flex items-center justify-end gap-1">
                    <Clock size={10} /> {formatTime(n.time)}
                  </span>
                  <Eye size={16} className="text-neutral-600 group-hover:text-brand-primary shrink-0 transition-colors" />
                </motion.div>
              );
            })
          )}
        </div>
      </div>

      {/* Detail Modal */}
      <AnimatePresence>
        {selectedNotif && <DetailModal notification={selectedNotif} onClose={() => setSelectedNotif(null)} />}
      </AnimatePresence>
    </div>
  );
};
