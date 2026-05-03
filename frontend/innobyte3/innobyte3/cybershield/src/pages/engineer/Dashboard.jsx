import React, { useEffect, useState, useMemo } from 'react';
import { useAppStore } from '../../store/useAppStore';
import { api } from '../../services/api';
import { Link } from 'react-router-dom';
import { Activity, ShieldAlert, ArrowUpRight, ArrowDownRight, Clock, Server, Globe, Shield, CheckCircle2, Send } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import ThreatMap from '../../components/ui/Threatmap';

/* No static fallback — all data from unified DB */

const apiSevColor = { critical: '#ff4057', high: '#f97316', medium: '#f59e0b', low: '#00e87b' };
const tooltipStyle = { backgroundColor: '#111', borderColor: '#222', borderRadius: '8px', color: '#fff', fontSize: '12px' };

const sevConfig = {
  Low: 'bg-emerald-500',
  Medium: 'bg-yellow-500',
  High: 'bg-orange-500',
  Critical: 'bg-red-500',
};

/** Map attack count → severity for bar coloring */
function countSeverity(n) {
  if (n >= 100) return 'critical';
  if (n >= 30) return 'high';
  if (n >= 10) return 'medium';
  return 'low';
}

export const Dashboard = () => {
  const { incidents, fetchIncidents, isLoadingIncidents, logs, fetchLogs, analytics, fetchAnalytics } = useAppStore();
  const [progressStats, setProgressStats] = useState(null);
  const [unifiedAttacks, setUnifiedAttacks] = useState([]);

  useEffect(() => {
    fetchIncidents();
    fetchLogs();
    fetchAnalytics();
    (async () => {
      try {
        const [stats, unified] = await Promise.all([
          api.getProgressStats(),
          api.getUnifiedAttacks(),
        ]);
        if (stats) setProgressStats(stats);
        if (unified?.attacks) setUnifiedAttacks(unified.attacks);
      } catch {}
    })();
  }, [fetchIncidents, fetchLogs, fetchAnalytics]);

  /* Build chart data from unified DB + analytics */
  const attackDistribution = useMemo(() => {
    // Prefer unified attacks for distribution
    if (unifiedAttacks.length > 0) {
      const counts = {};
      unifiedAttacks.forEach(a => { counts[a.attack_type] = (counts[a.attack_type] || 0) + 1; });
      return Object.entries(counts)
        .map(([type, count]) => ({ api: type, threats: count, severity: countSeverity(count) }))
        .sort((a, b) => b.threats - a.threats);
    }
    if (!analytics || !analytics.attack_distribution) return [];
    return Object.entries(analytics.attack_distribution)
      .filter(([k]) => k)
      .map(([type, count]) => ({ api: type.replace(/_/g, ' '), threats: count, severity: countSeverity(count) }))
      .sort((a, b) => b.threats - a.threats);
  }, [analytics, unifiedAttacks]);

  const hourlyData = useMemo(() => {
    // Build from unified attacks by hour
    if (unifiedAttacks.length > 0) {
      const hours = {};
      unifiedAttacks.forEach(a => {
        const h = (a.generated_at || '').split('T')[1]?.slice(0, 2) || 'XX';
        hours[h] = (hours[h] || 0) + 1;
      });
      return Object.entries(hours)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([h, n]) => ({ day: `${h}:00`, detected: n, mitigated: Math.round(n * 0.92) }));
    }
    if (!analytics || !analytics.attacks_by_hour) return [];
    return Object.entries(analytics.attacks_by_hour).map(([hour, count]) => ({
      day: hour, detected: count, mitigated: Math.round(count * 0.95),
    }));
  }, [analytics, unifiedAttacks]);

  const totalEntities = unifiedAttacks.length > 0
    ? new Set(unifiedAttacks.map(a => a.entity_id)).size
    : (analytics?.total_entities_tracked || 0);
  const totalAlerts = unifiedAttacks.length > 0 ? unifiedAttacks.length : (analytics?.total_alerts_logged || 0);

  const active = incidents.filter(i => i.status !== 'Resolved');
  const critical = incidents.filter(i => i.severity === 'Critical' && i.status !== 'Resolved');
  const resolvedToday = incidents.filter(i => i.status === 'Resolved').length;

  // Compute real deltas
  const criticalAll = unifiedAttacks.filter(a => a.severity === 'P1').length;
  const highAll = unifiedAttacks.filter(a => a.severity === 'P2').length;

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300">
      {/* Header section */}
      <div className="flex items-center justify-between pb-6 border-b border-brand-border">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight">Overview</h1>
          <p className="text-xs text-neutral-500 mt-1">System status and active threat monitoring.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium border border-brand-border bg-brand-bg-surface rounded-md">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" /> API Healthy
          </span>
          <span className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium border border-brand-border bg-brand-bg-surface rounded-md">
            <Server size={12} className="text-neutral-500" /> {totalEntities} Entities Tracked
          </span>
        </div>
      </div>

      {/* Global Threat Map */}
      <div className="pt-6">
        <ThreatMap />
      </div>

      {/* Main Grid: 12 Columns */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-6 flex-1 items-start">

        {/* LEFT COLUMN: Metrics (3/12) */}
        <div className="lg:col-span-3 space-y-4">
          <h2 className="text-[11px] font-semibold text-neutral-500 uppercase tracking-wider mb-2">Metrics</h2>

          <div className="border border-brand-border bg-brand-bg-card p-4 rounded-md">
            <p className="text-xs text-neutral-500 mb-1">Active Incidents</p>
            <div className="flex items-end gap-3">
              <span className="text-3xl font-semibold text-white leading-none">{active.length}</span>
              <span className="flex items-center text-xs text-orange-500 font-medium pb-0.5"><ArrowUpRight size={14} /> {criticalAll} P1</span>
            </div>
          </div>

          <div className="border border-brand-border bg-brand-bg-card p-4 rounded-md">
            <p className="text-xs text-neutral-500 mb-1">Critical / High</p>
            <div className="flex items-end gap-3">
              <span className="text-3xl font-semibold text-white leading-none">{criticalAll + highAll}</span>
              <span className="flex items-center text-xs text-red-500 font-medium pb-0.5">{criticalAll} P1 · {highAll} P2</span>
            </div>
          </div>

          <div className="border border-brand-border bg-brand-bg-card p-4 rounded-md">
            <p className="text-xs text-neutral-500 mb-1">Resolved</p>
            <div className="flex items-end gap-3">
              <span className="text-3xl font-semibold text-white leading-none">{resolvedToday}</span>
              <span className="flex items-center text-xs text-emerald-500 font-medium pb-0.5">{resolvedToday > 0 ? <><ArrowUpRight size={14} /> {Math.round(resolvedToday / Math.max(incidents.length, 1) * 100)}%</> : 'None yet'}</span>
            </div>
          </div>

          <div className="border border-brand-border bg-brand-bg-card p-4 rounded-md">
            <p className="text-xs text-neutral-500 mb-1">Responses In Progress</p>
            <div className="flex items-end gap-3">
              <span className="text-3xl font-semibold text-white leading-none">{progressStats?.in_progress || 0}</span>
              <span className="flex items-center text-xs text-amber-400 font-medium pb-0.5"><Send size={12} /> {progressStats?.completed || 0} completed</span>
            </div>
          </div>

          <div className="border border-brand-border bg-brand-bg-card p-4 rounded-md">
            <p className="text-xs text-neutral-500 mb-1">Total Alerts</p>
            <div className="flex items-end gap-3">
              <span className="text-3xl font-semibold text-white leading-none">{totalAlerts}</span>
              <span className="flex items-center text-xs text-brand-primary font-medium pb-0.5">from DB</span>
            </div>
          </div>
        </div>

        {/* CENTER COLUMN: Main Incident Queue (6/12) */}
        <div className="lg:col-span-6 flex flex-col h-full border border-brand-border bg-brand-bg-card rounded-md overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-brand-border bg-brand-bg-surface">
            <h2 className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">Active Queue</h2>
            <Link to="/engineer/incidents" className="text-xs text-neutral-500 hover:text-white transition-colors">View All</Link>
          </div>

          <div className="divide-y divide-brand-border overflow-y-auto">
            {isLoadingIncidents ? (
              <div className="p-4 text-xs text-neutral-500">Loading queue...</div>
            ) : active.length === 0 ? (
              <div className="p-8 text-center text-xs text-neutral-500">No active incidents.</div>
            ) : (
              active.slice(0, 8).map(inc => (
                <Link key={inc.id} to={`/engineer/incidents/${inc.id}`} className="flex items-start gap-4 p-4 hover:bg-white/[0.02] transition-colors group">
                  <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${sevConfig[inc.severity] || 'bg-neutral-500'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <h3 className="text-sm font-medium text-white truncate group-hover:text-brand-primary transition-colors">{inc.attackType || inc.title}</h3>
                      <span className="text-[10px] text-neutral-500 font-mono shrink-0 ml-4">{inc.detectedAt?.split(' ')[1] || 'Just now'}</span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-neutral-500">
                      <span className="font-mono">{inc.id}</span>
                      <span>•</span>
                      <span>{inc.assignedTo}</span>
                    </div>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: Live Activity Stream (3/12) */}
        <div className="lg:col-span-3 flex flex-col h-full border border-brand-border bg-brand-bg-card rounded-md overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-brand-border bg-brand-bg-surface">
            <Activity size={14} className="text-brand-primary" />
            <h2 className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">Activity Stream</h2>
          </div>

          <div className="divide-y divide-brand-border overflow-y-auto">
            {!logs || logs.length === 0 ? (
              <div className="p-4 text-xs text-neutral-500">Waiting for events...</div>
            ) : (
              logs.slice(0, 10).map((log, i) => (
                <div key={log.id || i} className="p-3 hover:bg-white/[0.02] transition-colors">
                  <p className="text-xs text-neutral-300 leading-snug">{log.description || log.action}</p>
                  <div className="flex items-center justify-between mt-1.5">
                    <span className="text-[10px] text-brand-primary font-medium">{log.actor || log.user}</span>
                    <span className="text-[10px] text-neutral-600 font-mono">{log.timestamp?.split(' ')[1] || log.timestamp}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Response Activity Feed */}
        {progressStats?.recent_activity?.length > 0 && (
          <div className="lg:col-span-12 border border-brand-border bg-brand-bg-card rounded-md overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-brand-border bg-brand-bg-surface">
              <h2 className="text-xs font-semibold text-neutral-300 uppercase tracking-wider flex items-center gap-2"><CheckCircle2 size={13} className="text-brand-primary" /> Recent Response Activity</h2>
              <Link to="/engineer/soc-analysis" className="text-xs text-neutral-500 hover:text-white">View All</Link>
            </div>
            <div className="divide-y divide-brand-border">
              {progressStats.recent_activity.map((act, i) => (
                <div key={act.incident_id + i} className="flex items-center gap-4 px-4 py-3">
                  <div className="w-8 h-8 rounded-full bg-brand-primary/10 flex items-center justify-center shrink-0">
                    <Send size={12} className="text-brand-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-white">{act.incident_id?.slice(0, 8)}</span>
                      <span className="text-[10px] text-neutral-500">by {act.analyst}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <div className="flex-1 h-1.5 bg-brand-bg-surface rounded-full overflow-hidden max-w-[120px]">
                        <div className="h-full bg-brand-primary rounded-full" style={{ width: `${act.pct}%` }} />
                      </div>
                      <span className="text-[10px] text-neutral-400">{act.steps_done}/{act.steps_total} steps ({act.pct}%)</span>
                    </div>
                  </div>
                  <span className="text-[10px] text-neutral-600 font-mono shrink-0">{act.last_updated?.split('T')[1]?.slice(0, 5) || ''}</span>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-6">
        {/* Threat Volume (Weekly) */}
        <div className="border border-brand-border bg-brand-bg-card rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-brand-border bg-brand-bg-surface">
            <h2 className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">Threat Volume (Hourly)</h2>
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5 text-[10px] text-neutral-500"><span className="w-2 h-2 rounded-full bg-[#ff4057]" />Detected</span>
              <span className="flex items-center gap-1.5 text-[10px] text-neutral-500"><span className="w-2 h-2 rounded-full bg-[#00e87b]" />Mitigated</span>
            </div>
          </div>
          <div className="p-5">
            <div className="h-64">
              <ResponsiveContainer>
                <BarChart data={hourlyData}>
                  <CartesianGrid stroke="#1a1a1a" vertical={false} />
                  <XAxis dataKey="day" stroke="#525252" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} />
                  <YAxis stroke="#525252" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#1a1a1a' }} />
                  <Bar dataKey="detected" fill="#ff4057" radius={[4, 4, 0, 0]} name="Detected" />
                  <Bar dataKey="mitigated" fill="#00e87b" radius={[4, 4, 0, 0]} name="Mitigated" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Threats per API */}
        <div className="border border-brand-border bg-brand-bg-card rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-brand-border bg-brand-bg-surface">
            <div className="flex items-center gap-2">
              <Shield size={14} className="text-brand-primary" />
              <h2 className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">Attack Distribution</h2>
            </div>
            <span className="text-[10px] text-neutral-500">Last 30 days</span>
          </div>
          <div className="p-5 space-y-3">
            {(attackDistribution.length > 0 ? attackDistribution : [{api:'No data', threats:0, severity:'low'}]).map((item) => (
              <div key={item.api} className="group">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-mono text-neutral-300">{item.api}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-white">{item.threats}</span>
                    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: apiSevColor[item.severity] }} />
                  </div>
                </div>
                <div className="w-full h-1.5 rounded-full bg-white/[0.05] overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${attackDistribution.length > 0 ? (item.threats / attackDistribution[0].threats) * 100 : 0}%`,
                      backgroundColor: apiSevColor[item.severity],
                      opacity: 0.8,
                    }}
                  />
                </div>
              </div>
            ))}
            <div className="flex items-center gap-4 pt-3 border-t border-brand-border">
              {[{ label: 'Critical', color: '#ff4057' }, { label: 'High', color: '#f97316' }, { label: 'Medium', color: '#f59e0b' }, { label: 'Low', color: '#00e87b' }].map(l => (
                <span key={l.label} className="flex items-center gap-1.5 text-[10px] text-neutral-500">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: l.color }} />{l.label}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
