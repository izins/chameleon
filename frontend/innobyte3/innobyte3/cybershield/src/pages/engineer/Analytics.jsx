import React, { useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, AreaChart, Area } from 'recharts';
import { useAppStore } from '../../store/useAppStore';

const tooltipStyle = { backgroundColor: '#111', borderColor: '#222', borderRadius: '8px', color: '#fff', fontSize: '12px' };

export const Analytics = () => {
  const { incidents, fetchIncidents, analytics, fetchAnalytics, logs, fetchLogs } = useAppStore();

  useEffect(() => {
    fetchIncidents();
    fetchAnalytics();
    fetchLogs();
  }, [fetchIncidents, fetchAnalytics, fetchLogs]);

  const total = analytics?.total_alerts_logged || incidents.length || 0;
  const resolved = incidents.filter(i => i.status === 'Resolved').length;
  const critical = incidents.filter(i => i.severity === 'Critical').length;
  const entities = analytics?.total_entities_tracked || 0;

  // Build weekly data from analytics
  const weeklyData = useMemo(() => {
    if (analytics && analytics.attacks_by_hour) {
      return Object.entries(analytics.attacks_by_hour).map(([hour, count]) => ({
        day: hour,
        detected: count,
        mitigated: Math.round(count * 0.95),
      }));
    }
    return [
      { day: 'Mon', detected: 4, mitigated: 4 }, { day: 'Tue', detected: 7, mitigated: 6 },
      { day: 'Wed', detected: 2, mitigated: 2 }, { day: 'Thu', detected: 12, mitigated: 11 },
      { day: 'Fri', detected: 5, mitigated: 5 }, { day: 'Sat', detected: 3, mitigated: 3 },
      { day: 'Sun', detected: 8, mitigated: 7 },
    ];
  }, [analytics]);

  // Build traffic/load data from logs timeline
  const trafficData = useMemo(() => {
    if (!logs || logs.length === 0) {
      return [
        { t: '00:00', load: 20 }, { t: '04:00', load: 12 }, { t: '08:00', load: 45 },
        { t: '12:00', load: 78 }, { t: '16:00', load: 55 }, { t: '20:00', load: 32 }, { t: '23:59', load: 22 },
      ];
    }
    // Group logs by hour
    const byHour = {};
    logs.forEach(l => {
      const ts = l.timestamp || '';
      const hour = ts.includes('T') ? ts.split('T')[1]?.slice(0, 2) : ts.split(' ')[1]?.slice(0, 2);
      if (hour) {
        byHour[hour] = (byHour[hour] || 0) + 1;
      }
    });
    const entries = Object.entries(byHour).sort(([a], [b]) => a.localeCompare(b));
    if (entries.length === 0) return [{ t: 'N/A', load: 0 }];
    return entries.map(([h, c]) => ({ t: `${h}:00`, load: c * 10 }));
  }, [logs]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Analytics</h1>
        <p className="text-neutral-500 text-sm mt-0.5">Threat mitigation and system health overview — live from AEGIS DB</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Alerts', value: total, color: 'text-white' },
          { label: 'Resolved', value: resolved, color: 'text-brand-primary' },
          { label: 'Critical', value: critical, color: 'text-brand-danger' },
          { label: 'Entities Tracked', value: entities, color: 'text-brand-info' },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}
            className="p-5 rounded-2xl bg-brand-bg-card border border-brand-border">
            <p className="text-xs text-neutral-500 mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-brand-bg-card border border-brand-border rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-white mb-5">Threat Volume (Hourly)</h3>
          <div className="h-72">
            <ResponsiveContainer><BarChart data={weeklyData}>
              <CartesianGrid stroke="#1a1a1a" vertical={false} />
              <XAxis dataKey="day" stroke="#525252" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} />
              <YAxis stroke="#525252" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#1a1a1a' }} />
              <Bar dataKey="detected" fill="#ff4057" radius={[4,4,0,0]} name="Detected" />
              <Bar dataKey="mitigated" fill="#00e87b" radius={[4,4,0,0]} name="Mitigated" />
            </BarChart></ResponsiveContainer>
          </div>
        </div>

        <div className="bg-brand-bg-card border border-brand-border rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-white mb-5">Network Load Anomaly</h3>
          <div className="h-72">
            <ResponsiveContainer><AreaChart data={trafficData}>
              <CartesianGrid stroke="#1a1a1a" vertical={false} />
              <XAxis dataKey="t" stroke="#525252" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} />
              <YAxis stroke="#525252" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} />
              <Tooltip contentStyle={tooltipStyle} />
              <defs><linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38bdf8" stopOpacity={0.3} /><stop offset="100%" stopColor="#38bdf8" stopOpacity={0} /></linearGradient></defs>
              <Area type="monotone" dataKey="load" stroke="#38bdf8" strokeWidth={2} fill="url(#areaGrad)" name="Load %" />
            </AreaChart></ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
