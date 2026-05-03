import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, TrendingUp, CheckCircle2, AlertTriangle, Clock, Users, FileText,
  Zap, ArrowUpRight, ArrowDownRight, Briefcase, Scale, Wrench
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

/* ═══ Plain-Language Data ═══ */
const weeklyTrend = [
  { day: 'Mon', blocked: 12, resolved: 10 },
  { day: 'Tue', blocked: 8, resolved: 9 },
  { day: 'Wed', blocked: 15, resolved: 13 },
  { day: 'Thu', blocked: 6, resolved: 7 },
  { day: 'Fri', blocked: 19, resolved: 14 },
  { day: 'Sat', blocked: 4, resolved: 5 },
  { day: 'Sun', blocked: 3, resolved: 3 },
];

const teamActivity = {
  engineer: [
    { text: 'Investigating suspicious network activity', status: 'In Progress', person: 'Ahmed B.' },
    { text: 'Updated firewall protection rules', status: 'Done', person: 'Sarah M.' },
    { text: 'Reviewing employee device security', status: 'In Progress', person: 'Karim L.' },
  ],
  legal: [
    { text: 'Preparing incident report for regulators', status: 'In Progress', person: 'Legal Team' },
    { text: 'Updated company privacy policy', status: 'Done', person: 'Legal Team' },
    { text: 'Reviewing vendor data agreements', status: 'Pending', person: 'Legal Team' },
  ],
};

const taskStatus = {
  'In Progress': 'text-amber-400',
  'Done': 'text-emerald-400',
  'Pending': 'text-neutral-500',
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-brand-bg-card border border-brand-border rounded-lg p-3 shadow-xl">
      <p className="text-xs text-neutral-400 mb-1">{label}</p>
      {payload.map((p, i) => (
        <p key={i} className="text-sm font-medium" style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  );
};

/* ═══ MAIN COMPONENT ═══ */
export const AdminDashboard = () => {
  const [securityScore, setSecurityScore] = useState(87);

  useEffect(() => {
    const interval = setInterval(() => {
      setSecurityScore(prev => Math.max(75, Math.min(99, prev + (Math.random() > 0.5 ? 1 : -1))));
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const scoreColor = securityScore >= 85 ? 'text-emerald-400' : securityScore >= 70 ? 'text-amber-400' : 'text-red-400';
  const scoreLabel = securityScore >= 85 ? 'Your company is well protected' : securityScore >= 70 ? 'Some areas need attention' : 'Immediate action recommended';

  return (
    <div className="h-full flex flex-col font-sans text-neutral-300 space-y-6">
      {/* Welcome Header */}
      <div className="flex items-center justify-between pb-5 border-b border-brand-border">
        <div>
          <h1 className="text-xl font-semibold text-white tracking-tight">Welcome back, Director</h1>
          <p className="text-sm text-neutral-500 mt-1">Here's what's happening with your company's security today.</p>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 bg-brand-bg-card border border-brand-border rounded-xl">
          <Clock size={14} className="text-neutral-500" />
          <span className="text-xs text-neutral-400">{new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}</span>
        </div>
      </div>

      {/* Top KPIs — Plain Language */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Security Score */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="bg-brand-bg-card border border-brand-border rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 flex items-center justify-center text-emerald-400"><Shield size={18} /></div>
            <span className="text-xs text-neutral-500">Overall Protection</span>
          </div>
          <p className={`text-3xl font-bold ${scoreColor}`}>{securityScore}%</p>
          <p className="text-xs text-neutral-500 mt-1">{scoreLabel}</p>
        </motion.div>

        {/* Threats Blocked */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="bg-brand-bg-card border border-brand-border rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-9 h-9 rounded-xl bg-red-500/10 flex items-center justify-center text-red-400"><AlertTriangle size={18} /></div>
            <span className="text-xs text-neutral-500">Threats Stopped</span>
          </div>
          <p className="text-3xl font-bold text-white">67</p>
          <p className="text-xs text-neutral-500 mt-1">Attacks blocked this week</p>
        </motion.div>

        {/* Issues Resolved */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-brand-bg-card border border-brand-border rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-9 h-9 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-400"><CheckCircle2 size={18} /></div>
            <span className="text-xs text-neutral-500">Issues Resolved</span>
          </div>
          <p className="text-3xl font-bold text-white">61</p>
          <p className="text-xs text-emerald-400 mt-1 flex items-center gap-1"><ArrowUpRight size={12} /> 91% resolution rate</p>
        </motion.div>

        {/* Legal Compliance */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="bg-brand-bg-card border border-brand-border rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 flex items-center justify-center text-emerald-400"><Scale size={18} /></div>
            <span className="text-xs text-neutral-500">Legal Compliance</span>
          </div>
          <p className="text-2xl font-bold text-emerald-400">All Clear</p>
          <p className="text-xs text-neutral-500 mt-1">Meeting all legal requirements</p>
        </motion.div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1">

        {/* LEFT: Charts */}
        <div className="lg:col-span-5 space-y-5">
          {/* Weekly Security Activity */}
          <div className="bg-brand-bg-card border border-brand-border rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-white mb-1">This Week's Security Activity</h3>
            <p className="text-xs text-neutral-500 mb-4">How many threats were stopped vs resolved each day</p>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={weeklyTrend}>
                <defs>
                  <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ff4057" stopOpacity={0.25} />
                    <stop offset="100%" stopColor="#ff4057" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gResolved" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00e87b" stopOpacity={0.25} />
                    <stop offset="100%" stopColor="#00e87b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="day" tick={{ fill: '#737373', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#737373', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="blocked" name="Threats Stopped" stroke="#ff4057" fill="url(#gBlocked)" strokeWidth={2} />
                <Area type="monotone" dataKey="resolved" name="Issues Fixed" stroke="#00e87b" fill="url(#gResolved)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* RIGHT: Team Activity Summary */}
        <div className="lg:col-span-7 space-y-5">
          {/* IT Team */}
          <div className="bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-brand-border bg-brand-bg-surface">
              <Wrench size={13} className="text-brand-info" />
              <h3 className="text-[11px] font-semibold text-neutral-300 uppercase tracking-wider">IT Security Team</h3>
            </div>
            <div className="p-4 space-y-3">
              {teamActivity.engineer.map((t, i) => (
                <div key={i} className="flex items-start gap-2.5">
                  <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${t.status === 'Done' ? 'bg-emerald-500' : 'bg-amber-500 animate-pulse'}`} />
                  <div>
                    <p className="text-xs text-neutral-300 leading-snug">{t.text}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`text-[10px] font-medium ${taskStatus[t.status]}`}>{t.status}</span>
                      <span className="text-[10px] text-neutral-600">· {t.person}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Legal Team */}
          <div className="bg-brand-bg-card border border-brand-border rounded-2xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-brand-border bg-brand-bg-surface">
              <Scale size={13} className="text-brand-primary" />
              <h3 className="text-[11px] font-semibold text-neutral-300 uppercase tracking-wider">Legal & Compliance</h3>
            </div>
            <div className="p-4 space-y-3">
              {teamActivity.legal.map((t, i) => (
                <div key={i} className="flex items-start gap-2.5">
                  <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${t.status === 'Done' ? 'bg-emerald-500' : t.status === 'Pending' ? 'bg-neutral-600' : 'bg-amber-500 animate-pulse'}`} />
                  <div>
                    <p className="text-xs text-neutral-300 leading-snug">{t.text}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`text-[10px] font-medium ${taskStatus[t.status]}`}>{t.status}</span>
                      <span className="text-[10px] text-neutral-600">· {t.person}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Summary Box */}
          <div className="bg-gradient-to-br from-brand-primary/5 to-brand-info/5 border border-brand-primary/10 rounded-2xl p-4">
            <h4 className="text-xs font-semibold text-brand-primary mb-2 flex items-center gap-1.5"><Briefcase size={12} /> Bottom Line</h4>
            <p className="text-xs text-neutral-400 leading-relaxed">
              Your company blocked <span className="text-white font-semibold">67 threats</span> this week and resolved <span className="text-white font-semibold">91%</span> of all security issues. 
              Legal compliance is <span className="text-emerald-400 font-semibold">up to date</span>. No action needed from you right now.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
