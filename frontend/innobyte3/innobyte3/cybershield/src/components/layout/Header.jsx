import React, { useState, useRef, useEffect } from 'react';
import { Bell, Search } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppStore } from '../../store/useAppStore';

export const Header = ({ title }) => {
  const notifications = useAppStore(s => s.notifications);
  const markRead = useAppStore(s => s.markNotificationRead);
  const unreadCount = notifications.filter(n => n.unread).length;
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const severityColor = (s) => {
    if (s === 'critical') return 'bg-brand-danger/20 text-brand-danger';
    if (s === 'warning') return 'bg-brand-warning/20 text-brand-warning';
    return 'bg-brand-info/20 text-brand-info';
  };

  return (
    <header className="h-16 glass-strong border-b border-brand-border flex items-center justify-between px-8 sticky top-0 z-40">
      <h1 className="text-lg font-semibold text-white">{title}</h1>

      <div className="flex items-center gap-4">
        <div className="relative hidden md:block">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
          <input placeholder="Search incidents, IPs…" className="bg-brand-bg-card border border-brand-border rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-neutral-600 focus:outline-none focus:border-brand-primary/50 transition-colors w-60" />
        </div>

        <div ref={ref} className="relative">
          <button onClick={() => setOpen(!open)} className="relative p-2 text-neutral-400 hover:text-white transition-colors rounded-lg hover:bg-white/[0.04]">
            <Bell size={20} />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-brand-danger rounded-full animate-pulse" />
            )}
          </button>

          <AnimatePresence>
            {open && (
              <motion.div initial={{ opacity: 0, y: 8, scale: 0.96 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 8, scale: 0.96 }} transition={{ duration: 0.2 }} className="absolute right-0 mt-2 w-80 rounded-xl border border-brand-border bg-brand-bg-card shadow-2xl shadow-black/40 overflow-hidden z-50">
                <div className="p-4 border-b border-brand-border flex justify-between items-center">
                  <span className="font-semibold text-white text-sm">Notifications</span>
                  {unreadCount > 0 && <span className="text-xs bg-brand-primary-dim text-brand-primary px-2 py-0.5 rounded-full font-medium">{unreadCount} new</span>}
                </div>
                <div className="max-h-80 overflow-y-auto">
                  {notifications.length === 0 ? (
                    <p className="p-6 text-center text-neutral-500 text-sm">No notifications</p>
                  ) : notifications.map(n => (
                    <div key={n.id} onClick={() => markRead(n.id)} className={`p-4 border-b border-brand-border/50 hover:bg-white/[0.02] cursor-pointer transition-colors ${n.unread ? '' : 'opacity-50'}`}>
                      <div className="flex justify-between items-start mb-1.5">
                        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded ${severityColor(n.severity)}`}>{n.severity?.toUpperCase() || 'ALERT'}</span>
                        <span className="text-[11px] text-neutral-600">{new Date(n.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                      </div>
                      <p className="text-sm font-medium text-white">{n.title}</p>
                      <p className="text-xs text-neutral-500 mt-1 line-clamp-2">{n.message}</p>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </header>
  );
};
