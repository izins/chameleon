import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { LayoutDashboard, AlertTriangle, Activity, Share2, FileText, UserPlus, Shield, PanelLeftClose, PanelLeft, LogOut, Network, Link2 } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';

const navItems = [
  { name: 'Dashboard', path: '/engineer/dashboard', icon: LayoutDashboard },
  { name: 'Incidents', path: '/engineer/incidents', icon: AlertTriangle },
  { name: 'SOC Analysis', path: '/engineer/soc-analysis', icon: Activity },
  { name: 'Workflows', path: '/engineer/workflows', icon: Share2 },
  { name: 'Attack History', path: '/engineer/logs', icon: FileText },
  { name: 'Network Topology', path: '/engineer/topology', icon: Network },
  { name: 'Blockchain Ledger', path: '/engineer/blockchain', icon: Link2 },
  { name: 'Pentester Access', path: '/engineer/pentester-access', icon: UserPlus },
];

export const Sidebar = () => {
  const collapsed = useAppStore(s => s.sidebarCollapsed);
  const toggle = useAppStore(s => s.toggleSidebar);
  const navigate = useNavigate();

  return (
    <motion.aside
      animate={{ width: collapsed ? 72 : 256 }}
      transition={{ duration: 0.3, ease: [0.25, 0.4, 0.25, 1] }}
      className="h-screen fixed top-0 left-0 z-50 flex flex-col bg-brand-bg-surface border-r border-brand-border"
    >
      {/* Logo */}
      <div className="h-16 flex items-center px-5 border-b border-brand-border shrink-0">
        <img src="/image/logo.png" alt="Cameleon Logo" className="w-40 h-40 object-contain shrink-0" />

      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto overflow-x-hidden">
        {navItems.map(item => (
          <NavLink
            key={item.name}
            to={item.path}
            className={({ isActive }) =>
              `group flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 ${isActive
                ? 'bg-brand-primary/10 text-brand-primary border border-brand-primary/20'
                : 'text-neutral-400 hover:text-white hover:bg-white/[0.04] border border-transparent'
              }`
            }
            title={collapsed ? item.name : undefined}
          >
            <item.icon size={20} className="shrink-0" />
            {!collapsed && <span className="text-sm font-medium whitespace-nowrap">{item.name}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Bottom */}
      <div className="p-3 border-t border-brand-border space-y-2">
        <button onClick={toggle} className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-neutral-500 hover:text-white hover:bg-white/[0.04] transition-colors" title={collapsed ? 'Expand' : 'Collapse'}>
          {collapsed ? <PanelLeft size={20} /> : <PanelLeftClose size={20} />}
          {!collapsed && <span className="text-sm">Collapse</span>}
        </button>

        {!collapsed && (
          <div className="flex items-center gap-3 px-3 py-2">
            <div className="w-8 h-8 rounded-lg bg-brand-primary-dim flex items-center justify-center text-brand-primary text-xs font-bold shrink-0">AB</div>
            <div className="overflow-hidden">
              <p className="text-sm font-medium text-white truncate">Ahmed B.</p>
              <p className="text-xs text-neutral-500 truncate">IT/CS Engineer</p>
            </div>
          </div>
        )}

        <button onClick={() => navigate('/')} className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-neutral-500 hover:text-brand-danger hover:bg-brand-danger/10 transition-colors" title="Back to Landing">
          <LogOut size={18} className="shrink-0" />
          {!collapsed && <span className="text-sm">Sign Out</span>}
        </button>
      </div>
    </motion.aside>
  );
};
