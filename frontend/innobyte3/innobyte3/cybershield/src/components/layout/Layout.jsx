import React from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { Outlet, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAppStore } from '../../store/useAppStore';

const pageTitles = {
  '/engineer/dashboard': 'Overview Dashboard',
  '/engineer/incidents': 'Incident Management',
  '/engineer/soc-analysis': 'SOC Log Analysis',
  '/engineer/workflows': 'Response Workflows',
  '/engineer/logs': 'Audit Trail',
  '/engineer/topology': 'Network Topology',
  '/engineer/pentester-access': 'Pentester Access',
};

export const Layout = () => {
  const location = useLocation();
  const collapsed = useAppStore(s => s.sidebarCollapsed);

  const title = Object.entries(pageTitles).find(([k]) => location.pathname.startsWith(k))?.[1] || 'Cameleon';

  return (
    <div className="min-h-screen bg-brand-bg-deep bg-grid">
      <Sidebar />
      <motion.div
        animate={{ marginLeft: collapsed ? 72 : 256 }}
        transition={{ duration: 0.3, ease: [0.25, 0.4, 0.25, 1] }}
        className="flex flex-col min-h-screen"
      >
        <Header title={title} />
        <main className="flex-1 p-6 lg:p-8 overflow-y-auto">
          <motion.div key={location.pathname} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Outlet />
          </motion.div>
        </main>
      </motion.div>
    </div>
  );
};
