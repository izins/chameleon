import React from 'react';
import { AdminSidebar } from './AdminSidebar';
import { Header } from './Header';
import { Outlet, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAppStore } from '../../store/useAppStore';

const pageTitles = {
  '/admin/dashboard': 'Executive Dashboard',
  '/admin/notifications': 'Notifications',
  '/admin/reports': 'Reports & Compliance',
};

export const AdminLayout = () => {
  const location = useLocation();
  const collapsed = useAppStore(s => s.sidebarCollapsed);

  const title = Object.entries(pageTitles).find(([k]) => location.pathname.startsWith(k))?.[1] || 'Cameleon Admin';

  return (
    <div className="min-h-screen bg-brand-bg-deep bg-grid">
      <AdminSidebar />
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
