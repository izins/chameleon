import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

// Layouts
import { Layout } from './components/layout/Layout';
import { AdminLayout } from './components/layout/AdminLayout';
import { LegalLayout } from './components/layout/LegalLayout';

// Landing
import { Landing } from './pages/Landing';

// Engineer Pages
import { Dashboard } from './pages/engineer/Dashboard';
import { Incidents } from './pages/engineer/Incidents';
import { IncidentDetail } from './pages/engineer/IncidentDetail';
import { SOCAnalysis } from './pages/engineer/SOCAnalysis';
import { LogHistory } from './pages/engineer/LogHistory';
import { Workflows } from './pages/engineer/Workflows';
import { PentesterAccess } from './pages/engineer/PentesterAccess';
import { NetworkTopology } from './pages/engineer/NetworkTopology';
import { BlockchainExplorer } from './pages/engineer/BlockchainExplorer';


// Pentester
import { PentesterDashboard } from './pages/pentester/PentesterDashboard';

// Admin Pages
import { AdminDashboard } from './pages/admin/AdminDashboard';
import { AdminNotifications } from './pages/admin/AdminNotifications';
import { AdminReports } from './pages/admin/AdminReports';


// Legal Pages
import { LegalDashboard } from './pages/legal/LegalDashboard';
import { LegalDocuments } from './pages/legal/LegalDocuments';
import { LegalCompliance } from './pages/legal/LegalCompliance';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />

        {/* Engineer Routes */}
        <Route path="/engineer" element={<Layout />}>
          <Route index element={<Navigate to="/engineer/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="soc-analysis" element={<SOCAnalysis />} />
          <Route path="logs" element={<LogHistory />} />
          <Route path="workflows" element={<Workflows />} />
          <Route path="pentester-access" element={<PentesterAccess />} />
          <Route path="topology" element={<NetworkTopology />} />
          <Route path="blockchain" element={<BlockchainExplorer />} />

        </Route>

        {/* Admin / Executive Routes */}
        <Route path="/admin" element={<AdminLayout />}>
          <Route index element={<Navigate to="/admin/dashboard" replace />} />
          <Route path="dashboard" element={<AdminDashboard />} />
          <Route path="notifications" element={<AdminNotifications />} />
          <Route path="reports" element={<AdminReports />} />

        </Route>

        {/* Legal / Juridical Routes */}
        <Route path="/legal" element={<LegalLayout />}>
          <Route index element={<Navigate to="/legal/dashboard" replace />} />
          <Route path="dashboard" element={<LegalDashboard />} />
          <Route path="documents" element={<LegalDocuments />} />
          <Route path="compliance" element={<LegalCompliance />} />
        </Route>

        {/* Pentester — Isolated */}
        <Route path="/pentester" element={<PentesterDashboard />} />

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
