import { create } from 'zustand';
import { api } from '../services/api';

export const useAppStore = create((set, get) => ({
  // ── User ───────────────────────────
  user: null,
  setUser: (user) => set({ user }),
  logout: () => set({ user: null }),

  // ── Incidents (from /api/handler) ──
  incidents: [],
  isLoadingIncidents: true,
  fetchIncidents: async () => {
    set({ isLoadingIncidents: true });
    try {
      const data = await api.getIncidents();
      set({ incidents: data || [], isLoadingIncidents: false });
    } catch {
      set({ isLoadingIncidents: false });
    }
  },

  // ── Logs / Live Feed (from /api/soc/feed) ──
  logs: [],
  isLoadingLogs: true,
  fetchLogs: async () => {
    set({ isLoadingLogs: true });
    try {
      const data = await api.getLogs();
      set({ logs: data || [], isLoadingLogs: false });
    } catch {
      set({ isLoadingLogs: false });
    }
  },

  // ── ISO 27035 Lifecycle ────────────
  isoIncidents: [],
  isLoadingISO: false,
  fetchISOIncidents: async () => {
    set({ isLoadingISO: true });
    try {
      const data = await api.getISOIncidents();
      set({ isoIncidents: data || [], isLoadingISO: false });
    } catch {
      set({ isLoadingISO: false });
    }
  },

  // ── Network Topology ──────────────
  topology: null,
  isLoadingTopology: false,
  fetchTopology: async () => {
    set({ isLoadingTopology: true });
    try {
      const data = await api.getNetworkTopology();
      set({ topology: data, isLoadingTopology: false });
    } catch {
      set({ isLoadingTopology: false });
    }
  },

  // ── Legal Dashboard ────────────────
  legalData: null,
  isLoadingLegal: false,
  fetchLegalDashboard: async () => {
    set({ isLoadingLegal: true });
    try {
      const data = await api.getLegalDashboard();
      set({ legalData: data, isLoadingLegal: false });
    } catch {
      set({ isLoadingLegal: false });
    }
  },

  // ── Analytics ──────────────────────
  analytics: null,
  isLoadingAnalytics: false,
  fetchAnalytics: async () => {
    set({ isLoadingAnalytics: true });
    try {
      const data = await api.getAnalytics();
      set({ analytics: data, isLoadingAnalytics: false });
    } catch {
      set({ isLoadingAnalytics: false });
    }
  },

  // ── SOC Metrics ────────────────────
  socMetrics: null,
  fetchSOCMetrics: async () => {
    try {
      const data = await api.getSOCMetrics();
      set({ socMetrics: data });
    } catch {}
  },

  // ── Notifications ──────────────────
  notifications: [],
  addNotification: (notification) => set(state => ({
    notifications: [notification, ...state.notifications]
  })),
  markNotificationRead: (id) => set(state => ({
    notifications: state.notifications.map(n => n.id === id ? { ...n, unread: false } : n)
  })),
  clearNotifications: () => set({ notifications: [] }),

  // ── Sidebar ────────────────────────
  sidebarCollapsed: false,
  toggleSidebar: () => set(state => ({ sidebarCollapsed: !state.sidebarCollapsed })),
}));
