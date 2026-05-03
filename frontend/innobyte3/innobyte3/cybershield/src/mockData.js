export const mockIncidents = [
  { id: 'INC-2026-001', attackType: 'Phishing', detectedAt: '02/05/2026 08:15', severity: 'High', status: 'In Progress', assignedTo: 'Ahmed B.', workflow: 'Phishing Response', description: 'Spear phishing campaign targeting HR department.' },
  { id: 'INC-2026-002', attackType: 'Ransomware', detectedAt: '01/05/2026 23:40', severity: 'Critical', status: 'Open', assignedTo: 'Unassigned', workflow: 'Ransomware Containment', description: 'Multiple file servers showing encrypted extensions. Ransom note dropped.' },
  { id: 'INC-2026-003', attackType: 'DDoS', detectedAt: '30/04/2026 14:22', severity: 'Medium', status: 'Resolved', assignedTo: 'Sarah M.', workflow: 'DDoS Mitigation', description: 'Volumetric attack on main public portal.' },
  { id: 'INC-2026-004', attackType: 'Insider Threat', detectedAt: '28/04/2026 09:10', severity: 'High', status: 'In Progress', assignedTo: 'Karim L.', workflow: 'Insider Threat Investigation', description: 'Large data exfiltration detected from internal financial database.' },
  { id: 'INC-2026-005', attackType: 'Data Breach', detectedAt: '25/04/2026 11:05', severity: 'Critical', status: 'Resolved', assignedTo: 'Ahmed B.', workflow: 'Data Breach Notification', description: 'Customer PII found on dark web forum.' },
  { id: 'INC-2026-006', attackType: 'Malware', detectedAt: '24/04/2026 16:30', severity: 'Low', status: 'Resolved', assignedTo: 'Sarah M.', workflow: 'Malware Remediation', description: 'Adware detected on receptionist workstation.' },
  { id: 'INC-2026-007', attackType: 'Credential Leak', detectedAt: '22/04/2026 10:00', severity: 'High', status: 'Open', assignedTo: 'Unassigned', workflow: 'Credential Reset', description: 'Admin credentials found in public GitHub repository.' },
  { id: 'INC-2026-008', attackType: 'Lost Device', detectedAt: '20/04/2026 08:45', severity: 'Medium', status: 'Resolved', assignedTo: 'Karim L.', workflow: 'Device Wipe', description: 'Sales executive lost laptop at airport.' },
];

export const mockWorkflows = {
  'Phishing': [
    { id: 1, title: 'Isolate Affected Users', description: 'Disconnect affected user endpoints from the network.', role: 'IT/CS Engineer', sla: 'Within 15 minutes', legalRef: 'ISO 27035 Phase 3', status: 'Done' },
    { id: 2, title: 'Analyze Email Headers', description: 'Extract sender IP, domain, and malicious URLs.', role: 'SOC Analyst', sla: 'Within 30 minutes', legalRef: '', status: 'In Progress' },
    { id: 3, title: 'Block Malicious Domains', description: 'Add extracted IOCs to firewall blocklist.', role: 'IT/CS Engineer', sla: 'Within 1 hour', legalRef: '', status: 'Not Started' },
    { id: 4, title: 'User Awareness Training', description: 'Mandatory training for affected users.', role: 'HR', sla: 'Within 48 hours', legalRef: 'Law 18-07 Article 12', status: 'Not Started' },
  ],
  'Ransomware': [
    { id: 1, title: 'Immediate Network Isolation', description: 'Sever all network connections to affected segments.', role: 'IT/CS Engineer', sla: 'Immediate', legalRef: 'ISO 27035 Phase 3', status: 'Done' },
    { id: 2, title: 'Identify Strain & Patient Zero', description: 'Analyze logs to find entry point and ransomware variant.', role: 'SOC Analyst', sla: 'Within 2 hours', legalRef: '', status: 'Done' },
    { id: 3, title: 'Notify Authorities', description: 'Report incident to national cybersecurity agency.', role: 'Juridical Team', sla: 'Within 24 hours', legalRef: 'Law 18-07 Article 22', status: 'In Progress' },
    { id: 4, title: 'Restore from Backups', description: 'Wipe infected machines and restore from clean offline backups.', role: 'IT/CS Engineer', sla: 'Within 48 hours', legalRef: '', status: 'Not Started' },
  ],
  'DDoS': [
    { id: 1, title: 'Activate Anti-DDoS Protection', description: 'Route traffic through mitigation scrubbing center.', role: 'IT/CS Engineer', sla: 'Within 5 minutes', legalRef: '', status: 'Done' },
    { id: 2, title: 'Analyze Traffic Patterns', description: 'Identify attack vectors (e.g., SYN flood, amplification).', role: 'SOC Analyst', sla: 'Within 30 minutes', legalRef: '', status: 'Done' },
    { id: 3, title: 'Update Rate Limits', description: 'Adjust firewall rate limiting rules.', role: 'IT/CS Engineer', sla: 'Within 1 hour', legalRef: '', status: 'Done' },
  ]
};

export const mockLogs = [
  { id: 'LOG-001', timestamp: '02/05/2026 08:20', type: 'System', actor: 'Ahmed B.', description: 'Isolated workstation WS-HR-042', incidentId: 'INC-2026-001', sourceIp: '192.168.1.5' },
  { id: 'LOG-002', timestamp: '02/05/2026 08:15', type: 'Alert', actor: 'IDS System', description: 'Multiple failed login attempts detected', incidentId: 'INC-2026-001', sourceIp: '10.0.0.50' },
  { id: 'LOG-003', timestamp: '01/05/2026 23:45', type: 'Network', actor: 'Firewall', description: 'Blocked outbound traffic to known C2 server', incidentId: 'INC-2026-002', sourceIp: '192.168.5.10' },
  { id: 'LOG-004', timestamp: '01/05/2026 23:40', type: 'Alert', actor: 'EDR Agent', description: 'Mass file encryption detected', incidentId: 'INC-2026-002', sourceIp: '192.168.5.10' },
  { id: 'LOG-005', timestamp: '30/04/2026 14:30', type: 'System', actor: 'Sarah M.', description: 'Enabled Cloudflare Under Attack mode', incidentId: 'INC-2026-003', sourceIp: '192.168.1.12' },
];

export const mockPentesters = [
  { id: 'PEN-001', name: 'Yassine K.', email: 'y.karim@pentest.dz', assignedIncident: 'INC-2026-003', accessStatus: 'Active', expiry: '05/05/2026 18:00' },
  { id: 'PEN-002', name: 'Leila R.', email: 'l.riad@pentest.dz', assignedIncident: 'None', accessStatus: 'Revoked', expiry: 'Past' },
  { id: 'PEN-003', name: 'Omar T.', email: 'o.tariq@pentest.dz', assignedIncident: 'INC-2026-005', accessStatus: 'Active', expiry: '10/05/2026 12:00' },
];

export const mockNotifications = [
  { id: 1, type: 'critical', title: 'New Incident Detected', message: 'Critical Ransomware incident created (INC-2026-002)', read: false, time: '2 hours ago' },
  { id: 2, type: 'warning', title: 'Workflow Step Overdue', message: 'Isolate Affected Users is overdue for INC-2026-001', read: false, time: '5 hours ago' },
  { id: 3, type: 'info', title: 'Pentester Report Submitted', message: 'Yassine K. submitted findings for INC-2026-003', read: true, time: '1 day ago' },
];
