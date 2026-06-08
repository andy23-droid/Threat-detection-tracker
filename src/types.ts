export interface Vulnerability {
  id: string;
  cveId: string; // e.g. CVE-2026-3829
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss: number; // 0.0 - 10.0
  system: string;
  status: 'OPEN' | 'INVESTIGATING' | 'PATCHED' | 'IGNORED';
  detectedAt: string;
  description: string;
  mitigation: string;
  remediationPlaybook?: string; // Generated on demand by Gemini AI
}

export interface AlertRule {
  id: string;
  name: string;
  severityThreshold: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  systemPattern: string; // Match system name (or "*" for all)
  isActive: boolean;
  muteNotification: boolean;
}

export interface AlertLog {
  id: string;
  vulnerabilityId: string;
  cveId: string;
  title: string;
  message: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp: string;
  isAcknowledged: boolean;
}

export interface SystemMetrics {
  totalCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  patchedCount: number;
  openCount: number;
  investigatingCount: number;
}
