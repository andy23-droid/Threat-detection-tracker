import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Database, 
  Bell, 
  Play, 
  Sparkles, 
  RefreshCw, 
  Radio, 
  HelpCircle,
  AlertTriangle,
  FileCode
} from 'lucide-react';

import DashboardOverview from './components/DashboardOverview';
import VulnerabilityList from './components/VulnerabilityList';
import VulnerabilityDetailsModal from './components/VulnerabilityDetailsModal';
import AlertManager from './components/AlertManager';
import GeminiScanner from './components/GeminiScanner';

import { Vulnerability, AlertRule, AlertLog } from './types';

export default function App() {
  // Navigation active tab
  const [activeTab, setActiveTab] = useState<'DASHBOARD' | 'DATABASE' | 'ALERTS' | 'SCANNER'>('DASHBOARD');

  // Application database states
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [alerts, setAlerts] = useState<AlertLog[]>([]);

  // Selection state
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);

  // System Loading / Sync states
  const [isLoading, setIsLoading] = useState(true);
  const [isResetting, setIsResetting] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isGeneratingPlaybook, setIsGeneratingPlaybook] = useState(false);
  const [apiStatus, setApiStatus] = useState<'connected' | 'disconnected'>('connected');

  // Interactive UI triggers
  const [clientToast, setClientToast] = useState<{ message: string; type: 'success' | 'warn' | 'info' } | null>(null);

  const triggerToast = (message: string, type: 'success' | 'warn' | 'info' = 'info') => {
    setClientToast({ message, type });
    setTimeout(() => setClientToast(null), 4000);
  };

  // 1. Fetch Datasets from server of vulnerabilities, rules, and alert logs
  const fetchData = async (silent = false) => {
    if (!silent) setIsLoading(true);
    try {
      const [vulnRes, ruleRes, alertRes] = await Promise.all([
        fetch('/api/vulnerabilities'),
        fetch('/api/alert-rules'),
        fetch('/api/alerts')
      ]);

      if (!vulnRes.ok || !ruleRes.ok || !alertRes.ok) {
        throw new Error("HTTP Endpoint connection failed.");
      }

      const [vulnV, ruleV, alertV] = await Promise.all([
        vulnRes.json(),
        ruleRes.json(),
        alertRes.json()
      ]);

      // Check if new alerts arrived on silent updates to prompt local toast warnings
      if (silent && alertV.length > alerts.length) {
        const freshAlertsCount = alertV.length - alerts.length;
        triggerToast(`🚨 ${freshAlertsCount} new SecOps threat alerts triggered! Check incident feed.`, 'warn');
      }

      setVulnerabilities(vulnV);
      setRules(ruleV);
      setAlerts(alertV);
      setApiStatus('connected');
    } catch (err) {
      console.error("Failed to sync SecOps API structures:", err);
      setApiStatus('disconnected');
    } finally {
      if (!silent) setIsLoading(false);
    }
  };

  // Poll for live/real-time alert updates every 3.5 seconds
  useEffect(() => {
    fetchData(); // Initial full load

    const intervalId = setInterval(() => {
      fetchData(true); // Silent sync in background
    }, 3500);

    return () => clearInterval(intervalId);
  }, [alerts.length]); // Rebind triggers on length transitions

  // 2. Vulnerability Record Operations
  const handleUpdateStatus = async (id: string, status: Vulnerability['status']) => {
    try {
      const response = await fetch(`/api/vulnerabilities/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });

      if (!response.ok) throw new Error("Status patching failed");
      const updated = await response.json();

      // Reflect in local registers
      setVulnerabilities(prev => prev.map(v => v.id === id ? updated : v));
      if (selectedVulnerability?.id === id) {
        setSelectedVulnerability(updated);
      }
      triggerToast(`Status modified: ${updated.cveId} marked as ${status}.`, 'success');
    } catch (err: any) {
      triggerToast("Failed to compile status patch: " + err.message, 'warn');
    }
  };

  const handleDeleteVulnerability = async (id: string) => {
    if (!confirm("Are you sure you want to delete this threat record?")) return;
    try {
      const response = await fetch(`/api/vulnerabilities/${id}`, { method: 'DELETE' });
      if (!response.ok) throw new Error("Failed to delete vulnerability record");
      
      setVulnerabilities(prev => prev.filter(v => v.id !== id));
      if (selectedVulnerability?.id === id) {
        setSelectedVulnerability(null);
      }
      triggerToast("Vulnerability record wiped from administrative registry.", 'info');
    } catch (err: any) {
      triggerToast("Record delete failed: " + err.message, 'warn');
    }
  };

  const handleAddVulnerability = async (vulnPayload: Omit<Vulnerability, 'id' | 'detectedAt' | 'status'>) => {
    try {
      const response = await fetch('/api/vulnerabilities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(vulnPayload)
      });

      if (!response.ok) throw new Error("Registry insert failed");
      const created = await response.json();

      setVulnerabilities(prev => [created, ...prev]);
      triggerToast(`🔐 CVE Record [${created.cveId}] registered successfully! Evaluated rules.`, 'success');
    } catch (err: any) {
      triggerToast("Manual CVE insert failed: " + err.message, 'warn');
    }
  };

  // 3. Alert Rule Operations
  const handleAddRule = async (rulePayload: Omit<AlertRule, 'id'>) => {
    try {
      const response = await fetch('/api/alert-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rulePayload)
      });

      if (!response.ok) throw new Error("Failed to write rule");
      const created = await response.json();

      setRules(prev => [...prev, created]);
      triggerToast(`Guard Filter "${created.name}" injected.`, 'success');
    } catch (err: any) {
      triggerToast("Rule compilation failed: " + err.message, 'warn');
    }
  };

  const handleToggleRule = async (id: string, updates: Partial<AlertRule>) => {
    try {
      const response = await fetch(`/api/alert-rules/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates)
      });

      if (!response.ok) throw new Error("Rule state updates failed");
      const updated = await response.json();

      setRules(prev => prev.map(r => r.id === id ? updated : r));
      triggerToast(`Rule "${updated.name}" toggled ${updated.isActive ? 'Active' : 'Inactive'}.`, 'info');
    } catch (err: any) {
      triggerToast("Failed to modify rule status: " + err.message, 'warn');
    }
  };

  const handleDeleteRule = async (id: string) => {
    try {
      const response = await fetch(`/api/alert-rules/${id}`, { method: 'DELETE' });
      if (!response.ok) throw new Error("Delete rule query failed");

      setRules(prev => prev.filter(r => r.id !== id));
      triggerToast("Guard Filter removed from operations system.", 'info');
    } catch (err: any) {
      triggerToast("Failed to delete rule: " + err.message, 'warn');
    }
  };

  // 4. Alert Acknowledge Operations
  const handleAcknowledgeAlert = async (id: string) => {
    try {
      const response = await fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
      if (!response.ok) throw new Error("Ack failed");
      const updated = await response.json();

      setAlerts(prev => prev.map(a => a.id === id ? updated : a));
    } catch (err: any) {
      triggerToast("Alert acknowledgement failed: " + err.message, 'warn');
    }
  };

  const handleAcknowledgeAll = async () => {
    try {
      const response = await fetch('/api/alerts/acknowledge-all', { method: 'POST' });
      if (!response.ok) throw new Error("Ack all query failed");

      setAlerts(prev => prev.map(a => ({ ...a, isAcknowledged: true })));
      triggerToast("All pending active incident alarms cleared.", 'success');
    } catch (err: any) {
      triggerToast("Failed to acknowledge all logs: " + err.message, 'warn');
    }
  };

  // 5. Dynamic Intrusion Exploit Simulation
  const handleTriggerSimulation = async () => {
    setIsSimulating(true);
    triggerToast("⚡ Generating adversarial exploit payload targeting production gateway...", 'info');
    try {
      const response = await fetch('/api/vulnerabilities/simulate', { method: 'POST' });
      if (!response.ok) throw new Error("Failed to inject simulation exploit");
      const data = await response.json();

      // Fast-refresh lists
      await fetchData(true);
      triggerToast(`🚨 Simulated Exploit detected! Threat [${data.vulnerability.cveId}] created. ${data.alertsTriggeredCount} alert filters fired.`, 'warn');
    } catch (err: any) {
      triggerToast("Adversarial payload failure: " + err.message, 'warn');
    } finally {
      setIsSimulating(false);
    }
  };

  // 6. Gemini Auditing
  const handleScanStack = async (stackDescription: string, systemName: string) => {
    setIsScanning(true);
    try {
      const response = await fetch('/api/scan-stack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stackDescription, targetSystemName: systemName })
      });

      if (!response.ok) throw new Error("Stack audit transmission failed");
      const data = await response.json();

      await fetchData(true); // Load scanned entries
      triggerToast(`🛡️ Gemini Audit finished: Identified ${data.vulnerabilities.length} threat vectors.`, 'success');
      return data;
    } catch (err: any) {
      triggerToast("AI Audit compilation halted: " + err.message, 'warn');
      return null;
    } finally {
      setIsScanning(false);
    }
  };

  // 7. Gemini Playbook Generation
  const handleGeneratePlaybook = async (id: string) => {
    setIsGeneratingPlaybook(true);
    triggerToast("🤖 Contacting Gemini Security Engine for remediation runbook...", 'info');
    try {
      const response = await fetch(`/api/vulnerabilities/${id}/remediate`, { method: 'POST' });
      if (!response.ok) throw new Error("Playbook generation request failed");
      const data = await response.json();

      // Refetch vulnerabilities to store playbook in record
      await fetchData(true);
      triggerToast("⚡ Gemini remediation playbook synthesized completely!", 'success');
      return data.playbook;
    } catch (err: any) {
      triggerToast("Playbook generation failed: " + err.message, 'warn');
      return null;
    } finally {
      setIsGeneratingPlaybook(false);
    }
  };

  // 8. DB Seeding Restore Reset
  const handleResetDB = async () => {
    if (!confirm("Are you sure you want to reset the vulnerabilities and rules registry to the default seed state?")) return;
    setIsResetting(true);
    try {
      const response = await fetch('/api/vulnerabilities/reset', { method: 'POST' });
      if (!response.ok) throw new Error("Reset call failed");

      await fetchData();
      setSelectedVulnerability(null);
      triggerToast("Database entries reverted to compliance seed baselines.", 'info');
    } catch (err: any) {
      triggerToast("Reset query failed: " + err.message, 'warn');
    } finally {
      setIsResetting(false);
    }
  };

  // Compute stats for indicator badges
  const activeCriticalAlerts = alerts.filter(a => !a.isAcknowledged && a.severity === 'CRITICAL').length;
  const activeHighAlerts = alerts.filter(a => !a.isAcknowledged && a.severity === 'HIGH').length;
  const pendingAlertWarningCount = alerts.filter(a => !a.isAcknowledged).length;

  return (
    <div className="min-h-screen bg-[#020406] text-slate-300 flex flex-col font-sans relative overflow-x-hidden selection:bg-[#0891b2]/30">
      
      {/* Toast Notification HUD */}
      {clientToast && (
        <div 
          className={`fixed bottom-6 left-6 z-50 p-4 max-w-sm rounded bg-[#080b12] border border-slate-800 shadow-[0_0_20px_rgba(0,0,0,0.8)] transition-all duration-300 transform translate-y-0 animate-slide-in font-mono text-xs flex items-center gap-3 ${
            clientToast.type === 'success' 
              ? 'border-emerald-500/30 text-emerald-300' 
              : clientToast.type === 'warn'
              ? 'border-rose-500/30 text-rose-300 animate-pulse'
              : 'border-slate-700 text-slate-200'
          }`}
          id="system-toast-notif"
        >
          <Radio className="w-4 h-4 shrink-0 animate-ping text-cyan-400" />
          <div>{clientToast.message}</div>
        </div>
      )}

      {/* Primary Header */}
      <header className="h-14 border-b border-slate-800/50 bg-[#05080b]/90 backdrop-blur-md sticky top-0 z-40 select-none flex items-center">
        <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-4">
          
          {/* Logo Title section */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-gradient-to-br from-cyan-600 to-blue-700 rounded flex items-center justify-center shadow-[0_0_15px_rgba(8,145,178,0.3)]">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight text-slate-100 uppercase font-display leading-tight">Sentinel <span className="text-cyan-500">v8.2</span> <span className="text-slate-500 font-normal">| SecOps</span></h1>
              <p className="text-[9px] font-mono text-slate-500 font-semibold tracking-wide flex items-center gap-1 leading-none mt-0.5">
                <span>INCIDENT HUB</span>
                <span className="text-slate-850">|</span>
                <span className={`inline-flex items-center gap-1 ${apiStatus === 'connected' ? 'text-emerald-400' : 'text-rose-400'}`}>
                  <span className={`w-1 h-1 rounded-full inline-block ${apiStatus === 'connected' ? 'bg-emerald-400 animate-ping' : 'bg-rose-500'}`}></span>
                  {apiStatus === 'connected' ? 'SECURE SYNC' : 'OFFLINE'}
                </span>
              </p>
            </div>
          </div>

          {/* Tab Button Anchors */}
          <nav className="hidden md:flex items-center gap-6 ml-10 text-xs font-semibold tracking-widest uppercase select-none h-14" id="main-navigation">
            <button
              onClick={() => setActiveTab('DASHBOARD')}
              className={`py-4 px-1 border-b-2 text-[11px] transition-all cursor-pointer ${
                activeTab === 'DASHBOARD' 
                  ? 'text-cyan-400 border-cyan-400 font-bold' 
                  : 'text-slate-500 hover:text-slate-300 border-transparent hover:border-slate-800/40'
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => setActiveTab('DATABASE')}
              className={`py-4 px-1 border-b-2 text-[11px] transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'DATABASE' 
                  ? 'text-cyan-400 border-cyan-400 font-bold' 
                  : 'text-slate-500 hover:text-slate-300 border-transparent hover:border-slate-800/40'
              }`}
            >
              Vulnerabilities
            </button>
            <button
              onClick={() => setActiveTab('ALERTS')}
              className={`py-4 px-1 border-b-2 text-[11px] transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'ALERTS' 
                  ? 'text-cyan-400 border-cyan-400 font-bold' 
                  : 'text-slate-500 hover:text-slate-300 border-transparent hover:border-slate-800/40'
              }`}
            >
              Alerts Feed
              {pendingAlertWarningCount > 0 && (
                <span className="px-1.5 py-0.5 bg-rose-500 text-white font-black rounded-full text-[9px] animate-pulse">
                  {pendingAlertWarningCount}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('SCANNER')}
              className={`py-4 px-1 border-b-2 text-[11px] transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'SCANNER' 
                  ? 'text-cyan-400 border-cyan-400 font-bold' 
                  : 'text-slate-500 hover:text-slate-300 border-transparent hover:border-slate-800/40'
              }`}
            >
              AI Tech Scanner
            </button>
          </nav>

          {/* Quick Stats on right */}
          <div className="flex items-center gap-3">
            {activeCriticalAlerts > 0 && (
              <div 
                className="px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 text-[10px] font-mono uppercase font-black animate-pulse flex items-center gap-1.5 cursor-pointer"
                onClick={() => setActiveTab('ALERTS')}
                title="Critical Unresolved Threat Alarms Block"
              >
                <ShieldAlert className="w-3.5 h-3.5 text-rose-500 animate-bounce" /> {activeCriticalAlerts} CRITICAL
              </div>
            )}
            
            {/* Database indicator */}
            <div className="hidden sm:inline-flex text-[10px] items-center gap-1.5 font-mono text-slate-500 border border-slate-800/60 px-2.5 py-1.5 rounded bg-slate-900/30">
              <Database className="w-3 h-3 text-cyan-500" />
              <span>CVE INDEX: <strong className="text-slate-300 font-bold">{vulnerabilities.length}</strong></span>
            </div>
          </div>

        </div>
      </header>

      {/* Workspace Area Layout */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* Mobile Navigation controls */}
        <div className="md:hidden flex bg-[#05080b] p-1 rounded border border-slate-800/80 overflow-x-auto text-[10px] font-mono font-bold uppercase gap-1" id="mobile-navigation">
          <button
            onClick={() => setActiveTab('DASHBOARD')}
            className={`flex-1 text-center py-2 px-1.5 rounded whitespace-nowrap ${activeTab === 'DASHBOARD' ? 'bg-[#080b12] border border-slate-800 text-cyan-400' : 'text-slate-500'}`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('DATABASE')}
            className={`flex-1 text-center py-2 px-1.5 rounded whitespace-nowrap ${activeTab === 'DATABASE' ? 'bg-[#080b12] border border-slate-800 text-cyan-400' : 'text-slate-500'}`}
          >
            Vulnerabilities ({vulnerabilities.length})
          </button>
          <button
            onClick={() => setActiveTab('ALERTS')}
            className={`flex-1 text-center py-2 px-1.5 rounded whitespace-nowrap relative ${activeTab === 'ALERTS' ? 'bg-[#080b12] border border-slate-800 text-cyan-400' : 'text-slate-500'}`}
          >
            Alarms ({pendingAlertWarningCount})
          </button>
          <button
            onClick={() => setActiveTab('SCANNER')}
            className={`flex-1 text-center py-2 px-1.5 rounded whitespace-nowrap ${activeTab === 'SCANNER' ? 'bg-[#080b12] border border-slate-800 text-cyan-400' : 'text-slate-500'}`}
          >
            AI Scan
          </button>
        </div>

        {/* Global loader during initial boots */}
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-24 gap-4 font-mono text-slate-400 text-xs">
            <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
            <span>Connecting Sentinel Secure Registry. Resolving vulnerabilites...</span>
          </div>
        ) : (
          <div className="space-y-6 animate-fade-in">
            {activeTab === 'DASHBOARD' && (
              <DashboardOverview
                vulnerabilities={vulnerabilities}
                alerts={alerts}
                onTriggerSimulation={handleTriggerSimulation}
                isSimulating={isSimulating}
              />
            )}

            {activeTab === 'DATABASE' && (
              <VulnerabilityList
                vulnerabilities={vulnerabilities}
                onSelectVulnerability={setSelectedVulnerability}
                onUpdateStatus={handleUpdateStatus}
                onDeleteVulnerability={handleDeleteVulnerability}
                onAddVulnerability={handleAddVulnerability}
                onResetDB={handleResetDB}
                isResetting={isResetting}
              />
            )}

            {activeTab === 'ALERTS' && (
              <AlertManager
                rules={rules}
                alerts={alerts}
                onAddRule={handleAddRule}
                onToggleRule={handleToggleRule}
                onDeleteRule={handleDeleteRule}
                onAcknowledgeAlert={handleAcknowledgeAlert}
                onAcknowledgeAll={handleAcknowledgeAll}
                onTriggerSimulation={handleTriggerSimulation}
                isSimulating={isSimulating}
              />
            )}

            {activeTab === 'SCANNER' && (
              <GeminiScanner
                onScanStack={handleScanStack}
                isScanning={isScanning}
              />
            )}
          </div>
        )}

      </main>

      {/* Sliding details drawer modal */}
      {selectedVulnerability && (
        <VulnerabilityDetailsModal
          vulnerability={selectedVulnerability}
          onClose={() => setSelectedVulnerability(null)}
          onUpdateStatus={handleUpdateStatus}
          onGeneratePlaybook={handleGeneratePlaybook}
          isGeneratingPlaybook={isGeneratingPlaybook}
        />
      )}

      {/* Immersive HUD Bottom Footer */}
      <footer className="h-10 bg-[#0a0e14] border-t border-slate-800/50 px-4 sm:px-6 lg:px-8 flex items-center justify-between shrink-0 text-[10px] font-mono text-slate-500 select-none mt-12">
        <div className="flex items-center gap-6 uppercase tracking-wider">
          <span className="hidden sm:inline">Session: <span className="text-slate-300">SEC-OPS-992-ALPHA</span></span>
          <span>Connection: <span className="text-emerald-400 font-semibold">{apiStatus === 'connected' ? 'ENCRYPTED_SSL_AES256' : 'OFFLINE_RETRY'}</span></span>
          <span className="hidden md:inline">Index Count: <span className="text-slate-300 font-bold">{vulnerabilities.length}</span></span>
        </div>
        <div className="flex items-center gap-4 uppercase text-[10px]">
           <span className="hidden sm:inline">© 2026 SENTINEL SYSTEM</span>
           <div className="flex items-center gap-1.5">
             <span className={`animate-pulse ${apiStatus === 'connected' ? 'text-emerald-400' : 'text-slate-650'}`}>●</span> 
             <span>Live Sync</span>
           </div>
        </div>
      </footer>

    </div>
  );
}
