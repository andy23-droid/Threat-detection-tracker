import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Bug, Radio, AlertOctagon } from 'lucide-react';
import { Vulnerability, AlertLog } from '../types';

interface DashboardOverviewProps {
  vulnerabilities: Vulnerability[];
  alerts: AlertLog[];
  onTriggerSimulation: () => void;
  isSimulating: boolean;
}

export default function DashboardOverview({
  vulnerabilities,
  alerts,
  onTriggerSimulation,
  isSimulating,
}: DashboardOverviewProps) {
  // Compute Stats
  const openVulns = vulnerabilities.filter(v => v.status === 'OPEN').length;
  const investigatingVulns = vulnerabilities.filter(v => v.status === 'INVESTIGATING').length;
  const patchedVulns = vulnerabilities.filter(v => v.status === 'PATCHED').length;

  const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL' && v.status !== 'PATCHED').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'HIGH' && v.status !== 'PATCHED').length;
  const mediumCount = vulnerabilities.filter(v => v.severity === 'MEDIUM' && v.status !== 'PATCHED').length;
  const lowCount = vulnerabilities.filter(v => v.severity === 'LOW' && v.status !== 'PATCHED').length;

  const unacknowledgedAlertsCount = alerts.filter(a => !a.isAcknowledged).length;

  // Determine DEFCON Threat Index level (DEFCON 5 - 1)
  // DEFCON 1: Open Critical vulnerabilities > 0
  // DEFCON 2: Open High vulnerabilities > 0
  // DEFCON 3: Open Medium vulnerabilities > 0
  // DEFCON 4: Open Low vulnerabilities > 0
  // DEFCON 5: All vulnerabilities Patched or Ignored
  let defconLevel = 5;
  let defconStatus = "SECURE (DEFCON 5)";
  let defconColor = "bg-emerald-950/20 text-emerald-400 border-emerald-500/20";
  let defconDescription = "No active open threats detected. Guard post is green.";

  if (vulnerabilities.some(v => v.severity === 'CRITICAL' && v.status !== 'PATCHED')) {
    defconLevel = 1;
    defconStatus = "EMERGENCY (DEFCON 1)";
    defconColor = "bg-rose-950/25 text-rose-400 border-rose-500/30 animate-pulse";
    defconDescription = "CRITICAL security bypass exploits active in prod gateway. Immediate intervention required!";
  } else if (vulnerabilities.some(v => v.severity === 'HIGH' && v.status !== 'PATCHED')) {
    defconLevel = 2;
    defconStatus = "HIGH ALERT (DEFCON 2)";
    defconColor = "bg-orange-950/20 text-orange-400 border-orange-500/20";
    defconDescription = "High-risk RCEs identified on system layers. Enact immediate isolation sandbox routines.";
  } else if (vulnerabilities.some(v => v.severity === 'MEDIUM' && v.status !== 'PATCHED')) {
    defconLevel = 3;
    defconStatus = "ELEVATED (DEFCON 3)";
    defconColor = "bg-yellow-950/20 text-yellow-400 border-yellow-500/20";
    defconDescription = "Unpatched medium vulnerabilities detected. Monitor auditing routes closely.";
  } else if (vulnerabilities.some(v => v.severity === 'LOW' && v.status !== 'PATCHED')) {
    defconLevel = 4;
    defconStatus = "GUARD (DEFCON 4)";
    defconColor = "bg-blue-950/20 text-cyan-400 border-blue-500/20";
    defconDescription = "Minor environment key exposures detected. Schedule patch maintenance logs.";
  }

  // Percentage calculations
  const totalActive = openVulns + investigatingVulns;
  const totalCount = vulnerabilities.length;
  const patchedPercent = totalCount > 0 ? Math.round((patchedVulns / totalCount) * 100) : 100;

  return (
    <div className="space-y-6">
      {/* Dynamic Sub-header Banner */}
      <div className={`p-5 rounded border flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all duration-300 ${defconColor}`} id="defcon-banner">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-black/40 rounded border border-white/5 shrink-0">
            {defconLevel === 5 ? (
              <ShieldCheck className="w-8 h-8 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-8 h-8 text-rose-400 animate-bounce" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-mono tracking-wider px-2 py-0.5 bg-black/40 rounded border border-white/5">System Posture Index</span>
              <span className="font-bold text-base font-mono">{defconStatus}</span>
            </div>
            <p className="mt-1 text-xs max-w-2xl opacity-90 font-sans leading-relaxed">{defconDescription}</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs font-mono font-bold uppercase tracking-wider hidden lg:inline mr-2 opacity-75">SecOps Simulation Hub:</span>
          <button
            id="trigger-simulation-btn"
            onClick={onTriggerSimulation}
            disabled={isSimulating}
            className={`font-mono text-xs px-4 py-2.5 rounded font-semibold transition-all duration-200 border cursor-pointer select-none tracking-wider ${
              isSimulating
                ? 'bg-slate-900 text-slate-500 border-slate-800/50 cursor-not-allowed'
                : 'bg-black border-rose-500/40 text-rose-400 hover:bg-rose-500/15 hover:border-rose-500 active:scale-95 shadow-lg shadow-rose-500/5'
            }`}
          >
            {isSimulating ? 'SIMULATING THREAT...' : '🔥 INJECT EXPLOIT ATTEMPT'}
          </button>
        </div>
      </div>

      {/* Grid of Micro-Metrics Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total CVEs */}
        <div className="bg-[#080b12] hover:bg-[#0c101a] border border-slate-800/80 rounded p-5 transition-all" id="stat-total">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 font-bold mb-1 block">Total Database Records</span>
            <Bug className="w-4 h-4 text-slate-500" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono tracking-tight text-white">{totalCount}</span>
            <span className="text-xs text-slate-500 font-mono">CVEs logged</span>
          </div>
          <div className="mt-2 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
            <div className="bg-slate-600 h-full" style={{ width: '100%' }}></div>
          </div>
        </div>

        {/* Unresolved / Active Threats */}
        <div className="bg-[#080b12] hover:bg-[#0c101a] border border-slate-800/80 rounded p-5 transition-all" id="stat-active">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 font-bold mb-1 block">Active Intrusions</span>
            <AlertOctagon className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono tracking-tight text-orange-400">{totalActive}</span>
            <span className="text-xs text-slate-500 font-mono">open / active</span>
          </div>
          <div className="mt-2 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
            <div 
              className="bg-orange-550 bg-orange-500 h-full transition-all duration-500" 
              style={{ width: `${totalCount > 0 ? (totalActive / totalCount) * 100 : 0}%` }}
            ></div>
          </div>
        </div>

        {/* Patched Mitigations */}
        <div className="bg-[#080b12] hover:bg-[#0c101a] border border-slate-800/80 rounded p-5 transition-all" id="stat-patched">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 font-bold mb-1 block">Mitigations Applied</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono tracking-tight text-emerald-400">{patchedVulns}</span>
            <span className="text-xs text-slate-500 font-mono">({patchedPercent}%) patched</span>
          </div>
          <div className="mt-2 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
            <div 
              className="bg-emerald-500 h-full transition-all duration-500" 
              style={{ width: `${patchedPercent}%` }}
            ></div>
          </div>
        </div>

        {/* Action Alerts Unacknowledged */}
        <div className="bg-[#080b12] hover:bg-[#0c101a] border border-slate-800/80 rounded p-5 transition-all" id="stat-alerts">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 font-bold mb-1 block">Triggered Alarm Logs</span>
            <Radio className={`w-4 h-4 ${unacknowledgedAlertsCount > 0 ? 'text-[#f43f5e] animate-pulse' : 'text-slate-550 text-slate-500'}`} />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-3xl font-bold font-mono tracking-tight ${unacknowledgedAlertsCount > 0 ? 'text-[#f43f5e]' : 'text-white'}`}>
              {unacknowledgedAlertsCount}
            </span>
            <span className="text-xs text-slate-500 font-mono">unresolved alarms</span>
          </div>
          <div className="mt-2 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
            <div 
              className={`h-full transition-all duration-500 ${unacknowledgedAlertsCount > 0 ? 'bg-[#f43f5e]' : 'bg-slate-700'}`} 
              style={{ width: `${alerts.length > 0 ? (unacknowledgedAlertsCount / alerts.length) * 100 : 0}%` }}
            ></div>
          </div>
        </div>
      </div>

      {/* Breakdown Metrics and System Logs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Heat Map Scale / Severity Stack */}
        <div className="lg:col-span-4 bg-[#080b12] border border-slate-800 rounded p-5 flex flex-col justify-between" id="severity-breakdown">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Severity Distribution</h3>
            <p className="text-xs text-slate-500 mt-0.5 font-mono">Summary of threats in db registry</p>
          </div>

          <div className="space-y-4 my-6">
            {/* Critical */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-rose-500 font-bold uppercase tracking-wider flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-500 block shadow-[0_0_8px_#f43f5e]"></span> Critical ({criticalCount})
                </span>
                <span className="text-slate-400">{vulnerabilities.length > 0 ? Math.round((vulnerabilities.filter(v => v.severity === 'CRITICAL').length / vulnerabilities.length) * 100) : 0}%</span>
              </div>
              <div className="w-full bg-[#0a0e14] h-1.5 rounded-full overflow-hidden border border-slate-800/40">
                <div className="bg-rose-500 h-full" style={{ width: `${vulnerabilities.length > 0 ? (vulnerabilities.filter(v => v.severity === 'CRITICAL').length / vulnerabilities.length) * 100 : 0}%` }}></div>
              </div>
            </div>

            {/* High */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-orange-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-orange-400 block"></span> High ({highCount})
                </span>
                <span className="text-slate-400">{vulnerabilities.length > 0 ? Math.round((vulnerabilities.filter(v => v.severity === 'HIGH').length / vulnerabilities.length) * 100) : 0}%</span>
              </div>
              <div className="w-full bg-[#0a0e14] h-1.5 rounded-full overflow-hidden border border-slate-800/40">
                <div className="bg-orange-500 h-full" style={{ width: `${vulnerabilities.length > 0 ? (vulnerabilities.filter(v => v.severity === 'HIGH').length / vulnerabilities.length) * 100 : 0}%` }}></div>
              </div>
            </div>

            {/* Medium */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-yellow-405 text-yellow-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-yellow-400 block"></span> Medium ({mediumCount})
                </span>
                <span className="text-slate-400">{vulnerabilities.length > 0 ? Math.round((vulnerabilities.filter(v => v.severity === 'MEDIUM').length / vulnerabilities.length) * 100) : 0}%</span>
              </div>
              <div className="w-full bg-[#0a0e14] h-1.5 rounded-full overflow-hidden border border-slate-800/40">
                <div className="bg-yellow-400 h-full" style={{ width: `${vulnerabilities.length > 0 ? (vulnerabilities.filter(v => v.severity === 'MEDIUM').length / vulnerabilities.length) * 100 : 0}%` }}></div>
              </div>
            </div>

            {/* Low */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-cyan-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 block"></span> Low ({lowCount})
                </span>
                <span className="text-slate-400">{vulnerabilities.length > 0 ? Math.round((vulnerabilities.filter(v => v.severity === 'LOW').length / vulnerabilities.length) * 100) : 0}%</span>
              </div>
              <div className="w-full bg-[#0a0e14] h-1.5 rounded-full overflow-hidden border border-slate-800/40">
                <div className="bg-cyan-500 h-full" style={{ width: `${vulnerabilities.length > 0 ? (vulnerabilities.filter(v => v.severity === 'LOW').length / vulnerabilities.length) * 100 : 0}%` }}></div>
              </div>
            </div>
          </div>

          <div className="text-[10px] text-slate-500 font-mono border-t border-slate-800/50 pt-3 mt-auto">
            * Note: Percentages count resolved/unresolved entries in general indexes.
          </div>
        </div>

        {/* Real-time active console system log stream */}
        <div className="lg:col-span-8 bg-[#080b12] border border-slate-800 rounded p-5" id="console-stream">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/60">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-250 text-slate-300">Intrusion Audits & Logs Stream</h3>
              <p className="text-xs text-slate-500 mt-0.5 font-mono mr-2">Real-time alerts triggered on admin ports</p>
            </div>
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-rose-500/10 text-rose-455 text-rose-400 rounded border border-rose-500/20 animate-pulse text-[9px] font-mono uppercase font-bold tracking-wider shrink-0">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 inline-block animate-ping"></span> Live Sync Stream
            </div>
          </div>

          <div className="space-y-3 font-mono text-[11px] max-h-[240px] overflow-y-auto pr-1">
            {alerts.length === 0 ? (
              <div className="py-8 text-center text-slate-550 border border-slate-800/40 border-dashed rounded bg-[#05080b]/40">
                &gt;_ console listener quiet. No active alerts logs emitted.
              </div>
            ) : (
              alerts.slice(0, 5).map((alert) => {
                const badgeColor = 
                  alert.severity === 'CRITICAL' ? 'text-rose-400 bg-rose-500/10 border-rose-500/25' :
                  alert.severity === 'HIGH' ? 'text-orange-400 bg-orange-400/10 border-orange-500/20' :
                  alert.severity === 'MEDIUM' ? 'text-yellow-405 text-yellow-400 bg-yellow-405/10 border-yellow-501/20' :
                  'text-cyan-405 text-cyan-400 bg-cyan-400/10 border-cyan-505/20';

                return (
                  <div 
                    key={alert.id} 
                    className={`p-3 rounded border text-slate-300 flex justify-between items-start gap-4 transition-all ${
                      alert.isAcknowledged ? 'opacity-40 bg-transparent border-slate-850' : 'bg-[#05080b] shadow border-slate-800'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded font-bold text-[9px] uppercase font-mono tracking-wide border ${badgeColor}`}>
                          {alert.severity}
                        </span>
                        <span className="text-slate-100 font-bold">{alert.cveId}</span>
                        <span className="text-[10px] text-slate-500 hidden sm:inline">
                          [{new Date(alert.timestamp).toLocaleTimeString()}]
                        </span>
                      </div>
                      <p className="text-slate-300 font-sans leading-relaxed text-xs">{alert.message}</p>
                    </div>
                    {!alert.isAcknowledged && (
                      <span className="text-[9px] text-[#f43f5e] font-bold uppercase tracking-wider blink animate-pulse border border-[#f43f5e]/20 px-2 py-0.5 rounded bg-[#f43f5e]/5 shrink-0">
                        PENDING ACK
                      </span>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
