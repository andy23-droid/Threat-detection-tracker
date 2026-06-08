import React, { useState } from 'react';
import { Sparkles, Terminal, Cpu, Database, Server, Loader2, ArrowRight, CheckCircle2, AlertTriangle, Play } from 'lucide-react';
import { Vulnerability } from '../types';

interface GeminiScannerProps {
  onScanStack: (stackDescription: string, systemName: string) => Promise<{ vulnerabilities: Vulnerability[]; mode: 'LIVE' | 'DEMO' } | null>;
  isScanning: boolean;
}

const STACK_PRESETS = [
  {
    name: "Enterprise MERN Web API",
    systemName: "Gateway-API-Node",
    description: "Ubuntu 22.04 LTS, running Node v16.14.0 (vulnerable to memory heap vulnerabilities), Express 4.17.1, MongoDB v4.4, with loose CORS controls and public /admin endpoint routes."
  },
  {
    name: "Legacy Web Hosting Cluster",
    systemName: "Asset-Hosting-Apache",
    description: "CentOS 7, Apache HTTP Server v2.4.48 (vulnerable to CGI path traversal), PHP v7.4.3 with legacy phpMyAdmin configuration, with open root SSH passwords allowed."
  },
  {
    name: "FinTech Cloud Infrastructure",
    systemName: "Ledger-Cluster-Kubernetes",
    description: "Kubernetes cluster Node v1.24 running Docker containers, Redis Cache cluster v6.2 (vulnerable to CLIENT heap overflow), PostgreSQL v12.1 database engine with Row Level Security."
  }
];

export default function GeminiScanner({ onScanStack, isScanning }: GeminiScannerProps) {
  const [stackDescription, setStackDescription] = useState(STACK_PRESETS[0].description);
  const [systemName, setSystemName] = useState(STACK_PRESETS[0].systemName);
  const [activePreset, setActivePreset] = useState(0);
  
  const [scanResult, setScanResult] = useState<{ vulnerabilities: Vulnerability[]; mode: 'LIVE' | 'DEMO' } | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);

  const handleSelectPreset = (index: number) => {
    setActivePreset(index);
    setSystemName(STACK_PRESETS[index].systemName);
    setStackDescription(STACK_PRESETS[index].description);
    setScanResult(null);
  };

  const executeScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!stackDescription.trim() || !systemName.trim()) return;

    setScanResult(null);
    setTerminalLogs([
      `[info] Initiating SecOps Audit sequence for node [${systemName}]...`,
      `[info] Payload: "${stackDescription.substring(0, 50)}..."`,
      `[debug] Resolving compiler targets and inspecting standard port models...`
    ]);

    // Fast interval log simulation
    const logInterval = setInterval(() => {
      const logTemplates = [
        `[debug] Auditing stack structures against CVE indexing...`,
        `[debug] Querying Google Generative AI capabilities (Model: gemini-3.5-flash)...`,
        `[info] Scanning networking and credential bypass profiles...`
      ];
      const randomLog = logTemplates[Math.floor(Math.random() * logTemplates.length)];
      setTerminalLogs(prev => [...prev, randomLog]);
    }, 800);

    try {
      const response = await onScanStack(stackDescription, systemName);
      clearInterval(logInterval);
      
      if (response) {
        setScanResult(response);
        setTerminalLogs(prev => [
          ...prev,
          `[success] Tech-stack audit compiled completely under ${response.mode} mode!`,
          `[success] Detected ${response.vulnerabilities.length} security vulnerability patterns. Database logs synched.`
        ]);
      }
    } catch (err: any) {
      clearInterval(logInterval);
      setTerminalLogs(prev => [
        ...prev,
        `[error] Scan sequence trace broken: ${err.message || "Trace failed"}`
      ]);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pb-6 animate-fade-in">
      
      {/* Parameter Selection / Input Panel */}
      <div className="lg:col-span-6 bg-[#080b12] border border-slate-800 p-5 rounded space-y-5">
        <div>
          <h3 className="text-xs font-bold font-mono uppercase tracking-widest text-slate-350 flex items-center gap-1.5">
            <Cpu className="w-4 h-4 text-cyan-400" /> Technology stack Profile Analyzer
          </h3>
          <p className="text-xs text-slate-500 mt-0.5 font-mono">Describe your infrastructure parameters to trigger automated Gemini CVE auditories</p>
        </div>

        {/* Presets Grid Selector */}
        <div className="space-y-2">
          <label className="text-[10px] text-slate-400 font-mono font-bold uppercase block">Benchmark Infrastructure Profiles:</label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {STACK_PRESETS.map((preset, i) => (
              <button
                key={i}
                type="button"
                onClick={() => handleSelectPreset(i)}
                className={`p-3 rounded border text-left transition select-none cursor-pointer flex flex-col justify-between h-[100px] ${
                  activePreset === i
                    ? 'bg-cyan-500/10 border-cyan-500/40 text-white'
                    : 'bg-black border-slate-850 text-slate-450 hover:text-slate-200 hover:border-slate-800'
                }`}
              >
                <div>
                  <span className="text-xs font-bold font-sans line-clamp-1 block leading-tight">{preset.name}</span>
                  <span className="text-[9px] font-mono font-bold text-slate-500 mt-1 block leading-none">{preset.systemName}</span>
                </div>
                
                <span className="text-[9px] font-mono flex items-center gap-1 text-cyan-400 font-bold tracking-wider mt-auto">
                  Load <ArrowRight className="w-3 h-3" />
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Input Parameters Form */}
        <form onSubmit={executeScan} className="space-y-4 font-mono text-xs">
          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-400 font-bold uppercase">System Designation Name</label>
            <input
              type="text"
              required
              placeholder="e.g. Gateway-Proxy"
              value={systemName}
              onChange={(e) => setSystemName(e.target.value)}
              className="w-full bg-black border border-slate-800 rounded px-3 py-2.5 text-slate-200 focus:outline-none focus:border-cyan-500/30 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[10px] text-slate-400 font-bold uppercase">Software configuration specifications / OS / library versions</label>
            <textarea
              required
              rows={5}
              placeholder="Supply OS package definitions and versions (e.g. Ubuntu 20.04, OpenSSL 1.1.1f, Apache 2.4)..."
              value={stackDescription}
              onChange={(e) => setStackDescription(e.target.value)}
              className="w-full bg-black border border-slate-800 rounded px-3 py-3 text-slate-200 focus:outline-none focus:border-cyan-500/30 font-sans leading-relaxed text-xs"
            />
          </div>

          <button
            type="submit"
            disabled={isScanning}
            className="w-full bg-[#0891b2] hover:bg-[#06b6d4] disabled:bg-slate-950 disabled:text-slate-600 text-white font-semibold py-2.5 px-4 rounded flex items-center justify-center gap-1.5 shadow-lg shadow-cyan-500/10 cursor-pointer transition select-none disabled:cursor-not-allowed text-xs font-mono uppercase tracking-wider"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-cyan-300" /> Compiling Gemini Threat Model...
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 animate-pulse text-cyan-300" /> Launch Gemini SecOps Audit
              </>
            )}
          </button>
        </form>
      </div>

      {/* Terminal logs Output & results display panel */}
      <div className="lg:col-span-6 bg-black border border-slate-800 p-5 rounded flex flex-col justify-between h-[450px] font-mono shadow-inner">
        
        {/* Terminal Header */}
        <div className="flex items-center justify-between border-b border-slate-850 pb-2 mb-3 text-xs text-slate-500">
          <div className="flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5" />
            <span>AI SecOps Compiler Console</span>
          </div>
          <span className="text-[10px]">Tty/1 - active</span>
        </div>

        {/* Logs terminal body */}
        <div className="flex-1 overflow-y-auto space-y-1.5 text-xs text-slate-400 font-mono mb-4 bg-black/60 p-3 rounded border border-slate-900 scrollbar-thin">
          {terminalLogs.length === 0 && (
            <div className="py-12 text-center text-slate-500 h-full flex flex-col justify-center opacity-60">
              ⚡ Console inactive. Initiate stack scan to compile vulnerability logs.
            </div>
          )}
          {terminalLogs.map((log, index) => {
            let color = 'text-slate-400';
            if (log.includes('[success]')) color = 'text-emerald-400 font-semibold';
            if (log.includes('[error]')) color = 'text-rose-450 text-rose-400 font-semibold';
            if (log.includes('[debug]')) color = 'text-cyan-400';

            return (
              <div key={index} className={`${color} leading-normal`}>
                &gt;_ {log}
              </div>
            );
          })}
        </div>

        {/* Scan Results outputs block */}
        {scanResult && (
          <div className="bg-[#05080b] p-4 rounded border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-350 flex items-center gap-1.5 font-sans leading-none">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Audit Results Synched
              </span>

              {scanResult.mode === 'DEMO' && (
                <span className="text-[9px] font-bold text-rose-400 uppercase tracking-widest border border-rose-500/20 px-1.5 py-0.5 rounded bg-rose-500/5 select-none font-mono">
                  Sandbox FALLBACK
                </span>
              )}
            </div>

            <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
              Gemini parsed variables and registered <strong className="font-bold text-emerald-400 text-xs">{scanResult.vulnerabilities.length} matching vulnerability records</strong> inside the central index. Any active alerting watchdogs corresponding to this structure have issued alarms.
            </p>

            <div className="divide-y divide-slate-850 text-[10px]">
              {scanResult.vulnerabilities.map((v, i) => (
                <div key={i} className="py-1.5 flex justify-between items-center gap-4">
                  <div className="flex items-center gap-1.5">
                    <span className="font-bold text-slate-300 select-all font-mono">{v.cveId}</span>
                    <span className="text-slate-500 font-sans truncate line-clamp-1 max-w-[200px]" title={v.title}>{v.title}</span>
                  </div>
                  <span className={`px-1 rounded text-[8px] font-bold font-mono border ${
                    v.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' :
                    v.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                    v.severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'
                  }`}>
                    {v.severity}
                  </span>
                </div>
              ))}
            </div>

            {scanResult.mode === 'DEMO' && (
              <div className="flex items-center gap-1 font-sans text-[10px] text-slate-500 pt-1">
                <AlertTriangle className="w-3.5 h-3.5 text-slate-650" />
                Configure custom GEMINI_API_KEY in Secrets for live vulnerability searches.
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  );
}
