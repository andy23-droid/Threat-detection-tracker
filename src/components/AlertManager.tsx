import React, { useState } from 'react';
import { Radio, AlertTriangle, Power, Trash2, Plus, Check, ShieldAlert, Sliders, BellOff, Volume2, VolumeX } from 'lucide-react';
import { AlertRule, AlertLog } from '../types';

interface AlertManagerProps {
  rules: AlertRule[];
  alerts: AlertLog[];
  onAddRule: (rule: Omit<AlertRule, 'id'>) => void;
  onToggleRule: (id: string, updates: Partial<AlertRule>) => void;
  onDeleteRule: (id: string) => void;
  onAcknowledgeAlert: (id: string) => void;
  onAcknowledgeAll: () => void;
  onTriggerSimulation: () => void;
  isSimulating: boolean;
}

export default function AlertManager({
  rules,
  alerts,
  onAddRule,
  onToggleRule,
  onDeleteRule,
  onAcknowledgeAlert,
  onAcknowledgeAll,
  onTriggerSimulation,
  isSimulating
}: AlertManagerProps) {
  const [showAddRuleForm, setShowAddRuleForm] = useState(false);
  const [ruleForm, setRuleForm] = useState({
    name: '',
    severityThreshold: 'HIGH' as AlertRule['severityThreshold'],
    systemPattern: '*',
    muteNotification: false
  });
  const [newRuleError, setNewRuleError] = useState('');
  const [soundEnabled, setSoundEnabled] = useState(false);

  // Trigger synthetic diagnostic alarm sound on critical unacknowledged checks (browser audio synth)
  React.useEffect(() => {
    const criticalUnack = alerts.filter(a => !a.isAcknowledged && a.severity === 'CRITICAL');
    if (soundEnabled && criticalUnack.length > 0) {
      try {
        const audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(500, audioCtx.currentTime);
        osc.frequency.setValueAtTime(800, audioCtx.currentTime + 0.15);
        gain.gain.setValueAtTime(0.05, audioCtx.currentTime);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.3);
      } catch (e) {
        console.warn('Audio Context synthesize failed:', e);
      }
    }
  }, [alerts, soundEnabled]);

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleForm.name.trim() || !ruleForm.systemPattern.trim()) {
      setNewRuleError('Please complete all rule configuration fields.');
      return;
    }

    onAddRule({
      ...ruleForm,
      isActive: true
    });

    setRuleForm({
      name: '',
      severityThreshold: 'HIGH',
      systemPattern: '*',
      muteNotification: false
    });
    setNewRuleError('');
    setShowAddRuleForm(false);
  };

  const getSeverityColor = (sev: AlertRule['severityThreshold']) => {
    switch (sev) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case 'LOW': return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
      default: return 'text-zinc-400 bg-zinc-800';
    }
  };

  const unacknowledgedCount = alerts.filter(a => !a.isAcknowledged).length;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pb-6 animate-fade-in">
      
      {/* Alert Rules Panel */}
      <div className="lg:col-span-5 bg-[#080b12] border border-slate-800 p-5 rounded space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-bold font-mono uppercase tracking-widest text-slate-300">SecOps Warning Rules</h3>
            <p className="text-xs text-slate-500 mt-0.5 font-mono">Automated filters evaluating live scan CVSS risks</p>
          </div>

          <button
            onClick={() => setShowAddRuleForm(!showAddRuleForm)}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 text-slate-300 hover:text-white rounded text-xs font-mono font-bold flex items-center gap-1 cursor-pointer transition hover:border-cyan-500/40 hover:text-cyan-400"
          >
            <Plus className="w-3.5 h-3.5 text-cyan-400" /> New Rule
          </button>
        </div>

        {/* Create Rule Form inline */}
        {showAddRuleForm && (
          <form onSubmit={handleCreateRule} className="bg-[#05080b] p-4 rounded border border-slate-800 space-y-3.5 font-mono text-xs">
            <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Configure Filter Guard Threshold</h4>
            
            {newRuleError && <p className="text-[10px] text-rose-400">{newRuleError}</p>}

            <div className="space-y-2">
              <label className="text-[9px] text-slate-500 font-bold uppercase">Rule Name</label>
              <input
                type="text"
                required
                placeholder="e.g. Audit Failures Watcher"
                value={ruleForm.name}
                onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
                className="w-full bg-black border border-slate-800 rounded px-2.5 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/30"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <label className="text-[9px] text-slate-500 font-bold uppercase">Min Severity</label>
                <select
                  value={ruleForm.severityThreshold}
                  onChange={(e) => setRuleForm({ ...ruleForm, severityThreshold: e.target.value as AlertRule['severityThreshold'] })}
                  className="w-full bg-black border border-slate-800 rounded px-2 py-2 text-slate-200 focus:outline-none"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-[9px] text-slate-500 font-bold uppercase" title="Match string inside system names, or * for all">System Match</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Prod or *"
                  value={ruleForm.systemPattern}
                  onChange={(e) => setRuleForm({ ...ruleForm, systemPattern: e.target.value })}
                  className="w-full bg-black border border-slate-800 rounded px-2 py-2 text-slate-200 focus:outline-none"
                />
              </div>
            </div>

            <div className="pt-2 flex justify-end gap-2 text-[10px]">
              <button
                type="button"
                onClick={() => { setShowAddRuleForm(false); setNewRuleError(''); }}
                className="px-3 py-1.5 bg-slate-950 border border-slate-850 text-slate-400 hover:text-slate-200 rounded cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 bg-[#0891b2] hover:bg-[#06b6d4] text-white rounded cursor-pointer mb-1 block"
              >
                Assemble Rule
              </button>
            </div>
          </form>
        )}

        {/* Rules Iterator List */}
        <div className="space-y-2.5">
          {rules.length === 0 ? (
            <div className="py-6 text-center text-slate-500 text-xs font-mono border border-dashed border-slate-800/60 rounded">
              No alert warning filters configured.
            </div>
          ) : (
            rules.map((rule) => (
              <div 
                key={rule.id} 
                className={`p-3.5 rounded border flex items-center justify-between gap-4 transition ${
                  rule.isActive ? 'bg-black/45 border-slate-800' : 'bg-transparent border-slate-900/40 opacity-50'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-xs text-slate-200 font-sans">{rule.name}</span>
                    <span className={`px-1.5 py-0.5 text-[9px] font-bold font-mono rounded border ${getSeverityColor(rule.severityThreshold)}`}>
                      &gt;= {rule.severityThreshold}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono">
                    System filter: <span className="bg-black px-1.5 py-0.2 rounded text-slate-300 font-bold border border-slate-850">{rule.systemPattern}</span>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 font-mono text-xs">
                  {/* Toggle Active state */}
                  <button
                    onClick={() => onToggleRule(rule.id, { isActive: !rule.isActive })}
                    className={`p-1.5 rounded hover:bg-black/40 border transition cursor-pointer ${
                      rule.isActive ? 'text-cyan-400 border-slate-800' : 'text-slate-600 border-transparent'
                    }`}
                    title={rule.isActive ? "Deactivate Rule" : "Activate Rule"}
                  >
                    <Power className="w-3.5 h-3.5" />
                  </button>
                  
                  {/* Delete Rule */}
                  <button
                    onClick={() => onDeleteRule(rule.id)}
                    className="p-1.5 rounded hover:bg-black/40 text-slate-600 hover:text-rose-400 transition cursor-pointer"
                    title="Remove Rule filter permanently"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Live Warning Logs feed */}
      <div className="lg:col-span-7 bg-[#080b12] border border-slate-800 p-5 rounded flex flex-col justify-between min-h-[400px]">
        
        <div>
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-800/60 pb-3 mb-4">
            <div>
              <h3 className="text-xs font-bold font-mono uppercase tracking-widest text-[#f43f5e] flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full inline-block ${unacknowledgedCount > 0 ? 'bg-rose-500 animate-pulse shadow-[0_0_8px_#f43f5e]' : 'bg-slate-600'}`}></span>
                Incident Alarms historical Feed
              </h3>
              <p className="text-xs text-slate-500 mt-0.5 font-mono">Real-time alerts logs mapped from active vulnerability scans</p>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              {/* Sound alert synthesize controller Toggle */}
              <button
                onClick={() => setSoundEnabled(!soundEnabled)}
                className={`p-2 rounded border transition flex items-center gap-1.5 cursor-pointer ${
                  soundEnabled ? 'bg-slate-950 text-amber-400 border-amber-500/20' : 'bg-black border-slate-900 text-slate-500'
                }`}
                title={soundEnabled ? "Mute alert audio synthesizer" : "Enable critical alarm synth audio"}
              >
                {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5" />}
                <span className="hidden sm:inline font-mono text-[9px]">{soundEnabled ? 'Synth: ON' : 'Synth: OFF'}</span>
              </button>

              {alerts.length > 0 && unacknowledgedCount > 0 && (
                <button
                  onClick={onAcknowledgeAll}
                  className="px-3 py-2 bg-slate-950 hover:bg-black/50 border border-slate-800 rounded font-bold text-[9px] text-slate-300 transition cursor-pointer"
                >
                  Clear All Alarms
                </button>
              )}
            </div>
          </div>

          {/* Alarm Status block if critical unacknowledged exists */}
          {unacknowledgedCount > 0 && (
            <div className="mb-4 p-3 bg-rose-500/5 border border-rose-500/20 rounded-lg flex items-center justify-between animate-pulse">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-rose-455 text-rose-400">
                <ShieldAlert className="w-4 h-4 text-rose-400 animate-bounce" /> WARNING: {unacknowledgedCount} UNACKNOWLEDGED INCIDENTS PENDING ADVISORY
              </div>
              <button
                id="ack-all-banner-btn"
                onClick={onAcknowledgeAll}
                className="text-[9px] font-bold font-mono text-white bg-rose-600 hover:bg-rose-500 px-2 py-1 rounded cursor-pointer"
              >
                ACK ALL
              </button>
            </div>
          )}

          {/* Event log mapping stream list */}
          <div className="space-y-3 max-h-[350px] overflow-y-auto pr-1">
            {alerts.length === 0 ? (
              <div className="py-20 text-center text-slate-500 text-xs font-mono border border-dashed border-slate-800 rounded bg-black/10">
                No alert records emitted yet. 
                <div className="mt-4">
                  <button
                    onClick={onTriggerSimulation}
                    disabled={isSimulating}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-550 hover:bg-rose-500 text-white font-bold rounded cursor-pointer text-xs"
                  >
                    Simulate Intrusion Detect
                  </button>
                </div>
              </div>
            ) : (
              alerts.map((alert) => {
                const badgeColor = 
                  alert.severity === 'CRITICAL' ? 'text-rose-400 bg-rose-500/10 border-rose-500/25' :
                  alert.severity === 'HIGH' ? 'text-orange-400 bg-orange-400/10 border-orange-500/20' :
                  alert.severity === 'MEDIUM' ? 'text-yellow-405 text-yellow-400 bg-yellow-400/10 border-yellow-501/20' :
                  'text-cyan-405 text-cyan-400 bg-cyan-400/10 border-cyan-505/20';

                return (
                  <div 
                    key={alert.id} 
                    className={`p-4 rounded border flex items-start justify-between gap-4 transition ${
                      alert.isAcknowledged 
                        ? 'bg-transparent border-slate-900/60 opacity-40' 
                        : 'bg-[#05080b] border-slate-850 border-slate-800 shadow-sm'
                    }`}
                  >
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold font-mono uppercase border ${badgeColor}`}>
                          {alert.severity}
                        </span>
                        <span className="font-mono font-bold text-xs text-slate-350 text-slate-300">{alert.cveId}</span>
                        <span className="text-[10px] text-slate-500 font-mono font-sans">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      
                      <p className="text-slate-300 font-sans text-xs leading-relaxed">{alert.message}</p>
                    </div>

                    {!alert.isAcknowledged ? (
                      <button
                        onClick={() => onAcknowledgeAlert(alert.id)}
                        className="px-3 py-1.5 bg-black border border-slate-800 hover:border-slate-705 text-slate-205 text-slate-200 hover:text-white rounded text-xs font-mono font-bold flex items-center gap-1 transition shrink-0 cursor-pointer"
                        title="Mark Alert as Investigated/Resolved"
                      >
                        <Check className="w-3.5 h-3.5 text-emerald-400" /> ACK
                      </button>
                    ) : (
                      <span className="text-[10px] text-slate-500 font-mono uppercase bg-black/20 px-2 py-0.5 rounded border border-slate-850/40 select-none">
                        Resolved
                      </span>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Simulation Footer info banner */}
        {alerts.length > 0 && (
          <div className="pt-4 border-t border-slate-800/80 flex justify-between items-center text-xs text-slate-500 font-mono mt-4">
            <span>Total Logged incidents: {alerts.length}</span>
            <button
              onClick={onTriggerSimulation}
              disabled={isSimulating}
              className="text-[#f43f5e] hover:text-rose-400 hover:underline cursor-pointer disabled:text-zinc-600"
            >
              {isSimulating ? "Injecting payload..." : "⚡ Inject another simulation"}
            </button>
          </div>
        )}

      </div>
    </div>
  );
}
