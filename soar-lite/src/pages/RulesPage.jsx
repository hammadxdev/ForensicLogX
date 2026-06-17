import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Settings, Search, Filter, ToggleLeft, ToggleRight, Info, X } from 'lucide-react';
import { GlassCard, StatCard, SeverityBadge } from '../components/ui.jsx';
import { RULES_DATA } from '../data/mockData.js';

const SEVERITY_COLOR = {
  critical: '#ef4444',
  high:     '#f59e0b',
  medium:   '#60a5fa',
  low:      '#10b981',
};

const CATEGORIES = ['All', ...new Set(RULES_DATA.map(r => r.category))];

function RuleRow({ rule, onToggle, onSelect, isSelected }) {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass-card p-4 flex items-start gap-4 cursor-pointer transition-all ${isSelected ? 'border-cyan-500/30' : ''}`}
      style={isSelected ? { borderColor: 'rgba(0,212,255,0.25)', background: 'rgba(0,212,255,0.04)' } : {}}
      onClick={() => onSelect(rule.id)}>

      {/* Toggle */}
      <button
        onClick={e => { e.stopPropagation(); onToggle(rule.id); }}
        className="flex-shrink-0 mt-0.5 transition-all duration-300">
        {rule.enabled
          ? <ToggleRight size={22} style={{ color: '#10b981', filter: 'drop-shadow(0 0 4px #10b981)' }} />
          : <ToggleLeft size={22} style={{ color: 'rgba(255,255,255,0.25)' }} />
        }
      </button>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <span className="font-mono text-xs font-bold" style={{ color: '#00d4ff' }}>{rule.id}</span>
          <SeverityBadge severity={rule.severity} size="xs" />
          <span className="text-xs px-1.5 py-0.5 rounded-md"
            style={{ background: 'rgba(168,85,247,0.1)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.2)' }}>
            {rule.category}
          </span>
          {!rule.enabled && (
            <span className="text-xs px-1.5 py-0.5 rounded-md"
              style={{ background: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.35)' }}>
              DISABLED
            </span>
          )}
        </div>
        <p className="text-sm font-medium text-white truncate">{rule.name}</p>
        {isSelected && (
          <motion.p initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}
            className="text-xs mt-1.5" style={{ color: 'rgba(255,255,255,0.5)' }}>
            {rule.description}
          </motion.p>
        )}
      </div>

      {/* Triggers */}
      <div className="flex-shrink-0 text-right">
        <p className="text-lg font-bold" style={{ color: SEVERITY_COLOR[rule.severity] || '#fff' }}>
          {rule.triggers.toLocaleString()}
        </p>
        <p className="text-xs" style={{ color: 'rgba(255,255,255,0.35)' }}>triggers</p>
      </div>
    </motion.div>
  );
}

export default function RulesPage() {
  const [rules, setRules]           = useState(RULES_DATA);
  const [search, setSearch]         = useState('');
  const [filterCat, setFilterCat]   = useState('All');
  const [filterSev, setFilterSev]   = useState('all');
  const [filterEnb, setFilterEnb]   = useState('all');
  const [selectedId, setSelectedId] = useState(null);

  const toggleRule = id => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const filtered = rules.filter(r => {
    if (filterCat !== 'All' && r.category !== filterCat) return false;
    if (filterSev !== 'all' && r.severity !== filterSev) return false;
    if (filterEnb === 'enabled'  && !r.enabled) return false;
    if (filterEnb === 'disabled' && r.enabled)  return false;
    if (search && !`${r.id} ${r.name} ${r.category}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const enabledCnt  = rules.filter(r => r.enabled).length;
  const disabledCnt = rules.filter(r => !r.enabled).length;
  const totalTrig   = rules.reduce((s, r) => s + r.triggers, 0);

  return (
    <div className="space-y-5">

      {/* KPIs */}
      <div className="grid grid-cols-3 md:grid-cols-4 gap-4">
        <StatCard label="Total Rules"    value={rules.length}    icon={Settings}     color="blue" />
        <StatCard label="Active Rules"   value={enabledCnt}      icon={ToggleRight}  color="green" glow />
        <StatCard label="Disabled"       value={disabledCnt}     icon={ToggleLeft}   color="yellow" />
        <StatCard label="Total Triggers" value={totalTrig.toLocaleString()} icon={Filter} color="purple" />
      </div>

      {/* Filters */}
      <div className="glass-card p-4 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'rgba(255,255,255,0.35)' }} />
          <input className="field-input pl-9 h-9 text-xs w-full" placeholder="Search rules..."
            value={search} onChange={e => setSearch(e.target.value)} />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2">
              <X size={12} style={{ color: 'rgba(255,255,255,0.4)' }} />
            </button>
          )}
        </div>
        <select className="h-9 text-xs" value={filterCat} onChange={e => setFilterCat(e.target.value)}>
          {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="h-9 text-xs" value={filterSev} onChange={e => setFilterSev(e.target.value)}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select className="h-9 text-xs" value={filterEnb} onChange={e => setFilterEnb(e.target.value)}>
          <option value="all">All Rules</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>

        {/* Bulk actions */}
        <div className="flex gap-2 ml-auto">
          <button onClick={() => setRules(prev => prev.map(r => ({ ...r, enabled: true })))}
            className="px-3 h-9 text-xs font-medium rounded-xl transition-all"
            style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', color: '#10b981' }}>
            Enable All
          </button>
          <button onClick={() => setRules(prev => prev.map(r => ({ ...r, enabled: false })))}
            className="px-3 h-9 text-xs font-medium rounded-xl transition-all"
            style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
            Disable All
          </button>
        </div>
      </div>

      {/* Rules list */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <p className="text-xs" style={{ color: 'rgba(255,255,255,0.4)' }}>
            {filtered.length} of {rules.length} rules · Click to expand details
          </p>
        </div>
        <div className="space-y-2">
          <AnimatePresence>
            {filtered.length === 0 ? (
              <div className="glass-card py-12 text-center text-sm" style={{ color: 'rgba(255,255,255,0.3)' }}>
                No rules match your filters
              </div>
            ) : filtered.map(rule => (
              <RuleRow
                key={rule.id}
                rule={rule}
                onToggle={toggleRule}
                onSelect={id => setSelectedId(selectedId === id ? null : id)}
                isSelected={selectedId === rule.id}
              />
            ))}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
