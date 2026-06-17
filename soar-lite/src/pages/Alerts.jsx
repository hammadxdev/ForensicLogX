import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChevronDown, ChevronUp, Search, Filter, X, UserCheck,
  CheckCircle, AlertOctagon, ChevronRight, Shield,
} from 'lucide-react';
import { GlassCard, SeverityBadge } from '../components/ui.jsx';

const ANALYSTS = ['Alice Chen', 'Bob Martinez', 'Carol White', 'David Kim', 'Eve Johnson'];
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function AlertRow({ alert, isExpanded, onToggle, onUpdateAlert }) {
  const sevBg = {
    critical: 'rgba(239,68,68,0.05)',
    high:     'rgba(245,158,11,0.04)',
    medium:   'rgba(59,130,246,0.04)',
    low:      'rgba(16,185,129,0.04)',
  }[alert.severity] || '';

  return (
    <>
      <motion.tr
        layout
        onClick={onToggle}
        className="cursor-pointer transition-colors hover:bg-white/[0.03]"
        style={{ background: isExpanded ? sevBg : 'transparent' }}>
        <td className="px-4 py-3">
          <SeverityBadge severity={alert.severity} />
        </td>
        <td className="px-4 py-3">
          <div className="text-xs font-medium text-white">{alert.title}</div>
          <div className="text-xs mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{alert.attackType}</div>
        </td>
        <td className="px-4 py-3 font-mono text-xs" style={{ color: '#00d4ff' }}>{alert.sourceIp}</td>
        <td className="px-4 py-3 text-xs truncate max-w-xs" style={{ color: 'rgba(255,255,255,0.55)' }}>
          {alert.endpoint}
        </td>
        <td className="px-4 py-3">
          <span className="px-2 py-0.5 rounded-full text-xs font-medium"
            style={{
              background: alert.status === 'Resolved'      ? 'rgba(16,185,129,0.12)' :
                          alert.status === 'In Progress'   ? 'rgba(245,158,11,0.12)' :
                          alert.status === 'False Positive'? 'rgba(148,163,184,0.12)' : 'rgba(239,68,68,0.12)',
              color: alert.status === 'Resolved'      ? '#10b981' :
                     alert.status === 'In Progress'   ? '#f59e0b' :
                     alert.status === 'False Positive'? '#94a3b8' : '#ef4444',
            }}>
            {alert.status}
          </span>
        </td>
        <td className="px-4 py-3 text-xs" style={{ color: 'rgba(255,255,255,0.4)' }}>{alert.timeDisplay}</td>
        <td className="px-4 py-3 text-right">
          <span style={{ color: 'rgba(255,255,255,0.3)' }}>
            {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </span>
        </td>
      </motion.tr>

      <AnimatePresence>
        {isExpanded && (
          <motion.tr
            key="expanded"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}>
            <td colSpan={7} className="px-4 pb-4">
              <motion.div
                initial={{ height: 0 }}
                animate={{ height: 'auto' }}
                exit={{ height: 0 }}
                className="overflow-hidden">
                <div className="glass-card p-4 space-y-4"
                  style={{ borderColor: 'rgba(0,212,255,0.15)', background: 'rgba(0,212,255,0.03)' }}>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                    {[
                      { label: 'Rule Triggered', value: alert.rule || 'N/A', mono: true },
                      { label: 'Source Country', value: alert.country || 'Unknown' },
                      { label: 'HTTP Method',    value: alert.method },
                      { label: 'Alert ID',       value: `#${alert.id}`, mono: true },
                    ].map(({ label, value, mono }) => (
                      <div key={label}>
                        <p style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</p>
                        <p className={`mt-1 font-semibold text-white ${mono ? 'font-mono' : ''}`}>{value}</p>
                      </div>
                    ))}
                  </div>
                  <div>
                    <p className="text-xs mb-1.5" style={{ color: 'rgba(255,255,255,0.4)' }}>Details</p>
                    <p className="text-xs font-mono p-3 rounded-xl text-cyan-300"
                      style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(0,212,255,0.1)' }}>
                      {alert.details}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {/* Status change */}
                    {['Open','In Progress','Resolved','False Positive'].map(s => (
                      <button key={s}
                        onClick={() => onUpdateAlert(alert.id, { status: s })}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
                        style={{
                          background: alert.status === s ? 'rgba(0,212,255,0.15)' : 'rgba(255,255,255,0.05)',
                          border: `1px solid ${alert.status === s ? 'rgba(0,212,255,0.4)' : 'rgba(255,255,255,0.1)'}`,
                          color: alert.status === s ? '#00d4ff' : 'rgba(255,255,255,0.6)',
                        }}>
                        {s}
                      </button>
                    ))}
                    <div className="flex-1" />
                    {/* Assign */}
                    <select
                      value={alert.assignedTo || ''}
                      onChange={e => onUpdateAlert(alert.id, { assignedTo: e.target.value || null })}
                      className="h-8 text-xs">
                      <option value="">Assign to analyst…</option>
                      {ANALYSTS.map(a => <option key={a} value={a}>{a}</option>)}
                    </select>
                  </div>
                  {alert.assignedTo && (
                    <p className="text-xs" style={{ color: 'rgba(255,255,255,0.45)' }}>
                      Assigned to: <span className="text-cyan-400 font-medium">{alert.assignedTo}</span>
                    </p>
                  )}
                </div>
              </motion.div>
            </td>
          </motion.tr>
        )}
      </AnimatePresence>
    </>
  );
}

export default function Alerts({ alerts, onUpdateAlert }) {
  const [search, setSearch]         = useState('');
  const [filterSev, setFilterSev]   = useState('all');
  const [filterSt, setFilterSt]     = useState('all');
  const [sortField, setSortField]   = useState('id');
  const [sortDir, setSortDir]       = useState('desc');
  const [expandedId, setExpandedId] = useState(null);

  const handleSort = field => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDir('desc'); }
  };

  const filtered = alerts
    .filter(a => {
      if (filterSev !== 'all' && a.severity !== filterSev) return false;
      if (filterSt  !== 'all' && a.status.toLowerCase().replace(' ', '_') !== filterSt) return false;
      if (search && !JSON.stringify(a).toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    })
    .sort((a, b) => {
      let cmp = 0;
      if (sortField === 'id')       cmp = a.id - b.id;
      if (sortField === 'severity') cmp = SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
      if (sortField === 'status')   cmp = a.status.localeCompare(b.status);
      return sortDir === 'asc' ? cmp : -cmp;
    });

  const counts = {
    critical: alerts.filter(a => a.severity === 'critical').length,
    high:     alerts.filter(a => a.severity === 'high').length,
    medium:   alerts.filter(a => a.severity === 'medium').length,
    low:      alerts.filter(a => a.severity === 'low').length,
    open:     alerts.filter(a => a.status === 'Open').length,
    resolved: alerts.filter(a => a.status === 'Resolved').length,
  };

  const SortIcon = ({ field }) => {
    if (sortField !== field) return <ChevronRight size={12} className="opacity-30" />;
    return sortDir === 'asc' ? <ChevronUp size={12} style={{ color: '#00d4ff' }} /> : <ChevronDown size={12} style={{ color: '#00d4ff' }} />;
  };

  return (
    <div className="space-y-4">

      {/* Summary cards */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
        {[
          { label: 'Critical', value: counts.critical, color: '#ef4444' },
          { label: 'High',     value: counts.high,     color: '#f59e0b' },
          { label: 'Medium',   value: counts.medium,   color: '#60a5fa' },
          { label: 'Low',      value: counts.low,      color: '#10b981' },
          { label: 'Open',     value: counts.open,     color: '#ef4444' },
          { label: 'Resolved', value: counts.resolved, color: '#10b981' },
        ].map(({ label, value, color }) => (
          <div key={label} className="glass-card px-3 py-3 text-center" style={{ borderColor: color + '20' }}>
            <p className="text-xs mb-1" style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</p>
            <motion.p key={value} initial={{ scale: 0.8 }} animate={{ scale: 1 }}
              className="text-xl font-bold" style={{ color, textShadow: `0 0 10px ${color}` }}>
              {value}
            </motion.p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="glass-card p-4 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'rgba(255,255,255,0.35)' }} />
          <input className="field-input pl-9 h-9 text-xs w-full" placeholder="Search alerts..."
            value={search} onChange={e => setSearch(e.target.value)} />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2">
              <X size={12} style={{ color: 'rgba(255,255,255,0.4)' }} />
            </button>
          )}
        </div>
        <select className="h-9 text-xs" value={filterSev} onChange={e => setFilterSev(e.target.value)}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select className="h-9 text-xs" value={filterSt} onChange={e => setFilterSt(e.target.value)}>
          <option value="all">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
        <span className="text-xs" style={{ color: 'rgba(255,255,255,0.35)' }}>
          {filtered.length} of {alerts.length} alerts
        </span>
      </div>

      {/* Table */}
      <GlassCard title="Incident Queue" subtitle="Click a row to investigate">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th className="cursor-pointer" onClick={() => handleSort('title')}>
                  <span className="flex items-center gap-1">Title <SortIcon field="title" /></span>
                </th>
                <th>Source IP</th>
                <th>Endpoint</th>
                <th className="cursor-pointer" onClick={() => handleSort('status')}>
                  <span className="flex items-center gap-1">Status <SortIcon field="status" /></span>
                </th>
                <th>Time</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <AnimatePresence>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-sm" style={{ color: 'rgba(255,255,255,0.3)' }}>
                      No matching alerts
                    </td>
                  </tr>
                ) : filtered.slice(0, 100).map(alert => (
                  <AlertRow
                    key={alert.id}
                    alert={alert}
                    isExpanded={expandedId === alert.id}
                    onToggle={() => setExpandedId(expandedId === alert.id ? null : alert.id)}
                    onUpdateAlert={onUpdateAlert}
                  />
                ))}
              </AnimatePresence>
            </tbody>
          </table>
        </div>
      </GlassCard>
    </div>
  );
}
