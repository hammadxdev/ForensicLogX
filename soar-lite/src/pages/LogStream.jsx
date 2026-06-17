import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Filter, X, ChevronDown, Pause, Play } from 'lucide-react';
import { GlassCard, SeverityBadge } from '../components/ui.jsx';

const ATTACK_TYPES_FILTER = ['All', 'SQL Injection', 'XSS', 'Command Injection', 'Directory Traversal', 'Brute Force', 'SSRF', 'RCE', 'LFI', 'CSRF', 'XXE'];
const STATUS_CODES = ['All', '200', '301', '400', '401', '403', '404', '500'];

function highlightLog(endpoint, attackType) {
  if (!attackType) return endpoint;
  const keywords = {
    'SQL Injection':       ['UNION', 'SELECT', 'OR 1=1', 'AND 1=', '--', 'DROP', 'INSERT'],
    'XSS':                 ['<script>', 'alert(', 'onerror=', 'javascript:'],
    'Command Injection':   ['cmd=', 'exec', 'whoami', '|', ';'],
    'Directory Traversal': ['../', '..\\', 'etc/passwd', 'etc/shadow'],
    'LFI':                 ['../'],
    'RCE':                 ['eval(', 'system(', 'exec('],
  };
  const words = keywords[attackType] || [];
  let result = endpoint;
  words.forEach(word => {
    result = result.replaceAll(word, `⚠${word}⚠`);
  });
  return result;
}

function LogRow({ log, isNew }) {
  const sevColors = {
    critical: '#ef4444', high: '#f59e0b', medium: '#60a5fa', low: '#10b981', info: '#94a3b8',
  };
  const col = sevColors[log.severity] || '#94a3b8';

  return (
    <motion.div
      initial={isNew ? { opacity: 0, x: -8, backgroundColor: 'rgba(0,212,255,0.08)' } : false}
      animate={{ opacity: 1, x: 0, backgroundColor: 'rgba(0,0,0,0)' }}
      transition={{ duration: 0.5 }}
      className={`flex items-start gap-3 px-4 py-2.5 font-mono text-xs border-l-2 hover:bg-white/[0.02] transition-colors`}
      style={{ borderLeftColor: col, borderBottom: '1px solid rgba(255,255,255,0.03)' }}>

      <span className="text-[10px] flex-shrink-0 mt-0.5" style={{ color: 'rgba(255,255,255,0.35)', minWidth: 58 }}>
        {log.timeDisplay}
      </span>
      <span className="flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold"
        style={{ background: col + '18', color: col, minWidth: 48, textAlign: 'center' }}>
        {log.method}
      </span>
      <span className="flex-shrink-0 text-[10px] px-1.5 py-0.5 rounded"
        style={{
          color: log.status >= 500 ? '#ef4444' : log.status >= 400 ? '#f59e0b' : '#10b981',
          background: log.status >= 500 ? 'rgba(239,68,68,0.1)' : log.status >= 400 ? 'rgba(245,158,11,0.1)' : 'rgba(16,185,129,0.1)',
          minWidth: 36, textAlign: 'center',
        }}>
        {log.status}
      </span>
      <span className="flex-1 truncate" style={{ color: 'rgba(255,255,255,0.65)' }}>
        <span className="text-cyan-400">{log.ip}</span>
        <span style={{ color: 'rgba(255,255,255,0.3)' }}> → </span>
        <span style={{ color: log.attackType ? col : 'rgba(255,255,255,0.65)' }}>
          {log.endpoint}
        </span>
      </span>
      {log.attackType && (
        <span className="flex-shrink-0">
          <SeverityBadge severity={log.severity} size="xs" />
        </span>
      )}
    </motion.div>
  );
}

export default function LogStream({ logs, isLive, onToggleLive }) {
  const [search, setSearch]       = useState('');
  const [filterIP, setFilterIP]   = useState('');
  const [filterAtk, setFilterAtk] = useState('All');
  const [filterSt, setFilterSt]   = useState('All');
  const [autoScroll, setAutoScroll] = useState(true);
  const feedRef = useRef(null);
  const prevLen = useRef(logs.length);

  useEffect(() => {
    if (autoScroll && feedRef.current && logs.length > prevLen.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
    prevLen.current = logs.length;
  }, [logs.length, autoScroll]);

  const filtered = logs.filter(l => {
    if (search    && !JSON.stringify(l).toLowerCase().includes(search.toLowerCase())) return false;
    if (filterIP  && !l.ip.includes(filterIP)) return false;
    if (filterAtk !== 'All' && l.attackType !== filterAtk) return false;
    if (filterSt  !== 'All' && String(l.status) !== filterSt) return false;
    return true;
  });

  const suspicious = filtered.filter(l => l.attackType).length;

  return (
    <div className="space-y-4">

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Total Entries',  value: logs.length.toLocaleString(), color: '#00d4ff' },
          { label: 'Suspicious',     value: logs.filter(l => l.attackType).length, color: '#ef4444' },
          { label: 'Filtered View',  value: filtered.length, color: '#a855f7' },
        ].map(({ label, value, color }) => (
          <div key={label} className="glass-card px-4 py-3 flex items-center justify-between"
            style={{ borderColor: color + '20' }}>
            <span className="text-xs" style={{ color: 'rgba(255,255,255,0.45)' }}>{label}</span>
            <span className="text-lg font-bold font-mono" style={{ color, textShadow: `0 0 12px ${color}` }}>
              {value}
            </span>
          </div>
        ))}
      </div>

      {/* Filter bar */}
      <div className="glass-card p-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-48">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'rgba(255,255,255,0.35)' }} />
            <input className="field-input pl-9 h-9 text-xs w-full" placeholder="Search endpoint, IP, payload..."
              value={search} onChange={e => setSearch(e.target.value)} />
            {search && (
              <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2">
                <X size={12} style={{ color: 'rgba(255,255,255,0.4)' }} />
              </button>
            )}
          </div>
          {/* IP filter */}
          <input className="field-input h-9 text-xs w-36" placeholder="Filter IP..."
            value={filterIP} onChange={e => setFilterIP(e.target.value)} />
          {/* Attack type */}
          <select className="h-9 text-xs" value={filterAtk} onChange={e => setFilterAtk(e.target.value)}>
            {ATTACK_TYPES_FILTER.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          {/* Status */}
          <select className="h-9 text-xs" value={filterSt} onChange={e => setFilterSt(e.target.value)}>
            {STATUS_CODES.map(s => <option key={s} value={s}>{s === 'All' ? 'All Status' : s}</option>)}
          </select>

          {/* Auto-scroll toggle */}
          <button onClick={() => setAutoScroll(v => !v)}
            className={`flex items-center gap-1.5 px-3 h-9 rounded-xl text-xs font-medium transition-all`}
            style={{
              background: autoScroll ? 'rgba(16,185,129,0.1)' : 'rgba(255,255,255,0.05)',
              border: `1px solid ${autoScroll ? 'rgba(16,185,129,0.3)' : 'rgba(255,255,255,0.1)'}`,
              color: autoScroll ? '#10b981' : 'rgba(255,255,255,0.5)',
            }}>
            <ChevronDown size={12} /> Auto-scroll
          </button>

          {/* Live toggle */}
          <button onClick={onToggleLive}
            className="flex items-center gap-1.5 px-3 h-9 rounded-xl text-xs font-medium transition-all"
            style={{
              background: isLive ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)',
              border: `1px solid ${isLive ? 'rgba(239,68,68,0.3)' : 'rgba(16,185,129,0.3)'}`,
              color: isLive ? '#ef4444' : '#10b981',
            }}>
            {isLive ? <Pause size={12} /> : <Play size={12} />}
            {isLive ? 'Pause' : 'Resume'}
          </button>
        </div>
      </div>

      {/* Log feed */}
      <GlassCard
        title="Log Stream"
        subtitle={`${filtered.length} entries · ${suspicious} suspicious`}
        action={
          isLive && (
            <div className="flex items-center gap-1.5 text-xs" style={{ color: '#10b981' }}>
              <span className="pulse-dot" style={{ background: '#10b981', color: '#10b981' }} />
              LIVE
            </div>
          )
        }>
        <div ref={feedRef} className="overflow-y-auto" style={{ height: '55vh', minHeight: 320 }}>
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 gap-2" style={{ color: 'rgba(255,255,255,0.3)' }}>
              <Filter size={24} />
              <p className="text-sm">No matching log entries</p>
            </div>
          ) : (
            <AnimatePresence initial={false}>
              {[...filtered].reverse().slice(0, 500).map((log, i) => (
                <LogRow key={log.id} log={log} isNew={i === 0 && isLive} />
              ))}
            </AnimatePresence>
          )}
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-4 px-5 py-3 border-t text-xs"
          style={{ borderColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.35)' }}>
          {[
            { color: '#ef4444', label: 'Critical' },
            { color: '#f59e0b', label: 'High' },
            { color: '#60a5fa', label: 'Medium' },
            { color: '#10b981', label: 'Low / Clean' },
          ].map(({ color, label }) => (
            <span key={label} className="flex items-center gap-1.5">
              <span className="w-2 h-3 rounded-sm flex-shrink-0" style={{ background: color }} />
              {label}
            </span>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}
