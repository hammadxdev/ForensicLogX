import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Bell, RefreshCw, Wifi, WifiOff } from 'lucide-react';

const PAGE_TITLES = {
  dashboard: { title: 'Dashboard',        sub: 'Real-time security operations center' },
  logstream:  { title: 'Live Log Stream', sub: 'Real-time log ingestion and analysis' },
  alerts:     { title: 'Alerts & Incidents', sub: 'Active threats requiring investigation' },
  owasp:      { title: 'Attack Detection',   sub: 'OWASP Top 10 threat classification' },
  ipintel:    { title: 'IP Intelligence',    sub: 'Suspicious IP analysis and blocking' },
  rules:      { title: 'Detection Rules',    sub: 'ModSecurity / custom rule management' },
};

export default function Topbar({ page, alerts, isLive, onToggleLive }) {
  const [search, setSearch] = useState('');
  const [showNotif, setShowNotif] = useState(false);
  const { title, sub } = PAGE_TITLES[page] || {};
  const criticalAlerts = alerts.filter(a => a.severity === 'critical' && a.status === 'Open');

  return (
    <header className="sticky top-0 z-40 flex items-center gap-4 px-6 py-3"
      style={{
        background: 'rgba(4,6,15,0.85)',
        backdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>

      {/* Page title */}
      <div className="flex-1 min-w-0">
        <h1 className="text-base font-semibold text-white truncate">{title}</h1>
        <p className="text-xs truncate" style={{ color: 'rgba(255,255,255,0.4)' }}>{sub}</p>
      </div>

      {/* Search */}
      <div className="relative hidden md:block">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2"
          style={{ color: 'rgba(255,255,255,0.35)' }} />
        <input
          className="field-input pl-9 w-56 h-9 text-xs"
          placeholder="Search logs, IPs, rules..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {/* Live toggle */}
      <motion.button
        whileTap={{ scale: 0.95 }}
        onClick={onToggleLive}
        className="flex items-center gap-2 px-3 h-9 rounded-xl text-xs font-medium transition-all duration-200"
        style={{
          background: isLive ? 'rgba(16,185,129,0.12)' : 'rgba(255,255,255,0.05)',
          border: `1px solid ${isLive ? 'rgba(16,185,129,0.4)' : 'rgba(255,255,255,0.1)'}`,
          color: isLive ? '#10b981' : 'rgba(255,255,255,0.5)',
        }}>
        {isLive ? <Wifi size={13} /> : <WifiOff size={13} />}
        {isLive ? 'LIVE' : 'PAUSED'}
        {isLive && <span className="pulse-dot" style={{ background: '#10b981', color: '#10b981' }} />}
      </motion.button>

      {/* Notifications */}
      <div className="relative">
        <motion.button
          whileTap={{ scale: 0.92 }}
          onClick={() => setShowNotif(v => !v)}
          className="relative w-9 h-9 rounded-xl flex items-center justify-center transition-all duration-200"
          style={{
            background: 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.1)',
          }}>
          <Bell size={15} style={{ color: 'rgba(255,255,255,0.6)' }} />
          {criticalAlerts.length > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full text-xs flex items-center justify-center font-bold"
              style={{ background: '#ef4444', boxShadow: '0 0 8px #ef4444', color: '#fff', fontSize: '9px' }}>
              {criticalAlerts.length > 9 ? '9+' : criticalAlerts.length}
            </span>
          )}
        </motion.button>

        <AnimatePresence>
          {showNotif && (
            <motion.div
              initial={{ opacity: 0, y: 8, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.95 }}
              transition={{ duration: 0.15 }}
              className="absolute right-0 top-full mt-2 w-72 glass-card p-3 z-50"
              style={{ boxShadow: '0 20px 60px rgba(0,0,0,0.6)' }}>
              <div className="text-xs font-semibold text-white mb-2 px-1">Recent Alerts</div>
              <div className="space-y-1 max-h-64 overflow-y-auto">
                {criticalAlerts.slice(0, 5).map(a => (
                  <div key={a.id}
                    className="flex items-start gap-2 px-2 py-2 rounded-lg hover:bg-white/5 cursor-pointer transition-colors">
                    <div className="w-1.5 h-1.5 mt-1.5 rounded-full flex-shrink-0"
                      style={{ background: '#ef4444', boxShadow: '0 0 6px #ef4444' }} />
                    <div>
                      <div className="text-xs font-medium text-white leading-tight">{a.title}</div>
                      <div className="text-xs mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{a.timeDisplay}</div>
                    </div>
                  </div>
                ))}
                {criticalAlerts.length === 0 && (
                  <div className="text-xs text-center py-4" style={{ color: 'rgba(255,255,255,0.35)' }}>
                    No active critical alerts
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Refresh indicator */}
      <div className="flex items-center gap-1.5 text-xs"
        style={{ color: 'rgba(255,255,255,0.35)' }}>
        <RefreshCw size={11} className={isLive ? 'animate-spin' : ''} style={{ animationDuration: '3s' }} />
        <span className="hidden lg:block">Auto-refresh</span>
      </div>
    </header>
  );
}
