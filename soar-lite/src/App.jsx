import { useState, useEffect, useRef, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import Sidebar    from './components/Sidebar.jsx';
import Topbar     from './components/Topbar.jsx';
import Dashboard  from './pages/Dashboard.jsx';
import LogStream  from './pages/LogStream.jsx';
import Alerts     from './pages/Alerts.jsx';
import OWASPPage  from './pages/OWASPPage.jsx';
import IPIntelPage from './pages/IPIntelPage.jsx';
import RulesPage  from './pages/RulesPage.jsx';
import { generateLog, generateAlert } from './data/mockData.js';

const PAGE_COMPONENTS = {
  dashboard: Dashboard,
  logstream:  LogStream,
  alerts:     Alerts,
  owasp:      OWASPPage,
  ipintel:    IPIntelPage,
  rules:      RulesPage,
};

const PAGE_TRANSITION = {
  initial:  { opacity: 0, y: 12 },
  animate:  { opacity: 1, y: 0  },
  exit:     { opacity: 0, y: -6 },
  transition: { duration: 0.22, ease: 'easeOut' },
};

export default function App() {
  const [page, setPage]     = useState('dashboard');
  const [logs, setLogs]     = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [isLive, setIsLive] = useState(true);
  const intervalRef = useRef(null);

  // Simulate log ingestion
  const ingestLog = useCallback(() => {
    const log = generateLog();
    setLogs(prev => [...prev.slice(-2000), log]); // keep last 2000

    // ~30% chance to generate an alert for suspicious logs
    if (log.attackType && Math.random() < 0.3) {
      const alert = generateAlert(log);
      setAlerts(prev => [alert, ...prev.slice(0, 499)]);
    }
  }, []);

  useEffect(() => {
    if (isLive) {
      // Burst some initial data on mount
      for (let i = 0; i < 30; i++) ingestLog();
      intervalRef.current = setInterval(ingestLog, 800);
    } else {
      clearInterval(intervalRef.current);
    }
    return () => clearInterval(intervalRef.current);
  }, [isLive, ingestLog]);

  const handleUpdateAlert = useCallback((id, changes) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, ...changes } : a));
  }, []);

  const PageComponent = PAGE_COMPONENTS[page] || Dashboard;

  // Build page props
  const pageProps = {
    logs,
    alerts,
    isLive,
    onToggleLive: () => setIsLive(v => !v),
    onUpdateAlert: handleUpdateAlert,
  };

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <Sidebar active={page} onNavigate={setPage} />

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0" style={{ marginLeft: 240 }}>
        {/* Topbar */}
        <Topbar
          page={page}
          alerts={alerts}
          isLive={isLive}
          onToggleLive={() => setIsLive(v => !v)}
        />

        {/* Page content */}
        <main className="flex-1 p-5 overflow-x-hidden">
          <AnimatePresence mode="wait">
            <motion.div key={page} {...PAGE_TRANSITION}>
              <PageComponent {...pageProps} />
            </motion.div>
          </AnimatePresence>
        </main>

        {/* Footer */}
        <footer className="px-5 py-2 flex items-center justify-between text-xs border-t"
          style={{ borderColor: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.2)' }}>
          <span>ForensicLogX v2.0 — Real-Time SOC Dashboard</span>
          <span className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: '#10b981', boxShadow: '0 0 6px #10b981' }} />
            System Online · {logs.length.toLocaleString()} events · {alerts.length} alerts
          </span>
        </footer>
      </div>

      {/* Background orbs */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute w-[500px] h-[500px] rounded-full opacity-[0.04] blur-3xl"
          style={{ background: '#00d4ff', top: '-100px', left: '-100px' }} />
        <div className="absolute w-[400px] h-[400px] rounded-full opacity-[0.05] blur-3xl"
          style={{ background: '#7c3aed', bottom: '-80px', right: '-80px' }} />
        <div className="absolute w-[300px] h-[300px] rounded-full opacity-[0.03] blur-3xl"
          style={{ background: '#ef4444', top: '40%', left: '60%' }} />
      </div>
    </div>
  );
}
