import { motion } from 'framer-motion';
import {
  Shield, Activity, AlertTriangle, FileText, Wifi,
  Globe, Settings, ChevronRight, Zap, Eye,
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard',  icon: Activity,      label: 'Dashboard',        section: 'Core' },
  { id: 'logstream',  icon: Zap,           label: 'Live Log Stream',  section: 'Core' },
  { id: 'alerts',     icon: AlertTriangle, label: 'Alerts & Incidents',section: 'Core' },
  { id: 'owasp',      icon: Shield,        label: 'Attack Detection', section: 'Analysis' },
  { id: 'ipintel',    icon: Globe,         label: 'IP Intelligence',  section: 'Analysis' },
  { id: 'rules',      icon: Settings,      label: 'Detection Rules',  section: 'Config' },
];

export default function Sidebar({ active, onNavigate }) {
  const grouped = NAV_ITEMS.reduce((acc, item) => {
    if (!acc[item.section]) acc[item.section] = [];
    acc[item.section].push(item);
    return acc;
  }, {});

  return (
    <aside className="fixed left-0 top-0 h-screen w-60 flex flex-col z-50"
      style={{
        background: 'linear-gradient(180deg, rgba(4,6,15,0.98) 0%, rgba(8,13,26,0.98) 100%)',
        borderRight: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(20px)',
      }}>

      {/* Logo */}
      <div className="px-5 py-6 flex items-center gap-3">
        <div className="relative">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center"
            style={{ background: 'linear-gradient(135deg, #00d4ff, #7c3aed)', boxShadow: '0 0 20px rgba(0,212,255,0.4)' }}>
            <Shield size={18} className="text-white" />
          </div>
          <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-green-400"
            style={{ boxShadow: '0 0 8px #10b981' }} />
        </div>
        <div>
          <div className="text-sm font-bold text-white tracking-wide">ForensicLogX</div>
          <div className="text-xs" style={{ color: 'rgba(255,255,255,0.35)' }}>SOC Dashboard v2</div>
        </div>
      </div>

      {/* Nav groups */}
      <nav className="flex-1 px-3 overflow-y-auto space-y-6 pb-4">
        {Object.entries(grouped).map(([section, items]) => (
          <div key={section}>
            <div className="px-3 mb-2 text-xs font-semibold uppercase tracking-widest"
              style={{ color: 'rgba(255,255,255,0.25)' }}>
              {section}
            </div>
            <div className="space-y-0.5">
              {items.map(({ id, icon: Icon, label }) => (
                <motion.button
                  key={id}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => onNavigate(id)}
                  className={`nav-item w-full text-left ${active === id ? 'active' : ''}`}
                >
                  <Icon size={16} className="flex-shrink-0" />
                  <span className="flex-1">{label}</span>
                  {active === id && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="w-1.5 h-1.5 rounded-full bg-cyan-400"
                      style={{ boxShadow: '0 0 6px #00d4ff' }}
                    />
                  )}
                </motion.button>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold"
            style={{ background: 'linear-gradient(135deg, #00d4ff, #7c3aed)', color: '#fff' }}>
            GA
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-medium text-white truncate">Gohar Ali</div>
            <div className="text-xs truncate" style={{ color: 'rgba(255,255,255,0.35)' }}>SOC Analyst</div>
          </div>
        </div>
      </div>
    </aside>
  );
}
