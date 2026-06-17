import { motion } from 'framer-motion';

const SEVERITY_CONFIG = {
  critical: { label: 'CRITICAL', color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.3)' },
  high:     { label: 'HIGH',     color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)' },
  medium:   { label: 'MEDIUM',   color: '#60a5fa', bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.3)' },
  low:      { label: 'LOW',      color: '#10b981', bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.3)' },
  info:     { label: 'INFO',     color: '#94a3b8', bg: 'rgba(148,163,184,0.08)', border: 'rgba(148,163,184,0.2)' },
};

export function SeverityBadge({ severity, size = 'sm' }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  const px = size === 'xs' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs';
  return (
    <span className={`inline-flex items-center gap-1 ${px} rounded-full font-semibold`}
      style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}` }}>
      <span className="w-1 h-1 rounded-full flex-shrink-0" style={{ background: cfg.color }} />
      {cfg.label}
    </span>
  );
}

export function StatCard({ label, value, sub, icon: Icon, color = 'blue', trend, glow }) {
  const COLORS = {
    blue:   { primary: '#00d4ff', bg: 'rgba(0,212,255,0.08)',   border: 'rgba(0,212,255,0.2)',   shadow: 'rgba(0,212,255,0.15)' },
    purple: { primary: '#a855f7', bg: 'rgba(168,85,247,0.08)',  border: 'rgba(168,85,247,0.2)',  shadow: 'rgba(168,85,247,0.15)' },
    red:    { primary: '#ef4444', bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.25)',  shadow: 'rgba(239,68,68,0.2)' },
    green:  { primary: '#10b981', bg: 'rgba(16,185,129,0.08)',  border: 'rgba(16,185,129,0.2)',  shadow: 'rgba(16,185,129,0.15)' },
    yellow: { primary: '#f59e0b', bg: 'rgba(245,158,11,0.08)',  border: 'rgba(245,158,11,0.2)',  shadow: 'rgba(245,158,11,0.15)' },
  };
  const cfg = COLORS[color] || COLORS.blue;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card p-5 relative overflow-hidden"
      style={{ border: `1px solid ${cfg.border}`, boxShadow: glow ? `0 0 30px ${cfg.shadow}` : undefined }}>

      {/* Background glow */}
      <div className="absolute -top-6 -right-6 w-20 h-20 rounded-full opacity-20 blur-xl"
        style={{ background: cfg.primary }} />

      <div className="flex items-start justify-between relative">
        <div>
          <p className="text-xs font-medium mb-1" style={{ color: 'rgba(255,255,255,0.45)' }}>{label}</p>
          <motion.p
            key={value}
            initial={{ scale: 0.85, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="text-2xl font-bold tracking-tight"
            style={{ color: cfg.primary, textShadow: `0 0 20px ${cfg.primary}` }}>
            {value}
          </motion.p>
          {sub && <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.35)' }}>{sub}</p>}
          {trend !== undefined && (
            <p className="text-xs mt-1 font-medium"
              style={{ color: trend >= 0 ? '#ef4444' : '#10b981' }}>
              {trend >= 0 ? '↑' : '↓'} {Math.abs(trend)}% vs last hour
            </p>
          )}
        </div>
        {Icon && (
          <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}>
            <Icon size={18} style={{ color: cfg.primary }} />
          </div>
        )}
      </div>
    </motion.div>
  );
}

export function GlassCard({ children, className = '', title, subtitle, action, neon }) {
  const neonColors = {
    blue:   'rgba(0,212,255,0.2)',
    purple: 'rgba(168,85,247,0.2)',
    red:    'rgba(239,68,68,0.2)',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass-card ${className}`}
      style={neon ? { borderColor: neonColors[neon] || neonColors.blue } : {}}>
      {(title || action) && (
        <div className="flex items-center justify-between px-5 py-4 border-b"
          style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
          <div>
            {title && <h3 className="text-sm font-semibold text-white">{title}</h3>}
            {subtitle && <p className="text-xs mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{subtitle}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </motion.div>
  );
}

export function SkeletonCard({ lines = 3 }) {
  return (
    <div className="glass-card p-5 space-y-3">
      <div className="skeleton h-4 w-1/3" />
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="skeleton h-3" style={{ width: `${60 + Math.random() * 35}%` }} />
      ))}
    </div>
  );
}

export function ProgressBar({ value, max, color = '#00d4ff', label, showPercent = true }) {
  const pct = Math.min(100, Math.round((value / max) * 100));
  return (
    <div>
      {label && (
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-xs" style={{ color: 'rgba(255,255,255,0.6)' }}>{label}</span>
          {showPercent && <span className="text-xs font-mono font-semibold" style={{ color }}>{pct}%</span>}
        </div>
      )}
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          className="h-full rounded-full"
          style={{ background: `linear-gradient(90deg, ${color}99, ${color})`, boxShadow: `0 0 8px ${color}40` }}
        />
      </div>
    </div>
  );
}

export function CircleProgress({ value, max = 100, size = 80, strokeWidth = 6, color = '#00d4ff', label, sub }) {
  const pct = Math.min(100, (value / max) * 100);
  const radius = (size - strokeWidth) / 2;
  const circ = 2 * Math.PI * radius;
  const dash = (pct / 100) * circ;

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size/2} cy={size/2} r={radius}
            fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={strokeWidth} />
          <motion.circle
            cx={size/2} cy={size/2} r={radius}
            fill="none" stroke={color} strokeWidth={strokeWidth}
            strokeLinecap="round"
            initial={{ strokeDasharray: `0 ${circ}` }}
            animate={{ strokeDasharray: `${dash} ${circ}` }}
            transition={{ duration: 1, ease: 'easeOut' }}
            style={{ filter: `drop-shadow(0 0 4px ${color})` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-sm font-bold" style={{ color }}>{pct.toFixed(0)}%</span>
        </div>
      </div>
      {label && <span className="text-xs font-medium text-center" style={{ color: 'rgba(255,255,255,0.6)' }}>{label}</span>}
      {sub && <span className="text-xs text-center" style={{ color: 'rgba(255,255,255,0.3)' }}>{sub}</span>}
    </div>
  );
}
