import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { TrendingUp, AlertTriangle, Shield } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, RadarChart, PolarGrid,
  PolarAngleAxis, Radar, PieChart, Pie, Legend,
} from 'recharts';
import { GlassCard, StatCard, SeverityBadge } from '../components/ui.jsx';
import { OWASP_DATA } from '../data/mockData.js';

const OWASP_DESCRIPTIONS = {
  'SQL Injection':       'Attacker inserts malicious SQL into queries to manipulate the database.',
  'XSS':                'Malicious scripts injected into trusted websites, targeting other users.',
  'Command Injection':   'Attacker executes arbitrary OS commands via vulnerable input fields.',
  'Directory Traversal': 'Access files outside the web root by manipulating file path variables.',
  'Brute Force':         'Automated attempts to guess credentials using large password lists.',
  'SSRF':                'Forces server to make requests to internal/external resources.',
  'RCE':                 'Remote code execution through unvalidated user input or file upload.',
  'LFI':                 'Includes local files on the server through vulnerable include functions.',
  'CSRF':                'Forces authenticated users to submit unwanted requests.',
  'XXE':                 'Malicious XML input exploiting external entity processing.',
};

const CUSTOM_TOOLTIP = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-card px-3 py-2" style={{ border: '1px solid rgba(0,212,255,0.2)' }}>
      <p className="text-xs font-bold text-white mb-1">{label}</p>
      {payload.map((p, i) => (
        <div key={i} className="text-xs" style={{ color: p.fill || p.color }}>
          Detections: <span className="font-bold">{p.value}</span>
        </div>
      ))}
    </div>
  );
};

export default function OWASPPage({ logs }) {
  const [selected, setSelected] = useState(null);

  // Count from live logs
  const liveStats = useMemo(() => {
    const counts = {};
    logs.forEach(l => {
      if (l.attackType) counts[l.attackType] = (counts[l.attackType] || 0) + 1;
    });
    return counts;
  }, [logs]);

  const chartData = OWASP_DATA.map(d => ({
    ...d,
    count: (liveStats[d.name] || 0) + d.count, // combine live + seed
  })).sort((a, b) => b.count - a.count);

  const radarData = chartData.slice(0, 6).map(d => ({
    subject: d.shortName,
    A: d.count,
    fullMark: Math.max(...chartData.map(x => x.count)) * 1.2,
  }));

  const totalDetections = chartData.reduce((s, d) => s + d.count, 0);
  const topAttack       = chartData[0];
  const uniqueTypes     = chartData.filter(d => d.count > 0).length;

  const sel = selected ? chartData.find(d => d.name === selected) : null;

  return (
    <div className="space-y-5">

      {/* KPIs */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Total Detections" value={totalDetections.toLocaleString()} icon={TrendingUp} color="red" glow />
        <StatCard label="Attack Types"     value={uniqueTypes}    sub="Active threat vectors" icon={Shield} color="purple" />
        <StatCard label="Top Threat"       value={topAttack?.shortName || '—'} sub={`${topAttack?.count || 0} hits`} icon={AlertTriangle} color="yellow" />
      </div>

      {/* Bar + Radar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        <GlassCard title="Attack Frequency" subtitle="Click a bar to inspect" className="lg:col-span-2">
          <div className="px-3 pb-4 pt-2" style={{ height: 280 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 5, right: 5, bottom: 40, left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="shortName" tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }}
                  axisLine={false} tickLine={false} angle={-35} textAnchor="end" interval={0} />
                <YAxis tick={{ fill: 'rgba(255,255,255,0.35)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CUSTOM_TOOLTIP />} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={32}
                  onClick={d => setSelected(selected === d.name ? null : d.name)}>
                  {chartData.map((entry, i) => (
                    <Cell key={i} fill={entry.color}
                      opacity={selected && selected !== entry.name ? 0.3 : 1}
                      style={{ cursor: 'pointer', filter: `drop-shadow(0 0 6px ${entry.color}60)`, transition: 'opacity 0.2s' }}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>

        <GlassCard title="Threat Radar" subtitle="Top 6 attack vectors">
          <div className="pb-4 pt-2" style={{ height: 280 }}>
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="rgba(255,255,255,0.06)" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.45)', fontSize: 9 }} />
                <Radar name="Detections" dataKey="A" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.15}
                  strokeWidth={1.5} dot={{ fill: '#00d4ff', r: 3 }} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>
      </div>

      {/* Attack detail panel */}
      {sel && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-5"
          style={{ borderColor: sel.color + '40', boxShadow: `0 0 30px ${sel.color}15` }}>
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
              style={{ background: sel.color + '15', border: `1px solid ${sel.color}40` }}>
              <Shield size={20} style={{ color: sel.color }} />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <h3 className="text-base font-bold text-white">{sel.name}</h3>
                <span className="text-xs px-2 py-0.5 rounded-full font-semibold"
                  style={{ background: sel.color + '18', color: sel.color, border: `1px solid ${sel.color}30` }}>
                  {sel.count} detections
                </span>
              </div>
              <p className="text-sm" style={{ color: 'rgba(255,255,255,0.6)' }}>
                {OWASP_DESCRIPTIONS[sel.name] || 'Advanced web application attack vector.'}
              </p>
            </div>
            <button onClick={() => setSelected(null)} className="text-xs px-3 py-1.5 btn-ghost">Close</button>
          </div>
        </motion.div>
      )}

      {/* Attack cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
        {chartData.map((attack, i) => (
          <motion.button
            key={attack.name}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.04 }}
            whileHover={{ scale: 1.03, y: -2 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => setSelected(selected === attack.name ? null : attack.name)}
            className="glass-card p-4 text-left transition-all"
            style={{
              borderColor: selected === attack.name ? attack.color + '60' : attack.color + '20',
              boxShadow: selected === attack.name ? `0 0 20px ${attack.color}20` : undefined,
            }}>
            <div className="flex items-center justify-between mb-3">
              <div className="w-8 h-8 rounded-lg flex items-center justify-center"
                style={{ background: attack.color + '15' }}>
                <span className="text-xs font-bold" style={{ color: attack.color }}>A{i + 1}</span>
              </div>
              <span className="text-lg font-bold" style={{ color: attack.color,
                textShadow: `0 0 12px ${attack.color}` }}>
                {attack.count}
              </span>
            </div>
            <p className="text-xs font-semibold text-white leading-tight">{attack.shortName}</p>
            <div className="mt-2 h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
              <div className="h-full rounded-full" style={{
                width: `${(attack.count / chartData[0].count) * 100}%`,
                background: attack.color,
                boxShadow: `0 0 6px ${attack.color}`,
                transition: 'width 0.8s ease',
              }} />
            </div>
          </motion.button>
        ))}
      </div>
    </div>
  );
}
