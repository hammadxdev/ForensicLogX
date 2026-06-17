import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, Shield, ShieldOff, TrendingUp, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { GlassCard, StatCard, ProgressBar } from '../components/ui.jsx';
import { IP_DATA } from '../data/mockData.js';

function RiskBadge({ score }) {
  const cfg = score >= 80 ? { label: 'CRITICAL', color: '#ef4444' }
            : score >= 60 ? { label: 'HIGH',     color: '#f59e0b' }
            : score >= 40 ? { label: 'MEDIUM',   color: '#60a5fa' }
            :               { label: 'LOW',      color: '#10b981' };
  return (
    <span className="px-2 py-0.5 rounded-full text-xs font-bold"
      style={{ background: cfg.color + '15', color: cfg.color, border: `1px solid ${cfg.color}30` }}>
      {cfg.label} {score}
    </span>
  );
}

export default function IPIntelPage({ logs }) {
  const [blockedIPs, setBlockedIPs] = useState(
    () => new Set(IP_DATA.filter(d => d.blocked).map(d => d.ip))
  );
  const [selected, setSelected] = useState(null);

  // Live stats from logs
  const liveCounts = useMemo(() => {
    const counts = {};
    logs.forEach(l => { counts[l.ip] = (counts[l.ip] || 0) + 1; });
    return counts;
  }, [logs]);

  const enrichedData = IP_DATA.map(d => ({
    ...d,
    blocked: blockedIPs.has(d.ip),
    liveRequests: liveCounts[d.ip] || 0,
    totalRequests: d.requests + (liveCounts[d.ip] || 0),
  })).sort((a, b) => b.attacks - a.attacks);

  const toggleBlock = ip => {
    setBlockedIPs(prev => {
      const n = new Set(prev);
      n.has(ip) ? n.delete(ip) : n.add(ip);
      return n;
    });
  };

  const sel = selected ? enrichedData.find(d => d.ip === selected) : null;
  const blockedCount = blockedIPs.size;
  const totalAttacks = enrichedData.reduce((s, d) => s + d.attacks, 0);

  return (
    <div className="space-y-5">

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Tracked IPs"    value={enrichedData.length} icon={Globe}         color="blue" />
        <StatCard label="Blocked IPs"    value={blockedCount}        icon={ShieldOff}      color="red" glow={blockedCount > 0} />
        <StatCard label="Total Attacks"  value={totalAttacks}        sub="All sources"     icon={AlertTriangle} color="yellow" />
        <StatCard label="High Risk IPs"  value={enrichedData.filter(d => d.riskScore >= 70).length} icon={Shield} color="purple" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* IP Table */}
        <GlassCard title="Suspicious IP List" subtitle="Ranked by attack volume" className="lg:col-span-2">
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Country</th>
                  <th>Attacks</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {enrichedData.map((ip, i) => (
                  <motion.tr key={ip.ip}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.03 }}
                    className={`cursor-pointer ${selected === ip.ip ? 'bg-white/[0.03]' : ''}`}
                    onClick={() => setSelected(selected === ip.ip ? null : ip.ip)}>
                    <td>
                      <span className="font-mono text-xs text-cyan-400">{ip.ip}</span>
                      {ip.liveRequests > 0 && (
                        <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded-full"
                          style={{ background: 'rgba(0,212,255,0.12)', color: '#00d4ff' }}>
                          +{ip.liveRequests} live
                        </span>
                      )}
                    </td>
                    <td>
                      <span className="flex items-center gap-1.5 text-xs">
                        <span>{ip.countryFlag}</span>
                        <span style={{ color: 'rgba(255,255,255,0.6)' }}>{ip.country}</span>
                      </span>
                    </td>
                    <td className="font-bold text-sm" style={{ color: ip.attacks > 300 ? '#ef4444' : ip.attacks > 100 ? '#f59e0b' : '#60a5fa' }}>
                      {ip.attacks.toLocaleString()}
                    </td>
                    <td><RiskBadge score={ip.riskScore} /></td>
                    <td>
                      {ip.blocked ? (
                        <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.25)' }}>
                          BLOCKED
                        </span>
                      ) : (
                        <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981', border: '1px solid rgba(16,185,129,0.25)' }}>
                          ACTIVE
                        </span>
                      )}
                    </td>
                    <td onClick={e => { e.stopPropagation(); toggleBlock(ip.ip); }}>
                      <button className={`text-xs px-2.5 py-1 rounded-lg font-medium transition-all ${ip.blocked ? 'btn-ghost' : 'btn-danger'}`}>
                        {ip.blocked ? 'Unblock' : 'Block'}
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </GlassCard>

        {/* Side panel */}
        <div className="space-y-4">
          <AnimatePresence mode="wait">
            {sel ? (
              <motion.div key={sel.ip}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="space-y-4">
                <GlassCard title="IP Details" subtitle={sel.ip}>
                  <div className="px-5 pb-5 space-y-4">
                    <div className="flex items-center gap-3 py-3 border-b" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                      <span className="text-3xl">{sel.countryFlag}</span>
                      <div>
                        <p className="text-sm font-bold text-white">{sel.country}</p>
                        <p className="text-xs" style={{ color: 'rgba(255,255,255,0.45)' }}>{sel.isp}</p>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <ProgressBar value={sel.attacks} max={Math.max(...enrichedData.map(d => d.attacks))}
                        color="#ef4444" label={`${sel.attacks} attacks`} />
                      <ProgressBar value={sel.riskScore} max={100} color="#a855f7" label="Risk Score" />
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      {[
                        { label: 'Total Requests', value: sel.totalRequests.toLocaleString() },
                        { label: 'Live Requests',  value: sel.liveRequests },
                        { label: 'Last Seen',      value: new Date(sel.lastSeen).toLocaleTimeString() },
                        { label: 'ISP',            value: sel.isp },
                      ].map(({ label, value }) => (
                        <div key={label} className="px-3 py-2 rounded-xl"
                          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}>
                          <p style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</p>
                          <p className="font-semibold text-white mt-0.5">{value}</p>
                        </div>
                      ))}
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => toggleBlock(sel.ip)}
                        className={`flex-1 py-2 rounded-xl text-xs font-semibold transition-all ${sel.blocked ? 'btn-ghost' : 'btn-danger'}`}>
                        {sel.blocked ? '✓ Unblock IP' : '⊘ Block IP'}
                      </button>
                    </div>
                  </div>
                </GlassCard>
              </motion.div>
            ) : (
              <motion.div key="placeholder"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="glass-card p-8 text-center"
                style={{ color: 'rgba(255,255,255,0.3)' }}>
                <Globe size={32} className="mx-auto mb-3 opacity-40" />
                <p className="text-sm">Select an IP to view details</p>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Attack chart mini */}
          <GlassCard title="Top 5 Attackers">
            <div className="px-3 pb-4 pt-2" style={{ height: 180 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={enrichedData.slice(0, 5)} margin={{ top: 0, right: 5, bottom: 30, left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="ip" tick={{ fill: 'rgba(255,255,255,0.35)', fontSize: 9 }}
                    axisLine={false} tickLine={false} angle={-25} textAnchor="end" interval={0} />
                  <YAxis tick={{ fill: 'rgba(255,255,255,0.35)', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0c1224', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }}
                    labelStyle={{ color: '#fff', fontSize: 11 }}
                    itemStyle={{ color: '#ef4444', fontSize: 11 }}
                  />
                  <Bar dataKey="attacks" name="Attacks" radius={[4, 4, 0, 0]}>
                    {enrichedData.slice(0, 5).map((_, i) => (
                      <Cell key={i} fill={['#ef4444','#f59e0b','#a855f7','#60a5fa','#10b981'][i]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}
