import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, AlertTriangle, Shield, Zap, Cpu, Server,
  TrendingUp, Clock, Users, Eye,
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell, PieChart, Pie, Legend,
} from 'recharts';
import { StatCard, GlassCard, CircleProgress, ProgressBar, SeverityBadge } from '../components/ui.jsx';
import { generateTrafficData, OWASP_DATA, generateHealth } from '../data/mockData.js';

const CUSTOM_TOOLTIP = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-card px-3 py-2" style={{ border: '1px solid rgba(0,212,255,0.2)' }}>
      <p className="text-xs text-white font-semibold mb-1">{label}</p>
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-2 text-xs" style={{ color: p.color }}>
          <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          {p.name}: <span className="font-bold">{p.value}</span>
        </div>
      ))}
    </div>
  );
};

export default function Dashboard({ logs, alerts }) {
  const [traffic, setTraffic] = useState(() => generateTrafficData(20));
  const [health, setHealth] = useState(() => generateHealth());

  const critCount   = alerts.filter(a => a.severity === 'critical').length;
  const highCount   = alerts.filter(a => a.severity === 'high').length;
  const medCount    = alerts.filter(a => a.severity === 'medium').length;
  const lowCount    = alerts.filter(a => a.severity === 'low').length;
  const openCount   = alerts.filter(a => a.status === 'Open').length;
  const resolvedCnt = alerts.filter(a => a.status === 'Resolved').length;

  // Update health stats every 4 seconds
  useEffect(() => {
    const t = setInterval(() => setHealth(generateHealth()), 4000);
    return () => clearInterval(t);
  }, []);

  // Append new traffic point every 3s
  useEffect(() => {
    const t = setInterval(() => {
      setTraffic(prev => {
        const last = prev[prev.length - 1];
        const now = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
        const newPoint = {
          time: now,
          requests: Math.max(10, (last?.requests ?? 100) + Math.floor(Math.random() * 60 - 30)),
          attacks:  Math.max(0,  (last?.attacks  ?? 10)  + Math.floor(Math.random() * 10 - 4)),
          blocked:  Math.max(0,  (last?.blocked  ?? 5)   + Math.floor(Math.random() * 6 - 3)),
        };
        return [...prev.slice(-19), newPoint];
      });
    }, 3000);
    return () => clearInterval(t);
  }, []);

  const recentAlerts = [...alerts].sort((a,b) => b.id - a.id).slice(0, 6);

  return (
    <div className="space-y-5">

      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Log Events" value={logs.length.toLocaleString()} sub="This session" icon={Activity} color="blue" glow />
        <StatCard label="Critical Alerts"  value={critCount}  sub={`${openCount} open`}     icon={AlertTriangle} color="red"    glow />
        <StatCard label="High Severity"    value={highCount}  sub="Requires attention"       icon={Shield}        color="yellow" />
        <StatCard label="Resolved Today"   value={resolvedCnt} sub="Cleared incidents"       icon={Zap}           color="green" />
      </div>

      {/* Alert severity row */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Critical', count: critCount, color: '#ef4444' },
          { label: 'High',     count: highCount, color: '#f59e0b' },
          { label: 'Medium',   count: medCount,  color: '#60a5fa' },
          { label: 'Low',      count: lowCount,  color: '#10b981' },
        ].map(({ label, count, color }) => (
          <motion.div key={label}
            whileHover={{ scale: 1.02 }}
            className="glass-card px-4 py-3 flex items-center justify-between"
            style={{ borderColor: color + '30' }}>
            <div>
              <p className="text-xs" style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</p>
              <motion.p key={count} initial={{ scale: 0.8 }} animate={{ scale: 1 }}
                className="text-xl font-bold" style={{ color, textShadow: `0 0 12px ${color}` }}>
                {count}
              </motion.p>
            </div>
            <div className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: color + '15', border: `1px solid ${color}30` }}>
              <span className="text-xs font-bold" style={{ color }}>
                {alerts.length > 0 ? ((count / alerts.length) * 100).toFixed(0) : 0}%
              </span>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Main charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Traffic chart — 2 cols */}
        <GlassCard
          title="Live Traffic & Attacks"
          subtitle="Requests vs attacks over time"
          className="lg:col-span-2"
          action={
            <div className="flex items-center gap-1.5 text-xs" style={{ color: '#10b981' }}>
              <span className="pulse-dot w-2 h-2 rounded-full" style={{ background: '#10b981', color: '#10b981' }} />
              LIVE
            </div>
          }>
          <div className="px-3 pb-4 pt-2" style={{ height: 220 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={traffic} margin={{ top: 5, right: 5, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="reqGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="atkGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="time" tick={{ fill: 'rgba(255,255,255,0.35)', fontSize: 10 }} axisLine={false} tickLine={false} interval={3} />
                <YAxis tick={{ fill: 'rgba(255,255,255,0.35)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CUSTOM_TOOLTIP />} />
                <Area type="monotone" dataKey="requests" name="Requests" stroke="#00d4ff" strokeWidth={2} fill="url(#reqGrad)" dot={false} />
                <Area type="monotone" dataKey="attacks"  name="Attacks"  stroke="#ef4444" strokeWidth={2} fill="url(#atkGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="flex items-center gap-5 px-5 pb-4 text-xs" style={{ color: 'rgba(255,255,255,0.45)' }}>
            <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-cyan-400 inline-block rounded" />Requests</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-red-500 inline-block rounded" />Attacks</span>
          </div>
        </GlassCard>

        {/* System health */}
        <GlassCard title="System Health" subtitle="Real-time metrics">
          <div className="px-5 pb-5 pt-3 space-y-4">
            <div className="flex justify-around">
              <CircleProgress value={health.cpu}    max={100} size={72} color="#00d4ff" label="CPU"    sub={`${health.cpu}%`} />
              <CircleProgress value={health.memory} max={100} size={72} color="#a855f7" label="Memory" sub={`${health.memory}%`} />
            </div>
            <div className="space-y-3 pt-2">
              <ProgressBar value={health.logRate} max={2000} color="#10b981" label="Log Rate" />
              <div className="flex justify-between text-xs" style={{ color: 'rgba(255,255,255,0.45)' }}>
                <span>{health.logRate} logs/min</span>
                <span className="text-green-400">{health.agents} agents active</span>
              </div>
              <div className="flex items-center justify-between px-3 py-2 rounded-xl text-xs"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <span style={{ color: 'rgba(255,255,255,0.45)' }}>Uptime</span>
                <span className="font-mono text-green-400">{health.uptime}</span>
              </div>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* OWASP + Recent alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* OWASP chart */}
        <GlassCard title="OWASP Top 10 Distribution" subtitle="Attack type frequency">
          <div className="px-3 pb-4 pt-2" style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={OWASP_DATA} layout="vertical" margin={{ top: 0, right: 30, bottom: 0, left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="rgba(255,255,255,0.04)" />
                <XAxis type="number" tick={{ fill: 'rgba(255,255,255,0.35)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="shortName" width={90} tick={{ fill: 'rgba(255,255,255,0.5)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CUSTOM_TOOLTIP />} />
                <Bar dataKey="count" name="Detections" radius={[0, 4, 4, 0]} maxBarSize={14}>
                  {OWASP_DATA.map((entry, i) => (
                    <Cell key={i} fill={entry.color}
                      style={{ filter: `drop-shadow(0 0 4px ${entry.color}60)` }} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>

        {/* Recent Alerts */}
        <GlassCard title="Recent Alerts" subtitle="Latest security events"
          action={<span className="text-xs px-2 py-1 rounded-lg" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.25)' }}>
            {openCount} Open
          </span>}>
          <div className="divide-y" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
            {recentAlerts.length === 0 ? (
              <div className="px-5 py-8 text-center text-sm" style={{ color: 'rgba(255,255,255,0.3)' }}>
                No alerts yet — logs ingesting…
              </div>
            ) : recentAlerts.map((alert, i) => (
              <motion.div key={alert.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                className="flex items-center gap-3 px-5 py-3 hover:bg-white/[0.02] transition-colors">
                <div className="w-1.5 h-8 rounded-full flex-shrink-0"
                  style={{
                    background: alert.severity === 'critical' ? '#ef4444' :
                                alert.severity === 'high'     ? '#f59e0b' :
                                alert.severity === 'medium'   ? '#60a5fa' : '#10b981',
                  }} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-white truncate">{alert.title}</p>
                  <p className="text-xs mt-0.5 truncate" style={{ color: 'rgba(255,255,255,0.4)' }}>
                    {alert.sourceIp} · {alert.timeDisplay}
                  </p>
                </div>
                <SeverityBadge severity={alert.severity} size="xs" />
              </motion.div>
            ))}
          </div>
        </GlassCard>
      </div>
    </div>
  );
}
