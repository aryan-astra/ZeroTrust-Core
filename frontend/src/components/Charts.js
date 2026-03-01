import React, { useMemo } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from './ui';
import { BarChart3, TrendingUp, TrendingDown } from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell
} from 'recharts';

const CHART_COLORS = {
  primary: '#FFFFFF',
  secondary: '#A1A1A1',
  tertiary: '#6B6B6B',
  muted: '#4A4A4A',
  bg: '#1A1A1A',
};

// Custom tooltip
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-bg-elevated border border-border rounded-md px-3 py-2 shadow-lg">
      <p className="text-2xs text-text-muted mb-1">{label}</p>
      {payload.map((entry, i) => (
        <p key={i} className="text-xs font-mono text-text-primary">
          {entry.name}: {typeof entry.value === 'number' ? entry.value.toFixed(2) : entry.value}
        </p>
      ))}
    </div>
  );
}

// Trust score timeline chart
export function TrustScoreChart({ activities }) {
  const data = useMemo(() => {
    if (!activities?.length) return [];
    const recent = activities.slice(0, 50).reverse();
    return recent.map((a, i) => ({
      idx: i,
      time: new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      score: Math.round(a.trust_score || 0),
    }));
  }, [activities]);

  if (data.length < 2) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={BarChart3}>Trust Score Timeline</CardTitle>
        <span className="text-2xs text-text-muted">{data.length} events</span>
      </CardHeader>
      <CardContent className="h-48 -ml-4">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="trustGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={CHART_COLORS.primary} stopOpacity={0.15} />
                <stop offset="100%" stopColor={CHART_COLORS.primary} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="time" tick={{ fontSize: 10, fill: CHART_COLORS.muted }}
              axisLine={false} tickLine={false}
              interval="preserveStartEnd"
            />
            <YAxis
              domain={[0, 100]} tick={{ fontSize: 10, fill: CHART_COLORS.muted }}
              axisLine={false} tickLine={false}
              width={30}
            />
            <Tooltip content={<ChartTooltip />} />
            <Area
              type="monotone" dataKey="score" name="Trust Score"
              stroke={CHART_COLORS.primary} strokeWidth={1.5}
              fill="url(#trustGrad)" dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

// Status distribution pie chart
export function StatusDistributionChart({ stats }) {
  const data = useMemo(() => {
    if (!stats) return [];
    return [
      { name: 'Safe', value: stats.safe_devices || 0 },
      { name: 'Suspicious', value: stats.suspicious_devices || 0 },
      { name: 'Quarantined', value: stats.quarantined_devices || 0 },
    ].filter(d => d.value > 0);
  }, [stats]);

  const GRAY_SCALE = ['#FFFFFF', '#A1A1A1', '#4A4A4A'];

  if (!data.length) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={BarChart3}>Status Distribution</CardTitle>
      </CardHeader>
      <CardContent className="h-48 flex items-center">
        <ResponsiveContainer width="50%" height="100%">
          <PieChart>
            <Pie
              data={data} cx="50%" cy="50%"
              innerRadius={40} outerRadius={65}
              paddingAngle={2} dataKey="value"
              stroke="none"
            >
              {data.map((_, i) => (
                <Cell key={i} fill={GRAY_SCALE[i % GRAY_SCALE.length]} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="flex-1 space-y-2">
          {data.map((d, i) => (
            <div key={i} className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: GRAY_SCALE[i] }} />
              <span className="text-xs text-text-secondary">{d.name}</span>
              <span className="text-xs font-mono text-text-primary ml-auto">{d.value}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// Anomaly score histogram 
export function AnomalyDistributionChart({ devices }) {
  const data = useMemo(() => {
    if (!devices?.length) return [];
    const buckets = [
      { range: '0-.1', min: 0, max: 0.1, count: 0 },
      { range: '.1-.2', min: 0.1, max: 0.2, count: 0 },
      { range: '.2-.3', min: 0.2, max: 0.3, count: 0 },
      { range: '.3-.5', min: 0.3, max: 0.5, count: 0 },
      { range: '.5-.7', min: 0.5, max: 0.7, count: 0 },
      { range: '.7-1', min: 0.7, max: 1.0, count: 0 },
    ];
    devices.forEach(d => {
      const s = d.anomaly_score || 0;
      const bucket = buckets.find(b => s >= b.min && s < b.max) || buckets[buckets.length - 1];
      bucket.count++;
    });
    return buckets;
  }, [devices]);

  if (!data.length) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={BarChart3}>Anomaly Distribution</CardTitle>
      </CardHeader>
      <CardContent className="h-48 -ml-4">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <XAxis
              dataKey="range" tick={{ fontSize: 10, fill: CHART_COLORS.muted }}
              axisLine={false} tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 10, fill: CHART_COLORS.muted }}
              axisLine={false} tickLine={false}
              width={25}
            />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="count" name="Devices" fill={CHART_COLORS.secondary} radius={[2, 2, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
