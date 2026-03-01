import React from 'react';
import {
  Card, CardHeader, CardTitle, CardContent,
  MetricValue, ProgressBar
} from './ui';
import { Shield, Monitor, AlertTriangle, Lock, Activity, Cpu } from 'lucide-react';

export default function StatsCards({ stats, loading }) {
  if (loading) {
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="animate-pulse">
            <CardContent className="py-4">
              <div className="h-4 bg-bg-tertiary rounded w-16 mb-2" />
              <div className="h-8 bg-bg-tertiary rounded w-12" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  const total = stats?.total_devices || 0;
  const safe = stats?.safe_devices || 0;
  const suspicious = stats?.suspicious_devices || 0;
  const quarantined = stats?.quarantined_devices || 0;
  const avgScore = stats?.average_trust_score != null ? Math.round(stats.average_trust_score) : '—';
  const wsClients = stats?.ws_clients || 0;

  const items = [
    { label: 'Total Devices', value: total, icon: Monitor, sub: 'registered' },
    { label: 'Safe', value: safe, icon: Shield, sub: `${total > 0 ? Math.round((safe / total) * 100) : 0}%` },
    { label: 'Suspicious', value: suspicious, icon: AlertTriangle, sub: `${total > 0 ? Math.round((suspicious / total) * 100) : 0}%` },
    { label: 'Quarantined', value: quarantined, icon: Lock, sub: `${total > 0 ? Math.round((quarantined / total) * 100) : 0}%` },
    { label: 'Avg. Trust', value: avgScore, icon: Activity, sub: '/100' },
    { label: 'WS Clients', value: wsClients, icon: Cpu, sub: 'connected' },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
      {items.map((item, i) => (
        <Card key={i} className="animate-fade-in" style={{ animationDelay: `${i * 50}ms` }}>
          <CardContent className="py-4">
            <MetricValue
              label={item.label}
              value={item.value}
              sub={item.sub}
              icon={item.icon}
            />
            {typeof item.value === 'number' && item.label === 'Avg. Trust' && (
              <ProgressBar value={item.value} className="mt-3" />
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
