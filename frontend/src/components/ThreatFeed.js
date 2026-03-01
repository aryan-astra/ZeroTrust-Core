import React from 'react';
import { Card, CardHeader, CardTitle, CardContent, RelativeTime, EmptyState } from './ui';
import { Bell, AlertTriangle, Lock, Shield, Mail, Monitor } from 'lucide-react';

const ALERT_ICONS = {
  quarantine: Lock,
  phishing: Mail,
  manual_isolation: Lock,
  anomaly: AlertTriangle,
};

const SEVERITY_STYLE = {
  high: 'border-l-white/60',
  medium: 'border-l-white/30',
  low: 'border-l-white/10',
};

export default function ThreatFeed({ riskEvents, loading }) {
  if (loading) {
    return (
      <Card>
        <CardHeader><CardTitle icon={Bell}>Threat Feed</CardTitle></CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-14 bg-bg-tertiary rounded animate-pulse" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  const items = riskEvents || [];

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={Bell}>
          Threat Feed
          <span className="text-text-muted font-normal ml-2 text-xs">{items.length}</span>
        </CardTitle>
      </CardHeader>

      {items.length === 0 ? (
        <EmptyState icon={Shield} message="No active threats" sub="System operating normally" />
      ) : (
        <div className="max-h-[400px] overflow-y-auto">
          {items.map((ev, i) => {
            const Icon = ALERT_ICONS[ev.event_type] || AlertTriangle;
            const sevStyle = SEVERITY_STYLE[ev.severity] || SEVERITY_STYLE.low;
            return (
              <div
                key={ev.id || i}
                className={`flex items-start gap-3 px-4 py-3 border-b border-border last:border-0
                           border-l-2 ${sevStyle} hover:bg-bg-hover/30 transition-colors animate-fade-in`}
                style={{ animationDelay: `${i * 40}ms` }}
              >
                <div className="mt-0.5 p-1 bg-bg-tertiary rounded">
                  <Icon size={12} className="text-text-tertiary" strokeWidth={1.5} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-text-primary">{ev.device_id}</span>
                    <span className="badge bg-bg-tertiary text-text-muted border-border text-2xs">
                      {ev.severity}
                    </span>
                  </div>
                  <p className="text-xs text-text-secondary mt-0.5">{ev.event_type}</p>
                  {ev.penalty_applied > 0 && (
                    <p className="text-2xs text-text-muted mt-0.5 font-mono">
                      penalty: -{ev.penalty_applied}
                    </p>
                  )}
                </div>
                <RelativeTime timestamp={ev.timestamp} />
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}
