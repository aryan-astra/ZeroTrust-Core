import React from 'react';
import {
  Card, CardHeader, CardTitle, CardContent, StatusBadge, RelativeTime, EmptyState
} from './ui';
import { Activity, AlertTriangle, Shield, Lock, Monitor, Mail, Zap } from 'lucide-react';

const EVENT_ICONS = {
  NETWORK_ANALYSIS: Monitor,
  EMAIL_ANALYSIS: Mail,
  DEVICE_ANALYSIS: Activity,
  DEVICE_SUSPICIOUS: AlertTriangle,
  DEVICE_QUARANTINED: Lock,
  MANUAL_ISOLATION: Lock,
};

const EVENT_OPACITY = {
  SAFE: 'text-text-secondary',
  TRUSTED: 'text-text-secondary',
  SUSPICIOUS: 'text-text-secondary',
  QUARANTINED: 'text-text-tertiary',
};

export default function ActivityFeed({ activities, loading, limit = 30 }) {
  if (loading) {
    return (
      <Card>
        <CardHeader><CardTitle icon={Activity}>Activity Feed</CardTitle></CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex gap-3 animate-pulse">
                <div className="h-8 w-8 bg-bg-tertiary rounded" />
                <div className="flex-1 space-y-2">
                  <div className="h-3 bg-bg-tertiary rounded w-3/4" />
                  <div className="h-3 bg-bg-tertiary rounded w-1/2" />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  const items = (activities || []).slice(0, limit);

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={Activity}>
          Activity Feed
          <span className="text-text-muted font-normal ml-2 text-xs">{items.length}</span>
        </CardTitle>
      </CardHeader>

      {items.length === 0 ? (
        <EmptyState icon={Activity} message="No activity yet" sub="Events will appear here in real-time" />
      ) : (
        <div className="max-h-[500px] overflow-y-auto">
          {items.map((item, i) => {
            const Icon = EVENT_ICONS[item.event_type] || Activity;
            const opClass = EVENT_OPACITY[item.status] || 'text-text-secondary';
            return (
              <div
                key={item.id || i}
                className="flex items-start gap-3 px-4 py-2.5 border-b border-border last:border-0
                           hover:bg-bg-hover/30 transition-colors animate-fade-in"
                style={{ animationDelay: `${i * 30}ms` }}
              >
                <div className="mt-0.5 p-1.5 bg-bg-tertiary rounded">
                  <Icon size={13} className="text-text-tertiary" strokeWidth={1.5} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-text-primary truncate">
                      {item.device_id}
                    </span>
                    <StatusBadge status={item.status} />
                  </div>
                  <p className={`text-xs mt-0.5 truncate ${opClass}`}>
                    {item.reason || item.event_type}
                  </p>
                  <div className="flex items-center gap-3 mt-1 text-2xs text-text-muted font-mono">
                    <span>score: {Math.round(item.trust_score)}</span>
                    {item.anomaly_score > 0 && <span>anom: {item.anomaly_score.toFixed(3)}</span>}
                    {item.phishing_score > 0 && <span>phish: {item.phishing_score.toFixed(3)}</span>}
                  </div>
                </div>
                <RelativeTime timestamp={item.timestamp} />
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}
