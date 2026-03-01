import React, { useState, useEffect } from 'react';
import {
  Card, CardHeader, CardTitle, CardContent,
  StatusBadge, TrustScore, ProgressBar, RelativeTime, EmptyState
} from './ui';
import { X, Monitor, Activity, AlertTriangle, Shield, Clock, Cpu, Globe, Hash } from 'lucide-react';
import { getDeviceDetail } from '../services/api';

export default function DeviceDetailModal({ device, onClose }) {
  const [detail, setDetail] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!device?.id) return;
    setLoading(true);
    getDeviceDetail(device.id)
      .then(data => setDetail(data))
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
  }, [device?.id]);

  if (!device) return null;

  const d = detail?.device || device;
  const timeline = detail?.timeline || [];
  const riskEvents = detail?.risk_events || [];
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'risk', label: 'Risk Events' },
  ];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label={`Device detail: ${d.id}`}
    >
      <div
        className="bg-bg-secondary border border-border rounded-lg w-full max-w-2xl max-h-[85vh]
                    overflow-hidden shadow-2xl animate-slide-up"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-3">
            <Monitor size={18} className="text-text-tertiary" strokeWidth={1.5} />
            <div>
              <h2 className="text-sm font-semibold text-text-primary">{d.id}</h2>
              <p className="text-xs text-text-tertiary">{d.hostname || 'Unknown host'}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="btn-ghost p-1.5 rounded-md"
            aria-label="Close"
          >
            <X size={16} className="text-text-tertiary" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-border px-5">
          {tabs.map(tab => (
            <button
              key={tab.id}
              className={`px-3 py-2.5 text-xs font-medium border-b-2 transition-colors
                         ${activeTab === tab.id
                           ? 'border-white text-white'
                           : 'border-transparent text-text-tertiary hover:text-text-secondary'
                         }`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="overflow-y-auto max-h-[60vh]">
          {activeTab === 'overview' && (
            <div className="p-5 space-y-5">
              {/* Trust + Status */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <TrustScore score={d.trust_score} size="xl" />
                  <div>
                    <StatusBadge status={d.status} />
                    <p className="text-xs text-text-muted mt-1">{d.reason || '—'}</p>
                  </div>
                </div>
                <ProgressBar value={d.trust_score} className="w-32" />
              </div>

              {/* Grid details */}
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: 'IP Address', value: d.ip_address, icon: Globe },
                  { label: 'MAC Address', value: d.mac_address || '—', icon: Hash },
                  { label: 'Device Type', value: d.device_type || '—', icon: Cpu },
                  { label: 'Anomaly Score', value: d.anomaly_score?.toFixed(4) || '0', icon: AlertTriangle },
                  { label: 'Phishing Score', value: d.phishing_score?.toFixed(4) || '0', icon: Shield },
                  { label: 'Isolated', value: d.is_isolated ? 'Yes' : 'No', icon: Activity },
                ].map((item, i) => (
                  <div key={i} className="flex items-start gap-2.5 p-3 bg-bg-tertiary rounded-md">
                    <item.icon size={14} className="text-text-muted mt-0.5" strokeWidth={1.5} />
                    <div>
                      <p className="text-2xs text-text-muted uppercase tracking-wider">{item.label}</p>
                      <p className="text-sm font-mono text-text-primary mt-0.5">{item.value}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="p-5">
              {loading ? (
                <div className="space-y-3">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="h-12 bg-bg-tertiary rounded animate-pulse" />
                  ))}
                </div>
              ) : timeline.length === 0 ? (
                <EmptyState icon={Clock} message="No timeline data" />
              ) : (
                <div className="space-y-1">
                  {timeline.map((ev, i) => (
                    <div key={i} className="flex items-start gap-3 py-2.5 border-b border-border/50 last:border-0">
                      <div className="w-1.5 h-1.5 rounded-full bg-text-muted mt-2 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-text-primary">{ev.event_type}</span>
                          <StatusBadge status={ev.status} />
                        </div>
                        <p className="text-2xs text-text-muted mt-0.5 truncate">{ev.reason}</p>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <span className="text-xs font-mono text-text-secondary">{Math.round(ev.trust_score)}</span>
                        <RelativeTime timestamp={ev.timestamp} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'risk' && (
            <div className="p-5">
              {riskEvents.length === 0 ? (
                <EmptyState icon={AlertTriangle} message="No risk events" sub="This device has no recorded threats" />
              ) : (
                <div className="space-y-2">
                  {riskEvents.map((ev, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-bg-tertiary rounded-md">
                      <AlertTriangle size={14} className="text-text-muted flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-text-primary">{ev.event_type}</p>
                        <p className="text-2xs text-text-muted">severity: {ev.severity} | penalty: {ev.penalty_applied}</p>
                      </div>
                      <RelativeTime timestamp={ev.timestamp} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
