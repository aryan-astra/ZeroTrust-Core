import React, { useState, useMemo } from 'react';
import {
  Card, CardHeader, CardTitle, CardContent,
  StatusBadge, TrustScore, ProgressBar, RelativeTime, EmptyState
} from './ui';
import { Monitor, ArrowUpDown, ArrowUp, ArrowDown, Search, Filter, Lock } from 'lucide-react';

export default function DeviceTable({ devices, loading, onSelectDevice, onIsolate, searchQuery }) {
  const [sortField, setSortField] = useState('trust_score');
  const [sortDir, setSortDir] = useState('asc');
  const [statusFilter, setStatusFilter] = useState('all');

  const filteredDevices = useMemo(() => {
    let list = devices || [];

    // Status filter
    if (statusFilter !== 'all') {
      list = list.filter(d => d.status === statusFilter);
    }

    // Search filter
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(d =>
        (d.id || '').toLowerCase().includes(q) ||
        (d.hostname || '').toLowerCase().includes(q) ||
        (d.ip_address || '').toLowerCase().includes(q)
      );
    }

    // Sort
    list = [...list].sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (typeof aVal === 'string') aVal = aVal.toLowerCase();
      if (typeof bVal === 'string') bVal = bVal.toLowerCase();
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    return list;
  }, [devices, sortField, sortDir, statusFilter, searchQuery]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const SortIcon = ({ field }) => {
    if (sortField !== field) return <ArrowUpDown size={12} className="text-text-muted" />;
    return sortDir === 'asc'
      ? <ArrowUp size={12} className="text-text-secondary" />
      : <ArrowDown size={12} className="text-text-secondary" />;
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle icon={Monitor}>Devices</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex gap-4 animate-pulse">
                <div className="h-4 bg-bg-tertiary rounded w-24" />
                <div className="h-4 bg-bg-tertiary rounded w-32" />
                <div className="h-4 bg-bg-tertiary rounded w-20" />
                <div className="h-4 bg-bg-tertiary rounded w-16" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={Monitor}>
          Devices
          <span className="text-text-muted font-normal ml-2 text-xs">
            {filteredDevices.length}
          </span>
        </CardTitle>
        <div className="flex items-center gap-2">
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="input py-1 px-2 text-xs w-auto"
            aria-label="Filter by status"
          >
            <option value="all">All Status</option>
            <option value="SAFE">Safe</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="QUARANTINED">Quarantined</option>
          </select>
        </div>
      </CardHeader>

      {filteredDevices.length === 0 ? (
        <EmptyState icon={Monitor} message="No devices found" sub="Waiting for network activity" />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                {[
                  { field: 'id', label: 'Device ID' },
                  { field: 'hostname', label: 'Hostname' },
                  { field: 'ip_address', label: 'IP Address' },
                  { field: 'trust_score', label: 'Trust Score' },
                  { field: 'status', label: 'Status' },
                  { field: 'anomaly_score', label: 'Anomaly' },
                  { field: 'phishing_score', label: 'Phishing' },
                  { field: 'updated_at', label: 'Last Seen' },
                  { field: 'actions', label: '' },
                ].map(col => (
                  <th
                    key={col.field}
                    className="table-header cursor-pointer select-none"
                    onClick={() => col.field !== 'actions' && handleSort(col.field)}
                  >
                    <div className="flex items-center gap-1">
                      {col.label}
                      {col.field !== 'actions' && <SortIcon field={col.field} />}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredDevices.map(device => (
                <tr
                  key={device.id}
                  className="table-row"
                  onClick={() => onSelectDevice && onSelectDevice(device)}
                  tabIndex={0}
                  role="button"
                  aria-label={`View device ${device.id}`}
                  onKeyDown={e => e.key === 'Enter' && onSelectDevice && onSelectDevice(device)}
                >
                  <td className="table-cell font-mono text-xs text-text-primary">{device.id}</td>
                  <td className="table-cell text-text-secondary">{device.hostname || '—'}</td>
                  <td className="table-cell font-mono text-xs text-text-tertiary">{device.ip_address}</td>
                  <td className="table-cell">
                    <div className="flex items-center gap-2">
                      <TrustScore score={device.trust_score} size="sm" />
                      <ProgressBar value={device.trust_score} className="w-16" />
                    </div>
                  </td>
                  <td className="table-cell">
                    <StatusBadge status={device.status} />
                  </td>
                  <td className="table-cell font-mono text-xs text-text-tertiary">
                    {device.anomaly_score != null ? device.anomaly_score.toFixed(3) : '—'}
                  </td>
                  <td className="table-cell font-mono text-xs text-text-tertiary">
                    {device.phishing_score != null ? device.phishing_score.toFixed(3) : '—'}
                  </td>
                  <td className="table-cell">
                    <RelativeTime timestamp={device.updated_at} />
                  </td>
                  <td className="table-cell">
                    {!device.is_isolated && device.status !== 'SAFE' && device.status !== 'TRUSTED' && (
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          onIsolate && onIsolate(device.id);
                        }}
                        className="btn-ghost p-1 rounded text-text-muted hover:text-white"
                        title="Isolate device"
                        aria-label={`Isolate ${device.id}`}
                      >
                        <Lock size={13} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
