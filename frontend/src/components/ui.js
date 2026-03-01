import React from 'react';
import {
  Shield, Activity, Monitor, AlertTriangle, Lock, Search,
  Wifi, WifiOff, Clock, ChevronRight, Eye, BarChart3,
  Terminal, Zap, Server, RefreshCw, X, ArrowUpDown,
  ArrowDown, ArrowUp, ExternalLink, Copy, Filter,
  Settings, Bell, User, LogOut, Menu, MoreHorizontal,
  CheckCircle, XCircle, MinusCircle, Info, ChevronDown,
  Mail, Globe, Database, Cpu, TrendingDown, TrendingUp,
  Layers, Radio, CircleDot, Hash, FileText
} from 'lucide-react';

// Re-export all icons for consistent usage
export {
  Shield, Activity, Monitor, AlertTriangle, Lock, Search,
  Wifi, WifiOff, Clock, ChevronRight, Eye, BarChart3,
  Terminal, Zap, Server, RefreshCw, X, ArrowUpDown,
  ArrowDown, ArrowUp, ExternalLink, Copy, Filter,
  Settings, Bell, User, LogOut, Menu, MoreHorizontal,
  CheckCircle, XCircle, MinusCircle, Info, ChevronDown,
  Mail, Globe, Database, Cpu, TrendingDown, TrendingUp,
  Layers, Radio, CircleDot, Hash, FileText
};

// Status badge component
export function StatusBadge({ status }) {
  const config = {
    SAFE: { label: 'Safe', className: 'badge-trusted' },
    TRUSTED: { label: 'Trusted', className: 'badge-trusted' },
    SUSPICIOUS: { label: 'Suspicious', className: 'badge-suspicious' },
    QUARANTINED: { label: 'Quarantined', className: 'badge-quarantined' },
  };
  const c = config[status] || config.SAFE;
  return <span className={`badge ${c.className}`}>{c.label}</span>;
}

// Trust score display
export function TrustScore({ score, size = 'md' }) {
  const s = Math.round(score);
  const sizes = {
    sm: 'text-xs',
    md: 'text-sm font-mono',
    lg: 'text-2xl font-mono font-semibold',
    xl: 'text-4xl font-mono font-bold',
  };
  const opacity = s >= 80 ? 'text-white' : s >= 50 ? 'text-text-secondary' : 'text-text-tertiary';
  return <span className={`${sizes[size]} ${opacity} tabular-nums`}>{s}</span>;
}

// Progress bar
export function ProgressBar({ value, max = 100, className = '' }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  const opacity = pct >= 80 ? 'bg-white/80' : pct >= 50 ? 'bg-white/40' : 'bg-white/20';
  return (
    <div className={`progress-bar ${className}`}>
      <div className={`progress-fill ${opacity}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

// Skeleton loader
export function Skeleton({ className = '', count = 1 }) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className={`skeleton ${className}`} />
      ))}
    </>
  );
}

// Card wrapper
export function Card({ children, className = '', ...props }) {
  return (
    <div className={`card ${className}`} {...props}>
      {children}
    </div>
  );
}

export function CardHeader({ children, className = '' }) {
  return <div className={`card-header ${className}`}>{children}</div>;
}

export function CardTitle({ children, icon: Icon, className = '' }) {
  return (
    <div className={`card-title flex items-center gap-2 ${className}`}>
      {Icon && <Icon size={14} className="text-text-tertiary" />}
      {children}
    </div>
  );
}

export function CardContent({ children, className = '' }) {
  return <div className={`card-content ${className}`}>{children}</div>;
}

// Relative time formatter
export function RelativeTime({ timestamp }) {
  if (!timestamp) return <span className="text-text-muted">—</span>;
  const now = new Date();
  const then = new Date(timestamp);
  const diff = Math.floor((now - then) / 1000);

  let label;
  if (diff < 5) label = 'just now';
  else if (diff < 60) label = `${diff}s ago`;
  else if (diff < 3600) label = `${Math.floor(diff / 60)}m ago`;
  else if (diff < 86400) label = `${Math.floor(diff / 3600)}h ago`;
  else label = `${Math.floor(diff / 86400)}d ago`;

  return (
    <span className="text-text-tertiary text-xs font-mono tabular-nums" title={then.toLocaleString()}>
      {label}
    </span>
  );
}

// Empty state
export function EmptyState({ icon: Icon = Monitor, message = 'No data available', sub = '' }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <Icon size={32} className="text-text-muted mb-3" strokeWidth={1} />
      <p className="text-sm text-text-secondary">{message}</p>
      {sub && <p className="text-xs text-text-muted mt-1">{sub}</p>}
    </div>
  );
}

// Metric display
export function MetricValue({ label, value, sub, icon: Icon, trend }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-1.5 text-text-tertiary">
        {Icon && <Icon size={12} />}
        <span className="text-2xs uppercase tracking-wider font-medium">{label}</span>
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-2xl font-mono font-semibold text-text-primary tabular-nums">{value}</span>
        {sub && <span className="text-xs text-text-muted">{sub}</span>}
        {trend !== undefined && (
          <span className={`flex items-center text-xs ${trend > 0 ? 'text-text-secondary' : 'text-text-tertiary'}`}>
            {trend > 0 ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
            <span className="ml-0.5 font-mono">{Math.abs(trend)}%</span>
          </span>
        )}
      </div>
    </div>
  );
}
