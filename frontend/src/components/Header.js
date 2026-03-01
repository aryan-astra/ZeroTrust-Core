import React from 'react';
import { Search, Bell, Wifi, WifiOff, RefreshCw, CircleDot } from 'lucide-react';

export default function Header({ wsConnected, onRefresh, searchQuery, onSearchChange }) {
  return (
    <header className="h-14 bg-bg-secondary border-b border-border flex items-center justify-between px-5 sticky top-0 z-30">
      {/* Left: Title + Status */}
      <div className="flex items-center gap-4">
        <h1 className="text-sm font-medium text-text-primary tracking-tight">
          Security Operations Center
        </h1>
        <div className="flex items-center gap-1.5">
          <CircleDot
            size={10}
            className={wsConnected ? 'text-white' : 'text-text-muted'}
            fill={wsConnected ? 'white' : 'transparent'}
          />
          <span className="text-2xs text-text-tertiary uppercase tracking-wider">
            {wsConnected ? 'Live' : 'Offline'}
          </span>
        </div>
      </div>

      {/* Center: Search */}
      <div className="flex-1 max-w-md mx-8">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            placeholder="Search devices, IPs, hostnames..."
            className="input pl-9 py-1.5 text-xs"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            aria-label="Search devices"
          />
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2">
        <button
          onClick={onRefresh}
          className="btn-ghost p-1.5 rounded-md"
          aria-label="Refresh data"
          title="Refresh"
        >
          <RefreshCw size={14} className="text-text-secondary" />
        </button>
        <button className="btn-ghost p-1.5 rounded-md relative" aria-label="Notifications" title="Alerts">
          <Bell size={14} className="text-text-secondary" />
        </button>
        <div className="flex items-center gap-1.5 ml-2 pl-3 border-l border-border">
          {wsConnected ? (
            <Wifi size={14} className="text-white" />
          ) : (
            <WifiOff size={14} className="text-text-muted" />
          )}
        </div>
      </div>
    </header>
  );
}
