import React from 'react';
import { Shield, Activity, Monitor, BarChart3, Bell, Settings, Terminal, Menu } from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
  { id: 'devices', label: 'Devices', icon: Monitor },
  { id: 'activity', label: 'Activity', icon: Activity },
  { id: 'threats', label: 'Threats', icon: Bell },
];

export default function Sidebar({ currentView, onNavigate, collapsed, onToggle }) {
  return (
    <aside
      className={`fixed left-0 top-0 h-screen bg-bg-secondary border-r border-border
                   flex flex-col z-40 transition-all duration-200
                   ${collapsed ? 'w-14' : 'w-52'}`}
    >
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-3.5 h-14 border-b border-border">
        <Shield size={20} className="text-white flex-shrink-0" strokeWidth={1.5} />
        {!collapsed && (
          <span className="text-sm font-semibold tracking-tight text-white truncate">
            ZeroTrust
          </span>
        )}
        <button
          onClick={onToggle}
          className="ml-auto btn-ghost p-1 rounded"
          aria-label="Toggle sidebar"
        >
          <Menu size={14} className="text-text-tertiary" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2 px-2 space-y-0.5">
        {NAV_ITEMS.map(item => {
          const Icon = item.icon;
          const active = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm
                         transition-colors duration-100
                         ${active
                           ? 'bg-bg-hover text-white'
                           : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover/50'
                         }`}
              title={collapsed ? item.label : undefined}
              aria-label={item.label}
              aria-current={active ? 'page' : undefined}
            >
              <Icon size={16} strokeWidth={active ? 2 : 1.5} className="flex-shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-2 py-3 border-t border-border space-y-0.5">
        <button
          className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm
                     text-text-tertiary hover:text-text-secondary hover:bg-bg-hover/50 transition-colors"
          title="Settings"
        >
          <Settings size={16} strokeWidth={1.5} className="flex-shrink-0" />
          {!collapsed && <span>Settings</span>}
        </button>
        <button
          className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm
                     text-text-tertiary hover:text-text-secondary hover:bg-bg-hover/50 transition-colors"
          title="Console"
        >
          <Terminal size={16} strokeWidth={1.5} className="flex-shrink-0" />
          {!collapsed && <span>Console</span>}
        </button>
      </div>
    </aside>
  );
}
