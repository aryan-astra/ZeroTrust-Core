import React, { useState, useEffect, useCallback, useRef } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import StatsCards from './components/StatsCards';
import DeviceTable from './components/DeviceTable';
import ActivityFeed from './components/ActivityFeed';
import { TrustScoreChart, StatusDistributionChart, AnomalyDistributionChart } from './components/Charts';
import ThreatFeed from './components/ThreatFeed';
import DeviceDetailModal from './components/DeviceDetailModal';
import {
  getDevices, getActivity, getStats, getRiskEvents,
  isolateDevice, createWebSocket
} from './services/api';

const POLL_INTERVAL = 4000;

export default function App() {
  // State
  const [currentView, setCurrentView] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [wsConnected, setWsConnected] = useState(false);

  const [devices, setDevices] = useState([]);
  const [activities, setActivities] = useState([]);
  const [stats, setStats] = useState({});
  const [riskEvents, setRiskEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDevice, setSelectedDevice] = useState(null);

  const wsRef = useRef(null);
  const pollRef = useRef(null);

  // Fetch all data
  const fetchData = useCallback(async () => {
    try {
      const [devRes, actRes, statsRes, riskRes] = await Promise.all([
        getDevices().catch(() => ({ devices: [], stats: {} })),
        getActivity(100).catch(() => ({ activities: [] })),
        getStats().catch(() => ({})),
        getRiskEvents({ limit: 50 }).catch(() => ({ events: [] })),
      ]);
      setDevices(devRes.devices || []);
      setActivities(actRes.activities || []);
      setStats(statsRes || devRes.stats || {});
      setRiskEvents(riskRes.events || []);
    } catch (err) {
      console.error('Fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // WebSocket setup
  useEffect(() => {
    const connectWs = () => {
      wsRef.current = createWebSocket(
        // onMessage
        (data) => {
          if (data.type === 'device_update') {
            // Trigger a data refresh for device updates
            fetchData();
          } else if (data.type === 'alert') {
            fetchData();
          } else if (data.type === 'risk_event') {
            fetchData();
          }
        },
        // onOpen
        () => setWsConnected(true),
        // onClose
        () => {
          setWsConnected(false);
          // Reconnect after 3 seconds
          setTimeout(connectWs, 3000);
        }
      );
    };

    connectWs();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [fetchData]);

  // Polling fallback
  useEffect(() => {
    fetchData();
    pollRef.current = setInterval(fetchData, POLL_INTERVAL);
    return () => clearInterval(pollRef.current);
  }, [fetchData]);

  // Handlers
  const handleRefresh = () => {
    setLoading(true);
    fetchData();
  };

  const handleIsolate = async (deviceId) => {
    try {
      await isolateDevice(deviceId);
      fetchData();
    } catch (err) {
      console.error('Isolate error:', err);
    }
  };

  // Keyboard navigation
  useEffect(() => {
    const handler = (e) => {
      if (e.key === 'Escape' && selectedDevice) {
        setSelectedDevice(null);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [selectedDevice]);

  return (
    <div className="flex h-screen bg-bg-primary">
      {/* Sidebar */}
      <Sidebar
        currentView={currentView}
        onNavigate={setCurrentView}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(c => !c)}
      />

      {/* Main content */}
      <div className={`flex-1 flex flex-col transition-all duration-200 ${sidebarCollapsed ? 'ml-14' : 'ml-52'}`}>
        <Header
          wsConnected={wsConnected}
          onRefresh={handleRefresh}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
        />

        <main className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Dashboard View */}
          {currentView === 'dashboard' && (
            <>
              <StatsCards stats={stats} loading={loading} />

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                <div className="lg:col-span-2">
                  <TrustScoreChart activities={activities} />
                </div>
                <StatusDistributionChart stats={stats} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                <div className="lg:col-span-2">
                  <DeviceTable
                    devices={devices}
                    loading={loading}
                    onSelectDevice={setSelectedDevice}
                    onIsolate={handleIsolate}
                    searchQuery={searchQuery}
                  />
                </div>
                <ActivityFeed activities={activities} loading={loading} limit={15} />
              </div>
            </>
          )}

          {/* Devices View */}
          {currentView === 'devices' && (
            <>
              <StatsCards stats={stats} loading={loading} />
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
                <div className="lg:col-span-3">
                  <DeviceTable
                    devices={devices}
                    loading={loading}
                    onSelectDevice={setSelectedDevice}
                    onIsolate={handleIsolate}
                    searchQuery={searchQuery}
                  />
                </div>
                <AnomalyDistributionChart devices={devices} />
              </div>
            </>
          )}

          {/* Activity View */}
          {currentView === 'activity' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <ActivityFeed activities={activities} loading={loading} limit={100} />
              <TrustScoreChart activities={activities} />
            </div>
          )}

          {/* Threats View */}
          {currentView === 'threats' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <ThreatFeed riskEvents={riskEvents} loading={loading} />
              <div className="space-y-5">
                <StatusDistributionChart stats={stats} />
                <AnomalyDistributionChart devices={devices} />
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Device Detail Modal */}
      {selectedDevice && (
        <DeviceDetailModal
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
        />
      )}
    </div>
  );
}
