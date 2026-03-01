import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const WS_BASE = API_BASE.replace('http', 'ws');

const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

// JWT token management
let authToken = null;

export function setAuthToken(token) {
  authToken = token;
  if (token) {
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    delete api.defaults.headers.common['Authorization'];
  }
}

// API methods
export async function getHealth() {
  const { data } = await api.get('/health');
  return data;
}

export async function getDevices(params = {}) {
  const { data } = await api.get('/devices', { params });
  return data;
}

export async function getDeviceDetail(deviceId) {
  const { data } = await api.get(`/devices/${deviceId}`);
  return data;
}

export async function isolateDevice(deviceId) {
  const { data } = await api.post(`/devices/${deviceId}/isolate`);
  return data;
}

export async function getActivity(limit = 50) {
  const { data } = await api.get('/activity', { params: { limit } });
  return data;
}

export async function getRiskEvents(params = {}) {
  const { data } = await api.get('/risk-events', { params });
  return data;
}

export async function getStats() {
  const { data } = await api.get('/stats');
  return data;
}

export async function getFeatures() {
  const { data } = await api.get('/features');
  return data;
}

export async function analyzeNetwork(payload) {
  const { data } = await api.post('/analyze/network', payload);
  return data;
}

export async function analyzeEmail(payload) {
  const { data } = await api.post('/analyze/email', payload);
  return data;
}

export async function analyzeDevice(payload) {
  const { data } = await api.post('/analyze/device', payload);
  return data;
}

export async function login(username, password) {
  const { data } = await api.post('/auth/login', { username, password });
  return data;
}

// WebSocket connection
export function createWebSocket(onMessage, onOpen, onClose) {
  const ws = new WebSocket(`${WS_BASE}/ws`);

  ws.onopen = () => {
    console.log('[WS] Connected');
    if (onOpen) onOpen();
    // Start heartbeat
    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send('ping');
      } else {
        clearInterval(interval);
      }
    }, 30000);
    ws._heartbeat = interval;
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type !== 'pong' && onMessage) {
        onMessage(data);
      }
    } catch (e) {
      console.warn('[WS] Parse error:', e);
    }
  };

  ws.onclose = () => {
    console.log('[WS] Disconnected');
    if (ws._heartbeat) clearInterval(ws._heartbeat);
    if (onClose) onClose();
  };

  ws.onerror = (err) => {
    console.error('[WS] Error:', err);
  };

  return ws;
}

export default api;
