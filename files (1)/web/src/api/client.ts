import type { components } from './schema';

export type Scan = components['schemas']['Scan'];
export type DeviceResult = components['schemas']['DeviceResult'];
export type Cluster = components['schemas']['Cluster'];
export type SuggestionList = components['schemas']['SuggestionList'];
export type ConfirmRequest = components['schemas']['ConfirmRequest'];
export type Pack = components['schemas']['Pack'];
export type Framework = components['schemas']['Framework'];

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? 'http://127.0.0.1:8001';

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) { super(message); }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { message?: string } | null;
    throw new ApiError(payload?.message ?? `Request failed (${response.status})`, response.status);
  }
  return response.json() as Promise<T>;
}

export async function createScan(files: File[], framework: Framework): Promise<string> {
  const body = new FormData();
  files.forEach((file) => body.append('files', file));
  body.append('framework', framework);
  const result = await request<components['schemas']['ScanCreated']>('/api/scans', { method: 'POST', body });
  return result.scan_id;
}

export const getScan = (scanId: string) => request<Scan>(`/api/scans/${encodeURIComponent(scanId)}`);
export const getDevice = (scanId: string, deviceId: string) => request<DeviceResult>(`/api/scans/${encodeURIComponent(scanId)}/devices/${encodeURIComponent(deviceId)}`);
export const getClusters = (scanId: string) => request<Cluster[]>(`/api/scans/${encodeURIComponent(scanId)}/clusters`);
export const getSuggestions = (clusterId: string) => request<SuggestionList>(`/api/clusters/${encodeURIComponent(clusterId)}/suggestions`);
export const getPacks = () => request<Pack[]>('/api/packs');
export const confirmCluster = (clusterId: string, body: ConfirmRequest) => request<components['schemas']['ConfirmResult']>(`/api/clusters/${encodeURIComponent(clusterId)}/confirm`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
export const reevaluate = (scanId: string) => request<components['schemas']['ScanCreated']>(`/api/scans/${encodeURIComponent(scanId)}/reevaluate`, { method: 'POST' });
export const reportUrl = (scanId: string, deviceId: string) => `${API_BASE}/api/scans/${encodeURIComponent(scanId)}/devices/${encodeURIComponent(deviceId)}/report`;
