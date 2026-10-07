import type { components } from './schema';

export type Scan = components['schemas']['Scan'];
export type DeviceFindings = components['schemas']['DeviceFindings'];
export type Cluster = components['schemas']['Cluster'];
export type Suggestions = components['schemas']['Suggestions'];
export type ConfirmRequest = components['schemas']['ConfirmRequest'];
export type IgnoreRequest = components['schemas']['IgnoreRequest'];
export type ConfirmResult = components['schemas']['ConfirmResult'];
export type SchemaField = components['schemas']['SchemaField'];
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

export async function createScan(files: File[], frameworks: Framework[]): Promise<string> {
  const body = new FormData();
  files.forEach((file) => body.append('files', file));
  frameworks.forEach((framework) => body.append('frameworks', framework));
  const result = await request<components['schemas']['ScanCreated']>('/api/scans', { method: 'POST', body });
  return result.scan_id;
}

export const getScan = (scanId: string) => request<Scan>(`/api/scans/${encodeURIComponent(scanId)}`);
export const getDevice = (scanId: string, deviceId: string) => request<DeviceFindings>(`/api/scans/${encodeURIComponent(scanId)}/devices/${encodeURIComponent(deviceId)}`);
export const getClusters = async (scanId: string) => (await request<{ scan_id: string; clusters: Cluster[] }>(`/api/scans/${encodeURIComponent(scanId)}/clusters`)).clusters;
export const getSuggestions = (clusterId: string) => request<Suggestions>(`/api/clusters/${encodeURIComponent(clusterId)}/suggestions`);
export const getSchemaFields = async () => (await request<{ schema_version: string; fields: SchemaField[] }>('/api/schema/fields')).fields;
export const getPacks = async () => (await request<{ packs: Pack[] }>('/api/packs')).packs;
export const confirmCluster = (clusterId: string, body: ConfirmRequest, dryRun = false) => request<ConfirmResult>(`/api/clusters/${encodeURIComponent(clusterId)}/confirm${dryRun ? '?dry_run=true' : ''}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
export const ignoreCluster = (clusterId: string, body: IgnoreRequest, dryRun = false) => request<ConfirmResult>(`/api/clusters/${encodeURIComponent(clusterId)}/ignore${dryRun ? '?dry_run=true' : ''}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
export const reevaluate = (scanId: string) => request<components['schemas']['ScanCreated']>(`/api/scans/${encodeURIComponent(scanId)}/reevaluate`, { method: 'POST' });
export const reportUrl = (scanId: string, deviceId: string) => `${API_BASE}/api/scans/${encodeURIComponent(scanId)}/devices/${encodeURIComponent(deviceId)}/report`;
