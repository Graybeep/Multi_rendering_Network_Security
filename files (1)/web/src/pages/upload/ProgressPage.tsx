import { AlertCircle, CheckCircle2, Clock3, Server } from 'lucide-react';
import { useEffect } from 'react';
import { getScan } from '../../api/client';
import { EmptyState, ErrorState, LoadingState } from '../../components/StateViews';
import { useAsync } from '../../hooks/useAsync';

export function ProgressPage({ scanId, onDevice }: { scanId: string; onDevice: (scanId: string, deviceId: string) => void }) {
  const state = useAsync(() => getScan(scanId), [scanId]);
  useEffect(() => { if (!state.data || !['queued', 'running'].includes(state.data.status)) return; const timer = window.setInterval(state.reload, 1500); return () => window.clearInterval(timer); }, [state.data?.status, state.reload]);
  if (state.loading && !state.data) return <section className="page"><LoadingState label="Preparing device jobs" /></section>;
  if (state.error) return <section className="page"><ErrorState message={state.error} retry={state.reload} /></section>;
  if (!state.data) return <section className="page"><EmptyState title="Scan not found" detail="Start a new audit to create a scan." /></section>;
  const scan = state.data; const completed = scan.progress.done + scan.progress.failed; const percent = scan.progress.total ? Math.round(completed / scan.progress.total * 100) : 0;
  return <section className="page"><header className="page-header"><div><span className="eyebrow">Scan {scan.scan_id}</span><h1>{scan.status === 'completed' ? 'Batch processing complete' : 'Processing device configurations'}</h1><p>Results stream in as each device finishes; failed files remain isolated.</p></div><span className={`status-dot ${scan.status}`}>{scan.status}</span></header>
    <div className="progress-panel"><div className="progress-copy"><strong>{completed} of {scan.progress.total} processed</strong><span>{percent}%</span></div><div className="progress-track"><span style={{ width: `${percent}%` }} /></div><div className="metric-row"><Metric label="Complete" value={scan.progress.done} icon={<CheckCircle2 size={17} />} /><Metric label="Failed" value={scan.progress.failed} icon={<AlertCircle size={17} />} /><Metric label="Remaining" value={Math.max(0, scan.progress.total - completed)} icon={<Clock3 size={17} />} /></div></div>
    {scan.devices.length === 0 ? <EmptyState title="No device jobs yet" detail="The local service has accepted the scan but has not queued a device." /> : <div className="table-wrap"><table><thead><tr><th>Device</th><th>Vendor</th><th>Status</th><th className="num">Pass</th><th className="num">Fail</th><th className="num">Not determined</th><th></th></tr></thead><tbody>{scan.devices.map((device) => <tr key={device.device_id} className={device.status === 'failed' ? 'failed-row' : ''}><td><div className="device-cell"><Server size={16} /><div><strong>{device.hostname ?? device.filename}</strong><small>{device.filename}</small></div></div></td><td>{device.vendor ?? 'Detecting…'}</td><td><span className={`status-dot ${device.status}`}>{device.status}</span>{device.error && <small className="error-detail">{device.error.message}</small>}</td><td className="num pass-text">{device.counts.pass}</td><td className="num fail-text">{device.counts.fail}</td><td className="num unknown-text">{device.counts.not_determined}</td><td>{device.status === 'completed' && <button className="text-button" onClick={() => onDevice(scan.scan_id, device.device_id)}>View findings →</button>}</td></tr>)}</tbody></table></div>}
  </section>;
}
function Metric({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) { return <div className="metric">{icon}<span><small>{label}</small><strong>{value}</strong></span></div>; }
