import { Activity, Boxes, FileSearch, GraduationCap, Menu, Radar, Upload, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { PacksPage } from './pages/packs/PacksPage';
import { ResultsPage } from './pages/results/ResultsPage';
import { TrainingPage } from './pages/training/TrainingPage';
import { ProgressPage } from './pages/upload/ProgressPage';
import { UploadPage } from './pages/upload/UploadPage';

type Route = { page: 'upload' } | { page: 'progress'; scanId: string } | { page: 'results'; scanId: string; deviceId: string } | { page: 'training'; scanId?: string } | { page: 'packs' };

function parseHash(): Route {
  const parts = window.location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  if (parts[0] === 'scan' && parts[1] && parts[2] === 'device' && parts[3]) return { page: 'results', scanId: parts[1], deviceId: parts[3] };
  if (parts[0] === 'scan' && parts[1]) return { page: 'progress', scanId: parts[1] };
  if (parts[0] === 'training') return { page: 'training', scanId: parts[1] };
  if (parts[0] === 'packs') return { page: 'packs' };
  return { page: 'upload' };
}

export default function App() {
  const [route, setRoute] = useState<Route>(parseHash);
  const [menu, setMenu] = useState(false);
  const [trainingScan, setTrainingScan] = useState(() => window.localStorage.getItem('last_scan_id') ?? '');
  useEffect(() => { const update = () => { setRoute(parseHash()); setMenu(false); }; window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update); }, []);
  function navigate(hash: string) { window.location.hash = hash; }
  function rememberScan(scanId: string) { window.localStorage.setItem('last_scan_id', scanId); setTrainingScan(scanId); }
  return <div className="app-shell"><aside className={`sidebar ${menu ? 'open' : ''}`}><div className="brand"><div className="brand-mark"><Radar size={23} /></div><div className="brand-name"><strong>Multi_rendering_Network_Security</strong><span>Audit Console</span></div><button className="mobile-close" onClick={() => setMenu(false)}><X size={20} /></button></div><nav aria-label="Primary navigation"><NavButton active={route.page === 'upload'} icon={<Upload size={18} />} label="New audit" onClick={() => navigate('upload')} /><NavButton active={route.page === 'progress' || route.page === 'results'} icon={<Activity size={18} />} label="Scan activity" disabled={!trainingScan} onClick={() => navigate(`scan/${trainingScan}`)} /><NavButton active={route.page === 'training'} icon={<GraduationCap size={18} />} label="Mapping trainer" onClick={() => navigate(`training/${trainingScan}`)} /><NavButton active={route.page === 'packs'} icon={<Boxes size={18} />} label="Pack registry" onClick={() => navigate('packs')} /></nav><div className="sidebar-foot"><span className="connection"><i />Local service</span><small>Deterministic audit path</small></div></aside><main><div className="mobile-bar"><button onClick={() => setMenu(true)} aria-label="Open navigation"><Menu size={21} /></button><div><Radar size={19} /><strong>Multi_rendering_Network_Security</strong></div><span /></div>
    {route.page === 'upload' && <UploadPage onCreated={(scanId) => { rememberScan(scanId); navigate(`scan/${scanId}`); }} />}
    {route.page === 'progress' && <ProgressPage scanId={route.scanId} onDevice={(scanId, deviceId) => { rememberScan(scanId); navigate(`scan/${scanId}/device/${deviceId}`); }} />}
    {route.page === 'results' && <ResultsPage scanId={route.scanId} deviceId={route.deviceId} />}
    {route.page === 'training' && (route.scanId ? <TrainingPage scanId={route.scanId} /> : <ScanPrompt value={trainingScan} onChange={setTrainingScan} onOpen={(scanId) => { rememberScan(scanId); navigate(`training/${scanId}`); }} />)}
    {route.page === 'packs' && <PacksPage />}
  </main></div>;
}
function NavButton({ active, icon, label, onClick, disabled }: { active: boolean; icon: React.ReactNode; label: string; onClick: () => void; disabled?: boolean }) { return <button className={active ? 'active' : ''} onClick={onClick} disabled={disabled}>{icon}<span>{label}</span></button>; }
function ScanPrompt({ value, onChange, onOpen }: { value: string; onChange: (value: string) => void; onOpen: (value: string) => void }) { return <section className="page"><header className="page-header"><div><span className="eyebrow">Mapping trainer</span><h1>Open a scan’s learning queue</h1><p>Enter the scan identifier returned after a batch upload.</p></div></header><div className="panel scan-prompt"><FileSearch size={25} /><label className="field"><span>Scan ID</span><input value={value} onChange={(event) => onChange(event.target.value)} placeholder="scn_…" /></label><button className="button" disabled={!value} onClick={() => onOpen(value)}>Open queue</button></div></section>; }
