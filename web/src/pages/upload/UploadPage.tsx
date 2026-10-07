import { useCallback, useRef, useState } from 'react';
import { FileArchive, FolderUp, ShieldCheck, UploadCloud, X } from 'lucide-react';
import { createScan, type Framework } from '../../api/client';

export function UploadPage({ onCreated }: { onCreated: (scanId: string) => void }) {
  const [files, setFiles] = useState<File[]>([]);
  const [framework, setFramework] = useState<Framework>('cis');
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const add = useCallback((incoming: FileList | null) => {
    if (!incoming) return;
    setFiles((current) => [...current, ...Array.from(incoming).filter((file) => !current.some((item) => item.name === file.name && item.size === file.size))]);
  }, []);
  async function submit() {
    if (!files.length) { setError('Select at least one configuration file or a zip archive.'); return; }
    setSubmitting(true); setError(null);
    try { onCreated(await createScan(files, [framework])); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Upload failed.'); }
    finally { setSubmitting(false); }
  }
  return <section className="page upload-page">
    <header className="page-header"><div><span className="eyebrow">New audit</span><h1>Inspect a configuration batch</h1><p>Configuration stays on this machine. Each device is isolated, so one malformed file will not stop the batch.</p></div><div className="security-pill"><ShieldCheck size={16} />127.0.0.1 only</div></header>
    <div className="upload-grid">
      <div className={`dropzone ${dragging ? 'active' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); add(event.dataTransfer.files); }}>
        <input ref={input} type="file" multiple hidden onChange={(event) => add(event.target.files)} />
        <UploadCloud size={32} /><h2>Drop configuration files here</h2><p>Individual text exports or a batch archive. Raw configuration content is never stored in the browser.</p><button className="button" onClick={() => input.current?.click()}><FolderUp size={17} />Choose files</button>
      </div>
      <aside className="panel upload-settings"><span className="panel-label">Audit framework</span><div className="segmented">{(['cis', 'nist', 'stig', 'iso'] as Framework[]).map((item) => <button key={item} className={framework === item ? 'active' : ''} onClick={() => setFramework(item)}>{item.toUpperCase()}</button>)}</div><div className="callout"><strong>No guessed verdicts</strong><p>Unmapped settings return NOT DETERMINED and become training tasks.</p></div></aside>
    </div>
    <div className="panel file-panel"><div className="panel-heading"><div><span className="panel-label">Batch queue</span><h2>{files.length ? `${files.length} file${files.length === 1 ? '' : 's'} ready` : 'No files selected'}</h2></div>{files.length > 0 && <button className="text-button" onClick={() => setFiles([])}>Clear queue</button>}</div>{files.length === 0 ? <p className="muted">Selected files appear here before anything is sent.</p> : <div className="file-list">{files.map((file) => <div className="file-row" key={`${file.name}-${file.size}`}><FileArchive size={17} /><span>{file.name}</span><small>{formatBytes(file.size)}</small><button aria-label={`Remove ${file.name}`} onClick={() => setFiles((current) => current.filter((item) => item !== file))}><X size={15} /></button></div>)}</div>}
      {error && <p className="inline-error" role="alert">{error}</p>}<div className="submit-row"><span className="muted">Framework: {framework.toUpperCase()}</span><button className="button" disabled={submitting} onClick={submit}>{submitting ? 'Starting audit…' : 'Start audit'}</button></div>
    </div>
  </section>;
}
function formatBytes(size: number) { return size < 1024 ? `${size} B` : `${(size / 1024).toFixed(1)} KB`; }
