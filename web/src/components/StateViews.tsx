import { AlertTriangle, Inbox, LoaderCircle, RefreshCw } from 'lucide-react';

export function LoadingState({ label = 'Loading data' }: { label?: string }) {
  return <div className="state-card" role="status"><LoaderCircle className="spin" size={22} /><div><strong>{label}</strong><p>Reading from the local audit service.</p></div></div>;
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="state-card"><Inbox size={22} /><div><strong>{title}</strong><p>{detail}</p></div></div>;
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="state-card error" role="alert"><AlertTriangle size={22} /><div><strong>Could not load this view</strong><p>{message}</p>{retry && <button className="button secondary compact" onClick={retry}><RefreshCw size={14} />Retry</button>}</div></div>;
}
