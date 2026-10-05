import { Box, CheckCircle2, Database, PackageOpen, XCircle } from 'lucide-react';
import { getPacks } from '../../api/client';
import { EmptyState, ErrorState, LoadingState } from '../../components/StateViews';
import { useAsync } from '../../hooks/useAsync';

export function PacksPage() {
  const state = useAsync(getPacks, []);
  if (state.loading) return <section className="page"><LoadingState label="Reading installed pack registry" /></section>;
  if (state.error) return <section className="page"><ErrorState message={state.error} retry={state.reload} /></section>;
  if (!state.data?.length) return <section className="page"><header className="page-header"><div><span className="eyebrow">Runtime registry</span><h1>Installed packs</h1></div></header><EmptyState title="No packs installed" detail="Add vendor, rule, or fix packs to the local packs directory." /></section>;
  return <section className="page"><header className="page-header"><div><span className="eyebrow">Runtime registry</span><h1>Installed packs</h1><p>Read-only view of declarative artifacts loaded by the local engine.</p></div><div className="security-pill"><Database size={15} />{state.data.length} loaded</div></header><div className="pack-grid">{state.data.map((pack) => <article className="pack-card" key={`${pack.kind}-${pack.id}-${pack.version}`}><div className="pack-icon">{pack.source === 'learned' ? <PackageOpen size={21} /> : <Box size={21} />}</div><div><span className="pack-kind">{pack.kind}</span><h2>{pack.id}</h2><code>{pack.version}</code><p>{pack.path}</p></div><div className="pack-state">{pack.valid ? <><CheckCircle2 size={15} />Valid</> : <><XCircle size={15} />Invalid</>}<small>{pack.source}</small></div>{pack.error && <p className="inline-error">{pack.error}</p>}</article>)}</div></section>;
}
