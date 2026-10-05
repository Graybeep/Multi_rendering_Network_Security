import { Check, Copy, Download, Network, ShieldAlert } from 'lucide-react';
import { useMemo, useState } from 'react';
import { getDevice, reportUrl } from '../../api/client';
import { EmptyState, ErrorState, LoadingState } from '../../components/StateViews';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useAsync } from '../../hooks/useAsync';

export function ResultsPage({ scanId, deviceId }: { scanId: string; deviceId: string }) {
  const state = useAsync(() => getDevice(scanId, deviceId), [scanId, deviceId]);
  const [copied, setCopied] = useState<string | null>(null);
  const grouped = useMemo(() => {
    const groups = new Map<string, NonNullable<typeof state.data>['findings']>();
    state.data?.findings.forEach((finding) => groups.set(finding.severity, [...(groups.get(finding.severity) ?? []), finding]));
    return groups;
  }, [state.data]);
  if (state.loading) return <section className="page"><LoadingState label="Loading cited findings" /></section>;
  if (state.error) return <section className="page"><ErrorState message={state.error} retry={state.reload} /></section>;
  if (!state.data) return <section className="page"><EmptyState title="No result available" detail="This device may still be processing." /></section>;
  const result = state.data; const mapped = result.coverage.lines_mapped; const total = result.coverage.lines_total; const coverage = total ? Math.round(mapped / total * 100) : 0; const decided = result.findings.filter((f) => f.verdict !== 'NOT_DETERMINED'); const pass = decided.filter((f) => f.verdict === 'PASS').length; const compliance = decided.length ? Math.round(pass / decided.length * 100) : null;
  async function copy(id: string, commands: string[]) { await navigator.clipboard.writeText(commands.join('\n')); setCopied(id); window.setTimeout(() => setCopied(null), 1600); }
  return <section className="page"><header className="page-header"><div><span className="eyebrow">Device findings</span><h1>{result.identification.hostname ?? result.filename}</h1><p>{[result.identification.vendor, result.identification.os_version, result.identification.model].filter(Boolean).join(' · ') || 'Identification incomplete'}</p></div><a className="button secondary" href={reportUrl(scanId, deviceId)}><Download size={16} />Download PDF</a></header>
    <div className="score-grid"><Score label="Compliance" value={compliance === null ? '—' : `${compliance}%`} note={`${decided.length} determined controls`} /><Score label="Mapped coverage" value={`${coverage}%`} note={`${mapped} of ${total} config lines`} /><Score label="Not determined" value={result.findings.filter((f) => f.verdict === 'NOT_DETERMINED').length.toString()} note="Excluded from failure count" tone="unknown" /></div>
    {result.findings.length === 0 ? <EmptyState title="No findings returned" detail="The selected rule pack produced no controls for this device." /> : <div className="finding-groups">{['critical', 'high', 'medium', 'low', 'info'].map((severity) => { const findings = grouped.get(severity); if (!findings?.length) return null; return <section key={severity} className="finding-section"><div className="section-title"><ShieldAlert size={17} /><h2>{severity} severity</h2><span>{findings.length}</span></div>{findings.map((finding) => <article className="finding-card" key={finding.rule_id}><div className="finding-head"><VerdictBadge verdict={finding.verdict} /><div><span className="rule-id">{finding.rule_id}</span><h3>{finding.title}</h3></div></div>{finding.verdict === 'NOT_DETERMINED' && <div className="unknown-explainer"><Network size={16} /><span>This control was not evaluated because {finding.reason?.fields.join(', ') || 'required evidence'} could not be mapped.</span></div>}
      {finding.evidence.length > 0 && <div className="evidence-block"><span className="block-label">Cited evidence</span>{finding.evidence.map((evidence, index) => <div className="code-line" key={`${evidence.canonical_field}-${index}`}><span className="line-no">{evidence.line ?? 'default'}</span><code>{evidence.text ?? `${evidence.canonical_field} (${evidence.state})`}</code><span className="provenance">{evidence.mapping_id} · {evidence.pack_version}</span></div>)}</div>}
      {finding.remediation && <div className="remediation"><div className="remediation-head"><span className="block-label">Remediation CLI</span><button className="text-button" onClick={() => copy(finding.rule_id, finding.remediation!.commands)}>{copied === finding.rule_id ? <Check size={14} /> : <Copy size={14} />}{copied === finding.rule_id ? 'Copied' : 'Copy commands'}</button></div><pre>{finding.remediation.commands.join('\n')}</pre>{finding.remediation.reload_required && <span className="reload-warning">Reload required</span>}</div>}</article>)}</section>; })}</div>}
  </section>;
}
function Score({ label, value, note, tone }: { label: string; value: string; note: string; tone?: string }) { return <div className={`score-card ${tone ?? ''}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></div>; }
