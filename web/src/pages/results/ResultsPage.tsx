import { AlertTriangle, Check, Copy, Download, Network, ShieldAlert } from 'lucide-react';
import { useMemo, useState } from 'react';
import { getDevice, reportUrl, type DeviceFindings } from '../../api/client';
import { EmptyState, ErrorState, LoadingState } from '../../components/StateViews';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useAsync } from '../../hooks/useAsync';

type Finding = DeviceFindings['findings'][number];

export function ResultsPage({ scanId, deviceId }: { scanId: string; deviceId: string }) {
  const state = useAsync(() => getDevice(scanId, deviceId), [scanId, deviceId]);
  const [copied, setCopied] = useState<string | null>(null);
  const grouped = useMemo(() => {
    const groups = new Map<string, Finding[]>();
    state.data?.findings.forEach((finding) => groups.set(finding.severity, [...(groups.get(finding.severity) ?? []), finding]));
    return groups;
  }, [state.data]);

  if (state.loading) return <section className="page"><LoadingState label="Loading cited findings" /></section>;
  if (state.error) return <section className="page"><ErrorState message={state.error} retry={state.reload} /></section>;
  if (!state.data) return <section className="page"><EmptyState title="No result available" detail="This device may still be processing." /></section>;

  const result = state.data;
  const identity = result.identity;
  const coverage = result.coverage ? Math.round(result.coverage.ratio * 100) : null;
  const decided = result.findings.filter((finding) => finding.verdict !== 'NOT_DETERMINED');
  const pass = decided.filter((finding) => finding.verdict === 'PASS').length;
  const compliance = decided.length ? Math.round(pass / decided.length * 100) : null;
  const unknown = result.findings.filter((finding) => finding.verdict === 'NOT_DETERMINED').length;

  async function copy(id: string, commands: string[]) {
    await navigator.clipboard.writeText(commands.join('\n'));
    setCopied(id);
    window.setTimeout(() => setCopied(null), 1600);
  }

  return <section className="page">
    <header className="page-header"><div><span className="eyebrow">Device findings</span><h1>{identity?.hostname ?? result.filename}</h1><p>{[identity?.vendor, identity?.os_family, identity?.os_version, identity?.model].filter(Boolean).join(' · ') || 'Identification incomplete'}{result.vendor_pack ? ` · ${result.vendor_pack}` : ''}</p></div><a className="button secondary" href={reportUrl(scanId, deviceId)}><Download size={16} />Download PDF</a></header>
    <div className="score-grid"><Score label="Compliance" value={compliance === null ? '—' : `${compliance}%`} note={`${decided.length} determined controls · ${coverage === null ? 'coverage unavailable' : `${coverage}% coverage`}`} /><Score label="Canonical coverage" value={coverage === null ? '—' : `${coverage}%`} note={result.coverage ? `${result.coverage.mapped} mapped · ${result.coverage.defaulted} defaulted · ${result.coverage.unknown} unknown` : 'Coverage unavailable'} /><Score label="Not determined" value={unknown.toString()} note="Excluded from failure count" tone="unknown" /></div>
    {result.findings.length === 0 ? <EmptyState title="No findings returned" detail="The selected rule packs produced no controls for this device." /> : <div className="finding-groups">{['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
      const findings = grouped.get(severity);
      if (!findings?.length) return null;
      return <section key={severity} className="finding-section"><div className="section-title"><ShieldAlert size={17} /><h2>{severity} severity</h2><span>{findings.length}</span></div>{findings.map((finding) => <FindingCard key={`${finding.rule_pack_version}-${finding.rule_id}`} finding={finding} copied={copied === finding.rule_id} onCopy={() => copy(finding.rule_id, finding.remediation?.commands ?? [])} />)}</section>;
    })}</div>}
  </section>;
}

function FindingCard({ finding, copied, onCopy }: { finding: Finding; copied: boolean; onCopy: () => void }) {
  return <article className="finding-card"><div className="finding-head"><VerdictBadge verdict={finding.verdict} /><div><span className="rule-id">{finding.rule_id} · {finding.control ?? 'uncited control'} · {finding.rule_pack_version}</span><h3>{finding.title}</h3></div></div>
    {finding.verdict === 'NOT_DETERMINED' && <div className="unknown-explainer"><Network size={16} /><span>{finding.error ? `Evaluation could not complete: ${finding.error}` : `Required fields were not read: ${finding.missing_fields.join(', ') || 'unspecified canonical evidence'}.`}</span></div>}
    {finding.evidence.length > 0 && <div className="evidence-block"><span className="block-label">Cited evidence</span>{finding.evidence.map((evidence, index) => <div className="code-line" key={`${evidence.canonical_field}-${index}`}><span className="line-no">{evidence.line_no ?? (evidence.state === 'defaulted' ? 'default' : '—')}</span><code>{evidence.state === 'defaulted' ? `Not configured; pack default = ${formatValue(evidence.value)}` : evidence.text ?? `${evidence.canonical_field} (${evidence.state})`}</code><span className="provenance">{evidence.canonical_field} · {evidence.mapping_id ?? 'no mapping'} · {evidence.pack_version ?? 'pack unavailable'}</span></div>)}</div>}
    {finding.verdict === 'FAIL' && !finding.remediation && <div className="remediation-unavailable">No automated fix for this vendor or OS version.</div>}
    {finding.remediation && <div className="remediation"><div className="remediation-head"><span className="block-label">Remediation CLI · {finding.fix_pack_version ?? 'fix pack version unavailable'}</span><button className="text-button" onClick={onCopy}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? 'Copied' : finding.remediation.operator_input?.length ? 'Copy template' : 'Copy commands'}</button></div>{finding.remediation.operator_input && finding.remediation.operator_input.length > 0 && <div className="operator-warning"><AlertTriangle size={15} /><span>Replace before use: {finding.remediation.operator_input.join(', ')}</span></div>}{finding.remediation.note && <div className="operator-warning"><AlertTriangle size={15} /><span>{finding.remediation.note}</span></div>}<pre>{finding.remediation.commands.join('\n')}</pre>{finding.remediation.reload_required && <span className="reload-warning">Reload required</span>}{finding.remediation.rollback.length > 0 && <details className="rollback"><summary>Rollback commands</summary><pre>{finding.remediation.rollback.join('\n')}</pre></details>}</div>}
  </article>;
}

function formatValue(value: unknown) {
  if (typeof value === 'string') return value;
  if (value === undefined) return 'not supplied';
  return JSON.stringify(value);
}

function Score({ label, value, note, tone }: { label: string; value: string; note: string; tone?: string }) {
  return <div className={`score-card ${tone ?? ''}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></div>;
}
