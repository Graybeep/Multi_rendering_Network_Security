import type { components } from '../api/schema';

export function VerdictBadge({ verdict }: { verdict: components['schemas']['Verdict'] }) {
  return <span className={`verdict verdict-${verdict.toLowerCase()}`}>{verdict === 'NOT_DETERMINED' ? 'NOT DETERMINED' : verdict}</span>;
}
