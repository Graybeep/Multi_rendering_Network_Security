import { afterEach, describe, expect, it, vi } from 'vitest';
import { confirmCluster, createScan, getClusters, getPacks, ignoreCluster } from './client';

function reply(payload: unknown) {
  return Promise.resolve(new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } }));
}

afterEach(() => vi.unstubAllGlobals());

describe('OpenAPI client adapters', () => {
  it('uses the current multipart field names', async () => {
    const fetchMock = vi.fn(() => reply({ scan_id: 'scan-1' }));
    vi.stubGlobal('fetch', fetchMock);
    await createScan([new File(['hostname edge'], 'edge.cfg')], ['cis', 'nist']);

    const [, init] = (fetchMock.mock.calls as unknown as [RequestInfo | URL, RequestInit | undefined][])[0];
    const body = init?.body as FormData;
    expect(body.getAll('files')).toHaveLength(1);
    expect(body.getAll('frameworks')).toEqual(['cis', 'nist']);
    expect(body.has('framework')).toBe(false);
  });

  it('unwraps catalog and cluster envelopes', async () => {
    const fetchMock = vi.fn()
      .mockImplementationOnce(() => reply({ scan_id: 'scan-1', clusters: [{ cluster_id: 'c1' }] }))
      .mockImplementationOnce(() => reply({ packs: [{ id: 'junos' }] }));
    vi.stubGlobal('fetch', fetchMock);

    expect(await getClusters('scan-1')).toEqual([{ cluster_id: 'c1' }]);
    expect(await getPacks()).toEqual([{ id: 'junos' }]);
  });

  it('requests the backend dry-run before a mapping write', async () => {
    const fetchMock = vi.fn(() => reply({ written: false, fragment_yaml: 'id: learned', pack_path: 'packs/learned/junos.yaml', pack_version: '1.0.1', mapping_id: 'learned.1' }));
    vi.stubGlobal('fetch', fetchMock);
    await confirmCluster('cluster-1', { canonical_field: 'services.ssh.enabled', absent: 'unknown' }, true);

    const [url] = (fetchMock.mock.calls as unknown as [string, RequestInit | undefined][])[0];
    expect(url).toContain('/api/clusters/cluster-1/confirm?dry_run=true');
  });

  it('previews ignores and preserves the backend conflict message', async () => {
    const fetchMock = vi.fn()
      .mockImplementationOnce(() => reply({ written: false, fragment_yaml: 'ignore: true', pack_path: 'packs/learned/junos.yaml', pack_version: '1.0.1', mapping_id: 'ignored.1' }))
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify({ message: 'This line matches mapping junos.foo, which needs extending.' }), { status: 409, headers: { 'Content-Type': 'application/json' } })));
    vi.stubGlobal('fetch', fetchMock);

    await ignoreCluster('cluster-1', { reason: 'structural marker' }, true);
    expect(fetchMock.mock.calls[0][0]).toContain('/api/clusters/cluster-1/ignore?dry_run=true');
    await expect(ignoreCluster('cluster-1', { reason: 'structural marker' })).rejects.toMatchObject({ status: 409, message: 'This line matches mapping junos.foo, which needs extending.' });
  });
});
