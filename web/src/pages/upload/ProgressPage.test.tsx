import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getScan } from '../../api/client';
import { ProgressPage } from './ProgressPage';

vi.mock('../../api/client', () => ({ getScan: vi.fn() }));

const mockedGetScan = vi.mocked(getScan);

describe('ProgressPage', () => {
  beforeEach(() => mockedGetScan.mockReset());

  it('keeps malformed files isolated and shows coverage beside verdict counts', async () => {
    mockedGetScan.mockResolvedValue({
      scan_id: 'scan-1',
      status: 'completed',
      frameworks: ['cis'],
      created_at: '2026-10-07T00:00:00Z',
      progress: { total: 2, done: 1, error: 1 },
      devices: [
        {
          device_id: 'device-1',
          filename: 'edge.cfg',
          status: 'done',
          error: null,
          vendor_pack: 'cisco_ios@1.0.0',
          detection_ambiguous: false,
          identity: { hostname: 'edge-1', vendor: 'Cisco', os_family: 'IOS', os_version: null, model: null, serial: null },
          verdicts: { pass: 7, fail: 1, not_determined: 2 },
          coverage: { mapped: 30, defaulted: 5, unknown: 15, ratio: 0.7 },
        },
        {
          device_id: 'device-2',
          filename: 'broken.cfg',
          status: 'error',
          error: 'Unsupported binary input',
          vendor_pack: null,
          detection_ambiguous: false,
        },
      ],
    });

    render(<ProgressPage scanId="scan-1" onDevice={vi.fn()} />);

    expect(await screen.findByText('edge-1')).toBeInTheDocument();
    expect(screen.getByText('70%')).toBeInTheDocument();
    expect(screen.getByText('Unsupported binary input')).toBeInTheDocument();
    expect(screen.getByText('File errors').nextElementSibling).toHaveTextContent('1');
  });
});
