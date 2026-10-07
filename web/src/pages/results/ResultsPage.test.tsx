import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getDevice } from '../../api/client';
import { ResultsPage } from './ResultsPage';

vi.mock('../../api/client', () => ({
  getDevice: vi.fn(),
  reportUrl: (scanId: string, deviceId: string) => `/api/scans/${scanId}/devices/${deviceId}/report`,
}));

const mockedGetDevice = vi.mocked(getDevice);

describe('ResultsPage', () => {
  beforeEach(() => mockedGetDevice.mockReset());

  it('separates unknown verdicts from failures and cites evidence provenance', async () => {
    mockedGetDevice.mockResolvedValue({
      device_id: 'device-1',
      filename: 'edge.cfg',
      status: 'done',
      error: null,
      vendor_pack: 'cisco_ios@1.2.0',
      detection_ambiguous: false,
      identity: { hostname: 'edge-1', vendor: 'Cisco', os_family: 'IOS', os_version: '15.9', model: null, serial: null },
      verdicts: { pass: 0, fail: 1, not_determined: 1 },
      coverage: { mapped: 2, defaulted: 0, unknown: 2, ratio: 0.5 },
      findings: [
        {
          rule_id: 'CIS-1', title: 'Disable Telnet', control: '1.1', framework: 'cis', severity: 'high', verdict: 'FAIL', rule_pack_version: 'cis@1.0.0', missing_fields: [], error: null, fix_pack_version: null, remediation: null,
          evidence: [{ canonical_field: 'services.telnet.enabled', state: 'mapped', value: true, line_no: 42, text: 'transport input telnet', mapping_id: 'ios.telnet', pack_version: 'cisco_ios@1.2.0' }],
        },
        {
          rule_id: 'CIS-2', title: 'Configure NTP', control: null, framework: 'cis', severity: 'medium', verdict: 'NOT_DETERMINED', rule_pack_version: 'cis@1.0.0', evidence: [], missing_fields: ['services.ntp.servers[]'], error: null, fix_pack_version: null, remediation: null,
        },
      ],
    });

    render(<ResultsPage scanId="scan-1" deviceId="device-1" />);

    expect(await screen.findByText('edge-1')).toBeInTheDocument();
    expect(screen.getByText('50%')).toBeInTheDocument();
    expect(screen.getByText('transport input telnet')).toBeInTheDocument();
    expect(screen.getByText(/ios\.telnet · cisco_ios@1\.2\.0/)).toBeInTheDocument();
    expect(screen.getByText(/Required fields were not read: services\.ntp\.servers\[\]/)).toBeInTheDocument();
    expect(screen.getByText('Excluded from failure count')).toBeInTheDocument();
  });
});
