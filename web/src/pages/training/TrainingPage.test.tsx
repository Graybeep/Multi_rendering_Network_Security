import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { confirmCluster, getClusters, getSchemaFields, getSuggestions, ignoreCluster, reevaluate } from '../../api/client';
import { TrainingPage } from './TrainingPage';

vi.mock('../../api/client', () => ({
  confirmCluster: vi.fn(),
  getClusters: vi.fn(),
  getSchemaFields: vi.fn(),
  getSuggestions: vi.fn(),
  ignoreCluster: vi.fn(),
  reevaluate: vi.fn(),
}));

const mockedConfirm = vi.mocked(confirmCluster);
const mockedClusters = vi.mocked(getClusters);
const mockedFields = vi.mocked(getSchemaFields);
const mockedSuggestions = vi.mocked(getSuggestions);
const mockedIgnore = vi.mocked(ignoreCluster);

describe('TrainingPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedClusters.mockResolvedValue([{ cluster_id: 'cluster-1', vendor: 'cisco_ios', signature: 'ip helper-address <IPV4>', sample_line: 'ip helper-address 192.0.2.1', device_count: 12, occurrence_count: 18, scope: 'interface <IFACE>' }]);
    mockedFields.mockResolvedValue([{ path: 'interfaces[].dhcp_relay', type: 'string', enum: null, description: 'DHCP relay target', absent: 'unknown', collection: true }]);
    mockedSuggestions.mockResolvedValue({ cluster_id: 'cluster-1', candidates: [{ canonical_field: 'interfaces[].dhcp_relay', score: 0.91, tier: 'lexical', description: 'DHCP relay target' }] });
    mockedConfirm.mockResolvedValue({ written: false, pack_path: 'packs/learned/cisco_ios.yaml', pack_version: '1.0.1', mapping_id: 'learned.1', fragment_yaml: 'id: learned.1' });
    mockedIgnore.mockResolvedValue({ written: false, pack_path: 'packs/learned/cisco_ios.yaml', pack_version: '1.0.1', mapping_id: 'ignored.1', fragment_yaml: 'ignore: true' });
    vi.mocked(reevaluate).mockResolvedValue({ scan_id: 'scan-2' });
  });

  it('requires an exact backend preview before enabling the human-confirmed write', async () => {
    render(<TrainingPage scanId="scan-1" />);

    expect(await screen.findByText('12')).toBeInTheDocument();
    expect(await screen.findByText('None of these')).toBeInTheDocument();
    const confirm = screen.getByRole('button', { name: 'Confirm mapping' });
    expect(confirm).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Preview exact write' }));

    expect(await screen.findByText('id: learned.1')).toBeInTheDocument();
    expect(mockedConfirm).toHaveBeenCalledWith('cluster-1', expect.objectContaining({ canonical_field: 'interfaces[].dhcp_relay', absent: 'unknown' }), true);
    expect(confirm).toBeEnabled();

    fireEvent.click(confirm);
    await waitFor(() => expect(mockedConfirm).toHaveBeenLastCalledWith('cluster-1', expect.any(Object)));
  });

  it('never preselects ignore and requires its own exact preview before writing', async () => {
    render(<TrainingPage scanId="scan-1" />);

    const ignoreChoice = await screen.findByRole('button', { name: 'Not a security setting' });
    expect(screen.queryByRole('textbox', { name: /Reason/ })).not.toBeInTheDocument();
    fireEvent.click(ignoreChoice);

    const reason = screen.getByRole('textbox', { name: /Reason/ });
    expect(reason).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Preview ignore entry' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Confirm not a security setting' })).toBeDisabled();

    fireEvent.change(reason, { target: { value: 'structural marker' } });
    fireEvent.click(screen.getByRole('button', { name: 'Preview ignore entry' }));

    expect(await screen.findByText('ignore: true')).toBeInTheDocument();
    expect(mockedIgnore).toHaveBeenCalledWith('cluster-1', { reason: 'structural marker' }, true);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm not a security setting' }));
    await waitFor(() => expect(mockedIgnore).toHaveBeenLastCalledWith('cluster-1', { reason: 'structural marker' }));
  });

  it('requires an explicit matched value for a true/false field', async () => {
    mockedFields.mockResolvedValue([{ path: 'services.http.enabled', type: 'boolean', enum: null, description: 'HTTP service state', absent: 'default', collection: false }]);
    mockedSuggestions.mockResolvedValue({ cluster_id: 'cluster-1', candidates: [{ canonical_field: 'services.http.enabled', score: 0.8, tier: 'lexical', description: 'HTTP service state' }] });
    render(<TrainingPage scanId="scan-1" />);

    const preview = await screen.findByRole('button', { name: 'Preview exact write' });
    expect(preview).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Matched value — required for a true/false field'), { target: { value: 'true' } });
    expect(preview).toBeEnabled();
    fireEvent.click(preview);

    await waitFor(() => expect(mockedConfirm).toHaveBeenCalledWith('cluster-1', expect.objectContaining({ value: true }), true));
  });

  it('records the OS range with a verified scalar default', async () => {
    mockedFields.mockResolvedValue([{ path: 'session.idle_timeout', type: 'integer', enum: null, description: 'Idle timeout', absent: 'unknown', collection: false }]);
    mockedSuggestions.mockResolvedValue({ cluster_id: 'cluster-1', candidates: [{ canonical_field: 'session.idle_timeout', score: 0.8, tier: 'lexical', description: 'Idle timeout' }] });
    render(<TrainingPage scanId="scan-1" />);

    fireEvent.click(await screen.findByLabelText('Use a verified device default'));
    const preview = screen.getByRole('button', { name: 'Preview exact write' });
    expect(preview).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Verified default value'), { target: { value: '30' } });
    fireEvent.change(screen.getByLabelText('Default applies to OS versions'), { target: { value: '>=12.0' } });
    expect(preview).toBeEnabled();
    fireEvent.click(preview);

    await waitFor(() => expect(mockedConfirm).toHaveBeenCalledWith('cluster-1', expect.objectContaining({ default: 30, default_os_version: '>=12.0' }), true));
  });
});
