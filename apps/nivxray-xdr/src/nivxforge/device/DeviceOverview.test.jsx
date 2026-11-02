import React from 'react';
import { render, screen, act, cleanup } from '@testing-library/react';
import { vi, beforeEach, afterEach, test, expect } from 'vitest';
import DeviceOverview from './DeviceOverview';
const api = vi.hoisted(() => ({ computer: vi.fn(), detections: vi.fn() }));
vi.mock('@/nivxforge/onboardingApi', () => ({ getComputer: api.computer }));
vi.mock('@/nivxforge/edrApi', () => ({ listEndpointDetections: api.detections }));
vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }));
vi.mock('@/nivxforge/components/LinkedXdrIncidents', () => ({ default: () => null }));
vi.mock('@/xdr/nx/apiError', () => ({ apiErrorText: (e) => e.message }));
vi.mock('@/nivxforge/components/OpsPrimitives', () => ({
  Ago: ({iso}) => <span>{iso}</span>, NA: () => <span>UNAVAILABLE</span>,
  Kpi: ({label,value,testid}) => <div data-testid={testid}>{label}: {value}</div>,
  OpsTable: () => null, Refusal: ({body}) => <div>{body}</div>,
  Skeleton: () => <div>Loading</div>, StateChip: ({token}) => <span>{token}</span>,
}));
const data = (id='a', count=0) => ({ computer: { endpoint_id:id, status:'CONNECTED', telemetry:{report_count:count} } });
const flush = () => act(async () => { await Promise.resolve(); });
beforeEach(() => { vi.useFakeTimers(); api.computer.mockReset().mockResolvedValue(data()); api.detections.mockReset().mockResolvedValue({detections:[]}); });
afterEach(() => { cleanup(); vi.useRealTimers(); });
test('refreshes status after 30 seconds and stops after unmount', async () => {
  const view=render(<DeviceOverview endpointId="a"/>); await flush();
  api.computer.mockResolvedValue({...data(),computer:{...data().computer,status:'STALE'}});
  await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});
  expect(screen.getByTestId('edr-device-kpi-status').textContent).toContain('STALE');
  expect(api.computer).toHaveBeenCalledTimes(2); view.unmount();
  await act(async()=>{await vi.advanceTimersByTimeAsync(60000);});
  expect(api.computer).toHaveBeenCalledTimes(2);
});
test('does not overlap a slow request', async () => {
  let resolve; api.computer.mockImplementationOnce(()=>new Promise(r=>{resolve=r;}));
  render(<DeviceOverview endpointId="a"/>);
  await act(async()=>{await vi.advanceTimersByTimeAsync(90000);});
  expect(api.computer).toHaveBeenCalledTimes(1);
  await act(async()=>{resolve(data());});
  await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});
  expect(api.computer).toHaveBeenCalledTimes(2);
});
test('retains snapshot and shows refresh failure then recovers', async () => {
  render(<DeviceOverview endpointId="a"/>); await flush();
  api.computer.mockRejectedValueOnce(new Error('offline'));
  await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});
  expect(screen.getByTestId('edr-device-refresh-state').textContent).toContain('previous snapshot');
  expect(screen.getByTestId('edr-device-kpi-status').textContent).toContain('CONNECTED');
  await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});
  expect(screen.getByTestId('edr-device-refresh-state').textContent).not.toContain('Refresh failed');
});
test('ignores late replies from previous endpoint', async () => {
  let resolve; api.computer.mockImplementationOnce(()=>new Promise(r=>{resolve=r;}));
  const view=render(<DeviceOverview endpointId="a"/>);
  api.computer.mockResolvedValue(data('b')); view.rerender(<DeviceOverview endpointId="b"/>); await flush();
  await act(async()=>{resolve(data('a'));});
  expect(screen.getByText('b')).toBeTruthy();
  expect(screen.queryByText('a')).toBeNull();
});
test('preserves unknown report count and distinguishes zero', async () => {
  api.computer.mockResolvedValue(data('a',null)); const view=render(<DeviceOverview endpointId="a"/>); await flush();
  expect(screen.getByTestId('edr-device-kpi-events').textContent).toContain('UNAVAILABLE');
  api.computer.mockResolvedValue(data('b',0)); view.rerender(<DeviceOverview endpointId="b"/>); await flush();
  expect(screen.getByTestId('edr-device-kpi-events').textContent).toBe('Telemetry reports: 0');
});
test('first-load failure retries and recovers', async () => {
  api.computer.mockRejectedValueOnce(new Error('offline')); render(<DeviceOverview endpointId="a"/>); await flush();
  expect(screen.getByText('offline')).toBeTruthy();
  await act(async()=>{await vi.advanceTimersByTimeAsync(30000);});
  expect(screen.getByTestId('edr-device-overview')).toBeTruthy();
});
