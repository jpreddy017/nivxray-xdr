// @vitest-environment jsdom
import React, { lazy, Suspense } from 'react';
import { render, screen, cleanup } from '@testing-library/react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import PageErrorBoundary from './PageErrorBoundary';
afterEach(() => {cleanup();vi.restoreAllMocks();});
describe('Page loading recovery', () => {
  it('shows the recovery action when a deployed route chunk fails', async () => {
    vi.spyOn(console,'error').mockImplementation(() => {});
    const Broken = lazy(() => Promise.reject(new TypeError('Failed to fetch dynamically imported module')));
    render(<PageErrorBoundary><Suspense fallback={<p>Loading</p>}><Broken /></Suspense></PageErrorBoundary>);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByRole('button',{name:'Reload page'})).toBeTruthy();
    expect(screen.queryByText(/Failed to fetch dynamically/)).toBeNull();
  });
  it('does not replace a working page', () => {
    render(<PageErrorBoundary><h1>Computers</h1></PageErrorBoundary>);
    expect(screen.getByRole('heading',{name:'Computers'})).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
