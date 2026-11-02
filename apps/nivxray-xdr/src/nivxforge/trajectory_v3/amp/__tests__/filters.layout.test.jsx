// @vitest-environment jsdom
// Grouped filter layout: partial state, collapse, counts, reset.
// The selection contract itself is pinned by filters.contract.test.jsx.
import React from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { FiltersPanel } from '../Filters';
import { DEFAULT_ON, FILTER_GROUPS } from '../model';

afterEach(cleanup);

const groupId = (g) => g.split(' ')[1].replace(/[^A-Za-z]/g, '');
const FIRST = FILTER_GROUPS[0];
const box = (tid) => screen.getByTestId(tid).querySelector('input') || screen.getByTestId(tid);

test('a part-selected group reads as indeterminate, not as unselected', () => {
  const [g, items] = FIRST;
  const keys = items.filter((x) => !x[2]).map((x) => x[0]);
  expect(keys.length).toBeGreaterThan(1);
  render(<FiltersPanel applied={new Set([keys[0]])} onApply={() => {}} onCancel={() => {}} />);
  const head = screen.getByTestId(`v3-filter-group-${groupId(g)}`);
  expect(head.checked).toBe(false);
  expect(head.indeterminate).toBe(true);          // the point: "some", not "none"
  fireEvent.click(head);
  expect(screen.getByTestId(`v3-filter-group-${groupId(g)}`).checked).toBe(true);
});

test('All types is indeterminate while only one group is on', () => {
  const keys = FIRST[1].filter((x) => !x[2]).map((x) => x[0]);
  render(<FiltersPanel applied={new Set(keys)} onApply={() => {}} onCancel={() => {}} />);
  const all = screen.getByTestId('v3-filter-all-types');
  expect(all.checked).toBe(false);
  expect(all.indeterminate).toBe(true);
});

test('each group reports how many of its available types are selected', () => {
  const [g, items] = FIRST;
  const keys = items.filter((x) => !x[2]).map((x) => x[0]);
  render(<FiltersPanel applied={new Set([keys[0]])} onApply={() => {}} onCancel={() => {}} />);
  expect(screen.getByTestId(`v3-filter-count-${groupId(g)}`).textContent).toBe(`1/${keys.length}`);
});

test('collapsing a group hides it without changing the selection', () => {
  const [g, items] = FIRST;
  const key = items.filter((x) => !x[2])[0][0];
  const apply = vi.fn();
  render(<FiltersPanel applied={new Set(DEFAULT_ON)} onApply={apply} onCancel={() => {}} />);
  fireEvent.click(screen.getByTestId(`v3-filter-toggle-${groupId(g)}`));
  expect(screen.getByTestId(`v3-filter-${key}`)).toBeTruthy();   // still in the DOM
  fireEvent.click(screen.getByTestId('v3-filters-apply'));
  expect(apply.mock.calls[0][0].has(key)).toBe(true);            // still selected
});

test('reset restores the default selection', () => {
  render(<FiltersPanel applied={new Set()} onApply={() => {}} onCancel={() => {}} />);
  fireEvent.click(screen.getByTestId('v3-filters-reset'));
  for (const k of DEFAULT_ON) expect(box(`v3-filter-${k}`).checked).toBe(true);
});

test('clearing everything warns that the grid will be empty', () => {
  render(<FiltersPanel applied={new Set(DEFAULT_ON)} onApply={() => {}} onCancel={() => {}} />);
  expect(screen.queryByTestId('v3-filters-none-warning')).toBeNull();
  fireEvent.click(screen.getByTestId('v3-filter-all-types'));   // on -> off
  expect(screen.getByTestId('v3-filters-none-warning')).toBeTruthy();
});

test('a type this device never produced stays inert and uncheckable', () => {
  const dyn = FILTER_GROUPS.flatMap(([, xs]) => xs).find((x) => x[2])[0];
  render(<FiltersPanel applied={new Set()} present={new Set()} onApply={() => {}} onCancel={() => {}} />);
  const input = box(`v3-filter-${dyn}`);
  expect(input.disabled).toBe(true);
  expect(screen.getByTestId(`v3-filter-${dyn}`).textContent).toContain('not collected');
});
