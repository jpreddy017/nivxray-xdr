// @vitest-environment jsdom
import React from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { FiltersPanel } from '../Filters';
import { DEFAULT_ON, FILTER_GROUPS, passes } from '../model';
afterEach(cleanup);
const row = (flags) => ({ev:{},kind:{filter:'other'},shape:'square',ftype:null,flags});
const selected = (...flags) => new Set(['d_unknown',...flags]);
test('audit-only is selectable and matches audit evidence', () => {
 expect(DEFAULT_ON).toContain('f_audit');
 expect(passes(row({audit:true}),selected('f_audit'))).toBe(true);
 expect(passes(row({audit:true}),selected('f_none'))).toBe(false);
});
test('flags use OR and no-flag excludes every flagged row', () => {
 for (const [flag,key] of [['warn','f_warning'],['cmd','f_cmd'],['audit','f_audit']]) {
  expect(passes(row({[flag]:true}),selected(key))).toBe(true);
  expect(passes(row({[flag]:true}),selected('f_none'))).toBe(false);
 }
 expect(passes(row({audit:true,cmd:true}),selected('f_cmd'))).toBe(true);
 expect(passes(row({}),selected('f_none'))).toBe(true);
 expect(passes(row({}),selected('f_audit'))).toBe(false);
});
test('All types selects dynamically available types and Apply commits them', () => {
 const dynamic=FILTER_GROUPS.flatMap(([,xs])=>xs).find(x=>x[2])[0];
 const apply=vi.fn();
 render(<FiltersPanel applied={new Set()} present={new Set([dynamic])} onApply={apply} onCancel={()=>{}}/>);
 fireEvent.click(screen.getByTestId('v3-filter-all-types'));
 expect(screen.getByTestId('v3-filter-'+dynamic).querySelector('input').checked).toBe(true);
 expect(apply).not.toHaveBeenCalled();
 fireEvent.click(screen.getByTestId('v3-filters-apply'));
 expect(apply.mock.calls[0][0].has(dynamic)).toBe(true);
});
test('cancel discards draft and preserves applied selection', () => {
 const applied=new Set(DEFAULT_ON), original=[...applied], apply=vi.fn(), cancel=vi.fn();
 render(<FiltersPanel applied={applied} onApply={apply} onCancel={cancel}/>);
 fireEvent.click(screen.getByTestId('v3-filter-all-types'));
 fireEvent.click(screen.getByTestId('v3-filters-cancel'));
 expect([...applied]).toEqual(original); expect(apply).not.toHaveBeenCalled(); expect(cancel).toHaveBeenCalledOnce();
});
