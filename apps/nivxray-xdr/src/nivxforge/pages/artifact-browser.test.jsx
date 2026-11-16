// @vitest-environment jsdom
import React from 'react';
import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import {test,expect,afterEach} from 'vitest';
import ArtifactBrowser,{csvCell,evidenceColumns} from './ArtifactBrowser';
afterEach(cleanup);
const categories=[{category_id:'processes',name:'Processes',state:'PARTIAL',row_count:101,rows:Array.from({length:101},(_,i)=>({pid:i+1,name:`process-${i+1}`,...(i===100?{owner:'late-owner'}:{})}))},{category_id:'services',name:'Services',state:'UNAVAILABLE',rows:[],row_count:0,detail:'Access denied'}];
test('browser paginates actual evidence and retains fields occurring after row 100',()=>{
 render(<ArtifactBrowser categories={categories}/>);
 expect(screen.getByRole('button',{name:'owner'})).toBeTruthy();
 expect(screen.queryByText('late-owner')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Next category rows'}));
 expect(screen.getByText('late-owner')).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Inspect record 101'}));
 expect(screen.getByRole('region',{name:'Record details'})).toBeTruthy();
});
test('filter searches the whole category and switching categories clears previous evidence',()=>{
 render(<ArtifactBrowser categories={categories}/>);
 fireEvent.change(screen.getByLabelText('Filter category evidence'),{target:{value:'late-owner'}});
 expect(screen.getByText('late-owner')).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Inspect Services'}));
 expect(screen.getByText(/Access denied/)).toBeTruthy();expect(screen.queryByText('late-owner')).toBeNull();
});
test('numeric sorting changes row order',()=>{
 render(<ArtifactBrowser categories={[{...categories[0],rows:[{pid:10},{pid:2}],row_count:2}]}/>);
 fireEvent.click(screen.getByRole('button',{name:'pid'}));
 const cells=screen.getAllByRole('cell');expect(cells[0].textContent).toBe('2');expect(cells[1].textContent).toBe('10');
});
test('CSV export escapes quotes, newlines and spreadsheet formulas',()=>{
 expect(csvCell('=HYPERLINK("bad")')).toBe('"\'=HYPERLINK(""bad"")"');
 expect(csvCell('line1\nline2')).toBe('"line1\nline2"');expect(csvCell(0)).toBe('"0"');
 expect(evidenceColumns([{first:1},{later:2}])).toEqual(['first','later']);
});
