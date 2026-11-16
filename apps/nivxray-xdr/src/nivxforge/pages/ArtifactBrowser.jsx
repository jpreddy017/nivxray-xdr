import React, {useMemo, useState} from 'react';
import './artifact-browser.css';

const text = value => value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
export function csvCell(value) {
  let cell = text(value);
  if (/^[\s]*[=+@-]/.test(cell)) cell = `'${cell}`;
  return `"${cell.replaceAll('"', '""')}"`;
}
export function evidenceColumns(rows) {
  return [...new Set(rows.flatMap(row => Object.keys(row)))];
}
const stateLabel = value => String(value || 'UNKNOWN').replaceAll('_', ' ');
const date = value => !value ? 'Not reported' : Number.isNaN(new Date(value).getTime()) ? 'Invalid timestamp' : new Date(value).toISOString();

export default function ArtifactBrowser({categories, endpoint, capturedAt, trajectoryUrl, onClose}) {
  const [selected, setSelected] = useState(categories.find(item=>['COLLECTED','PARTIAL'].includes(item.state))?.category_id || categories[0]?.category_id);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const pageSize = 100;
  const [showCollection, setShowCollection] = useState(false);
  const [sort, setSort] = useState({key: '', direction: 1});
  const [detail, setDetail] = useState(null);
  const category = categories.find(item => item.category_id === selected) || categories[0];
  const allRows = category?.rows || [];
  const columns = useMemo(() => (allRows.length ? evidenceColumns(allRows) : category?.fields || []), [allRows, category?.fields]);
  const rows = useMemo(() => {
    const matching = allRows.filter(row => text(row).toLowerCase().includes(query.toLowerCase()));
    if (!sort.key) return matching;
    return [...matching].sort((a, b) => text(a[sort.key]).localeCompare(text(b[sort.key]), undefined, {numeric: true}) * sort.direction);
  }, [allRows, query, sort]);
  const lastPage = Math.max(0, Math.ceil(rows.length / pageSize) - 1);
  const currentPage = Math.min(page, lastPage);
  const visible = rows.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const partial = categories.filter(item => item.state === 'PARTIAL').length;
  const unavailable = categories.filter(item => !['COLLECTED', 'PARTIAL', 'NOT_SELECTED'].includes(item.state)).length;

  function select(item) {
    setSelected(item.category_id); setQuery(''); setPage(0); setSort({key: '', direction: 1}); setDetail(null);
  }
  function downloadCsv() {
    const body = [columns.map(csvCell).join(','), ...rows.map(row => columns.map(key => csvCell(row[key])).join(','))].join('\r\n');
    const url = URL.createObjectURL(new Blob(['\uFEFF', body], {type: 'text/csv;charset=utf-8'}));
    const link = document.createElement('a'); link.href = url;
    link.download = `snapshot-${category.category_id}.csv`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return <section className="artifact-workspace" aria-label="Artifact category evidence">
    <header className="artifact-heading"><h3>NivXForge Forensic Snapshot — {endpoint || 'Endpoint'} <time>{date(capturedAt)}</time></h3>{onClose&&<button type="button" className="artifact-close" aria-label="Close snapshot" onClick={onClose}>×</button>}</header>
    <div className="artifact-layout">
      <aside className="artifact-categories" aria-label="Snapshot categories"><div className="artifact-category-list">{categories.map(item => <button type="button" key={item.category_id} aria-label={`Inspect ${item.name}`} aria-pressed={category === item} onClick={() => {select(item);setShowCollection(false);}} className="artifact-category" title={`${item.name} · ${stateLabel(item.state)}`}><span>{item.name}</span><b>{(item.row_count || 0).toLocaleString()}{!['COLLECTED','NOT_SELECTED'].includes(item.state)&&<i aria-label={stateLabel(item.state)}> !</i>}</b></button>)}</div></aside>
      <div className="artifact-results"><h4>{category?.name}</h4>
        <div className="artifact-pagination"><div className="artifact-pager"><button type="button" aria-label="Previous category rows" disabled={!currentPage} onClick={() => setPage(currentPage - 1)}>‹</button><span>{currentPage + 1}</span><span>of {lastPage + 1}</span><button type="button" aria-label="Next category rows" disabled={currentPage >= lastPage} onClick={() => setPage(currentPage + 1)}>›</button></div><span>{rows.length ? currentPage * pageSize + 1 : 0} – {Math.min((currentPage + 1) * pageSize, rows.length)} of {rows.length.toLocaleString()} records</span><input aria-label="Filter category evidence" value={query} onChange={event => {setQuery(event.target.value); setPage(0); setDetail(null);}} placeholder="Search"/></div>
        {category?.state!=='COLLECTED'&&<p className="artifact-warning">{stateLabel(category?.state)}{category?.detail ? ` — ${category.detail}` : ''}{category?.rows_truncated?' — Collection limit reached.':''}</p>}
        <div className="artifact-grid"><table><thead><tr>{columns.map(key => <th key={key} aria-sort={sort.key === key ? sort.direction === 1 ? 'ascending' : 'descending' : 'none'}><button type="button" onClick={() => {setSort({key, direction: sort.key === key ? -sort.direction : 1}); setPage(0);}}>{key}{sort.key === key ? sort.direction === 1 ? ' ↑' : ' ↓' : ''}</button></th>)}</tr></thead><tbody>{visible.map((row, index) => <tr key={`${currentPage}-${index}`} onDoubleClick={()=>setDetail(row)}>{columns.map((key,columnIndex) => <td key={key} title={text(row[key])}>{columnIndex===0?<button className="artifact-cell-button" type="button" aria-label={`Inspect record ${currentPage * pageSize + index + 1}`} onClick={()=>setDetail(row)}>{text(row[key]) || '—'}</button>:text(row[key]) || '—'}</td>)}</tr>)}</tbody></table></div>
        {!rows.length && <p className="artifact-empty">{allRows.length ? 'No records match this filter.' : category?.state === 'COLLECTED' ? 'The query completed and returned no records. This is not proof that the activity never occurred.' : 'No evidence is available. Review the collection status above.'}</p>}
        {detail && <section className="artifact-record" aria-label="Record details"><div className="artifact-toolbar"><h4>Complete record</h4><button type="button" onClick={() => setDetail(null)}>Close record</button></div><dl>{Object.entries(detail).map(([key, value]) => <React.Fragment key={key}><dt>{key}</dt><dd><pre>{text(value) || '—'}</pre></dd></React.Fragment>)}</dl></section>}
      </div>
    </div>
    <footer className="artifact-footer"><button type="button" className="artifact-provenance" onClick={()=>setShowCollection(!showCollection)} aria-expanded={showCollection}>Collection details</button><div>{trajectoryUrl&&<a href={trajectoryUrl}>Device Trajectory</a>}<button type="button" disabled={!rows.length} onClick={downloadCsv}>Export to CSV</button></div></footer>
    {showCollection&&<section className="artifact-collection" aria-label="Collection details"><p>{categories.length} categories · {categories.reduce((sum,item)=>sum+(item.row_count||0),0).toLocaleString()} records · {partial} partial · {unavailable} unavailable</p><p>{date(category?.capture_started_at)} → {date(category?.capture_finished_at)}</p><p>{category?.detail}</p><p>{category?.description}</p>{category?.issues?.map((issue,index)=><p key={index}>{issue}</p>)}</section>}
  </section>;
}
