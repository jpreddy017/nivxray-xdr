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

export default function ArtifactBrowser({categories, endpoint, capturedAt}) {
  const [selected, setSelected] = useState(categories[0]?.category_id);
  const [categoryQuery, setCategoryQuery] = useState('');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(100);
  const [sort, setSort] = useState({key: '', direction: 1});
  const [detail, setDetail] = useState(null);
  const category = categories.find(item => item.category_id === selected) || categories[0];
  const allRows = category?.rows || [];
  const columns = useMemo(() => evidenceColumns(allRows), [allRows]);
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
    <header className="artifact-heading"><div><h3>Forensic evidence · {endpoint || 'Endpoint'}</h3><p>Captured {date(capturedAt)} · {categories.length} categories</p></div>
      <div className="artifact-health"><span>{categories.reduce((sum, item) => sum + (item.row_count || 0), 0).toLocaleString()} records</span><span>{partial} partial</span><span>{unavailable} unavailable</span></div>
    </header>
    <div className="artifact-layout">
      <aside className="artifact-categories" aria-label="Snapshot categories">
        <label>Find category<input value={categoryQuery} onChange={event => setCategoryQuery(event.target.value)} placeholder="Processes, DNS, startup…"/></label>
        <div className="artifact-category-list">{categories.filter(item => item.name.toLowerCase().includes(categoryQuery.toLowerCase())).map(item => <button type="button" key={item.category_id} aria-label={`Inspect ${item.name}`} aria-pressed={category === item} onClick={() => select(item)} className="artifact-category">
          <span>{item.name}<small data-state={item.state}>{stateLabel(item.state)}</small></span><b>{(item.row_count || 0).toLocaleString()}</b>
        </button>)}</div>
      </aside>
      <div className="artifact-results">
        <div className="artifact-toolbar"><div><h4>{category?.name}</h4><p>{stateLabel(category?.state)} · {allRows.length.toLocaleString()} collected rows</p></div><button type="button" disabled={!rows.length} onClick={downloadCsv}>Export filtered CSV</button></div>
        <p className="snapshot-note">{date(category?.capture_started_at)} → {date(category?.capture_finished_at)}</p>
        {category?.detail && <p className="snapshot-alert">{category.detail}</p>}
        {category?.rows_truncated && <p className="snapshot-alert">The collection limit was reached. This category is incomplete.</p>}
        {category?.issues?.map((issue, index) => <p className="snapshot-alert" key={index}>{issue}</p>)}
        <div className="artifact-search"><label>Filter category evidence<input value={query} onChange={event => {setQuery(event.target.value); setPage(0); setDetail(null);}} placeholder="Search every collected field…"/></label>
          <label>Rows per page<select value={pageSize} onChange={event => {setPageSize(Number(event.target.value)); setPage(0);}}>{[25, 100, 250].map(size => <option key={size} value={size}>{size}</option>)}</select></label></div>
        <div className="artifact-pagination"><button type="button" aria-label="Previous category rows" disabled={!currentPage} onClick={() => setPage(currentPage - 1)}>Previous</button><span>Page {currentPage + 1} of {lastPage + 1} · {rows.length ? currentPage * pageSize + 1 : 0}–{Math.min((currentPage + 1) * pageSize, rows.length)} of {rows.length.toLocaleString()} matching records</span><button type="button" aria-label="Next category rows" disabled={currentPage >= lastPage} onClick={() => setPage(currentPage + 1)}>Next</button></div>
        <div className="artifact-grid"><table><thead><tr><th>Record</th>{columns.map(key => <th key={key} aria-sort={sort.key === key ? sort.direction === 1 ? 'ascending' : 'descending' : 'none'}><button type="button" onClick={() => {setSort({key, direction: sort.key === key ? -sort.direction : 1}); setPage(0);}}>{key}{sort.key === key ? sort.direction === 1 ? ' ↑' : ' ↓' : ''}</button></th>)}</tr></thead>
          <tbody>{visible.map((row, index) => <tr key={`${currentPage}-${index}`}><td><button type="button" aria-label={`Inspect record ${currentPage * pageSize + index + 1}`} onClick={() => setDetail(row)}>{currentPage * pageSize + index + 1}</button></td>{columns.map(key => <td key={key} title={text(row[key])}>{text(row[key]) || '—'}</td>)}</tr>)}</tbody></table></div>
        {!rows.length && <p className="artifact-empty">{allRows.length ? 'No records match this filter.' : category?.state === 'COLLECTED' ? 'The query completed and returned no records. This is not proof that the activity never occurred.' : 'No evidence is available. Review the collection status and details above.'}</p>}
        {detail && <section className="artifact-record" aria-label="Record details"><div className="artifact-toolbar"><h4>Complete record</h4><button type="button" onClick={() => setDetail(null)}>Close record</button></div><dl>{Object.entries(detail).map(([key, value]) => <React.Fragment key={key}><dt>{key}</dt><dd><pre>{text(value) || '—'}</pre></dd></React.Fragment>)}</dl></section>}
      </div>
    </div>
  </section>;
}
