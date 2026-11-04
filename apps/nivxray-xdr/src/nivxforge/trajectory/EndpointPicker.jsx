import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { getComputers } from '@/nivxforge/onboardingApi';
import { TENANT_BOUND_EVENT } from '@/lib/tenant';

export default function EndpointPicker({ onSelect }) {
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState({ loading: true, computers: [], error: '' });
  const generation = useRef(0);
  useEffect(() => {
    const changed = () => {
      generation.current += 1;
      setState({ loading: true, computers: [], error: '' });
      setAttempt((n) => n + 1);
    };
    window.addEventListener(TENANT_BOUND_EVENT, changed);
    return () => window.removeEventListener(TENANT_BOUND_EVENT, changed);
  }, []);
  useEffect(() => {
    let live = true;
    const ticket = ++generation.current;
    setState({ loading: true, computers: [], error: '' });
    getComputers().then((data) => {
      if (!live || ticket !== generation.current) return;
      if (!Array.isArray(data?.computers)) throw new Error('Invalid computer directory response');
      setState({ loading: false, error: '', computers: data.computers.filter((c) => c.endpoint_id) });
    }).catch((e) => {
      if (!live || ticket !== generation.current) return;
      setState({ loading: false, computers: [], error: e.response?.status === 403
        ? 'You are not authorized to read this customer’s computer directory.'
        : 'The computer directory could not be loaded. Retry or open a device from Computers.' });
    });
    return () => { live = false; };
  }, [attempt]);
  return <section aria-label="Choose trajectory computer" style={{ padding: 16, border: '1px solid var(--line)', background: 'var(--panel)', color: 'var(--text)' }}>
    <h2>Device Trajectory</h2><p>Select a computer to investigate its recorded activity.</p>
    {state.loading ? <p role="status">Loading computers…</p> : state.error ? <p role="alert">{state.error}</p>
      : state.computers.length ? <label>Computer <select aria-label="Trajectory computer" defaultValue="" onChange={(e) => { if (e.target.value) onSelect(e.target.value); }}>
        <option value="" disabled>Select a computer</option>{state.computers.map((c) => <option key={c.endpoint_id} value={c.endpoint_id}>{c.hostname || c.endpoint_id}</option>)}
      </select></label> : <p role="status">No computers were returned for the selected customer. This does not prove there is no historical telemetry.</p>}
    <p><button type="button" disabled={state.loading} onClick={() => setAttempt((n) => n + 1)}>Refresh computers</button> · <Link to="/edr/computers">Open Computers</Link></p>
  </section>;
}
