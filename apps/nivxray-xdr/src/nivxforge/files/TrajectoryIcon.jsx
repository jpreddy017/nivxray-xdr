import React from 'react';
const paths = {
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12 M9 12a3 3 0 1 0 6 0a3 3 0 1 0-6 0',
  entry: 'M14 3h7v18h-7 M3 12h13 M10 6l6 6-6 6',
  process: 'M3 3h6v6H3z M15 15h6v6h-6z M6 9v9h9',
  file: 'M5 2h9l5 5v15H5z M14 2v6h5 M8 12h8 M8 16h6',
  network: 'M9 2h6v6H9z M2 16h6v6H2z M16 16h6v6h-6z M12 8v4 M5 16v-4h14v4',
  timeline: 'M2 12h20 M6 8v8 M12 6v12 M18 8v8',
  history: 'M3 10a9 9 0 1 1 1 8 M3 3v7h7 M12 7v5l4 3',
  computer: 'M2 3h20v14H2z M8 21h8 M12 17v4',
  lock: 'M5 10h14v12H5z M8 10V6a4 4 0 0 1 8 0v4',
  trash: 'M3 6h18 M9 6V3h6v3 M5 6l1 16h12l1-16 M10 10v8 M14 10v8',
  play: 'M7 3l14 9-14 9z',
  move: 'M2 12h20 M17 7l5 5-5 5 M7 7l-5 5 5 5',
};
export default function TrajectoryIcon({ name }) {
  return <svg className="ft-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] || paths.file} /></svg>;
}
