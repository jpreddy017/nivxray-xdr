import React from 'react';

export default class PageErrorBoundary extends React.Component {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (!this.state.failed) return this.props.children;
    return <main role="alert" style={{fontFamily:'Inter, Segoe UI, system-ui, sans-serif',fontSize:13,lineHeight:1.5,padding:24,margin:'24px auto',maxWidth:640,color:'CanvasText',background:'Canvas',border:'1px solid GrayText',borderRadius:4}}>
      <h1 style={{fontSize:19,margin:'0 0 8px'}}>This page could not load</h1>
      <p>A connection problem or an updated application may have interrupted loading. Reload to try again. Your current page address is preserved.</p>
      <button onClick={() => window.location.reload()} style={{font:'inherit',padding:'7px 12px',cursor:'pointer'}}>Reload page</button>
    </main>;
  }
}
