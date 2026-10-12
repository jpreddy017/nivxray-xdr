import React from 'react';
import '../../src/styles/globals.css';
import '../../src/xdr/xdr-console.css';
import '../../src/xdr/nx/nx-epistemic.css';
import '../../src/xdr/nx/nx-tokens.css';
import '../../src/xdr/nx/nx-theme.css';
// Page + actual theme; full-console route/RBAC acceptance remains separate.
export default function Shell({children}) { return <div className="xdr-console" data-nx-theme="light" style={{display:'block'}}><main style={{padding:16}}>{children}</main></div>; }
