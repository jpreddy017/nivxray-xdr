import React from 'react';
import {createRoot} from 'react-dom/client';
import {MemoryRouter} from 'react-router-dom';
import Page from '../../src/xdr/pages/XdrCommandIntelPage';
import {bindServerTenant} from '../../src/lib/tenant';
window.switchSyntheticTenant = () => bindServerTenant('synthetic-b', {switchable:true});
createRoot(document.getElementById('root')).render(<MemoryRouter><Page/></MemoryRouter>);
