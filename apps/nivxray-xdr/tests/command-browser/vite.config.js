import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
const here=path.dirname(new URL(import.meta.url).pathname);
export default defineConfig({root:here,plugins:[react()],resolve:{alias:[
 {find:'@/xdr/XdrShell',replacement:path.join(here,'shell.jsx')},
 {find:'@',replacement:path.resolve(here,'../../src')},
]},define:{'process.env.REACT_APP_BACKEND_URL':JSON.stringify('http://127.0.0.1:8197')},server:{host:'127.0.0.1',port:3197,strictPort:true,fs:{allow:[path.resolve(here,'../..')]}}});
