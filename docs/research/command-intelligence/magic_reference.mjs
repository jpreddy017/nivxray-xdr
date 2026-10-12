// Research only: unchanged upstream Magic selection/ranking and codec classes.
// Restricted registry avoids loading unrelated broken npm distribution modules.
import path from 'node:path';
import {pathToFileURL} from 'node:url';
if (!process.env.CYBERCHEF_ROOT) throw new Error('Set CYBERCHEF_ROOT to a scratch extraction of cyberchef 11.5.0');
const root=pathToFileURL(path.resolve(process.env.CYBERCHEF_ROOT)+'/');
const load=async p=>(await import(new URL(p,root))).default;
const [Magic,Dish,FromBase64,FromHex,Gunzip,ZlibInflate,DecodeText,URLDecode]=await Promise.all([
 'src/core/lib/Magic.mjs','src/core/Dish.mjs',
 ...['FromBase64','FromHex','Gunzip','ZlibInflate','DecodeText','URLDecode'].map(n=>'src/core/operations/'+n+'.mjs')
].map(load));
import {gzipSync} from 'node:zlib';
import fs from 'node:fs';
const ops = new Map([FromBase64,FromHex,Gunzip,ZlibInflate,DecodeText,URLDecode].map(C => {const o=new C();return [o.name,o];}));
const criteria = Magic._generateOpCriteria().filter(c => ops.has(c.op));
Magic.prototype._runRecipe = async function(recipe, input=this.inputBuffer) {
  const dish=new Dish(); dish.set(Uint8Array.from(input).buffer,Dish.ARRAY_BUFFER);
  try {
    for (const item of recipe) {
      const op=ops.get(item.op); if(!op)return new ArrayBuffer();
      dish.set(await op.run(await dish.get(op.inputType), item.args),op.outputType);
    }
    return await dish.get(Dish.ARRAY_BUFFER);
  }catch{return new ArrayBuffer();}
};
const script='Write-Output "hello"';
const b64=s=>Buffer.from(s).toString('base64');
const cases={base64:b64(script),nested:b64(b64(script)),gzip:b64(gzipSync(script)),utf16:b64(Buffer.from(script,'utf16le')),hex:Buffer.from(script).toString('hex'),encodedcommand:'powershell -enc '+b64(Buffer.from(script,'utf16le'))};
const results={version:'11.5.0',registry:[...ops.keys()],full_distribution:false,results:[]};
for(const [name,input] of Object.entries(cases)){
 const magic=new Magic(Uint8Array.from(Buffer.from(input)).buffer,criteria);
 const result=await magic.speculativeExecution(5,false,false);
 results.results.push({name,input,candidates:result.slice(0,4).map(r=>({recipe:r.recipe,data:r.data,isUTF8:r.isUTF8,entropy:r.entropy}))});
}
fs.writeFileSync(new URL('./cyberchef-11.5.0-restricted-results.json',import.meta.url),JSON.stringify(results,null,2));
console.log(JSON.stringify(results));
