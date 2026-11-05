// Host supplies its authenticated same-origin client. Never send credentials to providers.
export async function enrichIndicators(indicators, {request, signal, onResult}) {
  const unique = [...new Map(indicators.map(i => [i.type+':'+i.value,i])).values()];
  if (unique.length > 50) throw new Error('At most 50 indicators per analysis');
  let cursor=0;
  async function worker(){
    while(cursor<unique.length && !signal?.aborted){
      const i=unique[cursor++];
      try {
        const result=await request('/api/edr/forensics/ioc-reputation',{method:'POST',signal,body:{kind:i.type,value:i.value}});
        if(!signal?.aborted)onResult(i,result);
      } catch(error){if(!signal?.aborted)onResult(i,{ioc:i,providers:[],status:'unavailable'});}
    }
  }
  await Promise.all(Array.from({length:Math.min(3,unique.length)},worker));
}
