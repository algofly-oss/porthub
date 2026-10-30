// Bounded, account-lifetime cache. Concurrent readers share requests; abandoned
// searches are aborted and cannot replace a newer query's result.
export function createInventoryResource({ capacity = 48, now = Date.now } = {}) {
  const entries = new Map(), pending = new Map(), listeners = new Set();
  const get = key => { const value = entries.get(key); if (value) { entries.delete(key); entries.set(key,value); } return value; };
  const put = (key,value) => { entries.delete(key);entries.set(key,value);while(entries.size>capacity)entries.delete(entries.keys().next().value); };
  return {
    get,
    subscribe(callback) { listeners.add(callback); return ()=>listeners.delete(callback); },
    invalidate(kind) {
      const matches=key=>!kind || key.startsWith(`/api/inventory/${kind}?`);
      for(const [key,entry] of entries)if(matches(key))entry.stale=true;
      for(const [key,request] of pending)if(matches(key)){request.controller.abort();pending.delete(key);}
      for(const notify of listeners)notify(kind);
    },
    acquire(key,loader) {
      let request=pending.get(key);
      if(!request){
        const controller=new AbortController(), previous=get(key);
        request={controller,readers:0,finished:false};pending.set(key,request);
        request.promise=Promise.resolve().then(()=>loader({signal:controller.signal,etag:previous?.etag})).then(response=>{
          if(controller.signal.aborted)throw new DOMException("Request aborted","AbortError");
          const result={data:response.status===304 ? previous?.data : response.data,etag:response.etag || previous?.etag,updated:now(),stale:false};
          if(result.data === undefined)throw Error("Conditional response has no cached inventory");
          put(key,result);return result;
        }).finally(()=>{request.finished=true;if(pending.get(key)===request)pending.delete(key);});
      }
      request.readers++;let released=false;
      return {promise:request.promise,release(){if(released)return;released=true;request.readers--;if(!request.readers&&!request.finished){request.controller.abort();if(pending.get(key)===request)pending.delete(key);}}};
    },
    get size(){return entries.size;},
  };
}
export function inventoryUrl(kind,params={}) {
  const query=new URLSearchParams();
  for(const key of Object.keys(params).sort()){const value=params[key];if(value!==undefined&&value!==null)query.set(key,String(value));}
  return `/api/inventory/${kind}?${query}`;
}
