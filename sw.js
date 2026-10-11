// WIN PRO service worker: makes the app installable and openable. Only same-origin app shell is cached;
// OAuth, Deriv API, WebSocket and any cross-origin request go straight to the network.
const V='winpro-v1', SHELL=['./','index.html','manifest.json'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(SHELL)).catch(()=>{}));self.skipWaiting();});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==V).map(x=>caches.delete(x)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
  const r=e.request, u=new URL(r.url);
  if(r.method!=='GET'||u.origin!==location.origin) return;
  if(r.mode==='navigate'){ // network first so updates and OAuth ?code= redirects always load; cached shell when offline
    e.respondWith(fetch(r).catch(()=>caches.match('index.html').then(x=>x||caches.match('./'))));
    return;
  }
  e.respondWith(caches.match(r).then(h=>h||fetch(r).then(res=>{ if(res.ok){const c=res.clone();caches.open(V).then(ca=>ca.put(r,c));} return res; })));
});
