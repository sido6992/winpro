// WIN PRO Bot Store — Cloudflare Worker.  Binding needed:  KV namespace "STORE".
// Owner PIN: created from the app (Owner login) the first time. (Optional: a secret "ADMIN_KEY" also works as the PIN.)
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type,X-Admin-Key','Access-Control-Allow-Methods':'GET,POST,DELETE,OPTIONS'};
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{...CORS,'Content-Type':'application/json'}});
const rid=n=>[...crypto.getRandomValues(new Uint8Array(n))].map(b=>b.toString(16).padStart(2,'0')).join('');
const same=(a,b)=>{ a=String(a||''); b=String(b||''); if(a.length!==b.length||!b) return false; let r=0; for(let i=0;i<a.length;i++) r|=a.charCodeAt(i)^b.charCodeAt(i); return r===0; };
const get=async(env,k)=>{ const v=await env.STORE.get(k); return v?JSON.parse(v):null; };
const all=async(env,prefix)=>{ const l=await env.STORE.list({prefix}); return (await Promise.all(l.keys.map(k=>get(env,k.name)))).filter(Boolean); };
const sha=async s=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))].map(b=>b.toString(16).padStart(2,'0')).join('');
const isAdmin=async(req,env)=>{ const k=req.headers.get('X-Admin-Key')||''; if(env.ADMIN_KEY&&same(k,env.ADMIN_KEY)) return true; const h=await env.STORE.get('adminhash'); return !!(h&&k&&same(await sha(k),h)); };
const pub=b=>({id:b.id,name:b.name,price:b.price,desc:b.desc});
export default { async fetch(req,env){
  if(req.method==='OPTIONS') return new Response(null,{headers:CORS});
  const u=new URL(req.url), p=u.pathname.replace(/\/+$/,''), m=req.method, body=async()=>{ try{ return await req.json(); }catch(e){ return {}; } };
  try{
    if(m==='GET'&&p==='/bots') return J((await all(env,'bot:')).sort((a,b)=>b.created-a.created).map(pub));
    if(m==='GET'&&p==='/settings'){ const s=(await get(env,'settings'))||{}; return J({payInfo:s.payInfo||'',currency:s.currency||'USD'}); }
    if(m==='POST'&&p==='/orders'){ const b=await body(), bot=await get(env,'bot:'+b.botId); if(!bot) return J({error:'Bot not found'},404);
      const c=String(b.contact||'').slice(0,120), r=String(b.ref||'').slice(0,120); if(!c||!r) return J({error:'Contact and payment reference are required'},400);
      const o={id:rid(8),token:rid(16),botId:bot.id,contact:c,ref:r,status:'pending',created:Date.now()}; await env.STORE.put('order:'+o.id,JSON.stringify(o)); return J({id:o.id,token:o.token}); }
    let x=p.match(/^\/orders\/(\w+)$/);
    if(m==='GET'&&x){ const o=await get(env,'order:'+x[1]); if(!o||!same(u.searchParams.get('token'),o.token)) return J({error:'Not found'},404); return J({status:o.status}); }
    x=p.match(/^\/download\/(\w+)$/);
    if(m==='GET'&&x){ const bot=await get(env,'bot:'+x[1]); if(!bot) return J({error:'Bot not found'},404);
      if(bot.price>0){ const o=await get(env,'order:'+u.searchParams.get('order')); if(!o||o.botId!==bot.id||o.status!=='approved'||!same(u.searchParams.get('token'),o.token)) return J({error:'Payment not confirmed yet'},403); }
      return new Response(await env.STORE.get('xml:'+bot.id),{headers:{...CORS,'Content-Type':'text/xml; charset=utf-8'}}); }
    if(m==='GET'&&p==='/admin/status') return J({configured:!!(env.ADMIN_KEY||await env.STORE.get('adminhash'))});
    if(m==='POST'&&p==='/admin/setup'){ if(env.ADMIN_KEY||await env.STORE.get('adminhash')) return J({error:'Owner PIN already created'},403); const b=await body(), pin=String(b.pin||'');
      if(pin.length<6||pin.length>100) return J({error:'PIN must be at least 6 characters'},400); await env.STORE.put('adminhash',await sha(pin)); return J({ok:1}); }
    if(p.startsWith('/admin')){
      if(!(await isAdmin(req,env))) return J({error:'Unauthorized'},401);
      if(m==='GET'&&p==='/admin/orders') return J((await all(env,'order:')).map(o=>({id:o.id,botId:o.botId,contact:o.contact,ref:o.ref,status:o.status,created:o.created})).sort((a,b)=>b.created-a.created));
      x=p.match(/^\/admin\/orders\/(\w+)$/);
      if(m==='POST'&&x){ const o=await get(env,'order:'+x[1]), b=await body(); if(!o) return J({error:'Not found'},404); if(!['approved','rejected'].includes(b.status)) return J({error:'Bad status'},400); o.status=b.status; await env.STORE.put('order:'+o.id,JSON.stringify(o)); return J({ok:1}); }
      if(m==='POST'&&p==='/admin/bots'){ const b=await body(), xml=String(b.xml||'');
        if(!/<xml[\s>]/i.test(xml)||xml.length>900000) return J({error:'Invalid or too large XML file'},400); if(!String(b.name||'').trim()) return J({error:'Name required'},400);
        const bot={id:rid(6),name:String(b.name).slice(0,80),price:Math.max(0,+b.price||0),desc:String(b.desc||'').slice(0,300),created:Date.now()};
        await env.STORE.put('xml:'+bot.id,xml); await env.STORE.put('bot:'+bot.id,JSON.stringify(bot)); return J(pub(bot)); }
      x=p.match(/^\/admin\/bots\/(\w+)$/);
      if(m==='DELETE'&&x){ await env.STORE.delete('bot:'+x[1]); await env.STORE.delete('xml:'+x[1]); return J({ok:1}); }
      if(m==='POST'&&p==='/admin/settings'){ const b=await body(), s=(await get(env,'settings'))||{}; if(b.payInfo!=null) s.payInfo=String(b.payInfo).slice(0,1000); if(b.currency) s.currency=String(b.currency).slice(0,6); await env.STORE.put('settings',JSON.stringify(s)); return J({ok:1}); }
    }
    return J({error:'Not found'},404);
  }catch(e){ return J({error:'Server error'},500); }
}};
