const SESSION_COOKIE = '__Host-getvexel-session';
const STATE_COOKIE = '__Host-getvexel-oauth-state';

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function cleanSlug(value) {
  return String(value).toLowerCase().trim().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '').slice(0, 80);
}

function base64Url(bytes) {
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : Uint8Array.from(bytes);
  let binary = '';
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function unbase64Url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), ch => ch.charCodeAt(0));
}

async function signSession(secret, session) {
  const encoded = base64Url(new TextEncoder().encode(JSON.stringify(session)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(encoded));
  return encoded + '.' + base64Url(signature);
}

async function verifySession(secret, signed) {
  if (!signed) return null;
  const parts = signed.split('.');
  if (parts.length !== 2) return null;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key, unbase64Url(parts[1]), new TextEncoder().encode(parts[0])).catch(() => false);
  if (!valid) return null;
  try {
    const session = JSON.parse(new TextDecoder().decode(unbase64Url(parts[0])));
    return session.exp > Date.now() ? session : null;
  } catch { return null; }
}

function getCookie(request, name) {
  const match = request.headers.get('Cookie')?.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function cookie(name, value, options = '') {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax${options ? `; ${options}` : ''}`;
}

function redirect(location, status = 303, cookies = []) {
  const headers = new Headers({ Location: location });
  for (const value of cookies) headers.append('Set-Cookie', value);
  return new Response(null, { status, headers });
}

async function currentUser(request, env) {
  return verifySession(env.SESSION_SECRET, getCookie(request, SESSION_COOKIE));
}

function privateHeaders(extra = {}) {
  return { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, private', 'Pragma': 'no-cache', ...extra };
}

function shell(title, body) {
  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} – GetVexel</title><style>
  :root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#0b1220;color:#edf2f7}.wrap{max-width:980px;margin:auto;padding:32px 20px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}.brand{font-size:22px;font-weight:800}.card{background:#111c30;border:1px solid #263652;border-radius:14px;padding:20px;margin:12px 0}.row{display:flex;justify-content:space-between;align-items:center;gap:12px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}input,textarea{width:100%;padding:12px;border-radius:8px;border:1px solid #334a70;background:#0b1425;color:white;font:inherit}.actions{display:flex;gap:8px;flex-wrap:wrap}button,.button{display:inline-block;border:0;border-radius:8px;padding:11px 16px;background:#3b82f6;color:white;font-weight:700;text-decoration:none;cursor:pointer}.secondary{background:#263652}.danger{background:#b42318}.muted{color:#94a3b8;font-size:14px}@media(max-width:700px){.grid{grid-template-columns:1fr}.top,.row{align-items:flex-start;flex-direction:column}}
  </style></head><body><main class="wrap">${body}</main></body></html>`;
}

function dashboard(user, pages, origin, credits) {
  const rows = pages.map(page => `<article class="card row"><div><strong>${escapeHtml(page.slug)}</strong><div class="muted">${escapeHtml(origin)}/${escapeHtml(page.slug)}</div></div><div class="actions"><a class="button secondary" href="/${encodeURIComponent(page.slug)}" target="_blank">Ansehen</a><a class="button" href="/dashboard/edit/${encodeURIComponent(page.slug)}">Bearbeiten</a><button class="danger" type="button" onclick="removePage('${escapeHtml(page.slug)}')">Löschen</button></div></article>`).join('');
  return shell('Dashboard', `<div class="top"><div><div class="brand">GetVexel</div><div class="muted">${escapeHtml(user.email)} · ${credits} Credits</div></div><div class="actions"><a class="button" href="/dashboard/new">Neue Seite</a><a class="button secondary" href="/databases">Datenbanken</a><a class="button secondary" href="/auth/logout">Abmelden</a></div></div><h1>Meine Seiten</h1>${rows || '<div class="card"><p>Noch keine Seite erstellt.</p></div>'}<script>async function removePage(slug){if(!confirm('Seite wirklich löschen?'))return;const r=await fetch('/api/pages/'+encodeURIComponent(slug),{method:'DELETE'});if(r.ok)location.reload();else alert(await r.text())}</script>`);
}

const TEMPLATES = {
  blank: { name: 'Leere Seite', html: '<h1>Meine neue Seite</h1>\n<p>Hier beginnt dein Inhalt.</p>', css: '', js: '' },
  landing: { name: 'Landingpage', html: '<header><strong>Meine Marke</strong></header><main><h1>Dein Angebot</h1><p>Überzeuge deine Besucher.</p><button>Jetzt starten</button></main>', css: 'body{margin:0;font-family:system-ui,sans-serif}header{padding:24px 8%}main{padding:100px 8%;text-align:center;background:#eef4ff}button{padding:14px 24px;border:0;border-radius:8px;background:#2563eb;color:white}', js: '' },
  shop: { name: 'Online-Shop', html: '<nav class="shop-nav"><strong>Mein Shop</strong><button id="cart-open">Warenkorb (<span id="cart-count">0</span>)</button></nav><main class="shop-main"><h1>Unsere Produkte</h1><section class="products"><article class="product"><div class="product-image"></div><h3>Produkt 1</h3><p class="product-price">29,99 €</p><button class="add-cart">In den Warenkorb</button></article><article class="product"><div class="product-image"></div><h3>Produkt 2</h3><p class="product-price">39,99 €</p><button class="add-cart">In den Warenkorb</button></article></section></main><aside id="cart-panel"><button id="cart-close">Schließen</button><div id="cart-items"></div><strong id="cart-total">0,00 €</strong></aside>', css: 'body{margin:0;font-family:system-ui,sans-serif}.shop-nav{height:68px;padding:0 8%;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #ddd}.shop-main{padding:50px 8%}.products{display:grid;grid-template-columns:repeat(2,1fr);gap:20px}.product{border:1px solid #ddd;border-radius:10px;padding:20px}.product-image{height:180px;background:#dbeafe}.add-cart,#cart-open,#cart-close{border:0;border-radius:6px;background:#111;color:white;padding:10px 14px;cursor:pointer}#cart-panel{position:fixed;top:0;right:0;width:360px;height:100%;background:white;transform:translateX(100%);padding:20px;box-sizing:border-box}#cart-panel.open{transform:none}', js: 'const cart=[];document.querySelector("#cart-open").onclick=()=>document.querySelector("#cart-panel").classList.add("open");document.querySelector("#cart-close").onclick=()=>document.querySelector("#cart-panel").classList.remove("open");document.querySelectorAll(".add-cart").forEach(button=>button.onclick=()=>{const product=button.closest(".product");cart.push({name:product.querySelector("h3").textContent,price:product.querySelector(".product-price").textContent});document.querySelector("#cart-count").textContent=cart.length;document.querySelector("#cart-items").innerHTML=cart.map(item=>"<p>"+item.name+" — "+item.price+"</p>").join("")})' },
  portfolio: { name: 'Portfolio', html: '<main><p>FOTO · DESIGN · PROJEKTE</p><h1>Meine Arbeiten</h1><section id="projekte"><h2>Ausgewählte Projekte</h2></section></main>', css: 'body{margin:0;background:#111;color:white;font-family:system-ui,sans-serif}main{padding:80px 10%}h1{font-size:64px}', js: '' },
  blog: { name: 'Blog', html: '<header><strong>Mein Blog</strong></header><main><p>Neue Kategorie</p><h1>Mein erster Artikel</h1><p>Ein kurzer Einleitungstext.</p></main>', css: 'body{margin:0;font-family:Georgia,serif}header{padding:30px 8%;border-bottom:1px solid #ddd}main{max-width:800px;margin:auto;padding:60px 20px}', js: '' }
};

function templatesPage() {
  const cards = Object.entries(TEMPLATES).map(([key, item]) => `<article class="card"><h2>${escapeHtml(item.name)}</h2><a class="button" href="/dashboard/template/${key}">Vorlage verwenden</a></article>`).join('');
  return shell('Vorlagen', `<div class="top"><div class="brand">GetVexel Vorlagen</div><a class="button secondary" href="/dashboard">Zur Übersicht</a></div><div class="grid">${cards}</div>`);
}

function editorPage(page = null) {
  const slug = page?.slug || '';
  const content = page?.html || '<h1>Meine neue Seite</h1>\n<p>Hallo Welt!</p>';
  const project = page?.project || { html: content, css: '', js: '' };
  const projectJson = JSON.stringify(project).replace(/<\/script/gi, '<\\/script');
  return shell('Web-Editor', `
    <style>
      body{overflow:hidden}.wrap{max-width:none;height:100vh;padding:0}.ide{height:100vh;background:#1e1e1e;display:grid;grid-template-rows:44px 1fr 24px}.bar{height:44px;background:#181818;border-bottom:1px solid #333;padding:0 12px;display:flex;align-items:center;justify-content:space-between}.workspace{display:grid;grid-template-columns:180px 1fr 48%;min-height:0}.explorer{background:#252526;border-right:1px solid #333;padding:10px}.file{display:block;width:100%;border:0;background:transparent;color:#ccc;text-align:left;padding:8px;cursor:pointer}.file.active{background:#37373d;color:white}.editor{display:flex;flex-direction:column}.tabname{height:36px;background:#252526;border-bottom:1px solid #333;color:white;padding:9px 14px}.code{flex:1;width:100%;resize:none;border:0;outline:none;padding:16px;background:#1e1e1e;color:#d4d4d4;font:14px/1.5 ui-monospace,monospace;box-sizing:border-box}.preview{display:flex;flex-direction:column;background:#111;border-left:1px solid #333}.previewbar{height:36px;background:#252526;padding:0 10px;display:flex;align-items:center;justify-content:space-between}.previewframe{flex:1;border:0;background:white}.status{background:#007acc;color:white;font-size:12px;padding:3px 10px}.small{border:0;border-radius:4px;padding:7px 10px;background:#0e639c;color:white;cursor:pointer}.small.secondary{background:#3c3c3c}@media(max-width:900px){.workspace{grid-template-columns:150px 1fr}.preview{display:none}}
    </style>
    <div class="ide">
      <div class="bar"><div><input id="slug" value="${escapeHtml(slug)}" placeholder="seitenname" style="width:180px;margin-right:8px;padding:6px" ${page ? 'readonly' : ''}><strong>GetVexel Web-Editor</strong></div><div><button class="small secondary" id="save" type="button">Speichern</button> <button class="small" id="publish" type="button">Veröffentlichen</button></div></div>
      <div class="workspace">
        <aside class="explorer"><strong>EXPLORER</strong><button class="file active" data-file="html">index.html</button><button class="file" data-file="css">styles.css</button><button class="file" data-file="js">script.js</button></aside>
        <section class="editor"><div class="tabname" id="tabname">index.html</div><textarea id="code" class="code" spellcheck="false"></textarea></section>
        <section class="preview"><div class="previewbar"><strong>Vorschau</strong><button class="small secondary" id="refresh">Aktualisieren</button></div><iframe id="preview" class="previewframe" sandbox="allow-scripts allow-modals"></iframe></section>
      </div>
      <div class="status"><span id="position">Zeile 1, Spalte 1</span></div>
    </div>
    <script>
      const initial=${projectJson};
      const files={html:String(initial.html||''),css:String(initial.css||''),js:String(initial.js||'')};
      let active='html';
      const code=document.querySelector('#code');
      const preview=document.querySelector('#preview');
      const names={html:'index.html',css:'styles.css',js:'script.js'};
      function saveEditor(){files[active]=code.value}
      function openFile(name){saveEditor();active=name;code.value=files[name]||'';document.querySelector('#tabname').textContent=names[name];document.querySelectorAll('.file').forEach(button=>button.classList.toggle('active',button.dataset.file===name));code.focus();updatePreview()}
      function updatePreview(){saveEditor();const open='<scr'+'ipt>';const close='<\\/'+'scr'+'ipt>';let html;if(files.html.toLowerCase().includes('<html')){html=files.html;if(files.css)html=html.includes('</head>')?html.replace('</head>','<style>'+files.css+'</style></head>'):html+'<style>'+files.css+'</style>';if(files.js)html=html.includes('</body>')?html.replace('</body>',open+files.js+close+'</body>'):html+open+files.js+close}else{html='<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>'+files.css+'</style></head><body>'+files.html+(files.js?open+files.js+close:'')+'</body></html>'}preview.srcdoc=html}
      document.querySelectorAll('.file').forEach(button=>button.onclick=()=>openFile(button.dataset.file));
      code.oninput=()=>{saveEditor();const before=code.value.slice(0,code.selectionStart).split('\n');document.querySelector('#position').textContent='Zeile '+before.length+', Spalte '+(before.at(-1).length+1);updatePreview()};
      code.onkeydown=event=>{if(event.key==='Tab'){event.preventDefault();const start=code.selectionStart,end=code.selectionEnd;code.setRangeText('  ',start,end,'end');saveEditor();updatePreview()}};
      document.querySelector('#refresh').onclick=updatePreview;
      async function saveProject(){saveEditor();const name=document.querySelector('#slug').value.trim();if(!name){alert('Seitennamen eingeben');return null}const isEdit=${page ? 'true' : 'false'};const response=await fetch(isEdit?'/api/pages/'+encodeURIComponent(name):'/api/pages',{method:isEdit?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({slug:name,html:files.html,project:files})});if(!response.ok)alert(await response.text());return response}
      document.querySelector('#save').onclick=async()=>{const response=await saveProject();if(response?.ok)alert('Gespeichert')};
      document.querySelector('#publish').onclick=async()=>{const response=await saveProject();if(response?.ok)window.open('/'+encodeURIComponent(document.querySelector('#slug').value.trim()),'_blank')};
      openFile('html');
    </script>
  `);
}

async function monthlyCredits(env, ownerSub) {
  const month = new Date().toISOString().slice(0, 7);
  let account = await env.DB.prepare('SELECT credits, month FROM user_credits WHERE owner_sub=?').bind(ownerSub).first();
  if (!account) {
    await env.DB.prepare('INSERT INTO user_credits(owner_sub, month, credits) VALUES(?, ?, 5000)').bind(ownerSub, month).run();
    return 5000;
  }
  if (account.month !== month) {
    await env.DB.prepare('UPDATE user_credits SET month=?, credits=5000 WHERE owner_sub=?').bind(month, ownerSub).run();
    return 5000;
  }
  return account.credits;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let path;
    try { path = decodeURIComponent(url.pathname).replace(/^\/+|\/+$/g, ''); } catch { return new Response('Ungültiger Pfad', { status: 400 }); }

    if (!env.PAGES_KV) return new Response('PAGES_KV fehlt.', { status: 500 });

    if (path === 'auth/google' && request.method === 'GET') {
      if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.SESSION_SECRET) return new Response('Google-OAuth ist nicht konfiguriert.', { status: 500 });
      const state = crypto.randomUUID();
      const callback = `${url.origin}/auth/callback`;
      const authorize = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      authorize.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
      authorize.searchParams.set('redirect_uri', callback);
      authorize.searchParams.set('response_type', 'code');
      authorize.searchParams.set('scope', 'openid email profile');
      authorize.searchParams.set('prompt', 'select_account');
      authorize.searchParams.set('state', state);
      return redirect(authorize.toString(), 302, [cookie(STATE_COOKIE, state, 'Max-Age=600')]);
    }

    if (path === 'auth/callback' && request.method === 'GET') {
      try {
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        if (!code || !state || state !== getCookie(request, STATE_COOKIE)) return new Response('Ungültige OAuth-Anmeldung.', { status: 400 });
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: `${url.origin}/auth/callback`, grant_type: 'authorization_code' })
        });
        if (!tokenResponse.ok) return new Response('Google-Anmeldung fehlgeschlagen.', { status: 401 });
        const tokens = await tokenResponse.json();
        const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: 'Bearer ' + tokens.access_token } });
        if (!profileResponse.ok) return new Response('Google-Profil konnte nicht geladen werden.', { status: 401 });
        const profile = await profileResponse.json();
        if (!profile.sub || !profile.email) return new Response('Google-Konto ist unvollständig.', { status: 401 });
        const signed = await signSession(env.SESSION_SECRET, { sub: profile.sub, email: profile.email, name: profile.name || '', exp: Date.now() + 604800000 });
        return redirect(`${url.origin}/dashboard`, 303, [cookie(SESSION_COOKIE, signed, 'Max-Age=604800'), cookie(STATE_COOKIE, '', 'Max-Age=0')]);
      } catch (error) {
        return new Response(`OAuth-Fehler: ${error.message || error.name}`, { status: 500 });
      }
    }

    if (path === 'auth/logout' && request.method === 'GET') {
      return redirect(`${url.origin}/`, 303, [cookie(SESSION_COOKIE, '', 'Max-Age=0')]);
    }

    if (path === '' && request.method === 'GET') {
      const user = await currentUser(request, env);
      if (user) return redirect(`${url.origin}/dashboard`);
      return new Response(shell('Anmelden', `<section class="card" style="max-width:560px;margin:90px auto;text-align:center"><div class="brand">GetVexel</div><h1>Eigene Seiten erstellen</h1><p>Melde dich mit Google an.</p><a class="button" href="/auth/google">Mit Google anmelden</a></section>`), { headers: privateHeaders() });
    }

    if (path.startsWith('dashboard')) {
      if (request.method !== 'GET') return new Response('Method nicht erlaubt', { status: 405 });
      const user = await currentUser(request, env);
      if (!user) return redirect(`${url.origin}/auth/google`);

      if (path === 'dashboard') {
        const listing = await env.PAGES_KV.list({ prefix: `owner:${user.sub}:`, limit: 1000 });
        const pages = [];
        for (const key of listing.keys) {
          const slug = key.name.slice(`owner:${user.sub}:`.length);
          const html = await env.PAGES_KV.get(`page:${slug}`);
          if (html !== null) pages.push({ slug, html });
        }
        let credits = 5000;
        if (env.DB) credits = await monthlyCredits(env, user.sub);
        pages.sort((a, b) => a.slug.localeCompare(b.slug));
        return new Response(dashboard(user, pages, url.origin, credits), { headers: privateHeaders() });
      }

      if (path === 'dashboard/new') return new Response(templatesPage(), { headers: privateHeaders() });

      if (path.startsWith('dashboard/template/')) {
        const name = cleanSlug(path.slice('dashboard/template/'.length));
        const template = TEMPLATES[name];
        if (!template) return new Response('Vorlage nicht gefunden.', { status: 404 });
        return new Response(editorPage({ project: template }), { headers: privateHeaders() });
      }

      if (path.startsWith('dashboard/edit/')) {
        const slug = cleanSlug(decodeURIComponent(path.slice('dashboard/edit/'.length)));
        const meta = await env.PAGES_KV.get(`meta:${slug}`, 'json');
        if (!meta || meta.owner !== user.sub) return new Response('Seite nicht gefunden.', { status: 404 });
        const html = await env.PAGES_KV.get(`page:${slug}`);
        const project = await env.PAGES_KV.get(`project:${slug}`, 'json');
        return new Response(editorPage({ slug, html: html || '', project }), { headers: privateHeaders() });
      }

      return new Response('Seite nicht gefunden.', { status: 404 });
    }

    if (path === 'databases' && request.method === 'GET') {
      const user = await currentUser(request, env);
      if (!user) return redirect(`${url.origin}/auth/google`);
      if (!env.DB) return new Response('D1 ist nicht konfiguriert.', { status: 500 });
      const credits = await monthlyCredits(env, user.sub);
      const result = await env.DB.prepare('SELECT id, name FROM user_databases WHERE owner_sub = ? ORDER BY name').bind(user.sub).all();
      const cards = (result.results || []).map(db => `<article class="card row"><strong>${escapeHtml(db.name)}</strong><div class="actions"><button class="danger" onclick="removeDb('${escapeHtml(db.id)}')">Löschen</button></div></article>`).join('');
      return new Response(shell('Datenbanken', `<div class="top"><div><div class="brand">Meine Datenbanken</div><div class="muted">${credits} Credits</div></div><a class="button secondary" href="/dashboard">Zum Dashboard</a></div><form id="create-db"><input id="db-name" maxlength="40" placeholder="Datenbankname" required><br><br><button>Erstellen</button></form><h1>Datenbanken</h1>${cards || '<div class="card"><p>Noch keine Datenbank.</p></div>'}<script>document.querySelector('#create-db').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/databases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:document.querySelector('#db-name').value})});if(r.ok)location.reload();else alert(await r.text())};async function removeDb(id){if(confirm('Löschen?')){const r=await fetch('/api/databases/'+id,{method:'DELETE'});if(r.ok)location.reload();else alert(await r.text())}}</script>`), { headers: privateHeaders() });
    }

    if (path.startsWith('api/databases')) {
      const user = await currentUser(request, env);
      if (!user) return new Response('Anmeldung erforderlich.', { status: 401 });
      if (!env.DB) return new Response('D1 ist nicht konfiguriert.', { status: 500 });
      const id = cleanSlug(path.startsWith('api/databases/') ? path.slice('api/databases/'.length) : '');

      if (request.method === 'POST' && path === 'api/databases') {
        let body; try { body = await request.json(); } catch { return new Response('Ungültige Daten.', { status: 400 }); }
        const name = String(body.name || '').trim().slice(0, 40);
        if (!name) return new Response('Name fehlt.', { status: 400 });
        const count = await env.DB.prepare('SELECT COUNT(*) count FROM user_databases WHERE owner_sub=?').bind(user.sub).first();
        if ((count?.count || 0) >= 3) return new Response('Maximal drei Datenbanken.', { status: 409 });
        const databaseId = crypto.randomUUID();
        await env.DB.prepare('INSERT INTO user_databases(id, owner_sub, name) VALUES(?, ?, ?)').bind(databaseId, user.sub, name).run();
        return new Response(JSON.stringify({ id: databaseId, name }), { headers: { 'Content-Type': 'application/json' } });
      }

      if (request.method === 'POST' && id) {
        const owned = await env.DB.prepare('SELECT id FROM user_databases WHERE id=? AND owner_sub=?').bind(id, user.sub).first();
        if (!owned) return new Response('Datenbank nicht gefunden.', { status: 404 });
        let body; try { body = await request.json(); } catch { return new Response('Ungültige Daten.', { status: 400 }); }
        await monthlyCredits(env, user.sub);
        const itemId = crypto.randomUUID();
        const insert = env.DB.prepare('INSERT INTO database_items(id,database_id,owner_sub,name,json_data,created_at) SELECT ?,?,?,?, ?,? WHERE EXISTS (SELECT 1 FROM user_credits WHERE owner_sub=? AND credits>=10)').bind(itemId, id, user.sub, String(body.name || 'Eintrag').slice(0, 80), JSON.stringify(body.data || {}), Date.now(), user.sub);
        const charge = env.DB.prepare('UPDATE user_credits SET credits=credits-10 WHERE owner_sub=? AND credits>=10').bind(user.sub);
        const result = await env.DB.batch([insert, charge]);
        if (!result[0].meta.changes || !result[1].meta.changes) return new Response('Nicht genügend Credits.', { status: 402 });
        return new Response(JSON.stringify({ id: itemId }), { headers: { 'Content-Type': 'application/json' } });
      }

      if (request.method === 'GET' && id) {
        const owned = await env.DB.prepare('SELECT id,name FROM user_databases WHERE id=? AND owner_sub=?').bind(id, user.sub).first();
        if (!owned) return new Response('Datenbank nicht gefunden.', { status: 404 });
        await monthlyCredits(env, user.sub);
        const charge = env.DB.prepare('UPDATE user_credits SET credits=credits-5 WHERE owner_sub=? AND credits>=5').bind(user.sub);
        const items = env.DB.prepare('SELECT id,name,json_data,created_at FROM database_items WHERE database_id=? AND owner_sub=? ORDER BY created_at DESC').bind(id, user.sub);
        const result = await env.DB.batch([charge, items]);
        if (!result[0].meta.changes) return new Response('Nicht genügend Credits.', { status: 402 });
        return new Response(JSON.stringify({ database: owned, items: result[1].results || [] }), { headers: { 'Content-Type': 'application/json' } });
      }

      if (request.method === 'DELETE' && id) {
        await env.DB.prepare('DELETE FROM database_items WHERE database_id=? AND owner_sub=?').bind(id, user.sub).run();
        const deleted = await env.DB.prepare('DELETE FROM user_databases WHERE id=? AND owner_sub=?').bind(id, user.sub).run();
        if (!deleted.meta.changes) return new Response('Datenbank nicht gefunden.', { status: 404 });
        return new Response('OK');
      }
    }

    if (path === 'api/assets' && request.method === 'POST') {
      const user = await currentUser(request, env);
      if (!user) return new Response('Anmeldung erforderlich.', { status: 401 });
      const form = await request.formData();
      const file = form.get('file');
      if (!(file instanceof File) || !file.type.startsWith('image/')) return new Response('Keine gültige Bilddatei.', { status: 400 });
      if (file.size > 2097152) return new Response('Bild zu groß.', { status: 413 });
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = '';
      for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
      const id = crypto.randomUUID();
      await env.PAGES_KV.put(`asset:${id}`, JSON.stringify({ owner: user.sub, type: file.type, data: btoa(binary) }));
      return new Response(JSON.stringify({ url: `${url.origin}/assets/${id}` }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (path.startsWith('assets/') && request.method === 'GET') {
      const id = cleanSlug(path.slice('assets/'.length));
      const asset = await env.PAGES_KV.get(`asset:${id}`, 'json');
      if (!asset) return new Response('Bild nicht gefunden.', { status: 404 });
      const binary = atob(asset.data);
      return new Response(Uint8Array.from(binary, ch => ch.charCodeAt(0)), { headers: { 'Content-Type': asset.type || 'application/octet-stream', 'Cache-Control': 'public, max-age=31536000' } });
    }

    if (path === 'api/pages' || path.startsWith('api/pages/')) {
      const user = await currentUser(request, env);
      if (!user) return new Response('Anmeldung erforderlich.', { status: 401 });
      const slug = cleanSlug(path.startsWith('api/pages/') ? decodeURIComponent(path.slice('api/pages/'.length)) : '');

      if (request.method === 'POST' && path === 'api/pages') {
        let body; try { body = await request.json(); } catch { return new Response('Ungültige Daten.', { status: 400 }); }
        const name = cleanSlug(body.slug || '');
        if (!name) return new Response('Seitennamen eingeben.', { status: 400 });
        if (!body.project || !body.project.html) body.project = { html: String(body.html || ''), css: '', js: '' };
        if (await env.PAGES_KV.get(`meta:${name}`)) return new Response('Seitenname bereits vergeben.', { status: 409 });
        const html = combineProject(body.project);
        await env.PAGES_KV.put(`page:${name}`, html);
        await env.PAGES_KV.put(`project:${name}`, JSON.stringify(body.project));
        await env.PAGES_KV.put(`meta:${name}`, JSON.stringify({ owner: user.sub, updatedAt: Date.now() }));
        await env.PAGES_KV.put(`owner:${user.sub}:${name}`, '1');
        return new Response('OK');
      }

      if (request.method === 'PUT' && slug) {
        const meta = await env.PAGES_KV.get(`meta:${slug}`, 'json');
        if (!meta) return new Response('Seite nicht gefunden.', { status: 404 });
        if (meta.owner !== user.sub) return new Response('Nicht erlaubt.', { status: 403 });
        let body; try { body = await request.json(); } catch { return new Response('Ungültige Daten.', { status: 400 }); }
        if (!body.project) body.project = { html: String(body.html || ''), css: '', js: '' };
        await env.PAGES_KV.put(`page:${slug}`, combineProject(body.project));
        await env.PAGES_KV.put(`project:${slug}`, JSON.stringify(body.project));
        await env.PAGES_KV.put(`meta:${slug}`, JSON.stringify({ owner: user.sub, updatedAt: Date.now() }));
        return new Response('OK');
      }

      if (request.method === 'DELETE' && slug) {
        const meta = await env.PAGES_KV.get(`meta:${slug}`, 'json');
        if (!meta) return new Response('Seite nicht gefunden.', { status: 404 });
        if (meta.owner !== user.sub) return new Response('Nicht erlaubt.', { status: 403 });
        await env.PAGES_KV.delete(`page:${slug}`);
        await env.PAGES_KV.delete(`project:${slug}`);
        await env.PAGES_KV.delete(`meta:${slug}`);
        await env.PAGES_KV.delete(`owner:${user.sub}:${slug}`);
        return new Response('OK');
      }

      return new Response('Method nicht erlaubt.', { status: 405 });
    }

    if (request.method === 'GET' && path) {
      const saved = await env.PAGES_KV.get(`page:${path}`);
      if (saved !== null) return new Response(saved, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' } });
      const legacy = await env.PAGES_KV.get(path);
      if (legacy !== null) return new Response(legacy, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' } });
    }

    return new Response(shell('404', '<section class="card"><h1>404</h1><p>Diese Seite existiert nicht.</p><a class="button" href="/">Zur Startseite</a></section>'), { status: 404, headers: privateHeaders() });
  }
};
