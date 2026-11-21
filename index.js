const SESSION_COOKIE = '__Host-getvexel-session';
const STATE_COOKIE = '__Host-getvexel-oauth-state';

function base64UrlEncode(bytes) {
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : Uint8Array.from(bytes);
  let binary = '';
  for (let index = 0; index < view.length; index++) binary += String.fromCharCode(view[index]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function cleanSlug(value) {
  return String(value).toLowerCase().trim().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '').slice(0, 80);
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
  return { key, signature: await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value)) };
}

async function signValue(secret, value) {
  const encoded = base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
  const signature = await hmac(secret, encoded);
  return `${encoded}.${base64UrlEncode(signature.signature)}`;
}

async function verifySignedValue(secret, signed) {
  if (!signed) return null;
  const parts = signed.split('.');
  if (parts.length !== 2) return null;
  const { key } = await hmac(secret, parts[0]);
  if (!await crypto.subtle.verify('HMAC', key, base64UrlDecode(parts[1]), new TextEncoder().encode(parts[0]))) return null;
  try { return JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0]))); }
  catch { return null; }
}

function getCookie(request, name) {
  const match = request.headers.get('Cookie')?.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function getSession(request, env) {
  if (!env.SESSION_SECRET) return null;
  const session = await verifySignedValue(env.SESSION_SECRET, getCookie(request, SESSION_COOKIE));
  if (!session || session.exp < Date.now()) return null;
  return session;
}

function secureCookie(name, value, options = '') {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax${options ? `; ${options}` : ''}`;
}

function redirectResponse(location, status = 303, cookies = []) {
  const headers = new Headers({ Location: location });
  for (const cookie of cookies) headers.append('Set-Cookie', cookie);
  return new Response(null, { status, headers });
}

async function getMonthlyCredits(env, ownerSub) {
  const month = new Date().toISOString().slice(0, 7);
  let account = await env.DB.prepare('SELECT credits, month FROM user_credits WHERE owner_sub = ?').bind(ownerSub).first();
  if (!account) {
    await env.DB.prepare('INSERT INTO user_credits (owner_sub, month, credits) VALUES (?, ?, 5000)').bind(ownerSub, month).run();
    return 5000;
  }
  if (account.month !== month) {
    await env.DB.prepare('UPDATE user_credits SET month = ?, credits = 5000 WHERE owner_sub = ?').bind(month, ownerSub).run();
    return 5000;
  }
  return account.credits;
}

async function chargeCredits(env, ownerSub, cost) {
  await getMonthlyCredits(env, ownerSub);
  const result = await env.DB.prepare('UPDATE user_credits SET credits = credits - ? WHERE owner_sub = ? AND credits >= ?').bind(cost, ownerSub, cost).run();
  if (!result.meta.changes) return null;
  const account = await env.DB.prepare('SELECT credits FROM user_credits WHERE owner_sub = ?').bind(ownerSub).first();
  return account?.credits ?? null;
}

function privateHeaders() {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache'
  };
}

function combineProject(project) {
  const html = String(project?.html || '');
  const css = String(project?.css || '').replace(/<\/?style[^>]*>/gi, '');
  const js = String(project?.js || '').replace(/<\/?script[^>]*>/gi, '');
  if (html.toLowerCase().includes('<html')) {
    let output = html;
    if (css) output = output.replace('</head>', `<style>${css}</style></head>`).replace('<head>', `<head><style>${css}</style>`);
    if (js) output = output.replace('</body>', `<script>${js}<\/script></body>`);
    return output;
  }
  return `<!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${css}</style></head><body>${html}<script>${js}<\/script></body></html>`;
}

function htmlPage(title, body) {
  return `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} – GetVexel</title><style>
    :root{color-scheme:dark}*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#0b1220;color:#edf2f7}.shell{max-width:980px;margin:auto;padding:32px 20px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:28px}.brand{font-size:22px;font-weight:800}.card{background:#111c30;border:1px solid #263652;border-radius:14px;padding:22px;margin:16px 0}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}input,textarea{width:100%;padding:12px;border-radius:8px;border:1px solid #334a70;background:#0b1425;color:white;font:inherit}textarea{min-height:360px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.actions{display:flex;gap:10px;flex-wrap:wrap}button,.button{display:inline-block;border:0;border-radius:8px;padding:11px 16px;background:#3b82f6;color:white;font-weight:700;text-decoration:none;cursor:pointer}.button.secondary{background:#263652}.danger{background:#b42318}p{color:#b8c5d9}.page-row{display:flex;justify-content:space-between;align-items:center;gap:12px}.muted{color:#94a3b8;font-size:14px}@media(max-width:700px){.grid{grid-template-columns:1fr}.top,.page-row{align-items:flex-start;flex-direction:column}}
  </style></head><body><main class="shell">${body}</main></body></html>`;
}

function dashboardPage(user, pages, origin, credits) {
  const rows = pages.map(page => `<article class="card page-row"><div><strong>${escapeHtml(page.slug)}</strong><div class="muted">${escapeHtml(origin)}/${escapeHtml(page.slug)}</div></div><div class="actions"><a class="button secondary" href="/${encodeURIComponent(page.slug)}" target="_blank">Ansehen</a><a class="button" href="/dashboard/edit/${encodeURIComponent(page.slug)}">Bearbeiten</a><button class="danger" type="button" onclick="deletePage('${escapeHtml(page.slug)}')">Löschen</button></div></article>`).join('');
  return htmlPage('Dashboard', `<div class="top"><div><div class="brand">GetVexel</div><div class="muted">Angemeldet als ${escapeHtml(user.email)} · ${credits} Credits diesen Monat</div></div><div class="actions"><a class="button" href="/dashboard/new">Neue Seite</a><a class="button" href="/databases">Meine Datenbanken</a><a class="button secondary" href="/auth/logout">Abmelden</a></div></div><h1>Meine Seiten</h1>${rows || '<div class="card"><p>Du hast noch keine Seiten erstellt.</p></div>'}<script>async function deletePage(slug){if(!confirm('Diese Seite wirklich löschen?'))return;const response=await fetch('/api/pages/'+encodeURIComponent(slug),{method:'DELETE'});if(response.ok){location.reload()}else{alert(await response.text())}}</script>`);
}

function databasePage(databases, credits) {
  const cards = databases.map(db => `<article class="card page-row"><div><a class="button" href="/databases/${encodeURIComponent(db.id)}">${escapeHtml(db.name)}</a><div class="muted">ID: ${escapeHtml(db.id)}</div></div><button class="danger" onclick="deleteDatabase('${escapeHtml(db.id)}')">Löschen</button></article>`).join('');
  return htmlPage('Datenbanken', `<div class="top"><div><div class="brand">GetVexel Datenbanken</div><div class="muted">Bis zu drei Datenbanken pro Konto · ${credits} Credits verbleibend</div></div><a class="button secondary" href="/dashboard">Zum Dashboard</a></div><form id="create-db"><label>Name der Datenbank</label><input id="db-name" required maxlength="40" placeholder="Meine Datenbank"><br><br><button type="submit">Datenbank erstellen</button></form><h1>Meine Datenbanken</h1><div id="database-list">${cards || '<div class="card"><p>Noch keine Datenbank vorhanden.</p></div>'}</div><script>document.querySelector('#create-db').addEventListener('submit',async event=>{event.preventDefault();const name=document.querySelector('#db-name').value;const response=await fetch('/api/databases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});if(response.ok)location.reload();else alert(await response.text())});async function deleteDatabase(id){if(!confirm('Datenbank wirklich löschen?'))return;const response=await fetch('/api/databases/'+encodeURIComponent(id),{method:'DELETE'});if(response.ok)location.reload();else alert(await response.text())}</script>`);
}

function databaseDetailPage(database, items) {
  const rows = items.map(item => {
    let data = item.json_data;
    try { data = JSON.stringify(JSON.parse(item.json_data), null, 2); } catch {}
    const date = new Date(item.created_at).toLocaleString('de-DE');
    return `<article class="card"><div class="page-row"><strong>${escapeHtml(item.name)}</strong><span class="muted">${escapeHtml(date)}</span></div><pre style="white-space:pre-wrap">${escapeHtml(data)}</pre></article>`;
  }).join('');
  return htmlPage(database.name, `<div class="top"><div><div class="brand">${escapeHtml(database.name)}</div><div class="muted">Datenbankeinträge</div></div><a class="button secondary" href="/databases">Zur Übersicht</a></div>${rows || '<div class="card"><p>Diese Datenbank enthält noch keine Einträge.</p></div>'}`);
}

const pageTemplates = {
  blank: { name: 'Leere Seite', html: '<h1>Meine neue Seite</h1>\n<p>Hier beginnt dein Inhalt.</p>', css: '', js: '' },
  landing: { name: 'Landingpage', html: `<header style="padding:24px 8%;display:flex;justify-content:space-between;align-items:center"><strong>Meine Marke</strong><button>Kontakt</button></header><main style="padding:100px 8%;text-align:center;background:#eef4ff"><h1 style="font-size:56px;margin:0">Dein großes Angebot</h1><p style="font-size:20px">Ein klarer Text, der Besucher überzeugt.</p><button style="padding:14px 24px">Jetzt starten</button></main>`, css: 'body{margin:0;font-family:system-ui,sans-serif}button{border:0;border-radius:8px;background:#2563eb;color:white}', js: '' },
  shop: { name: 'Online-Shop', html: `<nav style="padding:20px 8%;display:flex;justify-content:space-between"><strong>Mein Shop</strong><span>Warenkorb (0)</span></nav><main style="padding:50px 8%"><h1>Unsere Produkte</h1><section style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px"><article style="border:1px solid #ddd;padding:20px"><div style="height:180px;background:#eee"></div><h3>Produkt 1</h3><p>29,99 €</p><button>In den Warenkorb</button></article><article style="border:1px solid #ddd;padding:20px"><div style="height:180px;background:#eee"></div><h3>Produkt 2</h3><p>39,99 €</p><button>In den Warenkorb</button></article><article style="border:1px solid #ddd;padding:20px"><div style="height:180px;background:#eee"></div><h3>Produkt 3</h3><p>49,99 €</p><button>In den Warenkorb</button></article></section></main>`, css: 'body{margin:0;font-family:system-ui,sans-serif}button{border:0;border-radius:6px;background:#111;color:white;padding:10px 14px}article{box-sizing:border-box}', js: '' },
  portfolio: { name: 'Portfolio', html: `<main style="min-height:100vh;padding:80px 10%;background:#111;color:white"><p>FOTO · DESIGN · PROJEKTE</p><h1 style="font-size:64px;max-width:700px">Ich gestalte klare digitale Erlebnisse.</h1><a href="#projekte" style="color:white">Meine Projekte ansehen</a></main><section id="projekte" style="padding:80px 10%"><h2>Ausgewählte Arbeiten</h2></section>`, css: 'body{margin:0;font-family:system-ui,sans-serif}', js: '' },
  blog: { name: 'Blog', html: `<header style="padding:30px 8%;border-bottom:1px solid #ddd"><strong>Mein Blog</strong></header><main style="max-width:800px;margin:auto;padding:60px 20px"><p style="color:#777">KATEGORIE · 21. November 2026</p><h1>Der erste Blogartikel</h1><p>Ein kurzer Einleitungstext für deinen neuen Beitrag.</p><h2>Ein Abschnitt</h2><p>Weiterer Inhalt für deine Leser.</p></main>`, css: 'body{margin:0;font-family:Georgia,serif}header{font-family:system-ui,sans-serif}', js: '' }
};

function templatePage() {
  const cards = Object.entries(pageTemplates).map(([key, template]) => `<article class="card" style="margin:0"><h2>${escapeHtml(template.name)}</h2><p>${{ blank: 'Mit einer leeren Seite beginnen', landing: 'Für Produkte, Unternehmen oder Angebote', shop: 'Mit Produktkarten und Warenkorb-Aufbau', portfolio: 'Für Arbeiten und persönliche Projekte', blog: 'Für Artikel und Beiträge' }[key]}</p><a class="button" href="/dashboard/template/${key}">Vorlage verwenden</a></article>`).join('');
  return htmlPage('Vorlagen', `<div class="top"><div><div class="brand">GetVexel Vorlagen</div><div class="muted">Wähle eine Vorlage für dein neues Projekt</div></div><a class="button secondary" href="/dashboard">Zur Übersicht</a></div><div class="grid" style="grid-template-columns:repeat(3,minmax(0,1fr))">${cards}</div>`);
}

function editorPage(page = null) {
  const slug = page?.slug || '';
  const content = page?.html || '<h1>Meine neue Seite</h1>\n<p>Hallo Welt!</p>';
  const project = page?.project || { html: content, css: '', js: '' };
  const body = `
    <style>
      body{overflow:hidden}.shell{max-width:none;height:100vh;padding:0}.ide{height:100vh;background:#1e1e1e;color:#ddd;display:grid;grid-template-rows:44px 1fr 24px}.titlebar{display:flex;align-items:center;justify-content:space-between;padding:0 12px;background:#181818;border-bottom:1px solid #333}.brand{font-size:15px}.workspace{display:grid;grid-template-columns:190px 1fr 48%;min-height:0}.explorer{background:#252526;border-right:1px solid #333;padding:10px}.explorer strong{display:block;margin-bottom:10px}.file{width:100%;text-align:left;padding:7px 8px;border:0;background:transparent;color:#ccc;cursor:pointer}.file.active{background:#37373d;color:white}.editor-pane{display:flex;flex-direction:column;min-width:0;background:#1e1e1e}.editor-tabs{height:36px;background:#252526;border-bottom:1px solid #333}.tab{height:36px;border:0;border-right:1px solid #333;background:#2d2d2d;color:#fff;padding:0 14px}.tab.active{background:#1e1e1e;border-top:1px solid #007acc}.code{flex:1;width:100%;resize:none;border:0;outline:none;padding:16px;background:#1e1e1e;color:#d4d4d4;font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;tab-size:2;box-sizing:border-box}.preview{border-left:1px solid #333;background:#111;display:flex;flex-direction:column}.preview-bar{height:36px;display:flex;align-items:center;justify-content:space-between;padding:0 10px;background:#252526}.preview-frame{flex:1;width:100%;border:0;background:white}.statusbar{background:#007acc;color:white;padding:3px 10px;font-size:12px}.small{background:#0e639c;border:0;color:white;padding:7px 10px;border-radius:4px;cursor:pointer}.small.secondary{background:#3c3c3c}.icon-button{border:0;background:transparent;color:#fff;font-size:18px;cursor:pointer}@media(max-width:900px){.workspace{grid-template-columns:150px 1fr}.preview{display:none}}
    </style>
    <div class="ide">
      <div class="titlebar"><div class="brand"><input id="slug" aria-label="Seitenname" value="${escapeHtml(slug)}" placeholder="seitenname" style="width:180px;margin-right:8px;padding:6px" ${page ? 'readonly' : ''}>GetVexel <span style="color:#888">— Web-Editor</span></div><div class="actions"><button class="small secondary" id="save" type="button">Speichern</button><button class="small" id="publish" type="button">Veröffentlichen</button></div></div>
      <div class="workspace">
        <aside class="explorer"><strong>EXPLORER</strong><button class="file active" type="button" data-file="html" onclick="switchFile('html')">index.html</button><button class="file" type="button" data-file="css" onclick="switchFile('css')">styles.css</button><button class="file" type="button" data-file="js" onclick="switchFile('js')">script.js</button></aside>
        <section class="editor-pane"><div class="editor-tabs"><button class="tab active" id="active-tab">index.html</button></div><textarea id="code" class="code" spellcheck="false"></textarea></section>
        <section class="preview"><div class="preview-bar"><strong>Vorschau</strong><button class="small secondary" id="refresh" type="button">Aktualisieren</button></div><iframe id="preview" class="preview-frame" title="Live-Vorschau" sandbox="allow-scripts allow-modals"></iframe></section>
      </div>
      <div class="statusbar"><span id="position">Zeile 1, Spalte 1</span>&nbsp;&nbsp; HTML/CSS/JavaScript</div>
    </div>
    <script>
      const loadedFiles=${JSON.stringify(project)};
      const files={html:String(loadedFiles.html||loadedFiles.content||''),css:String(loadedFiles.css||''),js:String(loadedFiles.js||'')};
      let active='html';
      const code=document.querySelector('#code');
      const preview=document.querySelector('#preview');
      const names={html:'index.html',css:'styles.css',js:'script.js'};
      function saveCode(){if(files[active]!==undefined)files[active]=code.value}
      function showFile(fileName){
        saveCode();
        if(!names[fileName]) return;
        active=fileName;
        code.value=String(files[active]||'');
        document.querySelector('#active-tab').textContent=names[active];
        document.querySelectorAll('.file').forEach(button=>button.classList.toggle('active',button.dataset.file===active));
        updatePreview();
        code.focus();
      }
      window.switchFile=showFile;
      function updatePreview(){saveCode();const html=files.html.includes('<html')?files.html:'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>'+files.css+'</style></head><body>'+files.html+'<script>'+files.js+'<\\/script></body></html>';preview.srcdoc=html}
      document.querySelectorAll('.file').forEach(button=>button.addEventListener('click',()=>showFile(button.dataset.file)));
      code.addEventListener('input',()=>{saveCode();updatePreview();const before=code.value.slice(0,code.selectionStart).split('\\n');document.querySelector('#position').textContent='Zeile '+before.length+', Spalte '+(before.at(-1).length+1)});
      code.addEventListener('keydown',event=>{if(event.key==='Tab'){event.preventEvent?.();event.preventDefault();const start=code.selectionStart,end=code.selectionEnd;code.setRangeText('  ',start,end,'end');saveCode();updatePreview()}});
      document.querySelector('#refresh').onclick=updatePreview;
      async function saveProject(){
        saveCode();
        const projectSlug=document.querySelector('#slug').value.trim();
        if(!projectSlug){alert('Bitte einen Seitennamen eingeben');return null}
        const isEdit=${page ? 'true' : 'false'};
        const response=await fetch(isEdit?'/api/pages/'+encodeURIComponent(projectSlug):'/api/pages',{method:isEdit?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({slug:projectSlug,html:files.html,project:files})});
        if(!response.ok)alert(await response.text());
        return response;
      }
      document.querySelector('#save').onclick=async()=>{const response=await saveProject();if(response?.ok)alert('Projekt gespeichert')};
      document.querySelector('#publish').onclick=async()=>{const response=await saveProject();if(response?.ok){window.open('/'+encodeURIComponent(document.querySelector('#slug').value.trim()),'_blank')}};
      showFile('html');
    </script>
  `;
  return htmlPage(page ? 'Web-Editor' : 'Neuer Web-Editor', body);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let path;
    try { path = decodeURIComponent(url.pathname).replace(/^\/+|\/+$/g, ''); }
    catch { return new Response('Ungültiger Pfad', { status: 400 }); }

    if (!env.PAGES_KV) return new Response('PAGES_KV ist nicht konfiguriert.', { status: 500 });

    if (request.method === 'GET' && path === 'auth/google') {
      try {
        if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.SESSION_SECRET) {
          return new Response('OAuth oder SESSION_SECRET ist nicht konfiguriert.', { status: 500 });
        }
        const random = crypto.getRandomValues(new Uint8Array(32));
        const state = base64UrlEncode(random);
        const callback = `${url.origin}/auth/callback`;
        const authorize = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        authorize.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
        authorize.searchParams.set('redirect_uri', callback);
        authorize.searchParams.set('response_type', 'code');
        authorize.searchParams.set('scope', 'openid email profile');
        authorize.searchParams.set('state', state);
        authorize.searchParams.set('prompt', 'select_account');
        return redirectResponse(authorize.toString(), 302, [secureCookie(STATE_COOKIE, state, 'Max-Age=600')]);
      } catch (error) {
        return new Response(`OAuth-Start fehlgeschlagen: ${error.name || 'Unbekannter Fehler'} – ${error.message || 'Keine Detailmeldung'}`, { status: 500 });
      }
    }

    if (request.method === 'GET' && path === 'auth/callback') {
      try {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state || state !== getCookie(request, STATE_COOKIE)) {
        return new Response('Ungültige OAuth-Anmeldung.', { status: 400 });
      }
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: `${url.origin}/auth/callback`, grant_type: 'authorization_code'
        })
      });
      if (!tokenResponse.ok) return new Response('Google-Anmeldung fehlgeschlagen.', { status: 401 });
      const tokens = await tokenResponse.json();
      const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: 'Bearer ' + tokens.access_token }
      });
      if (!profileResponse.ok) return new Response('Google-Profil konnte nicht geladen werden.', { status: 401 });
      const profile = await profileResponse.json();
      if (!profile.sub || !profile.email) return new Response('Google-Konto ist unvollständig.', { status: 401 });
      const sessionData = {
        sub: profile.sub, email: profile.email, name: profile.name || '', exp: Date.now() + 7 * 24 * 60 * 60 * 1000
      };
      await env.PAGES_KV.put(`account:${profile.sub}`, JSON.stringify({
        sub: profile.sub,
        email: profile.email,
        name: profile.name || '',
        lastLoginAt: Date.now()
      }));
      const session = await signValue(env.SESSION_SECRET, sessionData);
      return redirectResponse(`${url.origin}/dashboard`, 303, [
        secureCookie(SESSION_COOKIE, session, 'Max-Age=604800'),
        secureCookie(STATE_COOKIE, '', 'Max-Age=0')
      ]);
      } catch (error) {
        return new Response(`OAuth-Rückkehr fehlgeschlagen: ${error.name || 'Unbekannter Fehler'} – ${error.message || 'Keine Detailmeldung'}`, { status: 500 });
      }
    }

    if (request.method === 'GET' && path === 'auth/logout') {
      return redirectResponse(`${url.origin}/`, 303, [secureCookie(SESSION_COOKIE, '', 'Max-Age=0')]);
    }

    if (path === '' && request.method === 'GET') {
      const session = await getSession(request, env);
      if (session) return redirectResponse(`${url.origin}/dashboard`);
      return new Response(htmlPage('Anmelden', `<section class="card" style="max-width:560px;margin:90px auto;text-align:center"><div class="brand">GetVexel</div><h1>Erstelle deine eigene Webseite</h1><p>Melde dich mit Google an, um Seiten zu veröffentlichen, zu bearbeiten und zu löschen.</p><br><a class="button" href="/auth/google">Mit Google anmelden</a></section>`), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === 'dashboard' || path === 'dashboard/new' || path.startsWith('dashboard/edit/') || path.startsWith('dashboard/template/')) {
      if (request.method !== 'GET') return new Response('Method nicht erlaubt', { status: 405 });
      const session = await getSession(request, env);
      if (!session) return redirectResponse(`${url.origin}/auth/google`);

      if (path === 'dashboard') {
        const listing = await env.PAGES_KV.list({ prefix: `user-pages:${session.sub}:`, limit: 1000 });
        const pages = [];
        for (const key of listing.keys) {
          const slug = key.name.slice(`user-pages:${session.sub}:`.length);
          const html = await env.PAGES_KV.get(`page:${slug}`);
          if (html !== null) pages.push({ slug, html });
        }
        pages.sort((a, b) => a.slug.localeCompare(b.slug));
        const credits = await getMonthlyCredits(env, session.sub);
        return new Response(dashboardPage(session, pages, url.origin, credits), { headers: privateHeaders() });
      }

      if (path === 'dashboard/new') {
        return new Response(templatePage(), { headers: privateHeaders() });
      }

      if (path.startsWith('dashboard/template/')) {
        const templateName = cleanSlug(path.slice('dashboard/template/'.length));
        const template = pageTemplates[templateName];
        if (!template) return new Response('Vorlage nicht gefunden.', { status: 404 });
        return new Response(editorPage({ project: template }), { headers: privateHeaders() });
      }

      const slug = cleanSlug(decodeURIComponent(path.slice('dashboard/edit/'.length)));
      const meta = await env.PAGES_KV.get(`page-meta:${slug}`, 'json');
      if (!meta || meta.owner !== session.sub) return new Response('Seite nicht gefunden oder nicht dein Eigentum.', { status: 404 });
      const html = await env.PAGES_KV.get(`page:${slug}`);
      const project = await env.PAGES_KV.get(`project:${slug}`, 'json');
      return new Response(editorPage({ slug, html: html || '', project }), { headers: privateHeaders() });
    }

    if (path === 'databases' && request.method === 'GET') {
      const session = await getSession(request, env);
      if (!session) return redirectResponse(`${url.origin}/auth/google`);
      if (!env.DB) return new Response('D1-Datenbank ist nicht konfiguriert.', { status: 500 });
      const credits = await getMonthlyCredits(env, session.sub);
      const result = await env.DB.prepare('SELECT id, name FROM user_databases WHERE owner_sub = ? ORDER BY name').bind(session.sub).all();
      return new Response(databasePage(result.results || [], credits), { headers: privateHeaders() });
    }

    if (path.startsWith('databases/') && request.method === 'GET') {
      const session = await getSession(request, env);
      if (!session) return redirectResponse(`${url.origin}/auth/google`);
      if (!env.DB) return new Response('D1-Datenbank ist nicht konfiguriert.', { status: 500 });
      const id = cleanSlug(decodeURIComponent(path.slice('databases/'.length)));
      const database = await env.DB.prepare('SELECT id, name FROM user_databases WHERE id = ? AND owner_sub = ?').bind(id, session.sub).first();
      if (!database) return new Response('Datenbank nicht gefunden.', { status: 404 });
      const items = await env.DB.prepare('SELECT id, name, json_data, created_at FROM database_items WHERE database_id = ? AND owner_sub = ? ORDER BY created_at DESC').bind(id, session.sub).all();
      return new Response(databaseDetailPage(database, items.results || []), { headers: privateHeaders() });
    }

    if (path === 'api/databases' || path.startsWith('api/databases/')) {
      const session = await getSession(request, env);
      if (!session) return new Response('Bitte melde dich mit Google an.', { status: 401 });
      if (!env.DB) return new Response('D1-Datenbank ist nicht konfiguriert.', { status: 500 });

      const id = path.startsWith('api/databases/') ? cleanSlug(decodeURIComponent(path.slice('api/databases/'.length))) : '';

      if (request.method === 'POST' && path === 'api/databases') {
        let body; try { body = await request.json(); } catch { return new Response('Ungültige Daten.', { status: 400 }); }
        const name = String(body.name || '').trim().slice(0, 40);
        if (!name) return new Response('Bitte einen Datenbanknamen eingeben.', { status: 400 });
        const count = await env.DB.prepare('SELECT COUNT(*) AS count FROM user_databases WHERE owner_sub = ?').bind(session.sub).first();
        if ((count?.count || 0) >= 3) return new Response('Du kannst maximal drei Datenbanken erstellen.', { status: 409 });
        const databaseId = crypto.randomUUID();
        await env.DB.prepare('INSERT INTO user_databases (id, owner_sub, name) VALUES (?, ?, ?)').bind(databaseId, session.sub, name).run();
        return new Response(JSON.stringify({ id: databaseId, name }), { headers: { 'Content-Type': 'application/json' } });
      }

      if (request.method === 'POST' && id) {
        const database = await env.DB.prepare('SELECT id FROM user_databases WHERE id = ? AND owner_sub = ?').bind(id, session.sub).first();
        if (!database) return new Response('Datenbank nicht gefunden.', { status: 404 });
        let body; try { body = await request.json(); } catch { return new Response('Ungültige Daten.', { status: 400 }); }
        const name = String(body.name || 'Eintrag').trim().slice(0, 80);
        const remaining = await chargeCredits(env, session.sub, 10);
        if (remaining === null) return new Response('Nicht genügend Credits für einen Datenbank-Eintrag.', { status: 402 });
        const itemId = crypto.randomUUID();
        await env.DB.prepare('INSERT INTO database_items (id, database_id, owner_sub, name, json_data, created_at) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(itemId, id, session.sub, name, JSON.stringify(body.data || {}), Date.now()).run();
        return new Response(JSON.stringify({ id: itemId, name }), { headers: { 'Content-Type': 'application/json' } });
      }

      if (request.method === 'GET' && id) {
        const remaining = await chargeCredits(env, session.sub, 5);
        if (remaining === null) return new Response('Nicht genügend Credits für diesen Datenbank-Lesezugriff.', { status: 402 });
        const database = await env.DB.prepare('SELECT id, name FROM user_databases WHERE id = ? AND owner_sub = ?').bind(id, session.sub).first();
        if (!database) return new Response('Datenbank nicht gefunden.', { status: 404 });
        const items = await env.DB.prepare('SELECT id, name, json_data, created_at FROM database_items WHERE database_id = ? AND owner_sub = ? ORDER BY created_at DESC').bind(id, session.sub).all();
        return new Response(JSON.stringify({ database, items: items.results || [] }), { headers: { 'Content-Type': 'application/json' } });
      }

      if (request.method === 'DELETE' && id) {
        const deleted = await env.DB.prepare('DELETE FROM user_databases WHERE id = ? AND owner_sub = ?').bind(id, session.sub).run();
        if (!deleted.meta.changes) return new Response('Datenbank nicht gefunden.', { status: 404 });
        await env.DB.prepare('DELETE FROM database_items WHERE database_id = ? AND owner_sub = ?').bind(id, session.sub).run();
        return new Response('OK');
      }

      return new Response('Method nicht erlaubt', { status: 405 });
    }

    if (path === 'api/assets' && request.method === 'POST') {
      const session = await getSession(request, env);
      if (!session) return new Response('Bitte melde dich mit Google an.', { status: 401 });
      let form;
      try { form = await request.formData(); } catch { return new Response('Ungültige Datei.', { status: 400 }); }
      const file = form.get('file');
      if (!(file instanceof File)) return new Response('Keine Datei ausgewählt.', { status: 400 });
      if (!file.type?.startsWith('image/')) return new Response('Nur Bilddateien sind erlaubt.', { status: 400 });
      if (file.size > 2 * 1024 * 1024) return new Response('Das Bild darf maximal 2 MB groß sein.', { status: 413 });
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = '';
      for (let index = 0; index < bytes.length; index += 8192) {
        binary += String.fromCharCode(...bytes.subarray(index, index + 8192));
      }
      const id = crypto.randomUUID();
      await env.PAGES_KV.put(`asset:${id}`, JSON.stringify({ owner: session.sub, type: file.type, data: btoa(binary) }));
      return new Response(JSON.stringify({ url: `${url.origin}/assets/${id}` }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (path.startsWith('assets/') && request.method === 'GET') {
      const id = cleanSlug(path.slice('assets/'.length));
      if (!id) return new Response('Bild nicht gefunden.', { status: 404 });
      const asset = await env.PAGES_KV.get(`asset:${id}`, 'json');
      if (!asset?.data) return new Response('Bild nicht gefunden.', { status: 404 });
      const binary = atob(asset.data);
      const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
      return new Response(bytes, {
        headers: {
          'Content-Type': asset.type || 'application/octet-stream',
          'Cache-Control': 'public, max-age=31536000, immutable'
        }
      });
    }

    if (path === 'api/pages' || path.startsWith('api/pages/')) {
      const session = await getSession(request, env);
      if (!session) return new Response('Bitte melde dich mit Google an.', { status: 401 });
      const slug = cleanSlug(path.startsWith('api/pages/') ? decodeURIComponent(path.slice('api/pages/'.length)) : '');

      if (request.method === 'POST' && path === 'api/pages') {
        let body; try { body = await request.json(); } catch { return new Response('Ungültige Daten.', { status: 400 }); }
        const requestedSlug = cleanSlug(body.slug || '');
        if (!requestedSlug) return new Response('Bitte einen gültigen Seitennamen eingeben.', { status: 400 });
        if (!body.html) return new Response('Bitte HTML-Inhalt eingeben.', { status: 400 });
        if (['dashboard', 'auth', 'api'].includes(requestedSlug) || requestedSlug.startsWith('dashboard')) {
          return new Response('Dieser Seitenname ist reserviert.', { status: 400 });
        }
        const legacy = await env.PAGES_KV.get(requestedSlug);
        const meta = await env.PAGES_KV.get(`page-meta:${requestedSlug}`, 'json');
        if (legacy !== null || meta !== null) return new Response('Dieser Seitenname ist leider schon vergeben.', { status: 409 });
        const pageHtml = body.project ? combineProject(body.project) : String(body.html);
        await env.PAGES_KV.put(`page:${requestedSlug}`, pageHtml);
        if (body.project) await env.PAGES_KV.put(`project:${requestedSlug}`, JSON.stringify(body.project));
        await env.PAGES_KV.put(`page-meta:${requestedSlug}`, JSON.stringify({ owner: session.sub, email: session.email, updatedAt: Date.now() }));
        await env.PAGES_KV.put(`user-pages:${session.sub}:${requestedSlug}`, '1');
        return new Response('OK');
      }

      if (request.method === 'PUT' && slug) {
        const meta = await env.PAGES_KV.get(`page-meta:${slug}`, 'json');
        if (!meta) return new Response('Seite nicht gefunden.', { status: 404 });
        if (meta.owner !== session.sub) return new Response('Du darfst diese Seite nicht bearbeiten.', { status: 403 });
        let body; try { body = await request.json(); } catch { return new Response('Ungültige Daten.', { status: 400 }); }
        if (!body.html) return new Response('Bitte HTML-Inhalt eingeben.', { status: 400 });
        const pageHtml = body.project ? combineProject(body.project) : String(body.html);
        await env.PAGES_KV.put(`page:${slug}`, pageHtml);
        if (body.project) await env.PAGES_KV.put(`project:${slug}`, JSON.stringify(body.project));
        await env.PAGES_KV.put(`page-meta:${slug}`, JSON.stringify({ owner: session.sub, email: session.email, updatedAt: Date.now() }));
        return new Response('OK');
      }

      if (request.method === 'DELETE' && slug) {
        const meta = await env.PAGES_KV.get(`page-meta:${slug}`, 'json');
        if (!meta) return new Response('Seite nicht gefunden.', { status: 404 });
        if (meta.owner !== session.sub) return new Response('Du darfst diese Seite nicht löschen.', { status: 403 });
        await env.PAGES_KV.delete(`page:${slug}`);
        await env.PAGES_KV.delete(`page-meta:${slug}`);
        await env.PAGES_KV.delete(`project:${slug}`);
        await env.PAGES_KV.delete(`user-pages:${session.sub}:${slug}`);
        return new Response('OK');
      }

      return new Response('Method nicht erlaubt', { status: 405 });
    }

    if (request.method === 'GET' && path) {
      const savedHtml = await env.PAGES_KV.get(`page:${path}`);
      if (savedHtml !== null) {
        return new Response(savedHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' } });
      }
      const legacy = await env.PAGES_KV.get(path);
      if (legacy !== null) {
        return new Response(legacy, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' } });
      }
      return new Response(htmlPage('Nicht gefunden', '<section class="card"><h1>404</h1><p>Diese Seite existiert noch nicht.</p><a class="button" href="/">Zur Startseite</a></section>',), { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    return new Response('Not Found', { status: 404 });
  }
};
