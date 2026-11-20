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

function privateHeaders() {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache'
  };
}

function htmlPage(title, body) {
  return `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} – GetVexel</title><style>
    :root{color-scheme:dark}*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#0b1220;color:#edf2f7}.shell{max-width:980px;margin:auto;padding:32px 20px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:28px}.brand{font-size:22px;font-weight:800}.card{background:#111c30;border:1px solid #263652;border-radius:14px;padding:22px;margin:16px 0}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}input,textarea{width:100%;padding:12px;border-radius:8px;border:1px solid #334a70;background:#0b1425;color:white;font:inherit}textarea{min-height:360px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.actions{display:flex;gap:10px;flex-wrap:wrap}button,.button{display:inline-block;border:0;border-radius:8px;padding:11px 16px;background:#3b82f6;color:white;font-weight:700;text-decoration:none;cursor:pointer}.button.secondary{background:#263652}.danger{background:#b42318}p{color:#b8c5d9}.page-row{display:flex;justify-content:space-between;align-items:center;gap:12px}.muted{color:#94a3b8;font-size:14px}@media(max-width:700px){.grid{grid-template-columns:1fr}.top,.page-row{align-items:flex-start;flex-direction:column}}
  </style></head><body><main class="shell">${body}</main></body></html>`;
}

function dashboardPage(user, pages, origin) {
  const rows = pages.map(page => `<article class="card page-row"><div><strong>${escapeHtml(page.slug)}</strong><div class="muted">${escapeHtml(origin)}/${escapeHtml(page.slug)}</div></div><div class="actions"><a class="button secondary" href="/${encodeURIComponent(page.slug)}" target="_blank">Ansehen</a><a class="button" href="/dashboard/edit/${encodeURIComponent(page.slug)}">Bearbeiten</a><button class="danger" type="button" onclick="deletePage('${escapeHtml(page.slug)}')">Löschen</button></div></article>`).join('');
  return htmlPage('Dashboard', `<div class="top"><div><div class="brand">GetVexel</div><div class="muted">Angemeldet als ${escapeHtml(user.email)}</div></div><div class="actions"><a class="button" href="/dashboard/new">Neue Seite</a><a class="button secondary" href="/auth/logout">Abmelden</a></div></div><h1>Meine Seiten</h1>${rows || '<div class="card"><p>Du hast noch keine Seiten erstellt.</p></div>'}<script>async function deletePage(slug){if(!confirm('Diese Seite wirklich löschen?'))return;const response=await fetch('/api/pages/'+encodeURIComponent(slug),{method:'DELETE'});if(response.ok){location.reload()}else{alert(await response.text())}}</script>`);
}

function editorPage(page = null) {
  const slug = page?.slug || '';
  const content = page?.html || '<h1>Meine neue Seite</h1>\n<p>Hallo Welt!</p>';
  const pageJson = JSON.stringify(content);
  const body = `
    <style>
      .studio{display:grid;grid-template-columns:150px minmax(420px,1fr) 250px;min-height:650px;gap:12px}
      .panel{background:#111c30;border:1px solid #263652;border-radius:12px;padding:12px}
      .toolbox button{width:100%;margin:7px 0;text-align:left}.canvas-wrap{overflow:auto;padding:18px}
      .canvas-frame{width:100%;height:610px;border:0;border-radius:6px;background:white}
      .properties label{display:block;margin-top:12px}.properties input,.properties textarea{width:100%;margin-top:5px}
      .properties textarea{min-height:70px}.tabs{display:flex;gap:8px;margin-bottom:10px}
      .tabs button.active{outline:2px solid #93c5fd}#code{height:610px;font-family:ui-monospace,monospace}
      #image-upload{display:none}.upload-label{display:block!important;width:100%;padding:10px;margin:7px 0!important;text-align:left;background:#263652;border-radius:8px;cursor:pointer}
      @media(max-width:900px){.studio{grid-template-columns:1fr}.canvas-frame{height:600px}}
    </style>
    <div class="top"><div class="brand">GetVexel Studio</div><div class="actions"><a class="button secondary" href="/dashboard">Zur Übersicht</a><button class="button" id="publish" type="button">Veröffentlichen</button></div></div>
    <div class="tabs"><button type="button" id="visual-tab" class="active">Design-Ansicht</button><button type="button" id="code-tab">HTML/CSS/JS</button></div>
    <div id="visual-mode" class="studio">
      <aside class="panel toolbox"><strong>Elemente</strong>
        <button type="button" data-type="heading">Überschrift</button>
        <button type="button" data-type="text">Textabsatz</button>
        <button type="button" data-type="button">Button</button>
        <button type="button" data-type="box">Box</button>
        <label class="upload-label" for="image-upload">Bild hochladen</label><input id="image-upload" type="file" accept="image/*">
      </aside>
      <div class="panel canvas-wrap"><iframe id="canvas" class="canvas-frame" title="Design-Canvas" sandbox="allow-scripts allow-modals"></iframe></div>
      <aside class="panel properties"><strong>Ausgewähltes Element</strong>
        <label>Seitenname</label><input id="slug" value="${escapeHtml(slug)}" ${page ? 'readonly' : ''} required pattern="[A-Za-z0-9_-]+">
        <label>Text</label><textarea id="element-text"></textarea>
        <label>Breite (px)</label><input id="element-width" type="number" min="20">
        <label>Höhe (px)</label><input id="element-height" type="number" min="20">
        <label>X-Position</label><input id="element-left" type="number">
        <label>Y-Position</label><input id="element-top" type="number">
        <label>Hintergrund</label><input id="element-bg" type="color" value="#ffffff">
        <label>Textfarbe</label><input id="element-color" type="color" value="#111111">
        <button class="danger" id="delete-element" type="button">Element löschen</button>
      </aside>
    </div>
    <div id="code-mode" hidden><textarea id="code" aria-label="HTML, CSS und JavaScript">${escapeHtml(content)}</textarea></div>
    <script>
      const canvas=document.querySelector('#canvas');
      const code=document.querySelector('#code');
      const visual=document.querySelector('#visual-mode');
      const codeMode=document.querySelector('#code-mode');
      const visualTab=document.querySelector('#visual-tab');
      const codeTab=document.querySelector('#code-tab');
      let current=${pageJson};

      function editorScript(){
        return String.raw\`<script>
          document.querySelectorAll('*').forEach(el=>{if(el.matches('body,html,head,style,script'))return;el.setAttribute('data-gve','true')});
          let selected=null,drag=false,startX=0,startY=0,baseX=0,baseY=0;
          function select(el){if(selected)selected.classList.remove('gve-selected');selected=el;if(el){el.classList.add('gve-selected');sendInfo()}}
          function sendInfo(){if(!selected)return;const r=selected.getBoundingClientRect(),s=getComputedStyle(selected);parent.postMessage({type:'gve-select',text:selected.innerText||selected.alt||'',width:Math.round(r.width),height:Math.round(r.height),left:Math.round(r.left),top:Math.round(r.top),bg:s.backgroundColor,color:s.color},'*')}
          document.addEventListener('pointerdown',e=>{const el=e.target.closest('[data-gve]');if(!el)return;select(el);const r=el.getBoundingClientRect();drag=true;startX=e.clientX;startY=e.clientY;baseX=r.left;baseY=r.top;e.preventDefault();el.setPointerCapture?.(e.pointerId)});
          document.addEventListener('pointermove',e=>{if(!drag||!selected)return;selected.style.position='absolute';selected.style.left=(baseX+e.clientX-startX)+'px';selected.style.top=(baseY+e.clientY-startY)+'px';sendInfo()});
          document.addEventListener('pointerup',()=>drag=false);
          document.addEventListener('dblclick',e=>{const el=e.target.closest('[data-gve]');if(!el)return;el.setAttribute('contenteditable','true');el.focus()});
          addEventListener('message',e=>{const m=e.data;if(!m||!selected)return;if(m.type==='gve-set'){if(m.key==='text'){if(selected.tagName==='IMG')selected.alt=m.value;else selected.innerText=m.value}if(m.key==='width')selected.style.width=m.value+'px';if(m.key==='height')selected.style.height=m.value+'px';if(m.key==='left')selected.style.position='absolute',selected.style.left=m.value+'px';if(m.key==='top')selected.style.position='absolute',selected.style.top=m.value+'px';if(m.key==='bg')selected.style.background=m.value;if(m.key==='color')selected.style.color=m.value;sendInfo()}if(m.type==='gve-delete'){selected.remove();selected=null}if(m.type==='gve-add'){const el=document.createElement(m.tag);el.setAttribute('data-gve','true');el.style.position='absolute';el.style.left='40px';el.style.top='40px';if(m.tag==='h1'){el.textContent='Neue Überschrift';el.style.fontSize='32px'}if(m.tag==='p'){el.textContent='Neuer Textabsatz'}if(m.tag==='button'){el.textContent='Klick mich';el.style.padding='12px 18px'}if(m.tag==='div'){el.style.width='220px';el.style.height='140px';el.style.background='#dbeafe'}if(m.tag==='img'){el.src=m.url||'';el.style.width='220px'}document.body.appendChild(el);select(el)}if(m.type==='gve-serialize'){document.querySelectorAll('.gve-selected').forEach(el=>el.classList.remove('gve-selected'));document.querySelectorAll('[contenteditable]').forEach(el=>el.removeAttribute('contenteditable'));document.querySelectorAll('[data-gve]').forEach(el=>el.removeAttribute('data-gve'));parent.postMessage({type:'gve-html',html:'<!doctype html>'+document.documentElement.outerHTML},'*')}});
        <\/script>\`;
      }

      function render(){
        let value=current;
        if(!value.toLowerCase().includes('<html'))value='<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>html,body{min-height:100%;margin:0}.gve-selected{outline:3px solid #3b82f6!important}</style></head><body>'+value+'</body></html>';
        else value=value.replace('</head>','<style>html,body{min-height:100%;margin:0}.gve-selected{outline:3px solid #3b82f6!important}</style></head>');
        canvas.srcdoc=value.replace('</body>',editorScript()+'</body>');
      }

      visualTab.onclick=()=>{visual.hidden=false;codeMode.hidden=true;visualTab.classList.add('active');codeTab.classList.remove('active');current=code.value;render()};
      codeTab.onclick=()=>{visual.hidden=true;codeMode.hidden=false;codeTab.classList.add('active');visualTab.classList.remove('active')};
      code.addEventListener('input',()=>{current=code.value;render()});
      document.querySelectorAll('[data-type]').forEach(button=>button.onclick=()=>canvas.contentWindow.postMessage({type:'gve-add',tag:{heading:'h1',text:'p',button:'button',box:'div'}[button.dataset.type]},'*'));

      document.querySelector('#image-upload').addEventListener('change',async event=>{
        const file=event.target.files[0];if(!file)return;
        const form=new FormData();form.append('file',file);
        const response=await fetch('/api/assets',{method:'POST',body:form});
        if(!response.ok){alert(await response.text());return}
        const result=await response.json();canvas.contentWindow.postMessage({type:'gve-add',tag:'img',url:result.url},'*');event.target.value='';
      });

      const properties={text:'element-text',width:'element-width',height:'element-height',left:'element-left',top:'element-top',bg:'element-bg',color:'element-color'};
      addEventListener('message',e=>{const m=e.data;if(m.type==='gve-select'){document.querySelector('#element-text').value=m.text||'';document.querySelector('#element-width').value=m.width||'';document.querySelector('#element-height').value=m.height||'';document.querySelector('#element-left').value=m.left||'';document.querySelector('#element-top').value=m.top||''}});
      ['text','width','height','left','top','bg','color'].forEach(key=>document.querySelector('#'+properties[key]).addEventListener('input',event=>canvas.contentWindow.postMessage({type:'gve-set',key,value:event.target.value},'*')));
      document.querySelector('#delete-element').onclick=()=>canvas.contentWindow.postMessage({type:'gve-delete'},'*');

      let pendingResolve=null;addEventListener('message',e=>{if(e.data.type==='gve-html'&&pendingResolve){pendingResolve(e.data.html);pendingResolve=null}});
      async function serialize(){return new Promise(resolve=>{pendingResolve=resolve;canvas.contentWindow.postMessage({type:'gve-serialize'},'*');setTimeout(()=>{if(pendingResolve){pendingResolve=null;resolve(current)}},800)})}
      render();
      document.querySelector('#publish').onclick=async()=>{
        const slug=document.querySelector('#slug').value;
        const html=codeMode.hidden?await serialize():code.value;
        const published=window.open('about:blank','_blank');
        const response=await fetch(${page ? "'/api/pages/'+encodeURIComponent(slug)" : "'/api/pages'"},{method:${page ? "'PUT'" : "'POST'"},headers:{'Content-Type':'application/json'},body:JSON.stringify({slug,html})});
        if(response.ok){published.location.href='/'+encodeURIComponent(slug)}else{if(published)published.close();alert(await response.text())}
      };
    </script>
  `;
  return htmlPage(page ? 'Seite bearbeiten' : 'Neue Seite', body);
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

    if (path === 'dashboard' || path === 'dashboard/new' || path.startsWith('dashboard/edit/')) {
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
        return new Response(dashboardPage(session, pages, url.origin), { headers: privateHeaders() });
      }

      if (path === 'dashboard/new') {
        return new Response(editorPage(), { headers: privateHeaders() });
      }

      const slug = cleanSlug(decodeURIComponent(path.slice('dashboard/edit/'.length)));
      const meta = await env.PAGES_KV.get(`page-meta:${slug}`, 'json');
      if (!meta || meta.owner !== session.sub) return new Response('Seite nicht gefunden oder nicht dein Eigentum.', { status: 404 });
      const html = await env.PAGES_KV.get(`page:${slug}`);
      return new Response(editorPage({ slug, html: html || '' }), { headers: privateHeaders() });
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
        await env.PAGES_KV.put(`page:${requestedSlug}`, String(body.html));
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
        await env.PAGES_KV.put(`page:${slug}`, String(body.html));
        await env.PAGES_KV.put(`page-meta:${slug}`, JSON.stringify({ owner: session.sub, email: session.email, updatedAt: Date.now() }));
        return new Response('OK');
      }

      if (request.method === 'DELETE' && slug) {
        const meta = await env.PAGES_KV.get(`page-meta:${slug}`, 'json');
        if (!meta) return new Response('Seite nicht gefunden.', { status: 404 });
        if (meta.owner !== session.sub) return new Response('Du darfst diese Seite nicht löschen.', { status: 403 });
        await env.PAGES_KV.delete(`page:${slug}`);
        await env.PAGES_KV.delete(`page-meta:${slug}`);
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
