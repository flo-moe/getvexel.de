const SESSION_COOKIE = '__Host-getvexel-session';
const STATE_COOKIE = '__Host-getvexel-oauth-state';

function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
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
  return htmlPage(page ? 'Seite bearbeiten' : 'Neue Seite', `<div class="top"><div class="brand">GetVexel</div><a class="button secondary" href="/dashboard">Zur Übersicht</a></div><h1>${page ? 'Seite bearbeiten' : 'Neue Seite erstellen'}</h1><div class="card"><form id="editor"><label>Seitenname</label><input id="slug" name="slug" value="${escapeHtml(slug)}" ${page ? 'readonly' : ''} required pattern="[A-Za-z0-9_-]+" placeholder="meine-seite"><br><br><label>HTML-Inhalt</label><textarea id="html" name="html">${escapeHtml(content)}</textarea><br><br><div class="actions"><button type="submit">${page ? 'Änderungen veröffentlichen' : 'Seite veröffentlichen'}</button></div></form></div><script>document.querySelector('#editor').addEventListener('submit',async event=>{event.preventDefault();const slug=document.querySelector('#slug').value;const html=document.querySelector('#html').value;const response=await fetch(${page ? "'/api/pages/'+encodeURIComponent(slug)" : "'/api/pages'"},{method:${page ? "'PUT'" : "'POST'"},headers:{'Content-Type':'application/json'},body:JSON.stringify({slug,html})});if(response.ok){location.href='/' + encodeURIComponent(slug)}else{alert(await response.text())}})</script>`);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let path;
    try { path = decodeURIComponent(url.pathname).replace(/^\/+|\/+$/g, ''); }
    catch { return new Response('Ungültiger Pfad', { status: 400 }); }

    if (!env.PAGES_KV) return new Response('PAGES_KV ist nicht konfiguriert.', { status: 500 });

    if (request.method === 'GET' && path === 'auth/google') {
      if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.SESSION_SECRET) {
        return new Response('OAuth oder SESSION_SECRET ist nicht konfiguriert.', { status: 500 });
      }
      const state = crypto.randomUUID();
      await signValue(env.SESSION_SECRET, { state });
      const callback = `${url.origin}/auth/callback`;
      const authorize = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      authorize.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
      authorize.searchParams.set('redirect_uri', callback);
      authorize.searchParams.set('response_type', 'code');
      authorize.searchParams.set('scope', 'openid email profile');
      authorize.searchParams.set('state', state);
      authorize.searchParams.set('prompt', 'select_account');
      const response = Response.redirect(authorize.toString(), 302);
      response.headers.append('Set-Cookie', secureCookie(STATE_COOKIE, state, 'Max-Age=600'));
      return response;
    }

    if (request.method === 'GET' && path === 'auth/callback') {
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
        headers: { Authorization: `Bearer ${tokens.access_token}` }
      });
      if (!profileResponse.ok) return new Response('Google-Profil konnte nicht geladen werden.', { status: 401 });
      const profile = await profileResponse.json();
      if (!profile.sub || !profile.email) return new Response('Google-Konto ist unvollständig.', { status: 401 });
      const session = await signValue(env.SESSION_SECRET, {
        sub: profile.sub, email: profile.email, name: profile.name || '', exp: Date.now() + 7 * 24 * 60 * 60 * 1000
      });
      const response = Response.redirect(`${url.origin}/dashboard`, 303);
      response.headers.append('Set-Cookie', secureCookie(SESSION_COOKIE, session, 'Max-Age=604800'));
      response.headers.append('Set-Cookie', secureCookie(STATE_COOKIE, '', 'Max-Age=0'));
      return response;
    }

    if (request.method === 'GET' && path === 'auth/logout') {
      const response = Response.redirect(`${url.origin}/`, 303);
      response.headers.append('Set-Cookie', secureCookie(SESSION_COOKIE, '', 'Max-Age=0'));
      return response;
    }

    if (path === '' && request.method === 'GET') {
      const session = await getSession(request, env);
      if (session) return Response.redirect(`${url.origin}/dashboard`, 303);
      return new Response(htmlPage('Anmelden', `<section class="card" style="max-width:560px;margin:90px auto;text-align:center"><div class="brand">GetVexel</div><h1>Erstelle deine eigene Webseite</h1><p>Melde dich mit Google an, um Seiten zu veröffentlichen, zu bearbeiten und zu löschen.</p><br><a class="button" href="/auth/google">Mit Google anmelden</a></section>`), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === 'dashboard' || path === 'dashboard/new' || path.startsWith('dashboard/edit/')) {
      if (request.method !== 'GET') return new Response('Method nicht erlaubt', { status: 405 });
      const session = await getSession(request, env);
      if (!session) return Response.redirect(`${url.origin}/auth/google`, 303);

      if (path === 'dashboard') {
        const listing = await env.PAGES_KV.list({ prefix: `user-pages:${session.sub}:`, limit: 1000 });
        const pages = [];
        for (const key of listing.keys) {
          const slug = key.name.slice(`user-pages:${session.sub}:`.length);
          const html = await env.PAGES_KV.get(`page:${slug}`);
          if (html !== null) pages.push({ slug, html });
        }
        pages.sort((a, b) => a.slug.localeCompare(b.slug));
        return new Response(dashboardPage(session, pages, url.origin), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      if (path === 'dashboard/new') {
        return new Response(editorPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      const slug = cleanSlug(decodeURIComponent(path.slice('dashboard/edit/'.length)));
      const meta = await env.PAGES_KV.get(`page-meta:${slug}`, 'json');
      if (!meta || meta.owner !== session.sub) return new Response('Seite nicht gefunden oder nicht dein Eigentum.', { status: 404 });
      const html = await env.PAGES_KV.get(`page:${slug}`);
      return new Response(editorPage({ slug, html: html || '' }), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
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
