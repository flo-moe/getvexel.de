const SESSION_COOKIE = '__Host-getvexel-session';
const STATE_COOKIE = '__Host-getvexel-oauth-state';

const MAX_PROJECT_SIZE = 1000000;
const MAX_REQUEST_SIZE = 1200000;
const MAX_IMAGE_SIZE = 2097152;

const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[ch]));
}

function cleanSlug(value) {
  return String(value || '')
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-_]/g, '')
    .slice(0, 80);
}

function base64Url(bytes) {
  const view = bytes instanceof ArrayBuffer
    ? new Uint8Array(bytes)
    : Uint8Array.from(bytes);

  let binary = '';

  for (const byte of view) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function unbase64Url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - value.length % 4) % 4);

  return Uint8Array.from(atob(padded), ch => ch.charCodeAt(0));
}

async function signSession(secret, session) {
  const encoded = base64Url(
    new TextEncoder().encode(JSON.stringify(session))
  );

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(encoded)
  );

  return encoded + '.' + base64Url(signature);
}

async function verifySession(secret, signed) {
  if (!secret || !signed) return null;

  const parts = signed.split('.');

  if (parts.length !== 2) return null;

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      unbase64Url(parts[1]),
      new TextEncoder().encode(parts[0])
    );

    if (!valid) return null;

    const session = JSON.parse(
      new TextDecoder().decode(unbase64Url(parts[0]))
    );

    return session.exp > Date.now() ? session : null;
  } catch {
    return null;
  }
}

function assertSameOrigin(request, url) {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
    const origin = request.headers.get('Origin');

    if (!origin || origin !== url.origin) return false;

    const secFetchSite = request.headers.get('Sec-Fetch-Site');

    if (
      secFetchSite &&
      secFetchSite !== 'same-origin' &&
      secFetchSite !== 'none'
    ) {
      return false;
    }
  }

  return true;
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value)
  );

  return base64Url(digest);
}

async function verifyGoogleIdToken(idToken, clientId, nonce) {
  const parts = idToken.split('.');

  if (parts.length !== 3) {
    throw new Error('Ungültiges Google-ID-Token');
  }

  const header = JSON.parse(
    new TextDecoder().decode(unbase64Url(parts[0]))
  );

  const payload = JSON.parse(
    new TextDecoder().decode(unbase64Url(parts[1]))
  );

  if (header.alg !== 'RS256') {
    throw new Error('Ungültiger Signaturalgorithmus');
  }

  if (payload.aud !== clientId) {
    throw new Error('Ungültige Token-Zielgruppe');
  }

  if (
    payload.iss !== 'https://accounts.google.com' &&
    payload.iss !== 'accounts.google.com'
  ) {
    throw new Error('Ungültiger Token-Aussteller');
  }

  if (!payload.exp || payload.exp * 1000 <= Date.now()) {
    throw new Error('Token abgelaufen');
  }

  if (!nonce || payload.nonce !== nonce) {
    throw new Error('Ungültige OAuth-Nonce');
  }

  if (payload.email_verified !== true) {
    throw new Error('Google-E-Mail ist nicht verifiziert');
  }

  if (payload.iat && payload.iat * 1000 > Date.now() + 300000) {
    throw new Error('Ungültiges Token-Ausstellungsdatum');
  }

  if (payload.azp && payload.azp !== clientId) {
    throw new Error('Ungültiger autorisierter Client');
  }

  const jwksResponse = await fetch(
    'https://www.googleapis.com/oauth2/v3/certs'
  );

  if (!jwksResponse.ok) {
    throw new Error('Google-Schlüssel konnten nicht geladen werden');
  }

  const jwks = await jwksResponse.json();

  const key = (jwks.keys || []).find(
    item => item.kid === header.kid
  );

  if (!key) {
    throw new Error('Google-Signaturschlüssel nicht gefunden');
  }

  const cryptoKey = await crypto.subtle.importKey(
    'jwk',
    key,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    },
    false,
    ['verify']
  );

  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    unbase64Url(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1])
  );

  if (!valid) {
    throw new Error('Ungültige Google-Signatur');
  }

  return payload;
}

function getCookie(request, name) {
  const match = request.headers.get('Cookie')?.match(
    new RegExp(`(?:^|;\\s*)${name}=([^;]*)`)
  );

  if (!match) return null;

  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

function cookie(name, value, options = '') {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax${options ? `; ${options}` : ''}`;
}

function redirect(location, status = 303, cookies = []) {
  const headers = new Headers({ Location: location });

  for (const value of cookies) {
    headers.append('Set-Cookie', value);
  }

  return new Response(null, { status, headers });
}

async function currentUser(request, env) {
  if (!env.SESSION_SECRET) return null;

  return verifySession(
    env.SESSION_SECRET,
    getCookie(request, SESSION_COOKIE)
  );
}

function getPagesOrigin(env, url) {
  let origin = env.PAGES_ORIGIN;

  if (
    !origin &&
    url.hostname === 'getvexel.flomoe.workers.dev'
  ) {
    origin = 'https://getvexel-pages.flomoe.workers.dev';
  }

  if (!origin) {
    throw new Error('PAGES_ORIGIN ist nicht konfiguriert.');
  }

  let pagesUrl;

  try {
    pagesUrl = new URL(origin);
  } catch {
    throw new Error('PAGES_ORIGIN ist keine gültige URL.');
  }

  if (
    pagesUrl.protocol !== 'https:' ||
    pagesUrl.origin === url.origin
  ) {
    throw new Error(
      'PAGES_ORIGIN muss HTTPS verwenden und vom Dashboard getrennt sein.'
    );
  }

  return pagesUrl.origin;
}

function privateHeaders(extra = {}) {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
    ...extra
  };
}

function validImageBytes(bytes) {
  if (!bytes || bytes.length < 12) return null;

  // PNG
  if (
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return 'image/png';
  }

  // JPEG
  if (
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) {
    return 'image/jpeg';
  }

  // GIF
  if (
    bytes[0] === 0x47 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x38 &&
    (bytes[4] === 0x37 || bytes[4] === 0x39) &&
    bytes[5] === 0x61
  ) {
    return 'image/gif';
  }

  // WebP
  if (
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return 'image/webp';
  }

  return null;
}

function normalizeProject(project) {
  if (
    !project ||
    typeof project !== 'object' ||
    Array.isArray(project)
  ) {
    throw new Error('Ungültiges Projektformat.');
  }

  return {
    html: String(project.html || ''),
    css: String(project.css || ''),
    js: String(project.js || '')
  };
}

function combineProject(project) {
  const html = String(project.html || '');

  const css = String(project.css || '')
    .replace(/<\/?style[^>]*>/gi, '');

  const js = String(project.js || '')
    .replace(/<\/script/gi, '<\\/script');

  if (/<html[\s>]/i.test(html)) {
    let output = html;

    if (css) {
      if (/<\/head>/i.test(output)) {
        output = output.replace(
          /<\/head>/i,
          `<style>${css}</style></head>`
        );
      } else if (/<head[\s>]/i.test(output)) {
        output = output.replace(
          /<head[^>]*>/i,
          match => match + `<style>${css}</style>`
        );
      } else {
        output = `<style>${css}</style>` + output;
      }
    }

    if (js) {
      if (/<\/body>/i.test(output)) {
        output = output.replace(
          /<\/body>/i,
          `<script>${js}</script></body>`
        );
      } else {
        output += `<script>${js}</script>`;
      }
    }

    return output;
  }

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>${css}</style>
</head>
<body>
${html}
<script>${js}</script>
</body>
</html>`;
}

function shell(title, body) {
  return `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} – GetVexel</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#0b1220;color:#edf2f7}
.wrap{max-width:980px;margin:auto;padding:32px 20px}
.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}
.brand{font-size:22px;font-weight:800}
.card{background:#111c30;border:1px solid #263652;border-radius:14px;padding:20px;margin:12px 0}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
input,textarea{width:100%;padding:12px;border-radius:8px;border:1px solid #334a70;background:#0b1425;color:white;font:inherit}
.actions{display:flex;gap:8px;flex-wrap:wrap}
button,.button{display:inline-block;border:0;border-radius:8px;padding:11px 16px;background:#3b82f6;color:white;font-weight:700;text-decoration:none;cursor:pointer}
button:disabled{opacity:.55;cursor:not-allowed}
.secondary{background:#263652}
.danger{background:#b42318}
.muted{color:#94a3b8;font-size:14px}
@media(max-width:700px){
.grid{grid-template-columns:1fr}
.top,.row{align-items:flex-start;flex-direction:column}
}
</style>
</head>
<body>
<main class="wrap">${body}</main>
</body>
</html>`;
}

function dashboard(user, pages, pagesOrigin, credits) {
  const rows = pages.map(page => `
<article class="card row">
<div>
<strong>${escapeHtml(page.slug)}</strong>
<div class="muted">${escapeHtml(pagesOrigin)}/${escapeHtml(page.slug)}</div>
</div>
<div class="actions">
<a class="button secondary" href="${escapeHtml(pagesOrigin)}/${encodeURIComponent(page.slug)}" target="_blank" rel="noopener noreferrer">Ansehen</a>
<a class="button" href="/dashboard/edit/${encodeURIComponent(page.slug)}">Bearbeiten</a>
<button class="danger" type="button" onclick="removePage('${escapeHtml(page.slug)}')">Löschen</button>
</div>
</article>`).join('');

  return shell(
    'Dashboard',
    `
<div class="top">
<div>
<div class="brand">GetVexel</div>
<div class="muted">${escapeHtml(user.email)} · ${credits} Credits</div>
</div>
<div class="actions">
<a class="button" href="/dashboard/new">Neue Seite</a>
<a class="button secondary" href="/databases">Datenbanken</a>
<form method="POST" action="/auth/logout">
<button class="button secondary" type="submit">Abmelden</button>
</form>
</div>
</div>
<h1>Meine Seiten</h1>
${rows || '<div class="card"><p>Noch keine Seite erstellt.</p></div>'}
<script>
async function removePage(slug) {
  if (!confirm('Seite wirklich löschen?')) return;

  const response = await fetch(
    '/api/pages/' + encodeURIComponent(slug),
    { method: 'DELETE' }
  );

  if (response.ok) {
    location.reload();
  } else {
    alert(await response.text());
  }
}
</script>`
  );
}

/*
 * EDITOR
 * Neue Projekte beginnen immer mit leerem HTML, CSS und JavaScript.
 * Es gibt keine Vorlagen mehr.
 */

function editorPage(page = null) {
  const slug = page?.slug || '';

  const project = page?.project
    ? normalizeProject(page.project)
    : {
        html: page?.html || '',
        css: '',
        js: ''
      };

  const isExistingPage = Boolean(page?.slug);

  const projectJson = JSON.stringify(project)
    .replace(/</g, '\\u003C')
    .replace(/>/g, '\\u003E')
    .replace(/&/g, '\\u0026');

  return shell(
    'Web-Editor',
    `
<style>
body{overflow:hidden}
.wrap{max-width:none;height:100vh;padding:0}
.ide{height:100vh;display:grid;grid-template-rows:44px 1fr 24px;background:#1e1e1e;color:#ddd}
.bar{display:flex;align-items:center;justify-content:space-between;height:44px;padding:0 12px;background:#181818;border-bottom:1px solid #333}
.workspace{display:grid;grid-template-columns:180px minmax(220px,1fr) 48%;min-height:0}
.explorer{padding:10px;background:#252526;border-right:1px solid #333}
.explorer strong{display:block;margin-bottom:8px}
.file{display:block;width:100%;border:0;background:transparent;color:#ccc;text-align:left;padding:9px;cursor:pointer}
.file.active{background:#37373d;color:white}
.editor{display:flex;flex-direction:column;min-width:0}
.tabname{height:36px;padding:9px 14px;background:#252526;border-bottom:1px solid #333;color:white}
.code{flex:1;width:100%;resize:none;border:0;outline:none;padding:16px;background:#1e1e1e;color:#d4d4d4;font:14px/1.5 ui-monospace,monospace;box-sizing:border-box}
.preview{display:flex;flex-direction:column;border-left:1px solid #333;background:#111}
.previewbar{height:36px;padding:0 10px;display:flex;align-items:center;justify-content:space-between;background:#252526}
.previewframe{flex:1;width:100%;border:0;background:white}
.status{height:24px;padding:3px 10px;background:#007acc;color:white;font-size:12px}
.small{border:0;border-radius:4px;padding:7px 10px;background:#0e639c;color:white;cursor:pointer}
.small.secondary{background:#3c3c3c}
@media(max-width:900px){
.workspace{grid-template-columns:150px 1fr}
.preview{display:none}
}
</style>

<div class="ide">
<div class="bar">
<div>
<input
id="slug"
value="${escapeHtml(slug)}"
placeholder="seitenname"
style="width:220px;margin-right:8px;padding:8px;color:#111;background:#fff"
${isExistingPage ? 'readonly' : ''}
>
<strong>GetVexel Web-Editor</strong>
</div>

<div>
<button class="small secondary" id="save" type="button">Speichern</button>
<button class="small" id="publish" type="button">Veröffentlichen</button>
</div>
</div>

<div class="workspace">
<aside class="explorer">
<strong>EXPLORER</strong>
<button class="file active" type="button" data-file="html">index.html</button>
<button class="file" type="button" data-file="css">styles.css</button>
<button class="file" type="button" data-file="js">script.js</button>
</aside>

<section class="editor">
<div class="tabname" id="tabname">index.html</div>
<textarea id="code" class="code" spellcheck="false"></textarea>
</section>

<section class="preview">
<div class="previewbar">
<strong>Vorschau</strong>
<button class="small secondary" id="refresh" type="button">Aktualisieren</button>
</div>
<iframe id="preview" class="previewframe" title="Live-Vorschau"></iframe>
</section>
</div>

<div class="status">
<span id="position">Zeile 1, Spalte 1</span>
</div>
</div>

<script>
window.__GETVEXEL_PROJECT__=${projectJson};
window.__GETVEXEL_EDIT__=${isExistingPage ? 'true' : 'false'};
</script>

<script src="/editor.js?v=20261122-4" defer></script>
`
  );
}

async function monthlyCredits(env, ownerSub) {
  if (!env.DB) return 5000;

  const month = new Date().toISOString().slice(0, 7);

  await env.DB.batch([
    env.DB.prepare(
      'INSERT OR IGNORE INTO user_credits(owner_sub, month, credits) VALUES(?, ?, 5000)'
    ).bind(ownerSub, month),

    env.DB.prepare(
      'UPDATE user_credits SET month=?, credits=5000 WHERE owner_sub=? AND month<>?'
    ).bind(month, ownerSub, month)
  ]);

  const account = await env.DB.prepare(
    'SELECT credits, month FROM user_credits WHERE owner_sub=?'
  ).bind(ownerSub).first();

  return account?.credits ?? 5000;
}

async function readJson(request, maxSize) {
  const length = Number(request.headers.get('Content-Length') || 0);

  if (length > maxSize) {
    throw new Error('REQUEST_TOO_LARGE');
  }

  const text = await request.text();

  if (text.length > maxSize) {
    throw new Error('REQUEST_TOO_LARGE');
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error('INVALID_JSON');
  }
}

function validateProjectBody(body) {
  if (
    !body ||
    typeof body !== 'object' ||
    Array.isArray(body)
  ) {
    throw new Error('Ungültige Daten.');
  }

  const project = body.project
    ? normalizeProject(body.project)
    : {
        html: String(body.html || ''),
        css: '',
        js: ''
      };

  const totalSize =
    project.html.length +
    project.css.length +
    project.js.length;

  if (totalSize > MAX_PROJECT_SIZE) {
    throw new Error('Projekt ist zu groß.');
  }

  return project;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

function textResponse(message, status = 200) {
  return new Response(message, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    let path;

    try {
      path = decodeURIComponent(url.pathname)
        .replace(/^\/+|\/+$/g, '');
    } catch {
      return textResponse('Ungültiger Pfad.', 400);
    }

    if (!env.PAGES_KV) {
      return textResponse('PAGES_KV fehlt.', 500);
    }

    if (!assertSameOrigin(request, url)) {
      return textResponse(
        'Cross-Origin-Anfrage nicht erlaubt.',
        403
      );
    }

    try {
      // EDITOR JAVASCRIPT

      if (path === 'editor.js' && request.method === 'GET') {
        const script = `(() => {
          const boot = () => {
            const code = document.querySelector('#code');
            const preview = document.querySelector('#preview');

            if (!code || !preview) return;

            const project = window.__GETVEXEL_PROJECT__ || {
              html: '',
              css: '',
              js: ''
            };

            const files = {
              html: String(project.html || ''),
              css: String(project.css || ''),
              js: String(project.js || '')
            };

            const names = {
              html: 'index.html',
              css: 'styles.css',
              js: 'script.js'
            };

            let active = 'html';
            let isExisting = Boolean(window.__GETVEXEL_EDIT__);
            let saving = false;

            function saveCurrent() {
              files[active] = code.value;
            }

            function updateCursor() {
              const before = code.value
                .slice(0, code.selectionStart)
                .split('\\n');

              const position = document.querySelector('#position');

              if (position) {
                position.textContent =
                  'Zeile ' + before.length +
                  ', Spalte ' + (before[before.length - 1].length + 1);
              }
            }

            function updatePreview() {
              saveCurrent();

              let html;

              if (/<html[\\s>]/i.test(files.html)) {
                html = files.html;

                if (files.css) {
                  if (/<\\/head>/i.test(html)) {
                    html = html.replace(
                      /<\\/head>/i,
                      '<style>' + files.css + '</style></head>'
                    );
                  } else {
                    html += '<style>' + files.css + '</style>';
                  }
                }

                if (files.js) {
                  const scriptOpen = '<scr' + 'ipt>';
                  const scriptClose = '</scr' + 'ipt>';

                  if (/<\\/body>/i.test(html)) {
                    html = html.replace(
                      /<\\/body>/i,
                      scriptOpen + files.js + scriptClose + '</body>'
                    );
                  } else {
                    html += scriptOpen + files.js + scriptClose;
                  }
                }
              } else {
                const scriptOpen = '<scr' + 'ipt>';
                const scriptClose = '</scr' + 'ipt>';

                html =
                  '<!doctype html><html><head>' +
                  '<meta charset="utf-8">' +
                  '<meta name="viewport" content="width=device-width">' +
                  '<style>' + files.css + '</style>' +
                  '</head><body>' +
                  files.html +
                  (files.js ? scriptOpen + files.js + scriptClose : '') +
                  '</body></html>';
              }

              preview.srcdoc = html;
            }

            function openFile(name) {
              saveCurrent();

              active = name;
              code.value = files[name] || '';

              const tab = document.querySelector('#tabname');

              if (tab) tab.textContent = names[name];

              document.querySelectorAll('.file').forEach(button => {
                button.classList.toggle(
                  'active',
                  button.dataset.file === name
                );
              });

              updateCursor();
              code.focus();
              updatePreview();
            }

            document.querySelectorAll('.file').forEach(button => {
              button.addEventListener('click', () => {
                openFile(button.dataset.file);
              });
            });

            code.addEventListener('input', () => {
              saveCurrent();
              updateCursor();
              updatePreview();
            });

            code.addEventListener('keyup', updateCursor);
            code.addEventListener('click', updateCursor);

            code.addEventListener('keydown', event => {
              if (event.key !== 'Tab') return;

              event.preventDefault();

              const start = code.selectionStart;
              const end = code.selectionEnd;

              code.setRangeText('  ', start, end, 'end');

              saveCurrent();
              updatePreview();
            });

            const refresh = document.querySelector('#refresh');

            if (refresh) {
              refresh.addEventListener('click', updatePreview);
            }

            async function saveProject() {
              if (saving) return null;

              saveCurrent();

              const slugInput = document.querySelector('#slug');

              const name = slugInput
                ? slugInput.value.trim().toLowerCase()
                    .replace(/\\s+/g, '-')
                    .replace(/[^a-z0-9-_]/g, '')
                    .slice(0, 80)
                : '';

              if (!name) {
                alert('Bitte zuerst einen Seitennamen eingeben.');
                return null;
              }

              saving = true;

              const saveButton = document.querySelector('#save');
              const publishButton = document.querySelector('#publish');

              if (saveButton) saveButton.disabled = true;
              if (publishButton) publishButton.disabled = true;

              try {
                const response = await fetch(
                  isExisting
                    ? '/api/pages/' + encodeURIComponent(name)
                    : '/api/pages',
                  {
                    method: isExisting ? 'PUT' : 'POST',
                    headers: {
                      'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                      slug: name,
                      html: files.html,
                      project: files
                    })
                  }
                );

                if (!response.ok) {
                  const message = await response.text();
                  alert(message || 'Speichern fehlgeschlagen.');
                  return null;
                }

                isExisting = true;
                window.__GETVEXEL_EDIT__ = true;

                if (slugInput) {
                  slugInput.value = name;
                  slugInput.readOnly = true;
                }

                return response;
              } catch (error) {
                alert('Verbindung fehlgeschlagen. Bitte erneut versuchen.');
                return null;
              } finally {
                saving = false;

                if (saveButton) saveButton.disabled = false;
                if (publishButton) publishButton.disabled = false;
              }
            }

            const save = document.querySelector('#save');

            if (save) {
              save.addEventListener('click', async () => {
                const response = await saveProject();

                if (response && response.ok) {
                  alert('Deine Seite wurde gespeichert.');
                }
              });
            }

            // Veröffentlichen: Fenster synchron beim Klick öffnen.

            const publish = document.querySelector('#publish');

            if (publish) {
              publish.addEventListener('click', async () => {
                const slugInput = document.querySelector('#slug');

                const slug = slugInput
                  ? slugInput.value.trim().toLowerCase()
                      .replace(/\\s+/g, '-')
                      .replace(/[^a-z0-9-_]/g, '')
                      .slice(0, 80)
                  : '';

                if (!slug) {
                  alert('Bitte zuerst einen Seitennamen eingeben.');
                  return;
                }

                const newWindow = window.open('about:blank', '_blank');

                if (newWindow) {
                  newWindow.document.open();
                  newWindow.document.write(
                    '<!doctype html><html lang="de"><head>' +
                    '<meta charset="utf-8">' +
                    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
                    '<title>GetVexel – Veröffentlichung</title>' +
                    '<style>' +
                    'body{margin:0;min-height:100vh;display:grid;place-items:center;' +
                    'background:#0b1220;color:white;font-family:system-ui,sans-serif}' +
                    'main{text-align:center;padding:24px}p{color:#94a3b8}' +
                    '</style></head><body><main>' +
                    '<h2>Deine Seite wird veröffentlicht ...</h2>' +
                    '<p>Bitte einen Moment warten.</p>' +
                    '</main></body></html>'
                  );
                  newWindow.document.close();
                }

                const response = await saveProject();

                if (response && response.ok) {
                  const pageUrl = '/' + encodeURIComponent(slug);

                  if (newWindow && !newWindow.closed) {
                    newWindow.location.replace(pageUrl);
                  } else {
                    alert(
                      'Deine Seite wurde veröffentlicht:\\n' +
                      location.origin + pageUrl
                    );
                  }
                } else if (newWindow && !newWindow.closed) {
                  newWindow.close();
                }
              });
            }

            openFile('html');
          };

          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', boot);
          } else {
            boot();
          }
        })();`;

        return new Response(script, {
          headers: {
            'Content-Type': 'application/javascript; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate'
          }
        });
      }

      // GOOGLE OAUTH

      if (path === 'auth/google' && request.method === 'GET') {
        if (
          !env.GOOGLE_CLIENT_ID ||
          !env.GOOGLE_CLIENT_SECRET ||
          !env.SESSION_SECRET
        ) {
          return textResponse(
            'Google-OAuth ist nicht konfiguriert.',
            500
          );
        }

        const state = crypto.randomUUID();
        const nonce = crypto.randomUUID();

        const verifierBytes = crypto.getRandomValues(
          new Uint8Array(32)
        );

        const verifier = base64Url(verifierBytes);
        const challenge = await sha256Base64Url(verifier);

        const callback = `${url.origin}/auth/callback`;

        const authorize = new URL(
          'https://accounts.google.com/o/oauth2/v2/auth'
        );

        authorize.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
        authorize.searchParams.set('redirect_uri', callback);
        authorize.searchParams.set('response_type', 'code');
        authorize.searchParams.set('scope', 'openid email profile');
        authorize.searchParams.set('prompt', 'select_account');
        authorize.searchParams.set('state', state);
        authorize.searchParams.set('nonce', nonce);
        authorize.searchParams.set('code_challenge', challenge);
        authorize.searchParams.set('code_challenge_method', 'S256');

        const oauthCookie = base64Url(
          new TextEncoder().encode(
            JSON.stringify({ state, nonce, verifier })
          )
        );

        return redirect(
          authorize.toString(),
          302,
          [cookie(STATE_COOKIE, oauthCookie, 'Max-Age=600')]
        );
      }

      if (path === 'auth/callback' && request.method === 'GET') {
        try {
          const code = url.searchParams.get('code');
          const state = url.searchParams.get('state');
          const oauthCookie = getCookie(request, STATE_COOKIE);

          if (!code || !state || !oauthCookie) {
            return new Response(
              'Ungültige OAuth-Anmeldung.',
              { status: 400 }
            );
          }

          let oauthData;

          try {
            oauthData = JSON.parse(
              new TextDecoder().decode(unbase64Url(oauthCookie))
            );
          } catch {
            return new Response(
              'Ungültige OAuth-Anmeldung.',
              { status: 400 }
            );
          }

          if (state !== oauthData.state) {
            return new Response(
              'Ungültiger OAuth-State.',
              { status: 400 }
            );
          }

          const tokenResponse = await fetch(
            'https://oauth2.googleapis.com/token',
            {
              method: 'POST',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
              },
              body: new URLSearchParams({
                code,
                client_id: env.GOOGLE_CLIENT_ID,
                client_secret: env.GOOGLE_CLIENT_SECRET,
                redirect_uri: `${url.origin}/auth/callback`,
                grant_type: 'authorization_code',
                code_verifier: oauthData.verifier
              })
            }
          );

          if (!tokenResponse.ok) {
            return new Response(
              'Google-Anmeldung fehlgeschlagen.',
              { status: 401 }
            );
          }

          const tokens = await tokenResponse.json();

          if (!tokens.id_token) {
            return new Response(
              'Google-ID-Token fehlt.',
              { status: 401 }
            );
          }

          const claims = await verifyGoogleIdToken(
            tokens.id_token,
            env.GOOGLE_CLIENT_ID,
            oauthData.nonce
          );

          if (
            !claims.sub ||
            !claims.email ||
            claims.email_verified !== true
          ) {
            return new Response(
              'Google-Konto ist unvollständig oder die E-Mail ist nicht verifiziert.',
              { status: 401 }
            );
          }

          const signed = await signSession(
            env.SESSION_SECRET,
            {
              sub: claims.sub,
              email: claims.email,
              name: claims.name || '',
              exp: Date.now() + SESSION_DURATION
            }
          );

          return redirect(
            `${url.origin}/dashboard`,
            303,
            [
              cookie(SESSION_COOKIE, signed, 'Max-Age=604800'),
              cookie(STATE_COOKIE, '', 'Max-Age=0')
            ]
          );
        } catch (error) {
          console.error('OAuth callback failed', error.name);

          return new Response(
            'Google-Anmeldung konnte nicht abgeschlossen werden.',
            { status: 500 }
          );
        }
      }

      if (path === 'auth/logout' && request.method === 'POST') {
        return redirect(
          `${url.origin}/`,
          303,
          [cookie(SESSION_COOKIE, '', 'Max-Age=0')]
        );
      }

      // STARTSEITE

      if (path === '' && request.method === 'GET') {
        const user = await currentUser(request, env);

        if (user) {
          return redirect(`${url.origin}/dashboard`);
        }

        return new Response(
          shell(
            'Anmelden',
            `
<section class="card" style="max-width:560px;margin:90px auto;text-align:center">
<div class="brand">GetVexel</div>
<h1>Eigene Seiten erstellen</h1>
<p>Melde dich mit Google an.</p>
<a class="button" href="/auth/google">Mit Google anmelden</a>
</section>`
          ),
          { headers: privateHeaders() }
        );
      }

      // DASHBOARD

      if (path.startsWith('dashboard')) {
        if (request.method !== 'GET') {
          return textResponse('Method nicht erlaubt.', 405);
        }

        const user = await currentUser(request, env);

        if (!user) {
          return redirect(`${url.origin}/auth/google`);
        }

        if (path === 'dashboard') {
          const listing = await env.PAGES_KV.list({
            prefix: `owner:${user.sub}:`,
            limit: 1000
          });

          const pages = [];

          for (const key of listing.keys) {
            const slug = key.name.slice(
              `owner:${user.sub}:`.length
            );

            const html = await env.PAGES_KV.get(`page:${slug}`);
            const meta = await env.PAGES_KV.get(
              `meta:${slug}`,
              'json'
            );

            if (html !== null && meta?.owner === user.sub) {
              pages.push({ slug, html });
            }
          }

          const credits = env.DB
            ? await monthlyCredits(env, user.sub)
            : 5000;

          pages.sort((a, b) => a.slug.localeCompare(b.slug));

          const pagesOrigin = getPagesOrigin(env, url);

          return new Response(
            dashboard(user, pages, pagesOrigin, credits),
            { headers: privateHeaders() }
          );
        }

        // NEUES PROJEKT: DIREKT EIN LEERER EDITOR

        if (path === 'dashboard/new') {
          return new Response(
            editorPage(),
            { headers: privateHeaders() }
          );
        }

        // BESTEHENDE SEITE BEARBEITEN

        if (path.startsWith('dashboard/edit/')) {
          const slug = cleanSlug(
            path.slice('dashboard/edit/'.length)
          );

          const meta = await env.PAGES_KV.get(
            `meta:${slug}`,
            'json'
          );

          if (!meta || meta.owner !== user.sub) {
            return textResponse('Seite nicht gefunden.', 404);
          }

          const html = await env.PAGES_KV.get(`page:${slug}`);

          const project = await env.PAGES_KV.get(
            `project:${slug}`,
            'json'
          );

          return new Response(
            editorPage({ slug, html: html || '', project }),
            { headers: privateHeaders() }
          );
        }

        return textResponse('Seite nicht gefunden.', 404);
      }

      // DATENBANKEN-SEITE

      if (path === 'databases' && request.method === 'GET') {
        const user = await currentUser(request, env);

        if (!user) {
          return redirect(`${url.origin}/auth/google`);
        }

        if (!env.DB) {
          return textResponse('D1 ist nicht konfiguriert.', 500);
        }

        const credits = await monthlyCredits(env, user.sub);

        const result = await env.DB.prepare(
          'SELECT id, name FROM user_databases WHERE owner_sub = ? ORDER BY name'
        ).bind(user.sub).all();

        const cards = (result.results || []).map(db => `
<article class="card row">
<strong>${escapeHtml(db.name)}</strong>
<div class="actions">
<button class="danger" onclick="removeDb('${escapeHtml(db.id)}')">Löschen</button>
</div>
</article>`).join('');

        return new Response(
          shell(
            'Datenbanken',
            `
<div class="top">
<div>
<div class="brand">Meine Datenbanken</div>
<div class="muted">${credits} Credits</div>
</div>
<a class="button secondary" href="/dashboard">Zum Dashboard</a>
</div>

<form id="create-db">
<input id="db-name" maxlength="40" placeholder="Datenbankname" required>
<br><br>
<button>Erstellen</button>
</form>

<h1>Datenbanken</h1>

${cards || '<div class="card"><p>Noch keine Datenbank.</p></div>'}

<script>
document.querySelector('#create-db').onsubmit = async event => {
  event.preventDefault();

  const response = await fetch('/api/databases', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: document.querySelector('#db-name').value
    })
  });

  if (response.ok) {
    location.reload();
  } else {
    alert(await response.text());
  }
};

async function removeDb(id) {
  if (!confirm('Löschen?')) return;

  const response = await fetch(
    '/api/databases/' + encodeURIComponent(id),
    { method: 'DELETE' }
  );

  if (response.ok) {
    location.reload();
  } else {
    alert(await response.text());
  }
}
</script>`
          ),
          { headers: privateHeaders() }
        );
      }

      // DATENBANK-API

      if (
        path === 'api/databases' ||
        path.startsWith('api/databases/')
      ) {
        const user = await currentUser(request, env);

        if (!user) {
          return textResponse('Anmeldung erforderlich.', 401);
        }

        if (!env.DB) {
          return textResponse('D1 ist nicht konfiguriert.', 500);
        }

        const id = path.startsWith('api/databases/')
          ? path.slice('api/databases/'.length)
          : '';

        if (id && !/^[a-zA-Z0-9-]{1,80}$/.test(id)) {
          return textResponse('Ungültige Datenbank-ID.', 400);
        }

        if (request.method === 'POST' && path === 'api/databases') {
          let body;

          try {
            body = await readJson(request, 65536);
          } catch (error) {
            return textResponse(
              error.message === 'REQUEST_TOO_LARGE'
                ? 'Anfrage ist zu groß.'
                : 'Ungültige Daten.',
              error.message === 'REQUEST_TOO_LARGE' ? 413 : 400
            );
          }

          if (
            !body ||
            typeof body !== 'object' ||
            Array.isArray(body)
          ) {
            return textResponse('Ungültige Daten.', 400);
          }

          const name = String(body.name || '').trim().slice(0, 40);

          if (!name) {
            return textResponse('Name fehlt.', 400);
          }

          const databaseId = crypto.randomUUID();

          try {
            await env.DB.prepare(
              'INSERT INTO user_databases(id, owner_sub, name) VALUES(?, ?, ?)'
            ).bind(databaseId, user.sub, name).run();
          } catch (error) {
            if (
              String(error.message || error).includes(
                'database limit reached'
              )
            ) {
              return textResponse('Maximal drei Datenbanken.', 409);
            }

            throw error;
          }

          return jsonResponse({ id: databaseId, name });
        }

        if (request.method === 'POST' && id) {
          const owned = await env.DB.prepare(
            'SELECT id FROM user_databases WHERE id=? AND owner_sub=?'
          ).bind(id, user.sub).first();

          if (!owned) {
            return textResponse('Datenbank nicht gefunden.', 404);
          }

          let body;

          try {
            body = await readJson(request, 65536);
          } catch (error) {
            return textResponse(
              error.message === 'REQUEST_TOO_LARGE'
                ? 'Anfrage ist zu groß.'
                : 'Ungültige Daten.',
              error.message === 'REQUEST_TOO_LARGE' ? 413 : 400
            );
          }

          if (
            !body ||
            typeof body !== 'object' ||
            Array.isArray(body)
          ) {
            return textResponse('Ungültige Daten.', 400);
          }

          await monthlyCredits(env, user.sub);

          const itemId = crypto.randomUUID();

          const data = JSON.stringify(
            body.data && typeof body.data === 'object'
              ? body.data
              : {}
          );

          const insert = env.DB.prepare(
            `INSERT INTO database_items
            (id,database_id,owner_sub,name,json_data,created_at)
            SELECT ?,?,?,?,?,?
            WHERE EXISTS (
              SELECT 1 FROM user_credits
              WHERE owner_sub=? AND credits>=10
            )`
          ).bind(
            itemId,
            id,
            user.sub,
            String(body.name || 'Eintrag').slice(0, 80),
            data,
            Date.now(),
            user.sub
          );

          const charge = env.DB.prepare(
            'UPDATE user_credits SET credits=credits-10 WHERE owner_sub=? AND credits>=10'
          ).bind(user.sub);

          const result = await env.DB.batch([insert, charge]);

          if (
            !result[0].meta.changes ||
            !result[1].meta.changes
          ) {
            return textResponse('Nicht genügend Credits.', 402);
          }

          return jsonResponse({ id: itemId });
        }

        if (request.method === 'GET' && id) {
          const owned = await env.DB.prepare(
            'SELECT id,name FROM user_databases WHERE id=? AND owner_sub=?'
          ).bind(id, user.sub).first();

          if (!owned) {
            return textResponse('Datenbank nicht gefunden.', 404);
          }

          await monthlyCredits(env, user.sub);

          const charge = env.DB.prepare(
            'UPDATE user_credits SET credits=credits-5 WHERE owner_sub=? AND credits>=5'
          ).bind(user.sub);

          const items = env.DB.prepare(
            'SELECT id,name,json_data,created_at FROM database_items WHERE database_id=? AND owner_sub=? ORDER BY created_at DESC'
          ).bind(id, user.sub);

          const result = await env.DB.batch([charge, items]);

          if (!result[0].meta.changes) {
            return textResponse('Nicht genügend Credits.', 402);
          }

          return jsonResponse({
            database: owned,
            items: result[1].results || []
          });
        }

        if (request.method === 'DELETE' && id) {
          await env.DB.prepare(
            'DELETE FROM database_items WHERE database_id=? AND owner_sub=?'
          ).bind(id, user.sub).run();

          const deleted = await env.DB.prepare(
            'DELETE FROM user_databases WHERE id=? AND owner_sub=?'
          ).bind(id, user.sub).run();

          if (!deleted.meta.changes) {
            return textResponse('Datenbank nicht gefunden.', 404);
          }

          return textResponse('OK');
        }

        return textResponse('Method nicht erlaubt.', 405);
      }

      // BILDER-UPLOAD

      if (path === 'api/assets' && request.method === 'POST') {
        const user = await currentUser(request, env);

        if (!user) {
          return textResponse('Anmeldung erforderlich.', 401);
        }

        const contentLength = Number(
          request.headers.get('Content-Length') || 0
        );

        if (contentLength > 2200000) {
          return textResponse('Upload zu groß.', 413);
        }

        let form;

        try {
          form = await request.formData();
        } catch {
          return textResponse('Ungültiger Upload.', 400);
        }

        const file = form.get('file');

        if (!(file instanceof File)) {
          return textResponse('Keine gültige Bilddatei.', 400);
        }

        if (file.size > MAX_IMAGE_SIZE) {
          return textResponse('Bild zu groß.', 413);
        }

        const bytes = new Uint8Array(
          await file.arrayBuffer()
        );

        const detectedType = validImageBytes(bytes);

        if (!detectedType) {
          return textResponse(
            'Nur PNG, JPEG, GIF oder WebP sind erlaubt.',
            415
          );
        }

        let binary = '';

        for (let i = 0; i < bytes.length; i += 8192) {
          binary += String.fromCharCode(
            ...bytes.subarray(i, i + 8192)
          );
        }

        const id = crypto.randomUUID();

        await env.PAGES_KV.put(
          `asset:${id}`,
          JSON.stringify({
            owner: user.sub,
            type: detectedType,
            data: btoa(binary)
          })
        );

        const pagesOrigin = getPagesOrigin(env, url);

        return jsonResponse({
          url: `${pagesOrigin}/assets/${id}`
        });
      }

      // ALTE ASSET-URLS WEITERLEITEN

      if (path.startsWith('assets/') && request.method === 'GET') {
        const pagesOrigin = getPagesOrigin(env, url);

        return redirect(
          `${pagesOrigin}/${path}`,
          302
        );
      }

      // SEITEN-API

      if (
        path === 'api/pages' ||
        path.startsWith('api/pages/')
      ) {
        const user = await currentUser(request, env);

        if (!user) {
          return textResponse('Anmeldung erforderlich.', 401);
        }

        const slug = path.startsWith('api/pages/')
          ? cleanSlug(path.slice('api/pages/'.length))
          : '';

        // NEUE SEITE ERSTELLEN

        if (
          request.method === 'POST' &&
          path === 'api/pages'
        ) {
          if (!env.DB) {
            return textResponse('D1 ist nicht konfiguriert.', 500);
          }

          let body;

          try {
            body = await readJson(request, MAX_REQUEST_SIZE);
          } catch (error) {
            return textResponse(
              error.message === 'REQUEST_TOO_LARGE'
                ? 'Projekt ist zu groß.'
                : 'Ungültige Daten.',
              error.message === 'REQUEST_TOO_LARGE' ? 413 : 400
            );
          }

          if (
            !body ||
            typeof body !== 'object' ||
            Array.isArray(body)
          ) {
            return textResponse('Ungültige Daten.', 400);
          }

          const name = cleanSlug(body.slug || '');

          if (!name) {
            return textResponse('Seitennamen eingeben.', 400);
          }

          let project;

          try {
            project = validateProjectBody(body);
          } catch (error) {
            return textResponse(error.message, 400);
          }

          // Seitenname reservieren.

          try {
            await env.DB.prepare(
              'INSERT INTO reserved_slugs(slug, owner_sub, status) VALUES(?, ?, ?)'
            ).bind(name, user.sub, 'pending').run();
          } catch (error) {
            const message = String(error.message || error);

            if (
              message.includes('UNIQUE') ||
              message.includes('PRIMARY')
            ) {
              const existing = await env.DB.prepare(
                'SELECT owner_sub, status FROM reserved_slugs WHERE slug=?'
              ).bind(name).first();

              if (!existing) {
                return textResponse(
                  'Seitenname konnte nicht geprüft werden.',
                  409
                );
              }

              if (existing.owner_sub !== user.sub) {
                return textResponse(
                  'Seitenname bereits vergeben.',
                  409
                );
              }

              const meta = await env.PAGES_KV.get(
                `meta:${name}`,
                'json'
              );

              if (meta && existing.status === 'complete') {
                return textResponse(
                  'Seitenname bereits vergeben.',
                  409
                );
              }

              await env.PAGES_KV.delete(`page:${name}`);
              await env.PAGES_KV.delete(`project:${name}`);
              await env.PAGES_KV.delete(`meta:${name}`);
              await env.PAGES_KV.delete(`owner:${user.sub}:${name}`);

              await env.DB.prepare(
                "UPDATE reserved_slugs SET status='pending' WHERE slug=? AND owner_sub=?"
              ).bind(name, user.sub).run();
            } else {
              throw error;
            }
          }

          const html = combineProject(project);

          try {
            await env.PAGES_KV.put(
              `page:${name}`,
              html
            );

            await env.PAGES_KV.put(
              `project:${name}`,
              JSON.stringify(project)
            );

            await env.PAGES_KV.put(
              `meta:${name}`,
              JSON.stringify({
                owner: user.sub,
                updatedAt: Date.now()
              })
            );

            await env.PAGES_KV.put(
              `owner:${user.sub}:${name}`,
              '1'
            );

            await env.DB.prepare(
              "UPDATE reserved_slugs SET status='complete' WHERE slug=? AND owner_sub=?"
            ).bind(name, user.sub).run();
          } catch (error) {
            await env.DB.prepare(
              "UPDATE reserved_slugs SET status='failed' WHERE slug=? AND owner_sub=?"
            ).bind(name, user.sub).run();

            console.error(
              'Incomplete page creation',
              name,
              error.name
            );

            return textResponse(
              'Seite konnte nicht vollständig veröffentlicht werden.',
              500
            );
          }

          return textResponse('OK');
        }

        // BESTEHENDE SEITE BEARBEITEN

        if (
          request.method === 'PUT' &&
          slug
        ) {
          const meta = await env.PAGES_KV.get(
            `meta:${slug}`,
            'json'
          );

          if (!meta) {
            return textResponse('Seite nicht gefunden.', 404);
          }

          if (meta.owner !== user.sub) {
            return textResponse('Nicht erlaubt.', 403);
          }

          let body;

          try {
            body = await readJson(request, MAX_REQUEST_SIZE);
          } catch (error) {
            return textResponse(
              error.message === 'REQUEST_TOO_LARGE'
                ? 'Projekt ist zu groß.'
                : 'Ungültige Daten.',
              error.message === 'REQUEST_TOO_LARGE' ? 413 : 400
            );
          }

          let project;

          try {
            project = validateProjectBody(body);
          } catch (error) {
            return textResponse(error.message, 400);
          }

          await env.PAGES_KV.put(
            `page:${slug}`,
            combineProject(project)
          );

          await env.PAGES_KV.put(
            `project:${slug}`,
            JSON.stringify(project)
          );

          await env.PAGES_KV.put(
            `meta:${slug}`,
            JSON.stringify({
              owner: user.sub,
              updatedAt: Date.now()
            })
          );

          return textResponse('OK');
        }

        // SEITE LÖSCHEN

        if (
          request.method === 'DELETE' &&
          slug
        ) {
          const meta = await env.PAGES_KV.get(
            `meta:${slug}`,
            'json'
          );

          if (!meta) {
            return textResponse('Seite nicht gefunden.', 404);
          }

          if (meta.owner !== user.sub) {
            return textResponse('Nicht erlaubt.', 403);
          }

          await env.PAGES_KV.delete(`page:${slug}`);
          await env.PAGES_KV.delete(`project:${slug}`);
          await env.PAGES_KV.delete(`meta:${slug}`);
          await env.PAGES_KV.delete(`owner:${user.sub}:${slug}`);

          if (env.DB) {
            await env.DB.prepare(
              'DELETE FROM reserved_slugs WHERE slug=? AND owner_sub=?'
            ).bind(slug, user.sub).run();
          }

          return textResponse('OK');
        }

        return textResponse('Method nicht erlaubt.', 405);
      }

      // VERÖFFENTLICHTE SEITEN WEITERLEITEN

      if (request.method === 'GET' && path) {
        const saved = await env.PAGES_KV.get(
          `page:${path}`
        );

        if (saved !== null) {
          const pagesOrigin = getPagesOrigin(env, url);

          return redirect(
            `${pagesOrigin}/${encodeURIComponent(path)}`,
            302
          );
        }

        const legacy = await env.PAGES_KV.get(path);

        if (legacy !== null) {
          const pagesOrigin = getPagesOrigin(env, url);

          return redirect(
            `${pagesOrigin}/${encodeURIComponent(path)}`,
            302
          );
        }
      }

      // 404

      return new Response(
        shell(
          '404',
          `
<section class="card">
<h1>404</h1>
<p>Diese Seite existiert nicht.</p>
<a class="button" href="/">Zur Startseite</a>
</section>`
        ),
        {
          status: 404,
          headers: privateHeaders()
        }
      );
    } catch (error) {
      console.error('Worker request failed:', error.name);

      return textResponse(
        'Interner Serverfehler. Bitte später erneut versuchen.',
        500
      );
    }
  }
};