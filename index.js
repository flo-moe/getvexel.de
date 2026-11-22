
const SESSION_COOKIE = '__Host-getvexel-session';
const STATE_COOKIE = '__Host-getvexel-oauth-state';

const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000;
const MAX_PROJECT_SIZE = 1_000_000;
const MAX_REQUEST_SIZE = 1_200_000;
const MAX_IMAGE_SIZE = 2_097_152;
const DEFAULT_CREDITS = 5000;

// ============================================================
// HILFSFUNKTIONEN
// ============================================================

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
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

  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}

function getCookie(request, name) {
  const cookies = request.headers.get('Cookie') || '';

  const match = cookies.match(
    new RegExp('(?:^|;\\s*)' + name + '=([^;]*)')
  );

  if (!match) return null;

  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

function cookie(name, value, options = '') {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax${options ? '; ' + options : ''}`;
}

function redirect(location, status = 303, cookies = []) {
  const headers = new Headers({
    Location: location,
    'Cache-Control': 'no-store'
  });

  for (const value of cookies) {
    headers.append('Set-Cookie', value);
  }

  return new Response(null, { status, headers });
}

function privateHeaders(extra = {}) {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    ...extra
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

function textResponse(message, status = 200) {
  return new Response(message, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

function assertSameOrigin(request, url) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
    return true;
  }

  const origin = request.headers.get('Origin');

  if (!origin || origin !== url.origin) {
    return false;
  }

  const fetchSite = request.headers.get('Sec-Fetch-Site');

  if (
    fetchSite &&
    fetchSite !== 'same-origin' &&
    fetchSite !== 'none'
  ) {
    return false;
  }

  return true;
}

async function readJson(request, maxSize = MAX_REQUEST_SIZE) {
  const contentLength = Number(
    request.headers.get('Content-Length') || 0
  );

  if (contentLength > maxSize) {
    throw new Error('REQUEST_TOO_LARGE');
  }

  const raw = await request.text();

  if (raw.length > maxSize) {
    throw new Error('REQUEST_TOO_LARGE');
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('INVALID_JSON');
  }
}

// ============================================================
// SESSION UND AUTHENTIFIZIERUNG
// ============================================================

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

    if (
      !session.sub ||
      !session.exp ||
      session.exp <= Date.now()
    ) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

async function currentUser(request, env) {
  if (!env.SESSION_SECRET) return null;

  return verifySession(
    env.SESSION_SECRET,
    getCookie(request, SESSION_COOKIE)
  );
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value)
  );

  return base64Url(digest);
}

// ============================================================
// GOOGLE OAUTH
// ============================================================

async function verifyGoogleIdToken(idToken, clientId, nonce) {
  const parts = idToken.split('.');

  if (parts.length !== 3) {
    throw new Error('Ungültiges Google-ID-Token.');
  }

  const header = JSON.parse(
    new TextDecoder().decode(unbase64Url(parts[0]))
  );

  const payload = JSON.parse(
    new TextDecoder().decode(unbase64Url(parts[1]))
  );

  if (header.alg !== 'RS256') {
    throw new Error('Ungültiger Signaturalgorithmus.');
  }

  if (payload.aud !== clientId) {
    throw new Error('Ungültige Zielgruppe.');
  }

  if (
    payload.iss !== 'https://accounts.google.com' &&
    payload.iss !== 'accounts.google.com'
  ) {
    throw new Error('Ungültiger Token-Aussteller.');
  }

  if (!payload.exp || payload.exp * 1000 <= Date.now()) {
    throw new Error('Token abgelaufen.');
  }

  if (
    !payload.iat ||
    payload.iat * 1000 > Date.now() + 300000
  ) {
    throw new Error('Ungültiges Token-Ausstellungsdatum.');
  }

  if (!nonce || payload.nonce !== nonce) {
    throw new Error('Ungültige OAuth-Nonce.');
  }

  if (payload.email_verified !== true) {
    throw new Error('E-Mail nicht verifiziert.');
  }

  if (payload.azp && payload.azp !== clientId) {
    throw new Error('Ungültiger autorisierter Client.');
  }

  const response = await fetch(
    'https://www.googleapis.com/oauth2/v3/certs'
  );

  if (!response.ok) {
    throw new Error('Google-Schlüssel konnten nicht geladen werden.');
  }

  const jwks = await response.json();

  const jwk = (jwks.keys || []).find(
    key => key.kid === header.kid
  );

  if (!jwk) {
    throw new Error('Google-Signaturschlüssel nicht gefunden.');
  }

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    },
    false,
    ['verify']
  );

  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    unbase64Url(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1])
  );

  if (!valid) {
    throw new Error('Ungültige Google-Signatur.');
  }

  return payload;
}

// ============================================================
// PAGES-ORIGIN
// ============================================================

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

  let parsed;

  try {
    parsed = new URL(origin);
  } catch {
    throw new Error('PAGES_ORIGIN ist ungültig.');
  }

  if (
    parsed.protocol !== 'https:' ||
    parsed.origin === url.origin ||
    parsed.username ||
    parsed.password
  ) {
    throw new Error(
      'PAGES_ORIGIN muss eine getrennte HTTPS-Origin sein.'
    );
  }

  return parsed.origin;
}

// ============================================================
// PROJEKTE
// ============================================================

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

  const size =
    new TextEncoder().encode(project.html).length +
    new TextEncoder().encode(project.css).length +
    new TextEncoder().encode(project.js).length;

  if (size > MAX_PROJECT_SIZE) {
    throw new Error('Projekt ist zu groß.');
  }

  return project;
}

function combineProject(project) {
  const html = String(project.html || '');

  const css = String(project.css || '')
    .replace(/<\/?style[^>]*>/gi, '')
    .replace(/<\/style/gi, '<\\/style');

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
      } else {
        output = output.replace(
          /<head[^>]*>/i,
          match => match + `<style>${css}</style>`
        );
      }
    }

    if (js) {
      const script = `<script>${js}</script>`;

      if (/<\/body>/i.test(output)) {
        output = output.replace(
          /<\/body>/i,
          script + '</body>'
        );
      } else {
        output += script;
      }
    }

    return output;
  }

  return `<!doctype html>
<html lang="de">
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

// ============================================================
// BILDER
// ============================================================

function validImageBytes(bytes) {
  if (!bytes || bytes.length < 12) return null;

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

  if (
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) {
    return 'image/jpeg';
  }

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

// ============================================================
// HTML LAYOUT
// ============================================================

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
body{margin:0;font-family:Inter,system-ui,-apple-system,sans-serif;background:#080d1b;color:#edf2ff}
a{color:inherit}
.wrap{max-width:1100px;margin:auto;padding:32px 22px}
.top{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:28px}
.brand{font-size:23px;font-weight:850;letter-spacing:-.7px}
.card{background:#111a2d;border:1px solid #273653;border-radius:16px;padding:22px;margin:14px 0}
.row{display:flex;justify-content:space-between;align-items:center;gap:14px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
input,textarea{width:100%;padding:12px;border-radius:9px;border:1px solid #34496d;background:#0b1425;color:white;font:inherit}
.actions{display:flex;gap:9px;flex-wrap:wrap;align-items:center}
button,.button{display:inline-flex;align-items:center;justify-content:center;border:0;border-radius:9px;padding:11px 16px;background:#477cf5;color:white;font-weight:750;text-decoration:none;cursor:pointer;font:inherit}
button:hover,.button:hover{filter:brightness(1.12)}
.secondary{background:#263653}
.danger{background:#a52b36}
.muted{color:#9aa9c2;font-size:14px}
h1{letter-spacing:-1px}
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

// ============================================================
// ÖFFENTLICHE LANDINGPAGE
// ============================================================

function landingPage() {
  return `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Erstelle und veröffentliche deine eigene Website direkt im Browser mit GetVexel.">
<title>GetVexel – Erstelle deine eigene Website</title>
<style>
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:#080d1b;color:#edf2ff;font-family:Inter,system-ui,-apple-system,sans-serif}
a{text-decoration:none;color:inherit}
button{font:inherit}
.container{width:min(1160px,calc(100% - 40px));margin:auto}
header{height:76px;border-bottom:1px solid #1d2941;background:#080d1bf2;position:sticky;top:0;z-index:10;backdrop-filter:blur(16px)}
.nav{height:100%;display:flex;align-items:center;justify-content:space-between}
.logo{font-size:23px;font-weight:900;letter-spacing:-1px}
.logo span{color:#6d8dff}
.links{display:flex;gap:30px;color:#aab8d0;font-size:14px}
.links a:hover{color:white}
.btn{display:inline-flex;align-items:center;justify-content:center;padding:13px 19px;border-radius:10px;font-weight:750;background:#557bfa;color:white;box-shadow:0 8px 28px #315ce733;transition:.2s}
.btn:hover{transform:translateY(-2px);filter:brightness(1.12)}
.btn.alt{background:#18243b;border:1px solid #344565;box-shadow:none}
.hero{padding:105px 0 80px;text-align:center;position:relative;overflow:hidden}
.hero:before{content:"";position:absolute;width:650px;height:450px;left:50%;top:-170px;transform:translateX(-50%);background:radial-gradient(ellipse,#345bd344,transparent 70%);pointer-events:none}
.tag{display:inline-flex;padding:8px 13px;border:1px solid #34466c;border-radius:30px;color:#a9c1ff;background:#17244388;font-size:13px}
h1{font-size:clamp(42px,7vw,76px);line-height:1.04;letter-spacing:-4px;max-width:900px;margin:25px auto}
h1 span{background:linear-gradient(90deg,#83a5ff,#a98aff);background-clip:text;color:transparent}
.lead{max-width:650px;margin:0 auto;color:#a6b4cc;font-size:18px;line-height:1.75}
.hero-actions{display:flex;justify-content:center;gap:13px;flex-wrap:wrap;margin-top:30px}
.editor{margin:75px auto 0;max-width:1000px;background:#151e30;border:1px solid #34435f;border-radius:16px;overflow:hidden;box-shadow:0 35px 100px #0008;text-align:left}
.editor-top{height:44px;display:flex;align-items:center;padding:0 16px;gap:8px;background:#111827;border-bottom:1px solid #2a3852}
.dot{width:10px;height:10px;border-radius:50%;background:#ef6b70}
.dot:nth-child(2){background:#eab45d}.dot:nth-child(3){background:#5bc58b}
.editor-title{margin-left:12px;color:#aebbd0;font-size:12px}
.editor-body{display:grid;grid-template-columns:170px 1fr 38%;min-height:320px}
.explorer{padding:17px;background:#111a2a;border-right:1px solid #2a3852;color:#8797b1;font-size:12px}
.explorer b{display:block;color:#c7d2e5;margin-bottom:15px}
.file{padding:9px 7px;border-radius:5px}
.file.active{background:#27395b;color:#e6edff}
.code{padding:24px 22px;font:13px/2 ui-monospace,monospace;color:#c4d2ea;white-space:pre-wrap;overflow:hidden}
.code .blue{color:#80a8ff}.code .purple{color:#c5a2ff}.code .green{color:#9bd6a8}
.preview{background:#f5f7fb;padding:16px;color:#1d2940}
.previewbar{font-size:11px;color:#73809a;margin-bottom:15px}
.preview-card{background:white;border-radius:9px;padding:20px;box-shadow:0 5px 18px #1c2b4412}
.preview-card h3{font-size:18px;margin:0 0 9px}
.preview-card p{font-size:11px;line-height:1.6;color:#66748b}
.preview-button{display:inline-block;background:#557bfa;color:white;padding:8px 12px;border-radius:5px;font-size:10px}
.section{padding:90px 0}
.section-head{text-align:center;max-width:680px;margin:0 auto 42px}
.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:2px;color:#8ba7ff;font-weight:800}
h2{font-size:clamp(30px,4vw,44px);letter-spacing:-1.8px;margin:13px 0}
.section-head p{color:#9cabc4;line-height:1.7}
.features{display:grid;grid-template-columns:repeat(4,1fr);gap:15px}
.feature{padding:23px;border:1px solid #263550;background:#101a2c;border-radius:14px}
.feature-icon{width:43px;height:43px;border-radius:12px;background:#263d72;display:grid;place-items:center;font-size:21px;margin-bottom:18px}
.feature h3{margin:0 0 9px;font-size:17px}
.feature p{color:#9baac3;font-size:14px;line-height:1.7;margin:0}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.step{padding:25px;border-radius:15px;border:1px solid #293954;background:#101a2c}
.number{font-size:13px;color:#91aaff;font-weight:800}
.step h3{font-size:19px}
.step p{color:#9baac3;line-height:1.7;font-size:14px}
.faq{max-width:780px;margin:auto}
details{padding:20px 0;border-bottom:1px solid #273550}
summary{font-weight:750;cursor:pointer}
details p{color:#9baac3;line-height:1.7}
.cta{padding:60px 30px;text-align:center;background:linear-gradient(135deg,#182d58,#29204c);border:1px solid #40517a;border-radius:20px}
.cta p{color:#c0c9dc;line-height:1.7}
footer{border-top:1px solid #1d2941;padding:28px 0;color:#8190aa;font-size:13px}
.footer{display:flex;justify-content:space-between;gap:15px;flex-wrap:wrap}
@media(max-width:850px){
.features{grid-template-columns:repeat(2,1fr)}
.editor-body{grid-template-columns:130px 1fr}
.preview{display:none}
}
@media(max-width:600px){
.links{display:none}
.hero{padding:75px 0 45px}
h1{letter-spacing:-2px}
.lead{font-size:16px}
.editor{margin-top:45px}
.editor-body{grid-template-columns:100px 1fr;min-height:270px}
.explorer{padding:12px 7px;font-size:10px}
.code{font-size:10px;padding:16px 10px}
.features,.steps{grid-template-columns:1fr}
.section{padding:65px 0}
}
</style>
</head>
<body>
<header>
<div class="container nav">
<a class="logo" href="/">Get<span>Vexel</span></a>
<nav class="links">
<a href="#funktionen">Funktionen</a>
<a href="#ablauf">So funktioniert's</a>
<a href="#faq">FAQ</a>
</nav>
<a class="btn" href="/auth/google">Anmelden</a>
</div>
</header>

<main>
<section class="hero">
<div class="container">
<div class="tag">✦ Dein Website-Editor im Browser</div>
<h1>Erstelle deine eigene Website.<br><span>Direkt im Browser.</span></h1>
<p class="lead">Schreibe HTML, CSS und JavaScript, sieh deine Änderungen live und veröffentliche deine Website mit wenigen Klicks.</p>
<div class="hero-actions">
<a class="btn" href="/auth/google">Kostenlos starten →</a>
<a class="btn alt" href="#funktionen">Funktionen entdecken</a>
</div>

<div class="editor">
<div class="editor-top">
<span class="dot"></span><span class="dot"></span><span class="dot"></span>
<span class="editor-title">GetVexel Editor · mein-projekt</span>
</div>
<div class="editor-body">
<div class="explorer">
<b>EXPLORER</b>
<div class="file active">▤ index.html</div>
<div class="file">▤ styles.css</div>
<div class="file">▤ script.js</div>
</div>
<div class="code"><span class="blue">&lt;!doctype html&gt;</span>
<span class="purple">&lt;html&gt;</span>
  <span class="purple">&lt;body&gt;</span>
    <span class="blue">&lt;h1&gt;</span>
      Willkommen!
    <span class="blue">&lt;/h1&gt;</span>
    <span class="green">&lt;p&gt;</span>
      Meine erste Website.
    <span class="green">&lt;/p&gt;</span>
  <span class="purple">&lt;/body&gt;</span>
<span class="purple">&lt;/html&gt;</span></div>
<div class="preview">
<div class="previewbar">LIVE-VORSCHAU</div>
<div class="preview-card">
<h3>Willkommen!</h3>
<p>Meine erste Website. Hier kannst du deine Ideen umsetzen und ausprobieren.</p>
<span class="preview-button">Mehr erfahren</span>
</div>
</div>
</div>
</div>
</div>
</section>

<section class="section" id="funktionen">
<div class="container">
<div class="section-head">
<div class="eyebrow">Alles an einem Ort</div>
<h2>Deine Ideen. Deine Website.</h2>
<p>Die Werkzeuge, die du brauchst, um eigene Websites zu entwickeln und online zu bringen.</p>
</div>
<div class="features">
<article class="feature">
<div class="feature-icon">⌨</div>
<h3>HTML, CSS & JS</h3>
<p>Schreibe deinen eigenen Code in einer übersichtlichen Entwicklungsumgebung.</p>
</article>
<article class="feature">
<div class="feature-icon">◉</div>
<h3>Live-Vorschau</h3>
<p>Sieh direkt, wie deine Website aussieht, während du sie bearbeitest.</p>
</article>
<article class="feature">
<div class="feature-icon">↗</div>
<h3>Veröffentlichen</h3>
<p>Speichere deine Projekte und veröffentliche deine Seiten unter einer eigenen Adresse.</p>
</article>
<article class="feature">
<div class="feature-icon">▦</div>
<h3>Datenbanken</h3>
<p>Verwalte Daten für deine Projekte mit den integrierten Datenbankfunktionen.</p>
</article>
</div>
</div>
</section>

<section class="section" id="ablauf">
<div class="container">
<div class="section-head">
<div class="eyebrow">Einfach loslegen</div>
<h2>In drei Schritten online.</h2>
<p>Vom ersten Code bis zur veröffentlichten Website.</p>
</div>
<div class="steps">
<article class="step">
<div class="number">SCHRITT 01</div>
<h3>Konto erstellen</h3>
<p>Melde dich an und öffne dein persönliches GetVexel-Dashboard.</p>
</article>
<article class="step">
<div class="number">SCHRITT 02</div>
<h3>Website entwickeln</h3>
<p>Erstelle ein leeres Projekt und gestalte deine Website mit HTML, CSS und JavaScript.</p>
</article>
<article class="step">
<div class="number">SCHRITT 03</div>
<h3>Veröffentlichen</h3>
<p>Speichere dein Projekt und stelle deine Website online.</p>
</article>
</div>
</div>
</section>

<section class="section" id="faq">
<div class="container">
<div class="section-head">
<div class="eyebrow">Fragen und Antworten</div>
<h2>Häufig gestellte Fragen.</h2>
</div>
<div class="faq">
<details>
<summary>Muss ich etwas installieren?</summary>
<p>Nein. GetVexel läuft direkt im Browser. Du brauchst keine zusätzliche Entwicklungssoftware.</p>
</details>
<details>
<summary>Welche Programmiersprachen kann ich verwenden?</summary>
<p>Der Editor unterstützt HTML, CSS und JavaScript.</p>
</details>
<details>
<summary>Kann ich meine Website veröffentlichen?</summary>
<p>Ja. Du kannst deine gespeicherten Projekte über GetVexel veröffentlichen.</p>
</details>
<details>
<summary>Kann ich meine Website später bearbeiten?</summary>
<p>Ja. Deine gespeicherten Projekte findest du in deinem Dashboard und kannst sie dort weiterbearbeiten.</p>
</details>
</div>
</div>
</section>

<section class="section">
<div class="container">
<div class="cta">
<div class="eyebrow">Dein nächstes Projekt wartet</div>
<h2>Starte mit deiner eigenen Website.</h2>
<p>Öffne den Editor und setze deine Ideen um.</p>
<a class="btn" href="/auth/google">Jetzt kostenlos starten →</a>
</div>
</div>
</section>
</main>

<footer>
<div class="container footer">
<a class="logo" href="/">Get<span style="color:#8ca7ff">Vexel</span></a>
<span>© ${new Date().getFullYear()} GetVexel</span>
<span>Erstelle. Gestalte. Veröffentliche.</span>
</div>
</footer>
</body>
</html>`;
}

// ============================================================
// DASHBOARD
// ============================================================

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
<button class="danger" type="button" data-delete-page="${escapeHtml(page.slug)}">Löschen</button>
</div>
</article>`).join('');

  return shell('Dashboard', `
<div class="top">
<div>
<div class="brand">GetVexel</div>
<div class="muted">${escapeHtml(user.email)} · ${credits} Credits</div>
</div>
<div class="actions">
<a class="button" href="/dashboard/new">+ Neue Seite</a>
<a class="button secondary" href="/databases">Datenbanken</a>
<form method="POST" action="/auth/logout">
<button class="secondary" type="submit">Abmelden</button>
</form>
</div>
</div>

<h1>Meine Websites</h1>
<p class="muted">Verwalte deine Projekte und veröffentliche deine Websites.</p>

${rows || '<div class="card"><p>Noch keine Website erstellt.</p><a class="button" href="/dashboard/new">Erste Website erstellen</a></div>'}

<script>
document.querySelectorAll('[data-delete-page]').forEach(button => {
  button.addEventListener('click', async () => {
    const slug = button.dataset.deletePage;

    if (!confirm('Website wirklich löschen?')) return;

    const response = await fetch(
      '/api/pages/' + encodeURIComponent(slug),
      { method: 'DELETE' }
    );

    if (response.ok) {
      location.reload();
    } else {
      alert(await response.text());
    }
  });
});
</script>
`);
}

// ============================================================
// EDITOR
// ============================================================

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

  return shell('Web-Editor', `
<style>
body{overflow:hidden}
.wrap{max-width:none;height:100vh;padding:0}
.ide{height:100vh;display:grid;grid-template-rows:48px 1fr 24px;background:#1e1e1e;color:#ddd}
.bar{display:flex;align-items:center;justify-content:space-between;gap:10px;height:48px;padding:0 12px;background:#181818;border-bottom:1px solid #333}
.workspace{display:grid;grid-template-columns:180px minmax(220px,1fr) 45%;min-height:0}
.explorer{padding:12px;background:#252526;border-right:1px solid #333}
.explorer strong{display:block;margin-bottom:12px;font-size:12px;color:#aaa}
.file{display:block;width:100%;border:0;background:transparent;color:#ccc;text-align:left;padding:10px;cursor:pointer}
.file.active{background:#37373d;color:white}
.editor{display:flex;flex-direction:column;min-width:0}
.tabname{height:36px;padding:9px 14px;background:#252526;border-bottom:1px solid #333;color:white;font-size:13px}
.code{flex:1;width:100%;resize:none;border:0;outline:none;border-radius:0;padding:16px;background:#1e1e1e;color:#d4d4d4;font:14px/1.5 ui-monospace,monospace}
.preview{display:flex;flex-direction:column;border-left:1px solid #333;background:#111}
.previewbar{height:36px;padding:0 10px;display:flex;align-items:center;justify-content:space-between;background:#252526}
.previewframe{flex:1;width:100%;border:0;background:white}
.status{height:24px;padding:3px 10px;background:#007acc;color:white;font-size:12px}
.small{border:0;border-radius:5px;padding:8px 11px;background:#0e639c;color:white;cursor:pointer}
.small.secondary{background:#3c3c3c}
@media(max-width:900px){
.workspace{grid-template-columns:140px 1fr}
.preview{display:none}
}
@media(max-width:600px){
.bar{padding:0 6px}
.bar input{width:115px!important}
.bar strong{display:none}
.small{padding:7px}
.workspace{grid-template-columns:105px 1fr}
}
</style>

<div class="ide">
<div class="bar">
<div style="display:flex;align-items:center;gap:8px">
<input id="slug" value="${escapeHtml(slug)}" placeholder="seitenname" style="width:200px;padding:8px;color:#111;background:#fff" ${isExistingPage ? 'readonly' : ''}>
<strong>GetVexel Editor</strong>
</div>
<div class="actions">
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
<strong>Live-Vorschau</strong>
<button class="small secondary" id="refresh" type="button">Aktualisieren</button>
</div>
<iframe id="preview" class="previewframe" title="Live-Vorschau" sandbox="allow-scripts allow-forms allow-modals"></iframe>
</section>
</div>

<div class="status"><span id="position">Zeile 1, Spalte 1</span></div>
</div>

<script>
window.__GETVEXEL_PROJECT__=${projectJson};
window.__GETVEXEL_EDIT__=${isExistingPage ? 'true' : 'false'};
</script>
<script src="/editor.js?v=20261122-5" defer></script>
`);
}

// ============================================================
// EDITOR JAVASCRIPT
// ============================================================

function editorScript() {
  return String.raw`(() => {
    function boot() {
      const code = document.querySelector('#code');
      const preview = document.querySelector('#preview');

      if (!code || !preview) return;

      const initial = window.__GETVEXEL_PROJECT__ || {};

      const files = {
        html: String(initial.html || ''),
        css: String(initial.css || ''),
        js: String(initial.js || '')
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
          .split('\n');

        const position = document.querySelector('#position');

        if (position) {
          position.textContent =
            'Zeile ' + before.length +
            ', Spalte ' + (before[before.length - 1].length + 1);
        }
      }

      function updatePreview() {
        saveCurrent();

        const css = files.css.replace(/<\/style/gi, '<\\/style');
        const js = files.js.replace(/<\/script/gi, '<\\/script');

        let html;

        if (/<html[\s>]/i.test(files.html)) {
          html = files.html;

          if (css) {
            if (/<\/head>/i.test(html)) {
              html = html.replace(
                /<\/head>/i,
                '<style>' + css + '</style></head>'
              );
            } else {
              html += '<style>' + css + '</style>';
            }
          }

          if (js) {
            const open = '<scr' + 'ipt>';
            const close = '</scr' + 'ipt>';

            if (/<\/body>/i.test(html)) {
              html = html.replace(
                /<\/body>/i,
                open + js + close + '</body>'
              );
            } else {
              html += open + js + close;
            }
          }
        } else {
          const open = '<scr' + 'ipt>';
          const close = '</scr' + 'ipt>';

          html =
            '<!doctype html><html lang="de"><head>' +
            '<meta charset="utf-8">' +
            '<meta name="viewport" content="width=device-width,initial-scale=1">' +
            '<style>' + css + '</style>' +
            '</head><body>' +
            files.html +
            (js ? open + js + close : '') +
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
        updatePreview();
        code.focus();
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
        updateCursor();
        updatePreview();
      });

      document.querySelector('#refresh')?.addEventListener(
        'click',
        updatePreview
      );

      async function saveProject() {
        if (saving) return null;

        saveCurrent();

        const slugInput = document.querySelector('#slug');

        const slug = slugInput
          ? slugInput.value.trim().toLowerCase()
              .replace(/\s+/g, '-')
              .replace(/[^a-z0-9-_]/g, '')
              .slice(0, 80)
          : '';

        if (!slug) {
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
              ? '/api/pages/' + encodeURIComponent(slug)
              : '/api/pages',
            {
              method: isExisting ? 'PUT' : 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                slug,
                project: files
              })
            }
          );

          if (!response.ok) {
            alert(await response.text());
            return null;
          }

          isExisting = true;
          window.__GETVEXEL_EDIT__ = true;

          if (slugInput) {
            slugInput.value = slug;
            slugInput.readOnly = true;
          }

          return { slug };
        } catch {
          alert('Verbindung fehlgeschlagen. Bitte erneut versuchen.');
          return null;
        } finally {
          saving = false;

          if (saveButton) saveButton.disabled = false;
          if (publishButton) publishButton.disabled = false;
        }
      }

      document.querySelector('#save')?.addEventListener(
        'click',
        async () => {
          const result = await saveProject();

          if (result) {
            alert('Deine Website wurde gespeichert.');
          }
        }
      );

      document.querySelector('#publish')?.addEventListener(
        'click',
        async () => {
          const popup = window.open('about:blank', '_blank');

          if (popup) {
            popup.document.write(
              '<!doctype html><html><head><title>GetVexel</title></head>' +
              '<body style="background:#0b1220;color:white;font-family:system-ui;padding:50px;text-align:center">' +
              '<h2>Deine Website wird vorbereitet ...</h2>' +
              '<p>Bitte einen Moment warten.</p></body></html>'
            );
          }

          const result = await saveProject();

          if (!result) {
            if (popup && !popup.closed) popup.close();
            return;
          }

          const target = '/' + encodeURIComponent(result.slug);

          if (popup && !popup.closed) {
            popup.location.replace(target);
          } else {
            alert(
              'Deine Website wurde gespeichert. Öffne sie hier:\\n' +
              location.origin + target
            );
          }
        }
      );

      openFile('html');
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', boot);
    } else {
      boot();
    }
  })();`;
}

// ============================================================
// CREDITS
// ============================================================

async function monthlyCredits(env, ownerSub) {
  if (!env.DB) return DEFAULT_CREDITS;

  const month = new Date().toISOString().slice(0, 7);

  await env.DB.batch([
    env.DB.prepare(
      `INSERT OR IGNORE INTO user_credits(owner_sub, month, credits)
       VALUES(?, ?, ?)`
    ).bind(ownerSub, month, DEFAULT_CREDITS),

    env.DB.prepare(
      `UPDATE user_credits
       SET month=?, credits=?
       WHERE owner_sub=? AND month<>?`
    ).bind(month, DEFAULT_CREDITS, ownerSub, month)
  ]);

  const account = await env.DB.prepare(
    'SELECT credits FROM user_credits WHERE owner_sub=?'
  ).bind(ownerSub).first();

  return account?.credits ?? DEFAULT_CREDITS;
}

// ============================================================
// DASHBOARD-SEITEN LADEN
// ============================================================

async function listUserPages(env, ownerSub) {
  const prefix = `owner:${ownerSub}:`;
  const pages = [];

  let cursor;

  do {
    const result = await env.PAGES_KV.list({
      prefix,
      limit: 1000,
      ...(cursor ? { cursor } : {})
    });

    for (const key of result.keys) {
      const slug = key.name.slice(prefix.length);

      const meta = await env.PAGES_KV.get(
        `meta:${slug}`,
        'json'
      );

      if (!meta || meta.owner !== ownerSub) continue;

      const html = await env.PAGES_KV.get(`page:${slug}`);

      if (html !== null) {
        pages.push({ slug });
      }
    }

    cursor = result.list_complete ? undefined : result.cursor;
  } while (cursor);

  pages.sort((a, b) => a.slug.localeCompare(b.slug));

  return pages;
}

// ============================================================
// ROUTER
// ============================================================

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

    if (!assertSameOrigin(request, url)) {
      return textResponse(
        'Cross-Origin-Anfrage nicht erlaubt.',
        403
      );
    }

    try {
      // ------------------------------------------------------
      // GRUNDLEGENDE KONFIGURATION
      // ------------------------------------------------------

      if (!env.PAGES_KV) {
        return textResponse('PAGES_KV ist nicht konfiguriert.', 500);
      }

      // ------------------------------------------------------
      // EDITOR JAVASCRIPT
      // ------------------------------------------------------

      if (path === 'editor.js' && request.method === 'GET') {
        return new Response(editorScript(), {
          headers: {
            'Content-Type': 'application/javascript; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff'
          }
        });
      }

      // ------------------------------------------------------
      // GOOGLE LOGIN STARTEN
      // ------------------------------------------------------

      if (path === 'auth/google' && request.method === 'GET') {
        if (
          !env.GOOGLE_CLIENT_ID ||
          !env.GOOGLE_CLIENT_SECRET ||
          !env.SESSION_SECRET
        ) {
          return textResponse(
            'Google-OAuth ist nicht vollständig konfiguriert.',
            500
          );
        }

        const state = crypto.randomUUID();
        const nonce = crypto.randomUUID();

        const verifier = base64Url(
          crypto.getRandomValues(new Uint8Array(32))
        );

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

        const stateData = base64Url(
          new TextEncoder().encode(
            JSON.stringify({ state, nonce, verifier })
          )
        );

        return redirect(
          authorize.toString(),
          302,
          [cookie(STATE_COOKIE, stateData, 'Max-Age=600')]
        );
      }

      // ------------------------------------------------------
      // GOOGLE CALLBACK
      // ------------------------------------------------------

      if (path === 'auth/callback' && request.method === 'GET') {
        const clearState = cookie(
          STATE_COOKIE,
          '',
          'Max-Age=0'
        );

        try {
          if (
            !env.GOOGLE_CLIENT_ID ||
            !env.GOOGLE_CLIENT_SECRET ||
            !env.SESSION_SECRET
          ) {
            throw new Error('OAuth nicht konfiguriert.');
          }

          const code = url.searchParams.get('code');
          const state = url.searchParams.get('state');
          const stateCookie = getCookie(request, STATE_COOKIE);

          if (!code || !state || !stateCookie) {
            return new Response(
              'Ungültige OAuth-Anmeldung.',
              {
                status: 400,
                headers: {
                  'Content-Type': 'text/plain; charset=utf-8',
                  'Set-Cookie': clearState
                }
              }
            );
          }

          let stateData;

          try {
            stateData = JSON.parse(
              new TextDecoder().decode(unbase64Url(stateCookie))
            );
          } catch {
            return new Response('Ungültiger OAuth-State.', {
              status: 400,
              headers: { 'Set-Cookie': clearState }
            });
          }

          if (state !== stateData.state) {
            return new Response('Ungültiger OAuth-State.', {
              status: 400,
              headers: { 'Set-Cookie': clearState }
            });
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
                code_verifier: stateData.verifier
              })
            }
          );

          if (!tokenResponse.ok) {
            return new Response(
              'Google-Anmeldung fehlgeschlagen.',
              {
                status: 401,
                headers: { 'Set-Cookie': clearState }
              }
            );
          }

          const tokens = await tokenResponse.json();

          if (!tokens.id_token) {
            return new Response('Google-ID-Token fehlt.', {
              status: 401,
              headers: { 'Set-Cookie': clearState }
            });
          }

          const claims = await verifyGoogleIdToken(
            tokens.id_token,
            env.GOOGLE_CLIENT_ID,
            stateData.nonce
          );

          if (
            !claims.sub ||
            !claims.email ||
            claims.email_verified !== true
          ) {
            return new Response('Google-Konto ungültig.', {
              status: 401,
              headers: { 'Set-Cookie': clearState }
            });
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
              clearState
            ]
          );
        } catch (error) {
          console.error('OAuth callback error:', error.name);

          return new Response(
            'Google-Anmeldung konnte nicht abgeschlossen werden.',
            {
              status: 500,
              headers: { 'Set-Cookie': clearState }
            }
          );
        }
      }

      // ------------------------------------------------------
      // LOGOUT
      // ------------------------------------------------------

      if (path === 'auth/logout' && request.method === 'POST') {
        return redirect(
          `${url.origin}/`,
          303,
          [
            cookie(SESSION_COOKIE, '', 'Max-Age=0'),
            cookie(STATE_COOKIE, '', 'Max-Age=0')
          ]
        );
      }

      // ------------------------------------------------------
      // STARTSEITE
      // ------------------------------------------------------

      if (path === '' && request.method === 'GET') {
        const user = await currentUser(request, env);

        if (user) {
          return redirect(`${url.origin}/dashboard`);
        }

        return new Response(landingPage(), {
          headers: privateHeaders()
        });
      }

      // ------------------------------------------------------
      // DASHBOARD
      // ------------------------------------------------------

      if (path === 'dashboard' || path.startsWith('dashboard/')) {
        if (request.method !== 'GET') {
          return textResponse('Method nicht erlaubt.', 405);
        }

        const user = await currentUser(request, env);

        if (!user) {
          return redirect(`${url.origin}/auth/google`);
        }

        if (path === 'dashboard') {
          const pages = await listUserPages(env, user.sub);

          const credits = env.DB
            ? await monthlyCredits(env, user.sub)
            : DEFAULT_CREDITS;

          const pagesOrigin = getPagesOrigin(env, url);

          return new Response(
            dashboard(user, pages, pagesOrigin, credits),
            { headers: privateHeaders() }
          );
        }

        // Neues leeres Projekt

        if (path === 'dashboard/new') {
          return new Response(editorPage(), {
            headers: privateHeaders()
          });
        }

        // Bestehendes Projekt bearbeiten

        if (path.startsWith('dashboard/edit/')) {
          const slug = cleanSlug(
            path.slice('dashboard/edit/'.length)
          );

          if (!slug) {
            return textResponse('Ungültiger Seitenname.', 400);
          }

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
            editorPage({
              slug,
              html: html || '',
              project
            }),
            { headers: privateHeaders() }
          );
        }

        return textResponse('Seite nicht gefunden.', 404);
      }

      // ------------------------------------------------------
      // DATENBANKEN-SEITE
      // ------------------------------------------------------

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
          `SELECT id, name
           FROM user_databases
           WHERE owner_sub=?
           ORDER BY name`
        ).bind(user.sub).all();

        const cards = (result.results || []).map(db => `
<article class="card row">
<strong>${escapeHtml(db.name)}</strong>
<div class="actions">
<button class="danger" data-delete-db="${escapeHtml(db.id)}" type="button">Löschen</button>
</div>
</article>`).join('');

        return new Response(
          shell('Datenbanken', `
<div class="top">
<div>
<div class="brand">Meine Datenbanken</div>
<div class="muted">${credits} Credits verfügbar</div>
</div>
<a class="button secondary" href="/dashboard">Zum Dashboard</a>
</div>

<div class="card">
<h2>Neue Datenbank</h2>
<form id="create-db">
<input id="db-name" maxlength="40" placeholder="Datenbankname" required>
<br><br>
<button type="submit">Datenbank erstellen</button>
</form>
</div>

<h2>Deine Datenbanken</h2>
${cards || '<div class="card"><p>Noch keine Datenbank erstellt.</p></div>'}

<script>
document.querySelector('#create-db').addEventListener('submit', async event => {
  event.preventDefault();

  const button = event.submitter;
  button.disabled = true;

  try {
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
  } finally {
    button.disabled = false;
  }
});

document.querySelectorAll('[data-delete-db]').forEach(button => {
  button.addEventListener('click', async () => {
    if (!confirm('Datenbank wirklich löschen?')) return;

    const response = await fetch(
      '/api/databases/' + encodeURIComponent(button.dataset.deleteDb),
      { method: 'DELETE' }
    );

    if (response.ok) {
      location.reload();
    } else {
      alert(await response.text());
    }
  });
});
</script>
`),
          { headers: privateHeaders() }
        );
      }

      // ------------------------------------------------------
      // DATENBANK-API
      // ------------------------------------------------------

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

        // Datenbank erstellen

        if (
          request.method === 'POST' &&
          path === 'api/databases'
        ) {
          let body;

          try {
            body = await readJson(request, 65536);
          } catch (error) {
            return textResponse(
              error.message === 'REQUEST_TOO_LARGE'
                ? 'Anfrage zu groß.'
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
            return textResponse('Datenbankname fehlt.', 400);
          }

          const databaseId = crypto.randomUUID();

          try {
            await env.DB.prepare(
              `INSERT INTO user_databases(id, owner_sub, name)
               VALUES(?, ?, ?)`
            ).bind(databaseId, user.sub, name).run();
          } catch (error) {
            if (
              String(error.message || error).includes(
                'database limit reached'
              )
            ) {
              return textResponse(
                'Du kannst maximal drei Datenbanken erstellen.',
                409
              );
            }

            throw error;
          }

          return jsonResponse({
            id: databaseId,
            name
          });
        }

        if (!id) {
          return textResponse('Datenbank-ID fehlt.', 400);
        }

        // Datenbankbesitz prüfen

        const owned = await env.DB.prepare(
          `SELECT id, name
           FROM user_databases
           WHERE id=? AND owner_sub=?`
        ).bind(id, user.sub).first();

        if (!owned) {
          return textResponse('Datenbank nicht gefunden.', 404);
        }

        // Eintrag hinzufügen

        if (request.method === 'POST') {
          let body;

          try {
            body = await readJson(request, 65536);
          } catch (error) {
            return textResponse(
              error.message === 'REQUEST_TOO_LARGE'
                ? 'Anfrage zu groß.'
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

          const data = body.data &&
            typeof body.data === 'object' &&
            !Array.isArray(body.data)
              ? body.data
              : {};

          const jsonData = JSON.stringify(data);

          if (jsonData.length > 50000) {
            return textResponse('Datensatz ist zu groß.', 413);
          }

          await monthlyCredits(env, user.sub);

          const itemId = crypto.randomUUID();

          const result = await env.DB.prepare(
            `INSERT INTO database_items
              (id, database_id, owner_sub, name, json_data, created_at)
             SELECT ?, ?, ?, ?, ?, ?
             WHERE EXISTS (
               SELECT 1 FROM user_credits
               WHERE owner_sub=? AND credits>=10
             )`
          ).bind(
            itemId,
            id,
            user.sub,
            String(body.name || 'Eintrag').slice(0, 80),
            jsonData,
            Date.now(),
            user.sub
          ).run();

          if (!result.meta.changes) {
            return textResponse('Nicht genügend Credits.', 402);
          }

          const charged = await env.DB.prepare(
            `UPDATE user_credits
             SET credits=credits-10
             WHERE owner_sub=? AND credits>=10`
          ).bind(user.sub).run();

          if (!charged.meta.changes) {
            await env.DB.prepare(
              'DELETE FROM database_items WHERE id=? AND owner_sub=?'
            ).bind(itemId, user.sub).run();

            return textResponse('Nicht genügend Credits.', 402);
          }

          return jsonResponse({ id: itemId });
        }

        // Datenbank lesen

        if (request.method === 'GET') {
          await monthlyCredits(env, user.sub);

          const charged = await env.DB.prepare(
            `UPDATE user_credits
             SET credits=credits-5
             WHERE owner_sub=? AND credits>=5`
          ).bind(user.sub).run();

          if (!charged.meta.changes) {
            return textResponse('Nicht genügend Credits.', 402);
          }

          const items = await env.DB.prepare(
            `SELECT id, name, json_data, created_at
             FROM database_items
             WHERE database_id=? AND owner_sub=?
             ORDER BY created_at DESC`
          ).bind(id, user.sub).all();

          return jsonResponse({
            database: owned,
            items: items.results || []
          });
        }

        // Datenbank löschen

        if (request.method === 'DELETE') {
          await env.DB.batch([
            env.DB.prepare(
              'DELETE FROM database_items WHERE database_id=? AND owner_sub=?'
            ).bind(id, user.sub),

            env.DB.prepare(
              'DELETE FROM user_databases WHERE id=? AND owner_sub=?'
            ).bind(id, user.sub)
          ]);

          return textResponse('OK');
        }

        return textResponse('Method nicht erlaubt.', 405);
      }

      // ------------------------------------------------------
      // BILDER-UPLOAD
      // ------------------------------------------------------

      if (path === 'api/assets' && request.method === 'POST') {
        const user = await currentUser(request, env);

        if (!user) {
          return textResponse('Anmeldung erforderlich.', 401);
        }

        const contentLength = Number(
          request.headers.get('Content-Length') || 0
        );

        if (contentLength > 2_200_000) {
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
          return textResponse('Keine Bilddatei gefunden.', 400);
        }

        if (!file.size || file.size > MAX_IMAGE_SIZE) {
          return textResponse('Bildgröße nicht erlaubt.', 413);
        }

        const bytes = new Uint8Array(await file.arrayBuffer());
        const type = validImageBytes(bytes);

        if (!type) {
          return textResponse(
            'Nur PNG, JPEG, GIF und WebP sind erlaubt.',
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
            type,
            data: btoa(binary)
          })
        );

        const pagesOrigin = getPagesOrigin(env, url);

        return jsonResponse({
          url: `${pagesOrigin}/assets/${id}`
        });
      }

      // ------------------------------------------------------
      // ASSET-WEITERLEITUNG
      // ------------------------------------------------------

      if (path.startsWith('assets/') && request.method === 'GET') {
        const pagesOrigin = getPagesOrigin(env, url);

        return redirect(
          `${pagesOrigin}/${path}`,
          302
        );
      }

      // ------------------------------------------------------
      // SEITEN-API
      // ------------------------------------------------------

      if (
        path === 'api/pages' ||
        path.startsWith('api/pages/')
      ) {
        const user = await currentUser(request, env);

        if (!user) {
          return textResponse('Anmeldung erforderlich.', 401);
        }

        const isCollection = path === 'api/pages';

        const slug = isCollection
          ? ''
          : cleanSlug(path.slice('api/pages/'.length));

        if (!isCollection && !slug) {
          return textResponse('Ungültiger Seitenname.', 400);
        }

        // Neue Seite erstellen

        if (
          request.method === 'POST' &&
          isCollection
        ) {
          if (!env.DB) {
            return textResponse('D1 ist nicht konfiguriert.', 500);
          }

          let body;

          try {
            body = await readJson(request);
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

          const name = cleanSlug(body.slug);

          if (!name) {
            return textResponse('Bitte einen Seitennamen eingeben.', 400);
          }

          let project;

          try {
            project = validateProjectBody(body);
          } catch (error) {
            return textResponse(error.message, 400);
          }

          // Reservierung des Namens

          try {
            await env.DB.prepare(
              `INSERT INTO reserved_slugs(slug, owner_sub, status)
               VALUES(?, ?, 'pending')`
            ).bind(name, user.sub).run();
          } catch (error) {
            const message = String(error.message || error);

            if (
              message.includes('UNIQUE') ||
              message.includes('PRIMARY')
            ) {
              const existing = await env.DB.prepare(
                `SELECT owner_sub, status
                 FROM reserved_slugs
                 WHERE slug=?`
              ).bind(name).first();

              if (!existing || existing.owner_sub !== user.sub) {
                return textResponse(
                  'Dieser Seitenname ist bereits vergeben.',
                  409
                );
              }

              const meta = await env.PAGES_KV.get(
                `meta:${name}`,
                'json'
              );

              if (meta) {
                return textResponse(
                  'Dieser Seitenname ist bereits vergeben.',
                  409
                );
              }

              await env.DB.prepare(
                `UPDATE reserved_slugs
                 SET status='pending'
                 WHERE slug=? AND owner_sub=?`
              ).bind(name, user.sub).run();
            } else {
              throw error;
            }
          }

          // Projekt speichern

          try {
            const html = combineProject(project);

            await env.PAGES_KV.put(`page:${name}`, html);

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
              `UPDATE reserved_slugs
               SET status='complete'
               WHERE slug=? AND owner_sub=?`
            ).bind(name, user.sub).run();
          } catch (error) {
            await env.DB.prepare(
              `UPDATE reserved_slugs
               SET status='failed'
               WHERE slug=? AND owner_sub=?`
            ).bind(name, user.sub).run();

            console.error('Page creation failed:', error.name);

            return textResponse(
              'Die Website konnte nicht vollständig gespeichert werden.',
              500
            );
          }

          return jsonResponse({
            success: true,
            slug: name
          });
        }

        // Bestehende Seite bearbeiten

        if (request.method === 'PUT' && slug) {
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
            body = await readJson(request);
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

          const html = combineProject(project);

          await env.PAGES_KV.put(`page:${slug}`, html);

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

          return jsonResponse({
            success: true,
            slug
          });
        }

        // Seite löschen

        if (request.method === 'DELETE' && slug) {
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

          await Promise.all([
            env.PAGES_KV.delete(`page:${slug}`),
            env.PAGES_KV.delete(`project:${slug}`),
            env.PAGES_KV.delete(`meta:${slug}`),
            env.PAGES_KV.delete(`owner:${user.sub}:${slug}`)
          ]);

          if (env.DB) {
            await env.DB.prepare(
              `DELETE FROM reserved_slugs
               WHERE slug=? AND owner_sub=?`
            ).bind(slug, user.sub).run();
          }

          return jsonResponse({ success: true });
        }

        return textResponse('Method nicht erlaubt.', 405);
      }

      // ------------------------------------------------------
      // VERÖFFENTLICHTE SEITEN
      // ------------------------------------------------------

      if (request.method === 'GET' && path) {
        // Interne Routen niemals als Seitennamen behandeln.
        if (
          path.startsWith('auth/') ||
          path.startsWith('api/') ||
          path.startsWith('dashboard/') ||
          path.startsWith('editor')
        ) {
          return textResponse('Seite nicht gefunden.', 404);
        }

        const slug = cleanSlug(path);

        if (slug !== path) {
          return textResponse('Seite nicht gefunden.', 404);
        }

        const saved = await env.PAGES_KV.get(`page:${slug}`);

        if (saved !== null) {
          const pagesOrigin = getPagesOrigin(env, url);

          return redirect(
            `${pagesOrigin}/${encodeURIComponent(slug)}`,
            302
          );
        }

        // Unterstützung älterer gespeicherter Seiten

        const legacy = await env.PAGES_KV.get(slug);

        if (legacy !== null) {
          const pagesOrigin = getPagesOrigin(env, url);

          return redirect(
            `${pagesOrigin}/${encodeURIComponent(slug)}`,
            302
          );
        }
      }

      // ------------------------------------------------------
      // 404
      // ------------------------------------------------------

      return new Response(
        shell('404', `
<section class="card" style="text-align:center;padding:55px 20px">
<div style="font-size:64px;font-weight:900;color:#6d8dff">404</div>
<h1>Diese Seite wurde nicht gefunden.</h1>
<p class="muted">Die angeforderte Seite existiert nicht oder wurde verschoben.</p>
<a class="button" href="/">Zur Startseite</a>
</section>
`),
        {
          status: 404,
          headers: privateHeaders()
        }
      );

    } catch (error) {
      console.error(
        'Worker request failed:',
        error.name,
        error.message
      );

      return textResponse(
        'Interner Serverfehler. Bitte später erneut versuchen.',
        500
      );
    }
  }
};
