export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = decodeURIComponent(url.pathname).replace(/^\/+|\/+$/g, '');

    if (request.method !== 'GET') {
      return new Response('Method nicht erlaubt', { status: 405 });
    }

    if (path.startsWith('assets/')) {
      const id = path.slice('assets/'.length).replace(/[^a-z0-9-]/gi, '');
      const asset = await env.PAGES_KV.get(`asset:${id}`, 'json');
      if (!asset?.data) return new Response('Bild nicht gefunden.', { status: 404 });
      const allowed = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
      if (!allowed.includes(asset.type)) return new Response('Dateityp nicht erlaubt.', { status: 415 });
      const binary = atob(asset.data);
      const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
      return new Response(bytes, { headers: { 'Content-Type': asset.type, 'Cache-Control': 'public, max-age=31536000, immutable', 'X-Content-Type-Options': 'nosniff' } });
    }

    const html = await env.PAGES_KV.get(`page:${path}`);
    if (html === null) {
      return new Response('404 – Diese Seite existiert nicht.', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' https: data: blob:; frame-ancestors 'none'",
        'Cross-Origin-Resource-Policy': 'same-origin'
      }
    });
  }
};
