export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Entfernt führende und abschliessende Schrägstriche (z. B. "/meine-seite" -> "meine-seite")
    const path = decodeURIComponent(url.pathname).replace(/^\/+|\/+$/g, '');

    // 1. SEITE ERSTELLEN (Wenn das Formular abgeschickt wird)
    if (request.method === 'POST' && path === 'api/create') {
      const formData = await request.formData();
      const rawName = formData.get('slug') || '';
      const htmlContent = formData.get('html') || '';

      // Macht aus "Meine erste Seite" automatisch "meine-erste-seite"
      const cleanSlug = rawName
        .toLowerCase()
        .trim()
        .replace(/\s+/g, '-')
        .replace(/[^a-z0-9-_]/g, '');

      if (!cleanSlug || !htmlContent) {
        return new Response('Bitte Namen und HTML-Inhalt eingeben!', { status: 400 });
      }

      // Prüfen, ob der Platz schon vergeben ist
      const existing = await env.PAGES_KV.get(cleanSlug);
      if (existing) {
        return new Response('Dieser Seitenname ist leider schon vergeben!', { status: 409 });
      }

      // Seite dauerhaft im KV-Speicher ablegen
      await env.PAGES_KV.put(cleanSlug, htmlContent);

      // Nutzer direkt auf seine neue Seite weiterleiten
      return Response.redirect(`${url.origin}/${cleanSlug}`, 303);
    }

    // 2. STARTSEITE ANZEIGEN (Formular zum Erstellen einer neuen Seite)
    if (path === '') {
      const homeHtml = `
        <!DOCTYPE html>
        <html lang="de">
        <head>
          <meta charset="UTF-8">
          <title>GetVexel – Erstelle deine Seite</title>
          <style>
            body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background: #0f172a; color: #f8fafc; }
            input, textarea { width: 100%; padding: 10px; margin: 10px 0 20px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white; box-sizing: border-box; }
            button { background: #3b82f6; color: white; border: none; padding: 12px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; }
            button:hover { background: #2563eb; }
          </style>
        </head>
        <body>
          <h1>Willkommen bei GetVexel</h1>
          <p>Erstelle kostenlos deine eigene Webseite unter <b>${url.host}/dein-name</b></p>
          <form action="/api/create" method="POST">
            <label>Dein Seitenname (z. B. meine erste seite):</label>
            <input type="text" name="slug" placeholder="meine erste seite" required />
            
            <label>Dein HTML-Code für die Seite:</label>
            <textarea name="html" rows="8" placeholder="<h1>Hallo Welt!</h1><p>Das ist meine erste Seite.</p>" required></textarea>
            
            <button type="submit">Seite jetzt veröffentlichen</button>
          </form>
        </body>
        </html>
      `;
      return new Response(homeHtml, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 3. NUTZER-SEITE AUSLIEFERN (z. B. getvexel.workers.dev/meine-erste-seite)
    const savedHtml = await env.PAGES_KV.get(path);

    if (!savedHtml) {
      return new Response('404 – Diese Seite existiert noch nicht.', { status: 404 });
    }

    return new Response(savedHtml, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        // Sicherheitsheader, damit fremder Code eingeschränkt wird
        'X-Content-Type-Options': 'nosniff'
      }
    });
  }
};
