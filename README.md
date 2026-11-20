# GetVexel

Cloudflare-Worker mit Google-Anmeldung und Seitenverwaltung.

Der Worker läuft auf seiner von Cloudflare bereitgestellten `*.workers.dev`-Adresse oder später auf einer beliebigen eigenen Domain.

## Google OAuth einrichten

1. In der Google Cloud Console ein neues OAuth-Webprojekt erstellen.
2. Unter **Zugriffsdaten** eine OAuth-Client-ID des Typs **Webanwendung** erstellen.
3. Als autorisierte Weiterleitungs-URI die konkrete Worker-Adresse, zum Beispiel `https://getvexel.flomoe.workers.dev/auth/callback`, eintragen.
4. Im Cloudflare-Worker unter **Einstellungen → Variablen** folgende verschlüsselte Variablen setzen:
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `SESSION_SECRET` – zufällige Zeichenfolge, mindestens 32 Zeichen
5. Die KV-Binding `PAGES_KV` bleibt bestehen.

## Verhalten

- Nicht angemeldete Besucher sehen die Anmeldeseite.
- Nur angemeldete Google-Nutzer können Seiten erstellen, bearbeiten oder löschen.
- Jede Seite gehört ihrem erstellenden Konto.
- Öffentliche Seiten werden direkt unter `https://<worker-adresse>/<slug>` ausgeliefert.
