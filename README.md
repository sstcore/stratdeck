# StratDeck — Strategy Console

End-to-end-encrypted strategy dashboard, hosted as a static site on **GitHub Pages**.

- The server (publisher) builds a per-strategy JSON payload and **encrypts it with a public key**.
- The **ciphertext** is uploaded to a **public S3 bucket**.
- This site fetches the ciphertext, asks for the **private key**, and **decrypts entirely in the browser** with WebCrypto.
- No key ever touches the repo, the server, or any third party. Only ciphertext is public.

## What you get

- **Login page** — paste the private key (PKCS#8 PEM or single-line base64). Wrong key → "Failed to log in."
- **Data-driven nav** — one tab per strategy plus a computed **ALL** aggregate tab.
- **Per-strategy dashboard**:
  - KPI cards: AUM, lifetime PnL ($ and %), 1-day PnL, today's PnL
  - **AUM line chart** (inline SVG, no chart library) with dashed initial-AUM baseline, current-point marker, and hover tooltip
  - Risk exposure gauge (utilised vs budget + long / short / net)
  - Drawdown gauges (lifetime + daily)
  - Open positions table
- **Staleness badge** — warns when the publish is older than ~15 minutes.
- **Refresh** re-fetches with a cache-buster; **Lock** clears the key.

## Files

| File | Purpose |
|---|---|
| `index.html` | Shell (login + app), strict CSP, no inline scripts |
| `app.js` | Fetch / decrypt / state / hash routing / renderers |
| `styles.css` | Dark fintech theme, zero external assets |

No build step, no dependencies, no CDN scripts.

## Data contract (do not invent fields)

Fetched from (base64 envelope, see `publish_dashboard.py`):

```
https://ss-strat-dash-8f21.s3.eu-west-1.amazonaws.com/data/dashboard_data.enc
```

Envelope: `version(1) | ephemeral P-256 pub (65) | salt (16) | nonce (12) | AES-256-GCM ciphertext`.
HKDF info string: `strat-dashboard-v1`. Decrypted payload fields are consumed as-is by `app.js`.

## Local development

WebCrypto needs a secure context, so serve over http://localhost:

```bash
cd web
python3 -m http.server 8000
# open http://localhost:8000
```

By default it fetches the S3 URL and you just paste your private key.

To test against a local ciphertext during development, serve the `.enc` file from the same
directory and pass a `?data=` override relative to the same origin:

```bash
# produces test.enc in this folder (encrypted with a throwaway key — never real data)
python3 ../publish_dashboard.py --encrypt --pubkey /path/to/test_public.b64 --enc-out test.enc

python3 -m http.server 8000
# open http://localhost:8000/?data=test.enc
```

The `?data=` override is for **local development only**; the deployed site always uses the S3 URL.

## Deploying to GitHub Pages

1. Create a **public** repo and push these four files to its root (the data is on S3, not in the repo).
2. Repo → **Settings → Pages → Source** → *Deploy from a branch* → branch `main`, folder `/ (root)`.
3. Site is at `https://<user>.github.io/<repo>/`.

S3 already returns `Access-Control-Allow-Origin: *`, so no CORS config is needed.
Optionally tighten the bucket CORS `AllowedOrigins` to your exact Pages URL later.

## Security rules (non-negotiable)

- **Never commit**: the private key, AWS access keys, `.env*` files, or plaintext payloads.
- The private key lives only in the browser tab's memory (and optionally `sessionStorage`, scoped to that tab).
- The site never sends the key or the decrypted data anywhere. Strict CSP: `script-src 'self'`, `connect-src` limited to the S3 origin.
- Losing the private key = data unrecoverable. Leaking it = all published history is readable.