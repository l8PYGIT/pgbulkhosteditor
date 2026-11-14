# PasarGuard Bulk Host Editor (`pgbulkhosteditor`)

A zero-dependency, single-file browser UI for bulk editing, bulk cloning, search-and-replace, and safe preview/backup of [PasarGuard](https://github.com/PasarGuard/panel) host entries (`GET/PUT /api/hosts`).

## Features

- **Bulk Edit Selected Hosts**: Update Host / Address (`address`), Port, Security, SNI, ALPN, Fingerprint, Mux, Status (`disable`), Inbound Tag, Weight, and extra fields across multiple selected hosts at once.
- **Bulk Clone with Suffix & New Address**: Clone checked hosts in a single `PUT /api/hosts` batch, appending a suffix (e.g. `(Server 2)`) and optionally setting a new address (e.g. `{TUN3DOMAIN}`).
- **Safe Preview & Backup**:
  - Automatic `Before / After` diff dialog (`#diff-dialog`) showing modified and cloned entries before writing to the panel.
  - Export JSON backups (`hosts-backup-*.json`) and restore/export via the Offline Swagger JSON modal (`#json-dialog`).
- **Dual Transport Mode**:
  - **GitHub Pages / Static Hosting (Direct Browser Mode)**: Runs completely client-side in your browser. Credentials live in browser memory (`sessionStorage` optional or none) and are never sent to any third-party backend.
  - **Local Python Proxy Mode (`server.py`)**: Bypasses strict panel CORS headers, Cloudflare Bot/Browser Integrity blocks (`error code: 1010`), `301`/`302` method downgrades (`405 Method Not Allowed`), and `pg_key_...` API key header formatting (`X-Api-Key`).

## Usage Options

### 1. Public Web UI (GitHub Pages)

Open the deployed site at:

```text
https://<your-github-username>.github.io/pgbulkhosteditor/
```

1. Enter your PasarGuard Panel Base URL (e.g. `https://panel.example.com` — trailing `/dashboard` paths are stripped automatically).
2. Authenticate using **Username + Password** (`POST /api/admin/token`) or a **Bearer JWT / `pg_key_...` API Key**.
3. Click **Connect & Load Hosts**.

> **Note on CORS / Mixed Content / Cloudflare:**
> - Your panel must be served over **HTTPS** if you access the editor over `https://...github.io` (browsers block HTTP requests from HTTPS pages).
> - If your PasarGuard panel restricts `ALLOWED_ORIGINS` (CORS) or sits behind a strict Cloudflare rule that blocks direct browser `fetch()`, use either **Offline JSON Import/Export** right inside the web UI or run the **Local Python Proxy** below.

### 2. Local Mode (Recommended for Strict CORS or Cloudflare Panels)

Requires only Python 3.10+ (zero third-party pip packages):

```bash
git clone https://github.com/<your-github-username>/pgbulkhosteditor.git
cd pgbulkhosteditor
python server.py
```

Then open `http://127.0.0.1:8787` in your browser. The UI automatically probes `/health` and switches to the local proxy transport.

### 3. Offline Swagger JSON Mode (No Direct Panel Network Needed)

Click **Offline JSON** in the web UI to:
1. Paste the JSON array returned by `GET /api/hosts` in your panel's Swagger UI (`/docs`).
2. Perform bulk edits or clones in the UI.
3. Export the generated payload and paste it into `PUT /api/hosts` in Swagger UI.

## Hosting Your Own Copy on GitHub Pages

This repository includes [`.github/workflows/pages.yml`](.github/workflows/pages.yml), which runs unit + JavaScript syntax checks on every push to `main` and publishes `index.html` to GitHub Pages.

1. Push this repository to GitHub as `pgbulkhosteditor`.
2. Go to **Repository Settings -> Pages**.
3. Under **Build and deployment -> Source**, select **GitHub Actions**.
4. Push to `main` (or trigger **Run workflow** manually under **Actions**).

## Running Tests Locally

```bash
python -m unittest test_app.py -v
```
