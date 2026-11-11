# 🛡️ BetterPent

> *Pentest, but better: we look, we never touch.*

**BetterPent** is a passive website security auditor for the terminal (built for Kali Linux, works on any Linux/macOS with Python 3.10+).
It reads what a website sends back and tells you what an attacker would see — **without attacking anything**: no payloads, no brute force, no fuzzing.

**BetterPent**, terminal için pasif bir web sitesi güvenlik denetim aracıdır (Kali Linux için yazıldı, Python 3.10+ olan her Linux/macOS'ta çalışır).
Sitenin döndürdüğü yanıtları okur ve bir saldırganın neler görebileceğini söyler — **hiçbir saldırı yapmadan**: payload yok, brute force yok, fuzzing yok.

> ⚠️ Only scan websites you own or have written permission to test. / Sadece sahibi olduğun veya yazılı izin aldığın siteleri tara.

---

## ✨ What it checks / Neleri kontrol eder

| Area / Alan | Checks / Kontroller |
|---|---|
| **Transport** | HTTPS used, HTTP → HTTPS redirect, HTTPS → HTTP downgrade in redirects |
| **TLS** | Certificate trust, expiry (days left), negotiated TLS version, legacy TLS 1.0/1.1 accepted |
| **Headers** | CSP (+ weak `unsafe-inline`/`unsafe-eval`), HSTS (+ short max-age), clickjacking (X-Frame-Options **or** CSP `frame-ancestors`), nosniff, Referrer-Policy, Permissions-Policy, version leaks (`Server`, `X-Powered-By`, ...) |
| **Cookies** | Secure / HttpOnly / SameSite, `SameSite=None` without Secure — including cookies set during redirects |
| **Forms** | Login form over HTTP, login via GET, missing CSRF token hint |
| **Mixed content** | Scripts/styles/iframes (active) and images/media (passive) loaded over HTTP on an HTTPS page |
| **CORS** | Arbitrary `Origin` reflected, with or without credentials |
| **Exposed files** | `.git`, `.env`, `.svn`, SQL dumps, backup archives, `wp-config` backups, `phpinfo`, `server-status`, `.DS_Store`, directory listing — every hit is confirmed by **content signature**, so soft-404 pages are not false positives |
| **Well-known files** | `security.txt` (RFC 9116), `robots.txt`, `sitemap.xml` (validated, not just "200 OK") |
| **Broken links** | Internal links on the page (HEAD, falls back to GET) |
| **Performance** | Response time, redirects, HTML size, compression, asset counts (info only — never changes the score) |
| **Technology** | Fingerprints from headers and specific markers (WordPress, Next.js, Cloudflare, ...) — no guessing from random words |

Score starts at **100**; every security finding subtracts its penalty. Levels: `good` ≥ 85, `fair` ≥ 70, `needs_improvement` ≥ 50, `critical` < 50.
An unreachable site gets **no score** (it is not "insecure", it is just not there).

---

## ⚙️ Installation / Kurulum (Kali Linux)

Kali's system Python is "externally managed", so use **pipx** (recommended) or a venv.
Kali'nin sistem Python'u pip ile doğrudan paket kurdurmaz; **pipx** (önerilen) ya da venv kullan.

```bash
# pipx (recommended / önerilen)
sudo apt install -y pipx git
pipx ensurepath
pipx install git+https://github.com/Xocsayh/web-site-tester.git
betterpent --version
```

```bash
# or a virtual environment / ya da sanal ortam
git clone https://github.com/Xocsayh/web-site-tester.git
cd web-site-tester
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

Update / Güncelle: `pipx upgrade betterpent` (or `pipx reinstall betterpent`)

---

## 🚀 Usage / Kullanım

```bash
betterpent example.com                 # short summary / kısa özet
betterpent example.com -v              # every finding + how to fix / tüm bulgular + çözüm
betterpent example.com -v --banner     # with banner / banner ile
betterpent https://example.com --html report.html --json report.json
betterpent example.com --json - | jq '.findings[] | select(.severity=="high")'
betterpent example.com -q --threshold 70 || echo "needs work"   # for scripts/CI
```

| Option | Description |
|---|---|
| `target` / `-u, --url` | URL or hostname. Without a scheme, `https://` is tried first, then `http://` |
| `-v, --verbose` | All findings with fixes, TLS and speed info |
| `-q, --quiet` | Print only when there is a risk |
| `--html FILE` / `--json FILE` | Save reports (`--json -` prints JSON to stdout) |
| `--threshold N` | Exit code 1 when score < N (default 50) |
| `--no-probe` | Skip sensitive-file probes (`.git`, `.env`, backups...) |
| `--no-links`, `--max-links N` | Skip / limit broken-link check (default 30) |
| `-k, --insecure` | Scan sites with an invalid certificate (still reported) |
| `-t, --timeout S` | Request timeout (default 8 s) |
| `--user-agent UA`, `--no-color`, `--banner`, `--version` | |

**Exit codes:** `0` ok · `1` score below threshold · `2` unreachable · `3` bad usage

### What traffic does it send? / Ne kadar istek atar?
About 25–60 normal GET/HEAD requests: the page itself, `http://` redirect test, one TLS handshake (+1 legacy-TLS attempt), 3 well-known files, ~15 exposure paths (bounded to 8 KB each, no redirects followed), one request with a fake `Origin` header, and up to `--max-links` internal links. Use `--no-probe --no-links` for the lightest scan.

---

## 🧪 Development / Geliştirme

```bash
pip install -e .
python -m unittest discover -s tests -v
```

Tests run fully offline against a local HTTP server (no internet needed).

New checks live in `betterpent/checks/` — a check is just a function `check_x(scan)` that calls `scan.add(...)`; register it in `checks/__init__.py`.

---

## 🙏 Thanks / Teşekkürler

Thank you for reviewing and contributing. This tool is for **educational and authorized testing purposes only**.
Projeyi inceleyip katkı sağladığınız için teşekkürler. Bu araç **yalnızca eğitim ve izinli testler** içindir.

MIT License © 2026 Ahmet Kugu
