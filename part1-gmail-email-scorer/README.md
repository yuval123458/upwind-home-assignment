# Gmail Email Scorer — Part 1

A Gmail Add-on that flags potentially malicious emails. When a user opens a message in Gmail, the add-on extracts the message and asks a backend API to score it on a 0–100 scale, returning a verdict (safe / suspicious / malicious), the individual signals that fired, and a short recommendation.

## Architecture

The system has two pieces:

The **add-on** (`addon/`) is a Google Apps Script project that registers as a Gmail contextual add-on. When an email is opened, Apps Script fires a trigger that runs `buildScanCard` (see `Code.gs`), which reads the open message via Gmail's add-on APIs, hashes any attachments locally, and POSTs the message data to the backend. The add-on attaches the user's Google identity ID token in the Authorization header so the backend knows who is asking. The card UI is rebuilt from the backend's response.

The **backend** (`backend/`) is a FastAPI service on Python 3.12. On every request it verifies the Google ID token against the configured OAuth client ID, looks the user up in SQLite (creating them on first sight), and runs the scoring pipeline. Each signal is an independent module under `app/scoring/signals/` so signals can be added or removed without touching anything else. Signals that hit external APIs (URL reputation, the LLM, attachment reputation, domain age) are fired in parallel via `asyncio.gather` so the per-request latency is roughly the slowest dependency rather than the sum. Signal scores are summed, capped at 100, and translated to a band using a per-user sensitivity threshold. The scan is written to a history table; the response goes back to the add-on for rendering.

Data is stored in a local SQLite file (`scorer.db`) via SQLModel: users, scan history, per-user settings, and per-user blocklist entries.

## APIs used

External services the backend calls:

- **Anthropic Claude** — content analysis. The model is asked to look at subject/sender/body for phishing indicators and to return a structured verdict using Claude's tool-use feature (so the output is a typed JSON object rather than free text). Temperature is set to 0 for stability.
- **VirusTotal** — URL reputation and file (attachment) reputation by SHA-256.
- **Google Safe Browsing (Lookup API v4)** — URL reputation, used alongside VirusTotal so the two cross-check each other.
- **Hybrid Analysis** — attachment reputation by SHA-256, complementing VirusTotal on file lookups.
- **RDAP (with WHOIS fallback)** — domain age lookup for the sender's domain; very young domains contribute points.
- **Google's public-key endpoint** — used inside the backend to verify the ID tokens that the add-on attaches to each request.

Google APIs the add-on itself talks to:

- **Gmail Add-on APIs** — message metadata, headers, body, attachments (via the OAuth scopes declared in `appsscript.json`).
- **Gmail Settings (`gmail.settings.basic`)** — used to create a real Gmail filter when the user adds a sender or domain to their personal blocklist, so blocked mail is auto-archived going forward.
- **OpenID / userinfo.email** — for issuing the ID token the backend verifies.

## Implemented features

Scoring signals (each is a module under `app/scoring/signals/`):

- **Authentication headers** — parses the `Authentication-Results` header to detect SPF / DKIM / DMARC failures.
- **Reply-To mismatch** — flags mail where the Reply-To domain differs from the From domain.
- **Link / anchor mismatch** — flags links whose visible text claims one URL while the actual href points somewhere else (classic phishing pattern).
- **URL reputation** — submits all URLs in the message to VirusTotal and Safe Browsing in parallel; either service flagging is enough to fire.
- **LLM content analysis** — Claude reviews subject/sender/body for phishing language and pretext, returning a structured verdict with confidence.
- **Attachment reputation** — for each attachment, the add-on computes a SHA-256 locally and the backend looks the hash up in VirusTotal and Hybrid Analysis. No file bytes leave the user's Gmail.
- **Sender domain age** — RDAP/WHOIS lookup; domains under a young-age threshold contribute points.

Per-user features:

- **Sensitivity setting** (low / medium / high) — adjusts the score thresholds that separate safe / suspicious / malicious.
- **Personal blocklist** — add a sender or domain from the add-on UI and the backend creates a Gmail filter under the user's account so future mail from that sender is auto-archived.
- **Scan history** — every score is persisted and surfaced to the add-on; if a user has scanned the same sender before, the new card shows the prior verdict.

Infrastructure / cross-cutting:

- **Authentication** — every backend request requires a valid Google ID token, verified against the add-on's OAuth client ID. Users are auto-created on first request.
- **Rate limiting** — per-IP, applied via `slowapi`. `/score` is capped at 30 per minute.

## Known limitations

- **Single-process deployment.** The backend uses SQLite (one file on disk) and an in-process rate limiter. Fine for the assignment and for a personal install, but anything multi-instance would need PostgreSQL and a shared rate-limit store (Redis).
- **Synchronous scoring path.** The HTTP request is held open until every signal returns. External APIs can be slow; per-call timeouts cap this but a real production system would push the work to a background worker and stream the result back.
- **Free-tier external APIs.** VirusTotal, Hybrid Analysis, and Safe Browsing all have low free-tier rate limits and short per-request quotas. The pipeline degrades gracefully when a service is unreachable, rate-limited, or returns an error — the affected signal simply does not fire, and the score reflects only the signals that succeeded. This means a determined attacker who can exhaust the user's quota can suppress some signals.
- **Attachment scanning is hash-only.** The add-on computes SHA-256 in the user's browser and sends only the hash, not the bytes. This is intentional (we do not want to ship attachment contents to third parties) but it means files unknown to VirusTotal or Hybrid Analysis are silent — there is no dynamic analysis.
- **LLM determinism.** Temperature is pinned to 0, but Claude does not guarantee bit-exact repeatability across model versions. Verdicts for borderline messages can shift over time.
- **No live-deployment URL.** Running the add-on against this backend during local development requires a public tunnel to the FastAPI server (ngrok or similar) because Google's add-on runtime cannot reach `localhost`. Production deployment of the backend (hosting, secret management, TLS) is out of scope for the assignment.
- **No admin or analyst portal.** This part of the assignment is built as a personal tool — there is no shared dashboard, no per-organization view, no centralized blocklist.
- **No analyst feedback loop.** The user cannot mark a verdict as wrong; nothing is fed back into the scoring weights. Sensitivity is the only knob.
- **Domain age cache is in-process.** WHOIS / RDAP lookups are cached in memory only, so cache state is lost on every restart. A multi-instance deployment would need a shared cache.
