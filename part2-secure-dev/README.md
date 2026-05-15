# PenguWave Analyst Portal — Part 2

A small full-stack app for an analyst portal that displays security events and lets admins manage user accounts. This is the implementation that follows the threat model at `../threat-model.md`. The repo is an npm workspaces monorepo with three packages: `frontend` (React + Vite + TypeScript), `backend` (Fastify + TypeScript on SQLite), and `shared` (Zod schemas reused by both sides).

## Design notes

A couple of decisions about how the project is laid out matter more than they look, and they point in the same direction.

The repo is a TypeScript-everywhere npm workspaces monorepo with three packages. The important one is `shared`. It exports the Zod schemas that describe every request and response shape — `LoginSchema`, `CreateUserSchema`, `UpdateUserSchema`, `SecurityEventSchema`, and so on — and both the frontend and the backend import those same schemas. The frontend uses them for form validation and TypeScript types; the backend uses them for request-body validation on every protected route. There is one source of truth for what a valid payload looks like, and it lives in one place. For a security-oriented app where the request contract is part of the threat model (the mass-assignment defense in particular lives in those `.strict()` schemas — they reject any field not on the allow-list, so a regular user cannot send `role: "admin"` and slip it past), keeping the validation layer in one shared package is the simplest way to make sure the client and the server never disagree about what is acceptable.

I deliberately did not use JWT for sessions. JWT is the default reach for "I need to know who is calling," but for this application it carries a real footgun: a JWT is a signed payload the client holds, and revocation is hard — once issued, it is valid until it expires, and "kill this user's sessions right now" requires building a denylist that defeats most of the point of going stateless in the first place. The portal has a real need to revoke immediately — when an admin disables a user, that user must be unable to make another authenticated request. So I chose opaque server-side session tokens instead. On login the server generates 256 random bits, stores the SHA-256 hash of that token in the `sessions` table (so a database dump does not yield usable tokens), and sets the raw token as an HttpOnly, SameSite=Strict cookie on the response. Every protected request then performs a quick DB lookup to validate the cookie. The extra DB read per request is the cost I accept; what I get is instant revocation, no token-decoding magic on the client, and a server-controlled definition of "who is logged in." At single-instance scale this is fine; at scale it needs to be rethought, which the production-deployment section below addresses.

Both decisions push the same way: every authority statement — "this payload is valid," "this user is logged in" — lives on the server. The frontend is never trusted to claim anything on its own. That is what makes the same React UI safe to ship without changing the security posture, even though the starter version of the frontend had several places where it would have lied to itself about both questions.

## How to run the project

Requirements: Node 20 or newer (developed on 24), npm 10 or newer. Nothing else — SQLite is embedded.

From the `part2-secure-dev` directory:

1. Install dependencies for all three workspaces in one shot.
   ```
   npm install
   ```
2. Copy the backend environment template.
   ```
   cp backend/.env.example backend/.env
   ```
   Defaults are fine for local development: backend on port 3001, frontend on port 5173, SQLite file at `backend/penguwave.db`.
3. Start the backend (terminal one). The first run creates the schema and seeds three demo users plus 50 mock events.
   ```
   npm run dev --workspace backend
   ```
4. Start the frontend (terminal two).
   ```
   npm run dev --workspace frontend
   ```
5. Open the frontend at `http://localhost:5173` and sign in with one of the seed accounts:
   - `admin@penguwave.local` / `password` (admin)
   - `analyst-a@penguwave.local` / `password1` (regular user)
   - `analyst-b@penguwave.local` / `password2` (regular user)

Delete `backend/penguwave.db*` to reset to a clean state — the seed runs again on next startup. The glob catches the SQLite file plus its `-shm` and `-wal` sidecars from WAL mode; deleting only `.db` and leaving the sidecars produces inconsistent state on next startup.

## How authentication works

Authentication is server-side and cookie-based.

When a user posts to `/api/auth/login`, the backend validates the body with a Zod schema, looks up the user by email, and verifies the password with argon2id. If the email does not exist the backend still runs an argon2 verify against a fixed decoy hash. This makes the login response take roughly the same time whether the email exists or not, so an attacker cannot enumerate accounts by measuring response times. The reply on both failure paths is the same generic message.

On success, the server generates a 256-bit random session token, stores only its SHA-256 hash in the `sessions` table (so a database dump does not yield usable tokens), and sets the token as the value of a cookie named `session`. The cookie is marked `HttpOnly` (JavaScript on the page cannot read it, so XSS cannot exfiltrate it), `SameSite=Strict` (the browser refuses to send it on cross-site requests, which removes CSRF as a concern), and `Secure` whenever `NODE_ENV=production` (so the cookie is only ever sent over HTTPS). Sessions expire after one hour.

The frontend has no notion of the token at all — it never reads it, never stores it, and never includes it manually. The browser attaches the cookie automatically to every same-origin request once `credentials: "include"` is set on the fetch calls. On page load the frontend calls `/api/auth/me`; if the cookie is missing or the session has expired, that call returns 401 and the app shows the login screen. Logging out hits `/api/auth/logout`, which deletes the session row server-side and clears the cookie.

There is also a rate limit of five login attempts per minute per source IP, applied only to `/api/auth/login`, to cap online brute force.

## How authorization is enforced

Authorization runs entirely on the backend. The frontend hides UI based on role for usability, but every protected route checks the session and the role on its own — bypassing the UI changes nothing.

Two Fastify preHandlers do the work. `requireAuth` resolves the cookie to a user, rejects unauthenticated requests with 401, rejects requests whose user has been disabled, and attaches the user record to the request. `requireAdmin` does the same and additionally returns 403 if the user is not an admin. Every API route declares which one it needs.

Regular users get row-level scoping on events. The `GET /api/events` list and `GET /api/events/:id` lookup both call user-scoped database functions (`listEventsForUser`, `findEventForUser`) so a non-admin can only ever see their own rows. Admins get the unfiltered view. If a non-admin asks for an event id that exists but belongs to someone else, the server responds with 404, identical to the response for an id that does not exist — so id enumeration reveals nothing.

User management routes (`/api/users` and friends) require admin. Input bodies are validated against strict Zod schemas with `.strict()` so unknown fields are rejected outright. This blocks mass-assignment — a regular user cannot self-promote by adding a `role: "admin"` field, because they cannot reach the endpoint at all, and even if they could the schema would only accept the documented fields. The update-user schema deliberately omits password and email so they cannot be changed through that endpoint.

Two extra rules in the user-management code prevent destructive admin mistakes. A last-admin guard refuses any change that would leave zero active admins, so the system cannot accidentally lock itself out. And when an admin disables a user, the backend immediately deletes every session row for that user, which means an attacker (or just a compromised account) cannot keep making requests with a previously issued cookie — access ends in the same request that flipped the status.

## How you would deploy this securely in production

The current code is built to run as a single process with SQLite on disk and session tokens stored in the database — fine for the assignment and for a small single-instance deployment, but a few things have to change before this is production-ready.

### Put a reverse proxy in front

The backend should run behind a reverse proxy (nginx, Caddy, an AWS load balancer, Cloudflare, etc.) that terminates TLS, serves the built frontend's static files, and adds security response headers globally — HSTS to force HTTPS, a content-security-policy as a second line of defense against XSS, X-Frame-Options to block clickjacking. The backend itself only speaks plain HTTP on the loopback interface. Setting `NODE_ENV=production` on the backend at the same time switches the session cookie's Secure flag on, so the cookie never travels over an unencrypted connection.

### Session storage will not scale as-is

Today every protected request looks up the session in the SQLite table. That's one read on a local file per request — invisible at single-instance scale, but it grows linearly with traffic, and it breaks the moment you want more than one backend instance because SQLite lives on one machine. There are two reasonable directions:

- **JWT (signed, stateless tokens).** The server signs a token containing the user id and an expiry, and verifies the signature on each request without any database lookup. No per-request DB load, and it works across any number of backend instances. The tradeoff is that revocation is hard — a leaked JWT is valid until it expires, so you typically pair it with short lifetimes and a refresh-token flow, or with a small denylist of revoked ids for instant-kill cases (like "admin disabled this user").
- **Opaque tokens in a shared cache.** Keep the current design but move the sessions table out of SQLite and into Redis (or similar). Lookups are fast and shared across all backend instances, and instant revocation still works the way it does today (delete the row).

For this codebase I would lean toward JWTs with short access-token lifetimes and a refresh-token flow, because the instant-kill paths (disable user, last-admin guard) are narrow enough that a small denylist covers them.

### Database needs to move off SQLite

SQLite is a single-file embedded database — there is no way for two separate backend processes on two machines to share it. Moving to PostgreSQL (or another managed relational database) gives you network access, real concurrent writes, replication, point-in-time backups, and proper user/permission separation. The schema in `backend/src/db/index.ts` is straightforward to port: add a migration step instead of `CREATE TABLE IF NOT EXISTS` on startup.

### Rate limiting also needs a shared store

The current rate limiter counts requests in-process, per backend instance. With two backend instances behind a load balancer, an attacker effectively gets twice as many login attempts because each instance has its own counter. Moving the rate limiter to Redis (or any shared store) is the standard fix.

### Operational hygiene

Lock CORS to the production frontend origin via `FRONTEND_ORIGIN` — never widen it to a wildcard. Build with `npm run build` in each workspace and run the backend under a process supervisor. Keep secrets out of the repo and load them from a secret store at deploy time. Rotate the seed credentials before any deployment outside local development. Ship application logs to an external, append-only sink so security-relevant events (logins, failed logins, admin actions, user disables) survive even if the app itself is compromised. Run `npm audit` regularly and keep dependencies current.

The threats this README's defenses correspond to are documented at `../threat-model.md`. Items deliberately deferred for the assignment (multi-factor authentication, password reset, email verification, external audit logging, multi-instance scale) are listed there.
