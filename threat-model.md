# Threat Model — PenguWave Analyst Portal

I reviewed the starter and identified the threats below before writing backend code. I model three attackers: an anonymous visitor on the public URL, an authenticated regular user attempting privilege escalation or cross-user access, and an attacker with JavaScript execution in a victim's browser.

1. Anyone can use the app without logging in. The LoginModal is a closeable popup, its closed-state lives only in the browser, and EventsPage and UsersPage render regardless — a visitor can dismiss the modal and use the app as if authenticated. Fix: real server-side authentication. The server starts a session after a password check, the frontend calls who-am-I on every page load, and every protected route independently re-checks; bypassing the frontend changes nothing.

2. Every user's password is exposed. The User type in the starter's types file carries a password attribute; UsersPage renders it as a visible column; LoginModal logs it to the browser console twice. Fix: remove the password attribute from the public User type (so the type system blocks rendering), store passwords as argon2id hashes that never appear in any response, drop the console logs, and remove the password column from the user table.

3. DOM-based and stored XSS on EventsPage, escalated to account takeover by the session token in localStorage. The search-results banner splices React state into raw HTML; the event detail view assigns the description field to inner HTML directly. Either gives JavaScript execution in a victim's browser, which can read localStorage — so the token-in-localStorage choice turns any XSS into permanent account takeover. Fix: stop inserting either value as raw HTML and rely on React's default text rendering, and move the session to an HttpOnly cookie. The cookie's SameSite=Strict flag blocks CSRF for free, and a strict Content-Security-Policy at the reverse proxy adds defense-in-depth.

4. Reading other users' events (insecure direct object reference). Each event carries an owner, but a naive "get event by id" lookup ignores ownership and lets any logged-in user read any other user's events. Fix: filter every event query by the current user (admins exempt) and return 404 — identical to a nonexistent id — when an id belongs to someone else, so an attacker cannot probe which ids exist.

5. Mass-assignment on create-user, leading to self-promotion. The create-user call sends email, password, and role; a naive backend trusts the role field and lets a regular user self-promote. Fix: only admins can call the endpoint, the request body is validated against a strict Zod schema that rejects fields not on the allow-list, and the update-user schema omits password and email so they cannot be changed through that route.

6. Brute-force login and account enumeration. Without protection an attacker can try thousands of passwords per minute, and distinct responses for "no such email" versus "wrong password" reveal which addresses are real. Fix: rate-limit login to 5 attempts per minute per source IP, return the same generic error for both failure paths, and run an argon2 verify against a fixed decoy hash when the email does not exist, so the response time does not reveal account existence.

## Out of scope

Deliberately deferred and called out as known limitations: multi-factor authentication, password reset, email verification, running more than one backend instance, external audit logging.

## Threats considered but not needing active defense

Cross-site request forgery is blocked by the SameSite=Strict cookie chosen in threat 3 — no separate token needed. SQL injection is prevented by parameterized queries throughout — no string concatenation into SQL anywhere. Transport-layer eavesdropping is handled by TLS termination at the reverse proxy.
