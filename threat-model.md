# Threat Model — PenguWave Analyst Portal

The provided starter for part 2 of the assignment was reviewed and the following threats found. This document explains what could go wrong, what an attacker would try, and how the system plans to defend.

1. Anyone can use the app without logging in. The LoginModal in the starter is a popup that the user can close. The information about whether it was closed lives in the browser, not on the server. The other pages — EventsPage and UsersPage — show up no matter what. A visitor can close the login window and use the whole app as if they were logged in.
   Plan: build real login on the backend. The server starts a session after the password is checked. The frontend asks the server who am I on every page load. If there is no session, the login window cannot be closed and no other pages show up. The server independently checks every protected request, so even if the frontend is bypassed, the backend rejects calls from anyone not logged in.

2. Every user's password is exposed. The User type in the starter's types file has a password attribute. UsersPage renders every user's password as a visible column, so any admin (or anyone who reaches that page through threat 1) sees every account's password at once. LoginModal also prints the password to the browser console twice. The new-user password input on UsersPage is a plain text box, so anyone watching the screen sees the password as it is typed. This is the worst kind of exposure because users reuse passwords across services, so a leak here puts other systems at risk too.
   Plan: remove the password attribute from the public User type — so the type system itself prevents components from rendering it. Store passwords on the server as one-way hashes using a slow password hashing function such as argon2id. Never include the hash in any response from the server. Remove the lines in LoginModal that print the password to the browser console. Change the input to a password-style input that shows dots. Remove the password column from the user table.

3. DOM-based and stored XSS on EventsPage, turned into full account takeover by the session token sitting in local storage. EventsPage contains two cross-site scripting holes:
   - A DOM-based XSS in the search-results banner above the events table. The payload never travels through the server — the search input is held in React state and the starter splices that state into an HTML snippet which is then written into the page as raw HTML. A search term containing a script tag runs in the searcher's own browser, entirely client-side.
   - A stored XSS in the event detail view. When a row is clicked, the description field is assigned to the detail element's inner HTML directly. Because event data comes from the backend (and ultimately the database), an attacker who can plant a malicious description — whether by submitting an event or by compromising the upstream feed — gets their script to run in every analyst who later opens that event.

   The source of the malicious code (DOM, or stored in the database) is independent of where the session token lives — but both XSS variants land at the same place: arbitrary JavaScript executing inside the victim's browser. Once attacker-controlled JS is running on the page, it can read anything in local storage. Because the starter keeps the session token there, every XSS in this app turns from in-session abuse (clicking buttons as the victim during one visit) into permanent account takeover: the script reads the token, sends it to a server the attacker controls, and the attacker now calls the backend as the victim from their own computer until the session expires.

   Plan: stop inserting either value as raw HTML and let the framework's default text rendering (auto-escaping) handle them — a script tag written into the search box or into event data then shows up on screen as the literal characters and never executes. In parallel, move the session out of local storage into an HttpOnly cookie that JavaScript cannot read, so even if a future XSS slips through the session cannot be stolen and the attack is bounded to the active visit. The same cookie carries the strict same-site setting, which also blocks cross-site request forgery for free.

4. Reading other users events (insecure direct object reference). Each event carries an owner, but the contract for getting one event by id does not say anything about filtering by owner. A simple build that looks up an event by id alone lets any logged-in user read any other user's events.
   Plan: every event lookup is filtered by the current user. Admins are exempt, since their job is to see all events. If a user asks for an id that exists but belongs to someone else, the server responds with not found, same as if the id did not exist — so an attacker cannot probe which ids are real.

5. Mass-assignment on the create-user request, leading to self-promotion. The create-user call from UsersPage sends an email, a password, and a role to the backend. A naive backend trusts the role value, letting a regular user call this request with role set to admin and self-promote.
   Plan: only admins are allowed to call the create-user request. The backend validates the request body against a strict schema that rejects any field not on the allow-list. The update-user request accepts only role and status — passwords and emails cannot be changed through it.

6. Brute-force login and account enumeration. Without protection, an attacker can try thousands of passwords per minute. Different responses for no such email versus wrong password let the attacker figure out which email addresses are real.
   Plan: rate-limit login attempts to 5 per minute per source IP. The error message is the same for both cases (invalid email or password). The password check (which is slow on purpose, about a tenth of a second) runs even when the email does not exist, so the response time does not reveal whether the account exists.

## Out of scope

The following are deliberately deferred and will be called out as known limitations in the README: multi-factor authentication, password reset, email verification, running more than one backend instance, external audit logging.

## Threats considered but not needing active defense

Cross-site request forgery is blocked by the strict same-site cookie setting chosen in threat 3 — no separate token is needed.
SQL injection is prevented by using parameterized queries throughout — no string concatenation into SQL anywhere.
