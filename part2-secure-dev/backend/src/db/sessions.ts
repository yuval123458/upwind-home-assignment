import { createHash, randomBytes } from "node:crypto";

import { db } from "./index.js";

export const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

export interface SessionRow {
  token_hash: string;
  user_id: string;
  created_at: string;
  expires_at: string;
}

/**
 * SHA-256 of the token. We store the hash, never the plaintext token, so that
 * a DB compromise does not yield valid session tokens. SHA-256 is fast and that
 * is fine here: the token is 256 bits of cryptographic randomness, so brute-force
 * preimage search is infeasible regardless of hash speed.
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function createSession(userId: string): { token: string; expiresAt: Date } {
  const token = randomBytes(32).toString("hex"); // 256 bits of entropy
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  db.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)"
  ).run(hashToken(token), userId, expiresAt.toISOString());
  return { token, expiresAt };
}

export function findSessionByToken(token: string): SessionRow | undefined {
  return db
    .prepare("SELECT * FROM sessions WHERE token_hash = ?")
    .get(hashToken(token)) as SessionRow | undefined;
}

export function deleteSessionByToken(token: string): boolean {
  const result = db
    .prepare("DELETE FROM sessions WHERE token_hash = ?")
    .run(hashToken(token));
  return result.changes > 0;
}

export function deleteSessionsForUser(userId: string): number {
  const result = db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
  return result.changes;
}

export function deleteExpiredSessions(): number {
  const now = new Date().toISOString();
  const result = db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(now);
  return result.changes;
}

export function isSessionValid(row: SessionRow): boolean {
  return row.expires_at > new Date().toISOString();
}
