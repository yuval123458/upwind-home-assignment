import type { Role, User, UserStatus } from "shared/schemas";

import { db } from "./index.js";

export interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  role: Role;
  status: UserStatus;
  created_at: string;
}

/**
 * Maps a DB row to the public API user shape. Critically, this never includes
 * password_hash — if you forget to use this function and return a UserRow directly,
 * the response will include the hash. Use this everywhere.
 */
export function toApiUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    role: row.role,
    status: row.status,
  };
}

export function findUserByEmail(email: string): UserRow | undefined {
  return db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email) as UserRow | undefined;
}

export function findUserById(id: string): UserRow | undefined {
  return db
    .prepare("SELECT * FROM users WHERE id = ?")
    .get(id) as UserRow | undefined;
}

export function listUsers(): UserRow[] {
  return db.prepare("SELECT * FROM users ORDER BY email").all() as UserRow[];
}

export function countActiveAdmins(): number {
  const row = db
    .prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND status = 'active'")
    .get() as { c: number };
  return row.c;
}

export function createUser(input: {
  id: string;
  email: string;
  password_hash: string;
  role: Role;
  status?: UserStatus;
}): UserRow {
  const status = input.status ?? "active";
  db.prepare(
    "INSERT INTO users (id, email, password_hash, role, status) VALUES (?, ?, ?, ?, ?)"
  ).run(input.id, input.email, input.password_hash, input.role, status);
  const row = findUserById(input.id);
  if (!row) throw new Error("Failed to retrieve user after insert");
  return row;
}

export function updateUser(
  id: string,
  fields: { role?: Role; status?: UserStatus }
): UserRow | undefined {
  const updates: string[] = [];
  const values: unknown[] = [];
  if (fields.role !== undefined) {
    updates.push("role = ?");
    values.push(fields.role);
  }
  if (fields.status !== undefined) {
    updates.push("status = ?");
    values.push(fields.status);
  }
  if (updates.length === 0) return findUserById(id);
  values.push(id);
  db.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).run(...values);
  return findUserById(id);
}

export function deleteUser(id: string): boolean {
  const result = db.prepare("DELETE FROM users WHERE id = ?").run(id);
  return result.changes > 0;
}
