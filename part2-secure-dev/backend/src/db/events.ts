import type { SecurityEvent, Severity } from "shared/schemas";

import { db } from "./index.js";

export interface EventRow {
  id: string;
  timestamp: string;
  severity: Severity;
  title: string;
  description: string;
  asset_hostname: string;
  asset_ip: string;
  source_ip: string;
  tags_json: string;
  user_id: string;
}

export function toApiEvent(row: EventRow): SecurityEvent {
  return {
    id: row.id,
    timestamp: row.timestamp,
    severity: row.severity,
    title: row.title,
    description: row.description,
    assetHostname: row.asset_hostname,
    assetIp: row.asset_ip,
    sourceIp: row.source_ip,
    tags: JSON.parse(row.tags_json) as string[],
    userId: row.user_id,
  };
}

/**
 * Admin-only: returns every event regardless of owner.
 */
export function listAllEvents(): EventRow[] {
  return db
    .prepare("SELECT * FROM events ORDER BY timestamp DESC")
    .all() as EventRow[];
}

/**
 * Per-user: returns only events owned by `userId`. This is the authz boundary
 * — non-admin callers MUST go through this function, never listAllEvents().
 */
export function listEventsForUser(userId: string): EventRow[] {
  return db
    .prepare("SELECT * FROM events WHERE user_id = ? ORDER BY timestamp DESC")
    .all(userId) as EventRow[];
}

/**
 * Admin lookup: any event by id.
 */
export function findEvent(id: string): EventRow | undefined {
  return db
    .prepare("SELECT * FROM events WHERE id = ?")
    .get(id) as EventRow | undefined;
}

/**
 * Per-user lookup: returns the event only if it belongs to `userId`. Returns
 * undefined when the event exists but is owned by someone else. This collapses
 * IDOR (existence-disclosure via different error codes) into a single 404 path.
 */
export function findEventForUser(id: string, userId: string): EventRow | undefined {
  return db
    .prepare("SELECT * FROM events WHERE id = ? AND user_id = ?")
    .get(id, userId) as EventRow | undefined;
}

export function createEvent(input: {
  id: string;
  timestamp: string;
  severity: Severity;
  title: string;
  description: string;
  asset_hostname: string;
  asset_ip: string;
  source_ip: string;
  tags: string[];
  user_id: string;
}): void {
  db.prepare(
    `INSERT INTO events
       (id, timestamp, severity, title, description,
        asset_hostname, asset_ip, source_ip, tags_json, user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    input.id,
    input.timestamp,
    input.severity,
    input.title,
    input.description,
    input.asset_hostname,
    input.asset_ip,
    input.source_ip,
    JSON.stringify(input.tags),
    input.user_id
  );
}

export function countEvents(): number {
  const row = db.prepare("SELECT COUNT(*) AS c FROM events").get() as { c: number };
  return row.c;
}
