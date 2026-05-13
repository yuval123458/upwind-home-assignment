import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import argon2 from "argon2";

import { SecurityEventSchema } from "shared/schemas";

import { createEvent, countEvents } from "./events.js";
import { createUser, findUserById, listUsers } from "./users.js";

/**
 * Idempotent seed. Creates three users on first run (one admin + two regular),
 * then loads the 50 mock events from the frontend's data file. Safe to call
 * on every startup — checks for existing data first.
 */
export async function seedIfEmpty(): Promise<void> {
  await seedUsersIfMissing();
  seedEventsIfEmpty();
}

const SEED_USERS: ReadonlyArray<{
  id: string;
  email: string;
  role: "admin" | "user";
  password: string;
}> = [
  { id: "usr-001", email: "admin@penguwave.local", role: "admin", password: "password" },
  { id: "usr-002", email: "analyst-a@penguwave.local", role: "user", password: "password1" },
  { id: "usr-003", email: "analyst-b@penguwave.local", role: "user", password: "password2" },
];

async function seedUsersIfMissing(): Promise<void> {
  if (listUsers().length > 0) return;

  for (const u of SEED_USERS) {
    const hash = await argon2.hash(u.password, { type: argon2.argon2id });
    createUser({
      id: u.id,
      email: u.email,
      password_hash: hash,
      role: u.role,
    });
  }
  console.log(
    `[seed] Created ${SEED_USERS.length} demo users:\n` +
      SEED_USERS.map((u) => `  - ${u.email} / ${u.password} (${u.role})`).join("\n")
  );
}

function seedEventsIfEmpty(): void {
  if (countEvents() > 0) return;

  // Mock events live in the frontend's data directory.
  const eventsPath = resolve(
    process.cwd(),
    "..",
    "frontend",
    "data",
    "mock_events.json"
  );
  const raw = readFileSync(eventsPath, "utf-8");
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error("mock_events.json must be an array");
  }

  let inserted = 0;
  for (const entry of parsed) {
    const event = SecurityEventSchema.parse(entry);
    if (!findUserById(event.userId)) {
      console.warn(`[seed] Skipping event ${event.id}: owner ${event.userId} not found`);
      continue;
    }
    createEvent({
      id: event.id,
      timestamp: event.timestamp,
      severity: event.severity,
      title: event.title,
      description: event.description,
      asset_hostname: event.assetHostname,
      asset_ip: event.assetIp,
      source_ip: event.sourceIp,
      tags: event.tags,
      user_id: event.userId,
    });
    inserted++;
  }
  console.log(`[seed] Loaded ${inserted} mock events from mock_events.json`);
}
