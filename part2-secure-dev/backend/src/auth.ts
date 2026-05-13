import type { CookieSerializeOptions } from "@fastify/cookie";
import type { FastifyReply, FastifyRequest } from "fastify";

import { deleteSessionByToken, findSessionByToken, isSessionValid } from "./db/sessions.js";
import { findUserById, type UserRow } from "./db/users.js";

export const SESSION_COOKIE_NAME = "session";

const IS_PROD = process.env.NODE_ENV === "production";

/**
 * Cookie flags for the session token:
 * - httpOnly: JavaScript can't read it (defense against XSS exfiltration)
 * - secure:   only sent over HTTPS (disabled in dev because localhost is http)
 * - sameSite: 'strict' blocks the cookie on cross-site requests (CSRF defense)
 * - path:     '/' so it's sent for every API path under this origin
 */
export const sessionCookieOptions: CookieSerializeOptions = {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: "strict",
  path: "/",
};

declare module "fastify" {
  interface FastifyRequest {
    user: UserRow;
  }
}

async function resolveUser(request: FastifyRequest): Promise<UserRow | null> {
  const token = request.cookies[SESSION_COOKIE_NAME];
  if (!token) return null;

  const session = findSessionByToken(token);
  if (!session) return null;

  if (!isSessionValid(session)) {
    deleteSessionByToken(token); // opportunistic cleanup
    return null;
  }

  const user = findUserById(session.user_id);
  if (!user || user.status !== "active") return null;
  return user;
}

/**
 * preHandler: requires any authenticated, active user. Replies 401 otherwise.
 * On success, sets request.user.
 */
export async function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const user = await resolveUser(request);
  if (!user) {
    reply.code(401).send({ error: "Authentication required" });
    return;
  }
  request.user = user;
}

/**
 * preHandler: requires an authenticated user with the admin role.
 * Replies 401 if unauthenticated, 403 if authenticated but not admin.
 */
export async function requireAdmin(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const user = await resolveUser(request);
  if (!user) {
    reply.code(401).send({ error: "Authentication required" });
    return;
  }
  if (user.role !== "admin") {
    reply.code(403).send({ error: "Admin role required" });
    return;
  }
  request.user = user;
}
