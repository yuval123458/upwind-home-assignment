import argon2 from "argon2";
import type { FastifyInstance } from "fastify";

import { LoginSchema } from "shared/schemas";

import { SESSION_COOKIE_NAME, requireAuth, sessionCookieOptions } from "../auth.js";
import { createSession, deleteSessionByToken } from "../db/sessions.js";
import { findUserByEmail, toApiUser } from "../db/users.js";

/**
 * Argon2 hash of a constant decoy password. Computed lazily on first login.
 * Used during login when the email doesn't exist, so verification still takes
 * ~argon2 time — eliminates timing-based user enumeration.
 */
let _decoyHash: string | null = null;
async function getDecoyHash(): Promise<string> {
  if (_decoyHash === null) {
    _decoyHash = await argon2.hash("__decoy__", { type: argon2.argon2id });
  }
  return _decoyHash;
}

export default async function authRoutes(app: FastifyInstance): Promise<void> {
  app.post(
    "/api/auth/login",
    {
      config: {
        rateLimit: { max: 5, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      const parsed = LoginSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "Invalid request body" });
      }
      const { email, password } = parsed.data;
      const user = findUserByEmail(email);

      // Constant-time path: always run argon2.verify, even if user is missing,
      // so response time doesn't reveal whether the email exists.
      let valid = false;
      if (user) {
        valid = await argon2.verify(user.password_hash, password);
      } else {
        await argon2.verify(await getDecoyHash(), password);
      }

      if (!user || !valid || user.status !== "active") {
        return reply.code(401).send({ error: "Invalid email or password" });
      }

      const { token, expiresAt } = createSession(user.id);
      reply.setCookie(SESSION_COOKIE_NAME, token, {
        ...sessionCookieOptions,
        expires: expiresAt,
      });

      return reply.send({ user: toApiUser(user) });
    }
  );

  app.get(
    "/api/auth/me",
    { preHandler: requireAuth },
    async (request) => toApiUser(request.user)
  );

  app.post("/api/auth/logout", async (request, reply) => {
    const token = request.cookies[SESSION_COOKIE_NAME];
    if (token) {
      deleteSessionByToken(token);
    }
    reply.clearCookie(SESSION_COOKIE_NAME, sessionCookieOptions);
    return reply.send({ message: "Logged out" });
  });
}
