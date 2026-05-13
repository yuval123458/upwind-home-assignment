import { randomUUID } from "node:crypto";

import argon2 from "argon2";
import type { FastifyInstance } from "fastify";

import { CreateUserSchema, UpdateUserSchema } from "shared/schemas";

import { requireAdmin } from "../auth.js";
import {
  countActiveAdmins,
  createUser,
  deleteUser,
  findUserByEmail,
  findUserById,
  listUsers,
  toApiUser,
  updateUser,
} from "../db/users.js";

export default async function usersRoutes(app: FastifyInstance): Promise<void> {
  app.get(
    "/api/users",
    { preHandler: requireAdmin },
    async () => listUsers().map(toApiUser)
  );

  app.post(
    "/api/users",
    { preHandler: requireAdmin },
    async (request, reply) => {
      const parsed = CreateUserSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: "Invalid request body: " + parsed.error.issues.map((i) => i.message).join("; "),
        });
      }
      const { email, password, role } = parsed.data;

      if (findUserByEmail(email)) {
        return reply.code(400).send({ error: "Email already in use" });
      }

      const hash = await argon2.hash(password, { type: argon2.argon2id });
      const created = createUser({
        id: randomUUID(),
        email,
        password_hash: hash,
        role,
      });
      return reply.code(201).send(toApiUser(created));
    }
  );

  app.patch<{ Params: { id: string } }>(
    "/api/users/:id",
    { preHandler: requireAdmin },
    async (request, reply) => {
      const parsed = UpdateUserSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: "Invalid request body: " + parsed.error.issues.map((i) => i.message).join("; "),
        });
      }
      const { id } = request.params;
      const target = findUserById(id);
      if (!target) {
        return reply.code(404).send({ error: "User not found" });
      }

      // Last-admin guard: refuse changes that would leave zero active admins.
      const willStopBeingActiveAdmin =
        target.role === "admin" &&
        target.status === "active" &&
        ((parsed.data.role !== undefined && parsed.data.role !== "admin") ||
          (parsed.data.status !== undefined && parsed.data.status !== "active"));
      if (willStopBeingActiveAdmin && countActiveAdmins() <= 1) {
        return reply.code(400).send({
          error: "Cannot demote or disable the only remaining active admin",
        });
      }

      const updated = updateUser(id, parsed.data);
      if (!updated) {
        return reply.code(404).send({ error: "User not found" });
      }
      return toApiUser(updated);
    }
  );

  app.delete<{ Params: { id: string } }>(
    "/api/users/:id",
    { preHandler: requireAdmin },
    async (request, reply) => {
      const { id } = request.params;
      const target = findUserById(id);
      if (!target) {
        return reply.code(404).send({ error: "User not found" });
      }

      // Last-admin guard
      if (
        target.role === "admin" &&
        target.status === "active" &&
        countActiveAdmins() <= 1
      ) {
        return reply.code(400).send({
          error: "Cannot delete the only remaining active admin",
        });
      }

      // Optional safety: prevent self-deletion. Admins should not orphan themselves.
      if (id === request.user.id) {
        return reply.code(400).send({ error: "Cannot delete your own account" });
      }

      deleteUser(id);
      return { message: "User deleted" };
    }
  );
}
