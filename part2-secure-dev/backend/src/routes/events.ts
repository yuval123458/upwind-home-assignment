import type { FastifyInstance } from "fastify";

import { requireAuth } from "../auth.js";
import {
  countAllEvents,
  countEventsForUser,
  findEvent,
  findEventForUser,
  listAllEvents,
  listEventsForUser,
  toApiEvent,
} from "../db/events.js";

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

function parsePagination(query: unknown): { page: number; limit: number } {
  const q = (query ?? {}) as Record<string, string | undefined>;
  let page = Number.parseInt(q.page ?? "1", 10);
  let limit = Number.parseInt(q.limit ?? String(DEFAULT_LIMIT), 10);
  if (!Number.isFinite(page) || page < 1) page = 1;
  if (!Number.isFinite(limit) || limit < 1) limit = DEFAULT_LIMIT;
  if (limit > MAX_LIMIT) limit = MAX_LIMIT;
  return { page, limit };
}

export default async function eventsRoutes(app: FastifyInstance): Promise<void> {
  app.get(
    "/api/events",
    { preHandler: requireAuth },
    async (request) => {
      const user = request.user;
      const { page, limit } = parsePagination(request.query);
      const offset = (page - 1) * limit;

      const isAdmin = user.role === "admin";
      const total = isAdmin ? countAllEvents() : countEventsForUser(user.id);
      const rows = isAdmin
        ? listAllEvents(limit, offset)
        : listEventsForUser(user.id, limit, offset);

      return {
        items: rows.map(toApiEvent),
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit)),
      };
    }
  );

  app.get<{ Params: { id: string } }>(
    "/api/events/:id",
    { preHandler: requireAuth },
    async (request, reply) => {
      const user = request.user;
      const { id } = request.params;
      const row =
        user.role === "admin" ? findEvent(id) : findEventForUser(id, user.id);
      if (!row) {
        return reply.code(404).send({ error: "Event not found" });
      }
      return toApiEvent(row);
    }
  );
}
