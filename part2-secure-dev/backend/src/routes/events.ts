import type { FastifyInstance } from "fastify";

import { requireAuth } from "../auth.js";
import {
  findEvent,
  findEventForUser,
  listAllEvents,
  listEventsForUser,
  toApiEvent,
} from "../db/events.js";

export default async function eventsRoutes(app: FastifyInstance): Promise<void> {
  app.get(
    "/api/events",
    { preHandler: requireAuth },
    async (request) => {
      const user = request.user;
      const rows = user.role === "admin" ? listAllEvents() : listEventsForUser(user.id);
      return rows.map(toApiEvent);
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
      // 404 either way — don't leak whether the event exists but is owned by someone else.
      if (!row) {
        return reply.code(404).send({ error: "Event not found" });
      }
      return toApiEvent(row);
    }
  );
}
