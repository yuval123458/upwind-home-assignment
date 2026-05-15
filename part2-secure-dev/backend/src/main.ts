import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";

import { initSchema } from "./db/index.js";
import { seedIfEmpty } from "./db/seed.js";
import authRoutes from "./routes/auth.js";
import eventsRoutes from "./routes/events.js";
import usersRoutes from "./routes/users.js";

const PORT = Number(process.env.PORT ?? "3001");
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN ?? "http://localhost:5173";

const app = Fastify({
  logger: { level: process.env.LOG_LEVEL ?? "info" },
});

await app.register(cookie);

await app.register(cors, {
  origin: FRONTEND_ORIGIN,
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
});

// Rate limiter is registered globally but disabled-by-default; routes opt in
// via per-route config so we cap only what needs capping (e.g., /login).
await app.register(rateLimit, { global: false });

initSchema();
await seedIfEmpty();

app.get("/health", async () => ({ status: "ok" }));

await app.register(authRoutes);
await app.register(eventsRoutes);
await app.register(usersRoutes);

try {
  await app.listen({ port: PORT, host: "127.0.0.1" });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
