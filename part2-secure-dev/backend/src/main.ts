import cors from "@fastify/cors";
import Fastify from "fastify";

const PORT = Number(process.env.PORT ?? "3001");
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN ?? "http://localhost:5173";

const app = Fastify({
  logger: { level: process.env.LOG_LEVEL ?? "info" },
});

await app.register(cors, {
  origin: FRONTEND_ORIGIN,
  credentials: true,
});

app.get("/health", async () => ({ status: "ok" }));

try {
  await app.listen({ port: PORT, host: "127.0.0.1" });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
