from contextlib import asynccontextmanager

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.db.session import init_db
from app.rate_limit import limiter
from app.routes import blocklist, history, me, score, settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Email Scorer API",
    description="Scores Gmail messages for maliciousness signals.",
    version="0.1.0",
    lifespan=lifespan,
)

# Rate limiter keyed by IP. Routes opt in via @limiter.limit(...).
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(me.router)
app.include_router(score.router)
app.include_router(blocklist.router)
app.include_router(history.router)
app.include_router(settings.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
