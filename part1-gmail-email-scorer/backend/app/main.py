from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db.session import init_db
from app.routes import blocklist, me, score


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

app.include_router(me.router)
app.include_router(score.router)
app.include_router(blocklist.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
