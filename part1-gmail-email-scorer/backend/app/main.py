from fastapi import FastAPI

app = FastAPI(
    title="Email Scorer API",
    description="Scores Gmail messages for maliciousness signals.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
