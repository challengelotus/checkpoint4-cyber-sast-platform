from fastapi import FastAPI

app = FastAPI(
    title="SAST Platform API",
    description="API para análise estática de código-fonte e detecção de vulnerabilidades.",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "sast-engine"}
