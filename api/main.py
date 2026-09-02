from fastapi import FastAPI
from pydantic import BaseModel

from engine.parser import SASTEngine

app = FastAPI(title="Plataforma SAST", description="API de Análise Estática de Código")


# Definindo o payload esperado pela API
class CodePayload(BaseModel):
    source_code: str


@app.post("/api/v1/analyze")
async def analyze_code(payload: CodePayload):
    engine = SASTEngine()
    results = engine.analyze(payload.source_code)

    return {
        "status": "success",
        "findings": results,
    }
