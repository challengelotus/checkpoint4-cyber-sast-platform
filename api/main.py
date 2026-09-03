from fastapi import FastAPI
from pydantic import BaseModel

from engine.parser import SASTEngine
from engine.semgrep_runner import SemgrepRunner

app = FastAPI(
    title="Plataforma SAST", description="API de Análise Estática e Taint Analysis"
)


class CodePayload(BaseModel):
    source_code: str


@app.post("/api/v1/analyze")
async def analyze_code(payload: CodePayload):
    # 1. Análise Estrutural (AST)
    ast_engine = SASTEngine()
    ast_results = ast_engine.analyze(payload.source_code)

    # 2. Taint Analysis (Semgrep)
    taint_engine = SemgrepRunner()
    taint_results = taint_engine.analyze(payload.source_code)

    # Unifica os resultados
    all_findings = ast_results + taint_results

    return {
        "status": "success",
        "total_findings": len(all_findings),
        "findings": all_findings,
    }
