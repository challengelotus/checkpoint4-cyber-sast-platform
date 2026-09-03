from fastapi import FastAPI
from pydantic import BaseModel

from ai_module.analyzer import AIAnalyzer
from engine.parser import SASTEngine
from engine.semgrep_runner import SemgrepRunner

app = FastAPI(
    title="Plataforma SAST",
    description="API de Análise Estática, Taint Analysis e IA",
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

    # Unifica resultados iniciais
    all_findings = ast_results + taint_results

    # 3. Análise Semântica e Remediação via IA
    ai_analyzer = AIAnalyzer()
    final_findings = ai_analyzer.get_remediation(payload.source_code, all_findings)

    return {
        "status": "success",
        "total_findings": len(all_findings),
        "findings": final_findings,
    }
