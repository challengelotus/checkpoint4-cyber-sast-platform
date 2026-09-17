from fastapi import Depends, FastAPI, File, UploadFile
from sqlalchemy.orm import Session

from ai_module.analyzer import AIAnalyzer
from api.database import Base, ScanResult, SessionLocal, engine
from engine.parser import SASTEngine
from engine.semgrep_runner import SemgrepRunner

# Cria as tabelas no banco de dados assim que a API iniciar
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Plataforma SAST V2",
    description="Análise Estática com Persistência",
)


# Injeção de dependência para pegar a sessão do banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/api/v2/analyze-file")
async def analyze_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Lê o conteúdo do arquivo enviado
    content = await file.read()
    source_code = content.decode("utf-8")

    # 1. Análise Estrutural e Fluxo
    ast_findings = SASTEngine().analyze(source_code)
    taint_findings = SemgrepRunner().analyze(source_code)
    all_findings = ast_findings + taint_findings

    # 2. Análise Semântica (IA)
    final_findings = AIAnalyzer().get_remediation(source_code, all_findings)

    # 3. Salva no Banco de Dados (Persistência)
    db_scan = ScanResult(
        filename=file.filename,
        total_findings=len(all_findings),
        findings_detail=final_findings,
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    return {
        "status": "success",
        "scan_id": db_scan.id,
        "filename": file.filename,
        "total_findings": db_scan.total_findings,
        "findings": final_findings,
    }


# Rota para o Dashboard buscar o histórico
@app.get("/api/v2/history")
async def get_history(db: Session = Depends(get_db)):
    scans = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).all()
    return scans
