import time
import uuid

from fastapi import Depends, FastAPI, File, Request, UploadFile
from sqlalchemy.orm import Session

from ai_module.analyzer import AIAnalyzer
from api.database import Base, ScanResult, SessionLocal, engine
from api.logger import log
from engine.parser import SASTEngine
from engine.semgrep_runner import SemgrepRunner

# Cria as tabelas no banco de dados assim que a API iniciar
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Plataforma SAST V2",
    description="Análise Estática com Persistência",
)


# --- MIDDLEWARE DE LOGS ESTRUTURADOS ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Gera um ID único para rastrear esta requisição específica
    request_id = str(uuid.uuid4())
    start_time = time.time()

    # Injeta contexto no log (ficará no nó 'extra' do JSON)
    context_log = log.bind(
        request_id=request_id,
        method=request.method,
        endpoint=request.url.path,
        client_ip=request.client.host,
    )

    context_log.info("Iniciando processamento da requisição")

    try:
        response = await call_next(request)
        process_time = time.time() - start_time

        context_log.bind(
            status_code=response.status_code,
            process_time_ms=round(process_time * 1000, 2),
        ).info("Requisição finalizada com sucesso")

        return response
    except Exception as e:
        process_time = time.time() - start_time
        context_log.bind(
            process_time_ms=round(process_time * 1000, 2),
        ).opt(exception=True).error(f"Falha interna no servidor: {str(e)}")
        raise


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
