import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ai_module.analyzer import AIAnalyzer
from api.core.config import settings
from api.core.logger import log
from api.core.security import (
    create_access_token,
    get_current_user,
    get_db,
    get_password_hash,
    verify_password,
)
from api.database import Base, ScanResult, SessionLocal, User, engine
from engine.parser import SASTEngine
from engine.semgrep_runner import SemgrepRunner


# --- DATABASE SEEDING & STARTUP ---
def init_db_seed():
    """Garante a existência do usuário administrador padrão sem hardcoding."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == settings.admin_username).first()
        if not admin:
            log.info(f"Criando usuário administrador padrão: {settings.admin_username}")
            hashed_pw = get_password_hash(settings.admin_password)
            new_admin = User(
                username=settings.admin_username,
                email=settings.admin_email,
                hashed_password=hashed_pw,
            )
            db.add(new_admin)
            db.commit()
        else:
            log.info("Verificação de startup: Administrador já existe no banco.")
    except Exception as e:
        log.error(f"Erro ao injetar administrador no banco de dados: {e}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Executa ao iniciar o servidor
    Base.metadata.create_all(bind=engine)
    init_db_seed()
    yield
    # Executa ao desligar o servidor (limpeza de recursos, se necessário)


app = FastAPI(
    title=settings.project_name,
    version=settings.api_version,
    description="Análise Estática com Persistência e Segurança DevSecOps",
    lifespan=lifespan,
)


# --- SCHEMAS DE DADOS (PYDANTIC) ---
class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


# --- MIDDLEWARE DE LOGS ESTRUTURADOS ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start_time = time.time()

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
        ).info("Requisição finalizada")

        return response
    except Exception as e:
        process_time = time.time() - start_time
        context_log.bind(
            process_time_ms=round(process_time * 1000, 2),
        ).opt(exception=True).error(f"Falha interna no servidor: {str(e)}")
        raise


# --- ROTAS DE IDENTIDADE E AUTENTICAÇÃO ---
@app.post(
    "/api/v2/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if (
        db.query(User)
        .filter((User.username == user.username) | (User.email == user.email))
        .first()
    ):
        raise HTTPException(
            status_code=400,
            detail="Nome de utilizador ou email já registado.",
        )

    hashed_pwd = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pwd,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log.bind(username=new_user.username).info("Novo utilizador registado com sucesso.")
    return new_user


@app.post("/api/v2/auth/login", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        log.bind(attempted_username=form_data.username).warning(
            "Tentativa de login falhada.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de utilizador ou palavra-passe incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.username})
    log.bind(username=user.username).info("Login efetuado com sucesso.")

    return {"access_token": access_token, "token_type": "bearer"}


# --- ROTAS DA PLATAFORMA SAST ---
@app.post("/api/v2/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    content = await file.read()
    source_code = content.decode("utf-8")

    ast_findings = SASTEngine().analyze(source_code)
    taint_findings = SemgrepRunner().analyze(source_code)
    all_findings = ast_findings + taint_findings
    final_findings = AIAnalyzer().get_remediation(source_code, all_findings)

    db_scan = ScanResult(
        filename=file.filename,
        total_findings=len(all_findings),
        findings_detail=final_findings,
        user_id=current_user.id,
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    log.bind(username=current_user.username, filename=file.filename).info(
        "Varredura SAST concluída e armazenada.",
    )

    return {
        "status": "success",
        "scan_id": db_scan.id,
        "filename": file.filename,
        "total_findings": db_scan.total_findings,
        "findings": final_findings,
    }


@app.get("/api/v2/history")
async def get_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scans = (
        db.query(ScanResult)
        .filter(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.timestamp.desc())
        .all()
    )

    return scans
