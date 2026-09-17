import datetime

from sqlalchemy import JSON, Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Cria um arquivo banco.db na raiz do projeto
SQLALCHEMY_DATABASE_URL = "sqlite:///./sast_results.db"

# check_same_thread=False é necessário para o SQLite funcionar bem com o FastAPI (assíncrono)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Definição da Tabela no Banco de Dados
class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    total_findings = Column(Integer)
    findings_detail = Column(JSON)  # Salva o relatório completo da IA e AST aqui
