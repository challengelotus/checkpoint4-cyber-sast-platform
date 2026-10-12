import datetime
from sqlalchemy import JSON, Column, DateTime, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

SQLALCHEMY_DATABASE_URL = "sqlite:///./sast_results.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- TABELA DE USUÁRIOS ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relacionamento: Um usuário possui várias varreduras
    scans = relationship("ScanResult", back_populates="owner")


# --- TABELA DE RESULTADOS ---
class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    total_findings = Column(Integer)
    findings_detail = Column(JSON)

    # FK: Vincula este resultado a um usuário específico
    user_id = Column(Integer, ForeignKey("users.id"))

    # Relacionamento: Esta varredura pertence a um usuário
    owner = relationship("User", back_populates="scans")
