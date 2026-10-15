import datetime

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from api.core.config import settings
from api.database import SessionLocal, User

# Define o endpoint que o Swagger UI e os clientes usarão para obter o token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v2/auth/login")


def get_db():
    """Fornece uma sessão isolada de base de dados para injeção de dependências."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_password_hash(password: str) -> str:
    """Gera o hash da palavra-passe utilizando bcrypt com salt gerado nativamente."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Valida se a palavra-passe em texto limpo corresponde ao hash guardado."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def create_access_token(data: dict) -> str:
    """Gera um token JWT assinado com a chave secreta do ambiente (DevSecOps)."""
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=settings.access_token_expire_minutes,
    )
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.algorithm,
    )
    return encoded_jwt


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Decodifica o token JWT, valida a sua expiração e integridade, e devolve
    o utilizador da base de dados. Levanta HTTP 401 caso seja inválido.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais de acesso",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="O seu token expirou. Por favor, inicie sessão novamente.",
        )
    except jwt.InvalidTokenError:
        raise credentials_exception

    # Prevenção de SQL Injection nativa pelo SQLAlchemy no filtro ORM
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    return user
