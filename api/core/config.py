from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Configurações Gerais
    project_name: str
    api_version: str
    environment: str
    log_level: str

    # Configurações de Segurança
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


# Instância global para ser importada na aplicação
settings = Settings()
