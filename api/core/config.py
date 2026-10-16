from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    project_name: str
    api_version: str
    environment: str
    log_level: str

    secret_key: str
    algorithm: str
    access_token_expire_minutes: int

    # Credenciais do Administrador (Database Seed)
    admin_username: str
    admin_email: str
    admin_password: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
