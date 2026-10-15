import sys

from loguru import logger

from api.core.config import settings


def setup_logger():
    # Remove a configuração padrão do Loguru
    logger.remove()

    # Configura a saída estruturada em JSON (stdout)
    logger.add(
        sys.stdout,
        format="{message}",
        level=settings.log_level.upper(),
        serialize=True,  # Força o formato JSON
        enqueue=True,  # Garante segurança em concorrência (assíncrono)
    )

    # Adiciona contexto estático do ambiente
    return logger.bind(environment=settings.environment, project=settings.project_name)


# Exporta a instância pronta a utilizar
log = setup_logger()
