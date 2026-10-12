import sys

from loguru import logger


def setup_logger():
    # Remove a configuração padrão do Loguru (que imprime logs coloridos em texto plano)
    logger.remove()

    # Adiciona a saída estruturada em JSON para o stdout (capturada pelo Docker)
    logger.add(
        sys.stdout,
        format="{message}",
        level="INFO",
        serialize=True,
        enqueue=True,
    )
    return logger


# Exporta a instância configurada para ser usada em toda a API
log = setup_logger()
