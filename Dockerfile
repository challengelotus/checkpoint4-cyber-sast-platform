FROM python:3.11-slim

WORKDIR /app

# Impede o Python de gravar arquivos .pyc no disco (ótimo para containers)
ENV PYTHONDONTWRITEBYTECODE 1
# Garante que a saída do terminal seja enviada direto para o console do Docker
ENV PYTHONUNBUFFERED 1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
