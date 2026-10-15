import json
from typing import Any, Dict, List

import requests

from api.core.logger import log


class AIAnalyzer:
    def __init__(
        self,
        ollama_url: str = "http://ollama:11434/api/generate",
        model: str = "llama3",
    ):
        self.ollama_url = ollama_url
        self.model = model

    def get_remediation(
        self,
        source_code: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not findings:
            return findings  # Não aciona a IA se o código estiver limpo

        # Monta o contexto para o LLM
        prompt = (
            "Você é um Especialista em AppSec e Engenheiro DevSecOps.\n"
            f"Analise o seguinte código Python:\n{source_code}\n\n"
            f"As seguintes vulnerabilidades foram detectadas pelas ferramentas SAST (AST e Semgrep):\n{json.dumps(findings, indent=2)}\n\n"
            "Sua tarefa é gerar um relatório técnico com os seguintes pontos para CADA vulnerabilidade:\n"
            "1. Severidade Real (classifique entre Baixo, Médio, Alto, Crítico).\n"
            "2. Falso Positivo (indique 'SIM' ou 'NÃO' e justifique brevemente).\n"
            "3. Sugestão de Correção (mostre como reescrever o código de forma segura).\n\n"
            "REGRAS ABSOLUTAS:\n"
            "- Você DEVE responder inteiramente em Português do Brasil (pt-BR).\n"
            "- Seja direto, técnico e conciso.\n"
            "- Não inclua saudações ou introduções genéricas."
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        try:
            log.bind(model=self.model).info(
                "Iniciando requisição ao motor de IA local...",
            )

            # Adicionado timeout de 120 segundos para evitar travamento síncrono da API
            response = requests.post(self.ollama_url, json=payload, timeout=120)
            response.raise_for_status()

            ai_result = response.json().get("response", "")

            log.info("Relatório de IA gerado com sucesso.")

            # Anexamos a análise da IA utilizando a chave que o frontend espera
            findings.append(
                {
                    "ai_analysis": f"Relatório Semântico ({self.model.capitalize()})",
                    "details": ai_result,
                },
            )

        except Exception as e:
            erro_msg = f"Falha na comunicação com o LLM local. Verifique se o container do Ollama está rodando e se o modelo '{self.model}' foi baixado.\nDetalhe técnico: {str(e)}"
            log.error(erro_msg)

            # Correção Crítica: utilizar a chave "ai_analysis" para forçar o Streamlit a exibir o erro
            findings.append(
                {
                    "ai_analysis": "Erro no Motor de IA",
                    "details": erro_msg,
                },
            )

        return findings
