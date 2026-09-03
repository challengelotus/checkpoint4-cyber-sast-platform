import json
from typing import Any, Dict, List

import requests


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
            "Você é um engenheiro de segurança DevSecOps avaliando código Python.\n"
            f"O seguinte código possui as seguintes vulnerabilidades detectadas:\n{json.dumps(findings, indent=2)}\n\n"
            f"Código Fonte:\n{source_code}\n\n"
            "Sua tarefa: Para cada vulnerabilidade, classifique a severidade real, valide se é um falso positivo "
            "e forneça uma sugestão de correção em um formato conciso."
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        try:
            response = requests.post(self.ollama_url, json=payload)
            response.raise_for_status()
            ai_result = response.json().get("response", "")

            # Anexamos a análise da IA como um relatório geral no final dos achados
            findings.append(
                {
                    "ai_analysis": "Relatório Semântico Llama 3",
                    "details": ai_result,
                },
            )

        except Exception as e:
            findings.append({"ai_error": f"Erro ao comunicar com Ollama: {str(e)}"})

        return findings
