import json
import os
import subprocess
import tempfile
from typing import Any, Dict, List


class SemgrepRunner:
    def __init__(self, rules_path: str = "engine/taint_rules.yml"):
        self.rules_path = rules_path

    def analyze(self, source_code: str) -> List[Dict[str, Any]]:
        findings = []

        # Cria um arquivo temporário para o Semgrep conseguir ler o código
        with tempfile.NamedTemporaryFile(
            suffix=".py",
            delete=False,
            mode="w",
        ) as temp_file:
            temp_file.write(source_code)
            temp_file_path = temp_file.name

        try:
            # Executa o Semgrep via subprocesso pedindo a saída em JSON
            command = [
                "semgrep",
                "scan",
                "--config",
                self.rules_path,
                "--json",
                "--quiet",
                temp_file_path,
            ]

            result = subprocess.run(command, capture_output=True, text=True)

            # Faz o parse do JSON retornado pelo Semgrep
            if result.stdout:
                output = json.loads(result.stdout)
                for item in output.get("results", []):
                    findings.append(
                        {
                            "vulnerability": "Vazamento de Fluxo de Dados (Taint)",
                            "severity": "CRÍTICO",
                            "description": item["extra"]["message"],
                            "line": item["start"]["line"],
                            "cwe": "CWE-94",
                        },
                    )

        except Exception as e:
            findings.append({"error": f"Erro ao executar Taint Analysis: {str(e)}"})
        finally:
            # Limpa o arquivo temporário por segurança
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

        return findings
