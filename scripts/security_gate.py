import os
import sys

# Adiciona a raiz do projeto ao path para conseguir importar os módulos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.parser import SASTEngine
from engine.semgrep_runner import SemgrepRunner


def scan_directory(directory="."):
    all_findings = []
    ast_engine = SASTEngine()
    taint_engine = SemgrepRunner()

    print("🔍 Iniciando varredura SAST Híbrida (AST + Semgrep)...\n")

    for root, _, files in os.walk(directory):
        for file in files:
            # Ignora pastas de ambiente virtual e testes
            if file.endswith(".py") and not any(
                ign in root for ign in ["venv", ".venv", "tests"]
            ):
                file_path = os.path.join(root, file)

                with open(file_path, "r", encoding="utf-8") as f:
                    code = f.read()

                # Executa os motores rápidos
                ast_findings = ast_engine.analyze(code)
                taint_findings = taint_engine.analyze(code)

                findings = ast_findings + taint_findings

                if findings:
                    print(f"❌ Vulnerabilidades em: {file_path}")
                    for finding in findings:
                        # Filtra erros de parse para focar só em segurança
                        if "vulnerability" in finding:
                            print(
                                f"  - [{finding['severity']}] {finding['vulnerability']}: {finding['description']} (Linha {finding.get('line', '?')})",
                            )
                    all_findings.extend(findings)

    return [f for f in all_findings if "vulnerability" in f]


if __name__ == "__main__":
    findings = scan_directory()

    print("\n" + "=" * 40)
    if findings:
        print(
            f"🚨 SECURITY GATE BLOQUEADO: {len(findings)} vulnerabilidade(s) crítica(s) detectada(s).",
        )
        print("Corrija o código antes de realizar o merge.")
        sys.exit(1)  # Código 1 faz o GitHub Actions falhar
    else:
        print(
            "✅ SECURITY GATE APROVADO: Nenhuma vulnerabilidade estrutural encontrada.",
        )
        sys.exit(0)  # Código 0 faz o GitHub Actions passar
