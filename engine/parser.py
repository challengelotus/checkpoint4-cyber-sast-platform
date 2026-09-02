import ast
from typing import Any, Dict, List


class SASTVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        # Lista de palavras-chave suspeitas para nomes de variáveis
        self.suspicious_vars = ["password", "secret", "token", "key", "senha"]

    def visit_Call(self, node: ast.Call):
        # 1. Regra para funções perigosas (eval e exec)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ["eval", "exec"]:
                self.findings.append(
                    {
                        "vulnerability": "Função de Execução Perigosa",
                        "severity": "CRÍTICO",
                        "description": f"Uso da função '{func_name}' permite execução de código arbitrário.",
                        "line": node.lineno,
                        "cwe": "CWE-94",
                    },
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # 2. Regra para Credenciais Hardcoded
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                # Verifica se o nome da variável contém alguma palavra suspeita
                if any(susp in var_name for susp in self.suspicious_vars):
                    # Verifica se o valor atribuído é uma string literal (hardcoded)
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value,
                        str,
                    ):
                        self.findings.append(
                            {
                                "vulnerability": "Credencial Hardcoded",
                                "severity": "ALTO",
                                "description": f"Possível segredo exposto na variável '{target.id}'.",
                                "line": node.lineno,
                                "cwe": "CWE-798",
                            },
                        )

        self.generic_visit(node)


class SASTEngine:
    def analyze(self, source_code: str) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(source_code)
            visitor = SASTVisitor()
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError as e:
            return [{"error": f"Erro de sintaxe na linha {e.lineno}: {e.msg}"}]
        except Exception as e:
            return [{"error": f"Erro interno durante a análise: {str(e)}"}]
