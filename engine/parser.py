import ast
from typing import Any, Dict, List


class SASTVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    # O NodeVisitor chama este método automaticamente sempre que encontra
    # uma chamada de função no código (ex: print(), eval(), requests.get())
    def visit_Call(self, node: ast.Call):
        # Aqui é onde, na próxima etapa, adicionaremos a regra para detectar 'eval' ou 'exec'

        # Para garantir que o parser continue visitando os nós filhos
        self.generic_visit(node)


class SASTEngine:
    def analyze(self, source_code: str) -> List[Dict[str, Any]]:
        try:
            # 1. Converte a string de código em uma Árvore AST
            tree = ast.parse(source_code)

            # 2. Inicializa nosso visitante
            visitor = SASTVisitor()

            # 3. Faz o visitante percorrer a árvore
            visitor.visit(tree)

            return visitor.findings

        except SyntaxError as e:
            return [{"error": f"Erro de sintaxe no código fornecido: {str(e)}"}]
        except Exception as e:
            return [{"error": f"Erro interno durante a análise: {str(e)}"}]
