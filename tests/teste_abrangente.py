import os

# 1. Risco ALTO: Senha hardcoded (Pego pelo AST)
senha_banco_producao = "admin_super_secreta_123"

def calcular_imposto():
    # 2. Risco CRÍTICO: Taint Analysis (Pego pelo Semgrep e AST)
    # Entrada de usuário fluindo diretamente para execução de código
    formula_usuario = input("Digite a fórmula de cálculo: ")
    resultado = eval(formula_usuario)
    return resultado

def inicializar_sistema():
    # 3. Risco MÉDIO/BAIXO: Uso de função perigosa, mas com dado estático e controlado
    # O AST vai sinalizar, mas a IA deve reduzir a severidade pois não há input externo
    exec("print('Sistema inicializado com sucesso')")

def configurar_ambiente():
    # 4. Risco ALTO: Outro tipo de credencial hardcoded
    token_api_aws = "AKIAIOSFODNN7EXAMPLE"
    os.environ["AWS_TOKEN"] = token_api_aws

if __name__ == "__main__":
    inicializar_sistema()
    configurar_ambiente()
    calcular_imposto()
