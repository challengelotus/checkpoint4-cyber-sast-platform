import sqlite3
import os

# 1. Vazamento de Segredos (Alvo: Parser AST)
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
db_password = "super_secret_admin_password_123"

def connect_db():
    # Simulando conexão insegura com credencial hardcoded
    return sqlite3.connect("users.db")

def execute_user_command():
    # 2. Taint Analysis / Execução de Código Arbitrário (Alvo: Semgrep + AST)
    # Source: Dado não confiável entrando no sistema
    user_input = input("Digite a expressão matemática para calcular: ")

    # Tentativa inútil de sanitização (a IA deve notar isso)
    sanitized_input = user_input.strip()

    # Sink: O dado sujo atinge uma função perigosa
    resultado = eval(sanitized_input)
    print(f"Resultado: {resultado}")

def get_user_profile(user_id):
    # 3. SQL Injection via concatenação (Alvo: IA Semântica e Taint Analysis)
    conn = connect_db()
    cursor = conn.cursor()

    # A concatenação direta de strings com variáveis externas é uma falha crítica
    query = f"SELECT * FROM users WHERE id = {user_id}"

    try:
        # Sink: Execução da query manipulada
        cursor.execute(query)
        profile = cursor.fetchone()
        return profile
    except Exception as e:
        print(f"Erro no banco: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    execute_user_command()
    get_user_profile(os.getenv("USER_ID", "1"))
