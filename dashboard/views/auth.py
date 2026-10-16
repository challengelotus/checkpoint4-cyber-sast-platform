import requests
import streamlit as st

API_URL = "http://sast-api:8000/api/v2"


def render():
    st.title("🛡️ Portal de Acesso")
    st.markdown("Autentique-se para acessar o seu ambiente de auditoria de código.")

    tab_login, tab_registo = st.tabs(["🔒 Iniciar Sessão", "📝 Criar Conta Gratuita"])

    with tab_login:
        with st.form("login_form"):
            login_user = st.text_input("Nome de Usuário")
            login_pass = st.text_input("Senha", type="password")
            submit_login = st.form_submit_button("Entrar")

            if submit_login:
                res = requests.post(
                    f"{API_URL}/auth/login",
                    data={"username": login_user, "password": login_pass},
                )
                if res.status_code == 200:
                    st.session_state.token = res.json().get("access_token")
                    st.session_state.username = login_user
                    st.rerun()
                else:
                    st.error("Credenciais inválidas. Verifique seu usuário e senha.")

    with tab_registo:
        with st.form("register_form"):
            reg_user = st.text_input("Nome de Usuário")
            reg_email = st.text_input("E-mail corporativo")
            reg_pass = st.text_input("Senha", type="password")
            submit_reg = st.form_submit_button("Registrar Conta Free")

            if submit_reg:
                res = requests.post(
                    f"{API_URL}/auth/register",
                    json={
                        "username": reg_user,
                        "email": reg_email,
                        "password": reg_pass,
                    },
                )
                if res.status_code == 201:
                    st.success(
                        "Conta criada com sucesso! Retorne à aba 'Iniciar Sessão' para acessar.",
                    )
                else:
                    st.error(
                        f"Erro ao registrar: {res.json().get('detail', 'Erro desconhecido')}",
                    )
