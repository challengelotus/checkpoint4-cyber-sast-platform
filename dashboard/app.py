import streamlit as st
from views import auth, home, panel, planos

# A configuração DEVE ser a primeira chamada do Streamlit
st.set_page_config(page_title="SAST Dashboard V4 SaaS", page_icon="🛡️", layout="wide")

# Inicialização da Sessão
if "token" not in st.session_state:
    st.session_state.token = None
if "username" not in st.session_state:
    st.session_state.username = None

# --- SIDEBAR & ROUTER ---
st.sidebar.image("https://img.icons8.com/color/96/000000/shield.png", width=64)
st.sidebar.title("Navegação")

if st.session_state.token is None:
    # Fluxo de Visitante (Deslogado)
    page = st.sidebar.radio(
        "Acesso Público",
        ["Página Inicial", "Planos Comerciais", "Login / Cadastro"],
    )

    if page == "Página Inicial":
        home.render()
    elif page == "Planos Comerciais":
        planos.render()
    elif page == "Login / Cadastro":
        auth.render()
else:
    # Fluxo de Cliente (Logado)
    st.sidebar.success(f"👤 Bem-vindo, **{st.session_state.username}**")
    page = st.sidebar.radio("Meu Workspace", ["Dashboard SAST", "Planos Comerciais"])

    if page == "Dashboard SAST":
        panel.render()
    elif page == "Planos Comerciais":
        planos.render()

    st.sidebar.divider()
    if st.sidebar.button("Sair (Logout)", type="secondary", use_container_width=True):
        st.session_state.token = None
        st.session_state.username = None
        st.rerun()
