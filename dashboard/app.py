import datetime

import markdown
import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from fpdf import FPDF

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(page_title="SAST Dashboard V3", page_icon="🛡️", layout="wide")
API_URL = "http://sast-api:8000/api/v2"

# --- INICIALIZAÇÃO DO ESTADO DE SESSÃO ---
if "token" not in st.session_state:
    st.session_state.token = None
if "username" not in st.session_state:
    st.session_state.username = None


# --- FUNÇÃO DE GERAÇÃO DE PDF ---
def gerar_pdf(nome_arquivo, relatorio_ia):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", style="B", size=16)
    pdf.cell(
        0,
        10,
        txt=f"Relatório de Auditoria SAST - {nome_arquivo}",
        ln=True,
        align="C",
    )
    pdf.ln(10)

    texto_limpo = (
        relatorio_ia.replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2018", "'")
        .replace("\u2019", "'")
    )

    html_content = markdown.markdown(texto_limpo)
    pdf.set_font("Helvetica", size=11)
    pdf.write_html(html_content)
    return pdf.output()


# ==========================================
# ECRÃ DE AUTENTICAÇÃO (LOGIN / REGISTO)
# ==========================================
if st.session_state.token is None:
    st.title("🛡️ Acesso Restrito - Plataforma SAST")
    st.markdown("Autentique-se para aceder à auditoria de código e ao histórico.")

    tab_login, tab_registo = st.tabs(["🔒 Iniciar Sessão", "📝 Criar Conta"])

    with tab_login:
        with st.form("login_form"):
            login_user = st.text_input("Nome de Utilizador")
            login_pass = st.text_input("Palavra-passe", type="password")
            submit_login = st.form_submit_button("Entrar")

            if submit_login:
                # OAuth2 no FastAPI exige envio via form-data (data=) e não JSON
                res = requests.post(
                    f"{API_URL}/auth/login",
                    data={"username": login_user, "password": login_pass},
                )
                if res.status_code == 200:
                    st.session_state.token = res.json().get("access_token")
                    st.session_state.username = login_user
                    st.rerun()
                else:
                    st.error("Credenciais inválidas. Tente novamente.")

    with tab_registo:
        with st.form("register_form"):
            reg_user = st.text_input("Nome de Utilizador")
            reg_email = st.text_input("Email")
            reg_pass = st.text_input("Palavra-passe", type="password")
            submit_reg = st.form_submit_button("Registar")

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
                        "Conta criada com sucesso! Mude para o separador de Login para entrar.",
                    )
                else:
                    st.error(
                        f"Erro ao registar: {res.json().get('detail', 'Erro desconhecido')}",
                    )

# ==========================================
# DASHBOARD EXECUTIVO (RESTRITO)
# ==========================================
else:
    # Sidebar com informações de sessão
    with st.sidebar:
        st.markdown(f"👤 **Logado como:** {st.session_state.username}")
        if st.button("Sair (Logout)", type="secondary"):
            st.session_state.token = None
            st.session_state.username = None
            st.rerun()

    st.title("🛡️ Dashboard SAST & DevSecOps")
    st.markdown("Plataforma de Análise Estática Estrutural, Taint Analysis e IA Local.")
    st.divider()

    tab1, tab2 = st.tabs(["🔍 Auditoria de Código", "📈 Dashboard Executivo"])
    headers = {"Authorization": f"Bearer {st.session_state.token}"}

    # --- ABA 1: AUDITORIA ATIVA ---
    with tab1:
        st.subheader("Nova Auditoria")
        uploaded_file = st.file_uploader(
            "Envie um ficheiro Python (.py) para análise",
            type=["py"],
        )

        if st.button("🚀 Executar Motor SAST", type="primary"):
            if uploaded_file is not None:
                with st.spinner("Motor a operar: AST ➡️ Semgrep ➡️ Llama 3..."):
                    files = {
                        "file": (
                            uploaded_file.name,
                            uploaded_file.getvalue(),
                            "text/x-python",
                        ),
                    }
                    try:
                        response = requests.post(
                            f"{API_URL}/analyze-file",
                            files=files,
                            headers=headers,
                        )
                        if response.status_code == 200:
                            data = response.json()
                            st.success(
                                f"✅ Análise concluída! (Scan ID: {data['scan_id']})",
                            )
                            st.subheader(f"Relatório de Falhas: {uploaded_file.name}")

                            ai_report = next(
                                (
                                    item
                                    for item in data["findings"]
                                    if "ai_analysis" in item
                                ),
                                None,
                            )
                            structural_findings = [
                                f for f in data["findings"] if "vulnerability" in f
                            ]

                            if not structural_findings:
                                st.info(
                                    "Nenhuma vulnerabilidade estrutural encontrada.",
                                )

                            for finding in structural_findings:
                                sev = finding.get("severity", "BAIXO")
                                with st.expander(
                                    f"🔴 [{sev}] {finding['vulnerability']} (Linha {finding.get('line', '?')})",
                                    expanded=True,
                                ):
                                    st.markdown(
                                        f"**Descrição:** {finding['description']}",
                                    )
                                    st.markdown(f"**CWE:** {finding.get('cwe', 'N/A')}")

                            if ai_report:
                                st.divider()
                                st.subheader("🤖 Relatório Semântico (Llama 3)")
                                st.info(ai_report["details"])
                                pdf_bytes = gerar_pdf(
                                    uploaded_file.name,
                                    ai_report["details"],
                                )
                                st.download_button(
                                    label="📄 Baixar Relatório em PDF",
                                    data=bytes(pdf_bytes),
                                    file_name=f"relatorio_sast_{uploaded_file.name}.pdf",
                                    mime="application/pdf",
                                )
                        else:
                            st.error(
                                f"Erro na API ({response.status_code}): {response.text}",
                            )
                    except Exception as e:
                        st.error(f"Erro de conexão com a API: {e}")
            else:
                st.warning("Selecione um ficheiro para iniciar.")

    # --- ABA 2: MÉTRICAS GLOBAIS ---
    with tab2:
        st.subheader(f"Métricas do Projeto - Workspace de {st.session_state.username}")
        try:
            history_res = requests.get(f"{API_URL}/history", headers=headers)

            if history_res.status_code == 200 and history_res.json():
                history_data = history_res.json()
                df = pd.DataFrame(history_data)

                severity_counts = {"CRÍTICO": 0, "ALTO": 0, "MÉDIO": 0, "BAIXO": 0}
                cwe_counts = {}
                file_risks = {}

                for scan in history_data:
                    filename = scan["filename"]
                    if filename not in file_risks:
                        file_risks[filename] = 0

                    for finding in scan.get("findings_detail", []):
                        if "vulnerability" in finding:
                            sev = finding.get("severity", "").upper()
                            if sev in severity_counts:
                                severity_counts[sev] += 1

                            file_risks[filename] += 1
                            cwe = finding.get("cwe", "Desconhecido")
                            vuln_name = finding.get("vulnerability", "Outros")
                            label = f"{cwe} - {vuln_name}"
                            cwe_counts[label] = cwe_counts.get(label, 0) + 1

                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Distribuição de Severidade**")
                    sev_df = pd.DataFrame(
                        list(severity_counts.items()),
                        columns=["Severidade", "Quantidade"],
                    )
                    sev_df = sev_df[sev_df["Quantidade"] > 0]
                    if not sev_df.empty:
                        fig_sev = px.pie(
                            sev_df,
                            values="Quantidade",
                            names="Severidade",
                            hole=0.4,
                            color="Severidade",
                            color_discrete_map={
                                "CRÍTICO": "darkred",
                                "ALTO": "darkorange",
                                "MÉDIO": "gold",
                                "BAIXO": "steelblue",
                            },
                        )
                        fig_sev.update_layout(margin=dict(t=0, b=0, l=0, r=0))
                        st.plotly_chart(fig_sev, use_container_width=True)
                    else:
                        st.info("Nenhuma falha para desenhar.")

                with col2:
                    st.markdown("**Categorias de Falhas Detectadas**")
                    cwe_df = pd.DataFrame(
                        list(cwe_counts.items()),
                        columns=["Categoria", "Ocorrências"],
                    )
                    cwe_df = cwe_df.sort_values(by="Ocorrências", ascending=True)
                    if not cwe_df.empty:
                        fig_cwe = px.bar(
                            cwe_df,
                            x="Ocorrências",
                            y="Categoria",
                            orientation="h",
                            color_discrete_sequence=["#ff4b4b"],
                        )
                        fig_cwe.update_layout(margin=dict(t=0, b=0, l=0, r=0))
                        st.plotly_chart(fig_cwe, use_container_width=True)
                    else:
                        st.info("Nenhuma categoria detetada.")

                st.divider()
                col3, col4 = st.columns(2)

                with col3:
                    st.markdown("**Tendência de Falhas (Histórico)**")
                    df["data_curta"] = pd.to_datetime(df["timestamp"]).dt.strftime(
                        "%d/%m/%Y",
                    )
                    trend_df = (
                        df.groupby("data_curta")["total_findings"].sum().reset_index()
                    )
                    if not trend_df.empty:
                        fig_trend = px.area(
                            trend_df,
                            x="data_curta",
                            y="total_findings",
                            markers=True,
                            color_discrete_sequence=["#1f77b4"],
                        )
                        fig_trend.update_layout(
                            xaxis_title="Data",
                            yaxis_title="Total de Vulnerabilidades",
                            margin=dict(t=0, b=0, l=0, r=0),
                        )
                        st.plotly_chart(fig_trend, use_container_width=True)

                with col4:
                    st.markdown("**Top 5 Ficheiros Críticos**")
                    risk_df = pd.DataFrame(
                        list(file_risks.items()),
                        columns=["Ficheiro", "Total de Falhas"],
                    )
                    risk_df = risk_df.sort_values(
                        by="Total de Falhas",
                        ascending=False,
                    ).head(5)
                    st.dataframe(risk_df, use_container_width=True, hide_index=True)

            else:
                st.info(
                    "Sem dados suficientes. Realize análises no separador 'Auditoria' para preencher os gráficos.",
                )

        except Exception as e:
            st.error(f"Erro ao carregar métricas: {e}")
