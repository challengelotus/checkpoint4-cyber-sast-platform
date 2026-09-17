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


# --- FUNÇÃO DE GERAÇÃO DE PDF ---
def gerar_pdf(nome_arquivo, relatorio_ia):
    pdf = FPDF()
    pdf.add_page()

    # Cabeçalho do Documento
    pdf.set_font("Helvetica", style="B", size=16)
    pdf.cell(
        0,
        10,
        txt=f"Relatório de Auditoria SAST - {nome_arquivo}",
        ln=True,
        align="C",
    )
    pdf.ln(10)

    # Limpeza de aspas curvas que podem quebrar o encoding
    texto_limpo = (
        relatorio_ia.replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2018", "'")
        .replace("\u2019", "'")
    )

    # Converte o texto Markdown da IA diretamente para HTML
    html_content = markdown.markdown(texto_limpo)

    # Define a fonte base para o interpretador HTML
    pdf.set_font("Helvetica", size=11)

    # Renderiza o HTML com quebra de linha automática (word-wrap) para palavras gigantes
    pdf.write_html(html_content)

    return pdf.output()


# --- CABEÇALHO DO DASHBOARD ---
st.title("🛡️ Dashboard SAST & DevSecOps")
st.markdown("Plataforma de Análise Estática Estrutural, Taint Analysis e IA Local.")
st.divider()

# --- CRIAÇÃO DAS ABAS ---
tab1, tab2 = st.tabs(["🔍 Auditoria de Código", "📈 Dashboard Executivo"])

# ==========================================
# ABA 1: AUDITORIA ATIVA & EXPORTAÇÃO PDF
# ==========================================
with tab1:
    st.subheader("Nova Auditoria")
    uploaded_file = st.file_uploader(
        "Envie um arquivo Python (.py) para análise",
        type=["py"],
    )

    if st.button("🚀 Executar Motor SAST", type="primary"):
        if uploaded_file is not None:
            with st.spinner("Motor operando: AST ➡️ Semgrep ➡️ Llama 3..."):
                files = {
                    "file": (
                        uploaded_file.name,
                        uploaded_file.getvalue(),
                        "text/x-python",
                    ),
                }
                try:
                    response = requests.post(f"{API_URL}/analyze-file", files=files)
                    if response.status_code == 200:
                        data = response.json()
                        st.success(
                            f"✅ Análise concluída! (Scan ID: {data['scan_id']})",
                        )

                        st.subheader(f"Relatório de Falhas: {uploaded_file.name}")

                        # Extrai a análise da IA e as falhas estruturais
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
                            st.info("Nenhuma vulnerabilidade estrutural encontrada.")

                        # Cards de Vulnerabilidade
                        for finding in structural_findings:
                            sev = finding.get("severity", "BAIXO")
                            color = (
                                "red"
                                if sev == "CRÍTICO"
                                else "orange"
                                if sev == "ALTO"
                                else "yellow"
                            )

                            with st.expander(
                                f"🔴 [{sev}] {finding['vulnerability']} (Linha {finding.get('line', '?')})",
                                expanded=True,
                            ):
                                st.markdown(f"**Descrição:** {finding['description']}")
                                st.markdown(f"**CWE:** {finding.get('cwe', 'N/A')}")

                        # Relatório da IA e Botão PDF
                        if ai_report:
                            st.divider()
                            st.subheader("🤖 Relatório Semântico (Llama 3)")
                            st.info(ai_report["details"])

                            # Geração e disponibilização do PDF
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
                        st.error(f"Erro na API: {response.text}")
                except Exception as e:
                    st.error(f"Erro de conexão com a API: {e}")
        else:
            st.warning("Selecione um arquivo para iniciar.")

# ==========================================
# ABA 2: DASHBOARD EXECUTIVO (MÉTRICAS COMPLETAS)
# ==========================================
with tab2:
    st.subheader("Métricas Globais do Projeto")

    try:
        history_res = requests.get(f"{API_URL}/history")

        if history_res.status_code == 200 and history_res.json():
            history_data = history_res.json()
            df = pd.DataFrame(history_data)

            # Estruturas para consolidação de dados
            severity_counts = {"CRÍTICO": 0, "ALTO": 0, "MÉDIO": 0, "BAIXO": 0}
            cwe_counts = {}
            file_risks = {}

            # Processamento do histórico
            for scan in history_data:
                filename = scan["filename"]
                if filename not in file_risks:
                    file_risks[filename] = 0

                for finding in scan.get("findings_detail", []):
                    if (
                        "vulnerability" in finding
                    ):  # Ignora o bloco da IA para a contagem
                        # Conta Severidade
                        sev = finding.get("severity", "").upper()
                        if sev in severity_counts:
                            severity_counts[sev] += 1

                        # Conta Arquivos Críticos
                        file_risks[filename] += 1

                        # Conta Categorias (Falhas Detectadas)
                        cwe = finding.get("cwe", "Desconhecido")
                        vuln_name = finding.get("vulnerability", "Outros")
                        label = f"{cwe} - {vuln_name}"
                        cwe_counts[label] = cwe_counts.get(label, 0) + 1

            # --- LINHA 1 DE GRÁFICOS ---
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
                    st.info("Nenhuma falha para plotar.")

            with col2:
                st.markdown("**Categorias de Falhas Detectadas**")
                cwe_df = pd.DataFrame(
                    list(cwe_counts.items()),
                    columns=["Categoria", "Ocorrências"],
                )
                cwe_df = cwe_df.sort_values(
                    by="Ocorrências",
                    ascending=True,
                )  # Ascending para o gráfico de barras ficar correto

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
                    st.info("Nenhuma categoria detectada.")

            st.divider()

            # --- LINHA 2 DE GRÁFICOS ---
            col3, col4 = st.columns(2)

            with col3:
                st.markdown("**Tendência de Falhas (Histórico)**")
                # Agrupa os scans por dia para criar a linha de tendência
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
                st.markdown("**Top 5 Arquivos Críticos**")
                risk_df = pd.DataFrame(
                    list(file_risks.items()),
                    columns=["Arquivo", "Total de Falhas"],
                )
                risk_df = risk_df.sort_values(
                    by="Total de Falhas",
                    ascending=False,
                ).head(5)
                st.dataframe(risk_df, use_container_width=True, hide_index=True)

        else:
            st.info(
                "Sem dados suficientes. Realize análises na aba 'Auditoria' para popular os gráficos.",
            )

    except Exception as e:
        st.error(f"Erro ao carregar métricas: {e}")
