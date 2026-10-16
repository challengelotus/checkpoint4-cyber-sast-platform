import markdown
import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from fpdf import FPDF

API_URL = "http://sast-api:8000/api/v2"


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


def render():
    st.title("🛡️ Dashboard SAST Executivo")
    st.markdown("Plataforma de Análise Estática Estrutural e Inteligência Artificial.")
    st.divider()

    tab1, tab2 = st.tabs(["🔍 Auditoria de Código", "📈 Métricas do Workspace"])
    headers = {"Authorization": f"Bearer {st.session_state.token}"}

    with tab1:
        st.subheader("Nova Auditoria")
        uploaded_file = st.file_uploader("Envie um arquivo Python (.py)", type=["py"])

        if st.button("🚀 Executar Motor SAST", type="primary"):
            if uploaded_file is not None:
                with st.spinner("Motor a operar: Submetendo análise segura..."):
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

                            # Controle visual condicionado à resposta do Backend (Premium vs Free)
                            if ai_report:
                                st.divider()
                                st.subheader("🤖 Relatório Semântico (Llama 3 Premium)")
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
                                st.divider()
                                st.warning(
                                    "🔒 **Recurso Premium:** A Inteligência Artificial (Llama 3) e a exportação de Laudos em PDF são exclusivas para usuários do Plano Premium.",
                                )
                        else:
                            st.error(
                                f"Erro na API ({response.status_code}): {response.text}",
                            )
                    except Exception as e:
                        st.error(f"Erro de conexão: {e}")
            else:
                st.warning("Selecione um arquivo para iniciar.")

    with tab2:
        st.subheader("Métricas Globais de Segurança")
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
                            label = f"{finding.get('cwe', 'Desc')} - {finding.get('vulnerability', 'Outros')}"
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
                            color_discrete_map={
                                "CRÍTICO": "darkred",
                                "ALTO": "darkorange",
                                "MÉDIO": "gold",
                                "BAIXO": "steelblue",
                            },
                        )
                        st.plotly_chart(fig_sev, use_container_width=True)
                    else:
                        st.info("Sem dados de falhas.")

                with col2:
                    st.markdown("**Categorias Detectadas**")
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
                        st.plotly_chart(fig_cwe, use_container_width=True)
                    else:
                        st.info("Sem categorias detectadas.")
            else:
                st.info("Sem dados suficientes no histórico.")
        except Exception as e:
            st.error(f"Erro ao carregar métricas: {e}")
