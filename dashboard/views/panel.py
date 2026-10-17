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

    tab1, tab2 = st.tabs(
        ["🔍 Auditoria de Código", "📈 Métricas e Histórico do Workspace"],
    )
    headers = {"Authorization": f"Bearer {st.session_state.token}"}

    # ==========================================
    # ABA 1: AUDITORIA DE CÓDIGO
    # ==========================================
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

    # ==========================================
    # ABA 2: MÉTRICAS GLOBAIS E HISTÓRICO DETALHADO
    # ==========================================
    with tab2:
        st.subheader("📊 Métricas Globais do Workspace")
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

                # --- LINHA 1 DE GRÁFICOS GLOBAIS ---
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Distribuição Global de Severidade**")
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
                        st.info("Sem dados de falhas globais.")

                with col2:
                    st.markdown("**Top Arquivos Mais Críticos**")
                    risk_df = pd.DataFrame(
                        list(file_risks.items()),
                        columns=["Arquivo", "Total de Falhas"],
                    )
                    risk_df = risk_df.sort_values(
                        by="Total de Falhas",
                        ascending=False,
                    ).head(5)
                    if not risk_df.empty:
                        fig_risk = px.bar(
                            risk_df,
                            x="Total de Falhas",
                            y="Arquivo",
                            orientation="h",
                            color_discrete_sequence=["#ff4b4b"],
                        )
                        fig_risk.update_layout(margin=dict(t=0, b=0, l=0, r=0))
                        st.plotly_chart(fig_risk, use_container_width=True)
                    else:
                        st.info("Nenhum arquivo crítico mapeado.")

                st.divider()

                # --- SEÇÃO DE HISTÓRICO E ANÁLISE INDIVIDUAL POR ARQUIVO ---
                st.subheader("📁 Histórico de Análises e Detalhes por Arquivo")
                st.markdown(
                    "Selecione uma varredura anterior no histórico para inspecionar os detalhes e vulnerabilidades específicas de cada arquivo enviado.",
                )

                # Cria uma tabela resumida para seleção
                summary_list = []
                for scan in history_data:
                    summary_list.append(
                        {
                            "Scan ID": scan["id"],
                            "Arquivo": scan["filename"],
                            "Data/Hora": scan["timestamp"],
                            "Total de Falhas": scan["total_findings"],
                        },
                    )

                summary_df = pd.DataFrame(summary_list)
                st.dataframe(summary_df, use_container_width=True, hide_index=True)

                # Seletor interativo para detalhar um arquivo específico
                scan_options = {
                    f"ID {scan['id']} - {scan['filename']} ({scan['timestamp']})": scan
                    for scan in history_data
                }
                selected_label = st.selectbox(
                    "🔎 Inspecionar detalhes de uma varredura específica:",
                    options=list(scan_options.keys()),
                )

                if selected_label:
                    chosen_scan = scan_options[selected_label]
                    st.markdown(f"### Detalhes do Arquivo: `{chosen_scan['filename']}`")
                    st.caption(
                        f"Data da Análise: {chosen_scan['timestamp']} | Scan ID: {chosen_scan['id']} | Total de Alertas: {chosen_scan['total_findings']}",
                    )

                    file_structural_findings = [
                        f
                        for f in chosen_scan.get("findings_detail", [])
                        if "vulnerability" in f
                    ]
                    file_ai_report = next(
                        (
                            item
                            for item in chosen_scan.get("findings_detail", [])
                            if "ai_analysis" in item
                        ),
                        None,
                    )

                    if not file_structural_findings:
                        st.info(
                            "Nenhuma vulnerabilidade estrutural registrada nesta varredura específica.",
                        )

                    for finding in file_structural_findings:
                        sev = finding.get("severity", "BAIXO")
                        with st.expander(
                            f"🔴 [{sev}] {finding['vulnerability']} (Linha {finding.get('line', '?')})",
                        ):
                            st.markdown(f"**Descrição:** {finding['description']}")
                            st.markdown(f"**CWE:** {finding.get('cwe', 'N/A')}")

                    if file_ai_report:
                        st.markdown("#### 🤖 Parecer Semântico Registrado (IA)")
                        st.info(file_ai_report["details"])

            else:
                st.info(
                    "Sem dados suficientes no histórico. Realize análises na aba 'Auditoria de Código' para preencher os painéis.",
                )

        except Exception as e:
            st.error(f"Erro ao carregar métricas e histórico: {e}")
