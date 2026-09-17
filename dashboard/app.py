import streamlit as st
import pandas as pd
import requests

# Configuração da Página
st.set_page_config(page_title="SAST Dashboard V2", page_icon="🛡️", layout="wide")
API_URL = "http://sast-api:8000/api/v2"

st.title("🛡️ Dashboard Executivo SAST & DevSecOps")
st.markdown("Plataforma de Análise Estática com Persistência e IA Local.")
st.divider()

# --- SEÇÃO 1: UPLOAD DE ARQUIVO ---
st.subheader("📤 Nova Auditoria de Código")
uploaded_file = st.file_uploader("Envie um arquivo Python (.py) para análise", type=["py"])

if st.button("🚀 Executar Motor SAST"):
    if uploaded_file is not None:
        with st.spinner("Analisando código com AST, Semgrep e Llama 3 (Isso pode levar alguns minutos)..."):
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "text/x-python")}
            try:
                response = requests.post(f"{API_URL}/analyze-file", files=files)
                if response.status_code == 200:
                    st.success(f"✅ Análise concluída com sucesso! (Scan ID: {response.json()['scan_id']})")
                else:
                    st.error(f"Erro na API: {response.text}")
            except Exception as e:
                st.error(f"Erro de conexão com o motor SAST: {e}")
    else:
        st.warning("Por favor, selecione um arquivo primeiro.")

st.divider()

# --- SEÇÃO 2: MÉTRICAS E HISTÓRICO ---
st.subheader("📊 Métricas Históricas (SQLite)")

try:
    # Busca o histórico real do banco de dados via API
    history_res = requests.get(f"{API_URL}/history")

    if history_res.status_code == 200:
        history_data = history_res.json()

        if not history_data:
            st.info("Nenhum histórico encontrado. Realize a primeira auditoria acima!")
        else:
            # Processamento de dados para os gráficos
            df = pd.DataFrame(history_data)

            # Contagem de Severidades
            severity_counts = {"CRÍTICO": 0, "ALTO": 0, "MÉDIO": 0, "BAIXO": 0}
            file_risks = {}

            for scan in history_data:
                filename = scan["filename"]
                if filename not in file_risks:
                    file_risks[filename] = 0

                for finding in scan.get("findings_detail", []):
                    sev = finding.get("severity", "").upper()
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                        file_risks[filename] += 1

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**Severidade Acumulada**")
                sev_df = pd.DataFrame(list(severity_counts.items()), columns=["Severidade", "Quantidade"]).set_index("Severidade")
                st.bar_chart(sev_df, color="#ff4b4b")

            with col2:
                st.markdown("**Arquivos Mais Críticos (Top 5)**")
                risk_df = pd.DataFrame(list(file_risks.items()), columns=["Arquivo", "Total de Falhas"])
                risk_df = risk_df.sort_values(by="Total de Falhas", ascending=False).head(5)
                st.dataframe(risk_df, use_container_width=True, hide_index=True)

            st.divider()

            # Tabela de Histórico Bruto
            st.markdown("**Histórico de Scans Recentes**")
            display_df = df[["id", "filename", "timestamp", "total_findings"]].copy()
            display_df["timestamp"] = pd.to_datetime(display_df["timestamp"]).dt.strftime('%d/%m/%Y %H:%M')
            st.dataframe(display_df, use_container_width=True, hide_index=True)

except Exception as e:
    st.error(f"Não foi possível carregar o histórico: {e}")
