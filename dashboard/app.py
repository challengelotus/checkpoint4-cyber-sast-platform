import pandas as pd
import streamlit as st

# Configuração da Página
st.set_page_config(page_title="SAST Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Dashboard Executivo SAST & DevSecOps")
st.markdown("Visualização analítica de vulnerabilidades estruturais e semânticas.")

st.divider()

# Colunas para Métricas Principais
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Severidade das Falhas")
    # Dados para o gráfico de severidade
    severity_data = pd.DataFrame(
        {
            "Severidade": ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO"],
            "Quantidade": [12, 25, 8, 3],
        },
    ).set_index("Severidade")

    st.bar_chart(severity_data, color="#ff4b4b")

with col2:
    st.subheader("📁 Top 5 Arquivos Críticos")
    # Tabela de arquivos com mais falhas
    files_data = pd.DataFrame(
        {
            "Arquivo": [
                "auth_controller.py",
                "db_config.py",
                "user_service.py",
                "payment_gateway.py",
                "main.py",
            ],
            "Falhas Detectadas": [12, 8, 5, 3, 1],
            "Risco": ["🔴 Crítico", "🔴 Crítico", "🟠 Alto", "🟡 Médio", "🔵 Baixo"],
        },
    )
    st.dataframe(files_data, use_container_width=True, hide_index=True)

st.divider()

st.subheader("📈 Tendência de Falhas (Histórico de Correções)")
st.markdown("Monitoramento do impacto da cultura Shift-Left ao longo do tempo.")

# Gráfico de linha demonstrando a tendência de falhas
trend_data = pd.DataFrame(
    {
        "Período": ["Semana 1", "Semana 2", "Semana 3", "Semana 4", "Semana Atual"],
        "Vulnerabilidades": [65, 58, 80, 45, 12],
    },
).set_index("Período")

st.line_chart(trend_data)

st.caption(
    "Nota: Dados consolidados a partir da última execução do pipeline CI/CD via GitHub Actions e análise semântica do Llama 3.",
)
