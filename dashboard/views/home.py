import streamlit as st


def render():
    st.title("🛡️ Plataforma SAST & DevSecOps")
    st.markdown("### A segurança do seu código elevada ao nível comercial.")
    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### 🔍 Análise Estrutural e Taint Analysis")
        st.write(
            "Identifique vulnerabilidades antes mesmo do deploy. Nossa plataforma utiliza motores de Parsing (AST) e rastreamento de fluxo (Semgrep) para proteger sua aplicação desde o primeiro commit.",
        )
        st.write(
            "Diga adeus às senhas expostas, *Path Traversal* e injeções de código indesejadas.",
        )

    with col2:
        st.markdown("#### 🤖 Inteligência Artificial ao seu lado")
        st.write(
            "Cansado de falsos positivos atrapalhando a produtividade do time? O nosso motor premium integra a IA Llama 3 para análise semântica profunda.",
        )
        st.write(
            "O sistema entende o contexto, filtra ruídos e entrega o bloco de código corrigido diretamente para os seus desenvolvedores.",
        )
