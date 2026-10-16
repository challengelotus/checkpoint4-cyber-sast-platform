import streamlit as st


def render():
    st.title("💎 Planos e Assinaturas")
    st.markdown(
        "Escolha o nível de proteção ideal para o seu ambiente de desenvolvimento.",
    )
    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.info("### Plano Free\n**Uso Pessoal e Acadêmico**")
        st.markdown("""
        - ✅ Análise Estrutural (AST)
        - ✅ Taint Analysis (Semgrep)
        - ✅ Histórico de Varreduras e Gráficos
        - ❌ Relatórios Semânticos com Inteligência Artificial
        - ❌ Geração de Laudos em PDF
        """)
        st.text("")  # Espaçamento
        if st.button("Começar Gratuitamente", key="btn_free", use_container_width=True):
            st.warning(
                "Acesse a página 'Login / Cadastro' no menu lateral para criar sua conta gratuita.",
            )

    with col2:
        st.success("### Plano Premium\n**Para Times Corporativos**")
        st.markdown("""
        - ✅ Análise Estrutural (AST)
        - ✅ Taint Analysis (Semgrep)
        - ✅ Histórico de Varreduras e Gráficos
        - ✅ **Análise Semântica (Llama 3 Local)**
        - ✅ **Remediação Automática de Código**
        - ✅ **Exportação de Laudo Executivo (PDF)**
        """)
        if st.button(
            "Assinar Premium",
            type="primary",
            key="btn_premium",
            use_container_width=True,
        ):
            st.warning(
                "Funcionalidade de simulação comercial: Em um ambiente real, este botão o levaria para um gateway de pagamento (ex: Stripe).",
            )
