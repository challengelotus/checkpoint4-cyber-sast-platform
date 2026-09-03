<div align="center">
  <img src="https://img.icons8.com/color/512/cyber-security.png" alt="Logo SAST" width="150"/>
  <h1>🛡️ Motor SAST & DevSecOps</h1>
  <p><em>Análise Estática de Segurança e Rastreamento de Vulnerabilidades</em></p>
  <p>
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
    <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
    <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
    <img src="https://img.shields.io/badge/Ollama-black?style=for-the-badge&logo=ai&logoColor=white" alt="Ollama LLM"/>
    <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License MIT"/>
  </p>
  <p>
    <b>Status do Projeto:</b> ✅ Checkpoint 1 Concluído | 🚧 Checkpoint 2 em andamento
  </p>
</div>

---

## 📝 Descrição do Projeto

A **Plataforma SAST & DevSecOps** é um motor de análise estática de segurança focado em auditoria de código-fonte Python. O projeto tem como missão aplicar a cultura *Shift-Left*, trazendo a segurança para as fases iniciais do ciclo de desenvolvimento de software (SDLC).

Em vez de depender de expressões regulares (Regex) falhas, nossa plataforma utiliza o módulo nativo `ast` do Python para construir uma **Árvore de Sintaxe Abstrata (AST)**, permitindo uma inspeção estrutural profunda. A ferramenta é capaz de interceptar variáveis sensíveis expostas e funções perigosas antes que o código chegue ao ambiente de produção.

---

## 🏛️ Arquitetura do Sistema (C4 Model)

> *O diagrama abaixo ilustra a arquitetura técnica da plataforma, detalhando a comunicação entre a API Síncrona (FastAPI) e o Motor de Análise (AST) dentro do ambiente conteinerizado.*

<div align="center">
  <img src="docs/diagrama.png" alt="Diagrama de Arquitetura C4" width="800"/>
  <p><i>Arquitetura Nível 2 (Container)</i></p>
</div>

---

## ✨ Principais Funcionalidades

- ✅ **Parsing Estrutural (AST):** Conversão de código-fonte em nós de sintaxe abstrata para análise precisa.
- ✅ **Detecção de Senhas Hardcoded:** Identificação de credenciais e chaves fixadas no código-fonte.
- ✅ **Bloqueio de Funções Perigosas:** Rastreamento do uso de funções críticas de execução como `eval` e `exec`.
- ✅ **API Síncrona Automática:** Endpoint de escaneamento exposto via FastAPI com documentação Swagger (OpenAPI) nativa.
- ✅ **Ambiente Conteinerizado:** Setup plug-and-play utilizando Docker e Docker Compose.
- 🚧 *Em breve (Checkpoint 2): Integração com Semgrep para Taint Analysis.*
- 🚧 *Em breve (Checkpoint 2): Sugestões automáticas de remediação de código via IA (Ollama Llama 3).*

---

## 🛠️ Tecnologias Utilizadas

| Ferramenta | Finalidade |
| :--- | :--- |
| **Python 3.11** | Linguagem base da aplicação e alvo principal do SAST. |
| **FastAPI** | Framework moderno para construção e exposição da API. |
| **Módulo nativo `ast`** | Geração e navegação pelos nós da Árvore de Sintaxe Abstrata. |
| **Docker & Compose** | Orquestração, conteinerização e padronização do ambiente local. |
| **Uvicorn** | Servidor ASGI de alta performance para rodar a aplicação FastAPI. |
| **Ollama (Planejado)** | Integração de LLM local para análise semântica e autocorreção sem vazamento de dados. |

---

## 🚀 Como Instalar e Rodar o Projeto

Siga os passos abaixo para subir a infraestrutura completa do SAST na sua máquina.

### 📋 Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/) instalado e rodando.
- [Docker Compose](https://docs.docker.com/compose/install/) configurado.
- [Git](https://git-scm.com/)

### 🔧 Instalação e Execução

1.  **Clone o repositório**
    ```bash
    git clone [https://github.com/challengelotus/checkpoint4-cyber-sast-platform.git](https://github.com/challengelotus/checkpoint4-cyber-sast-platform.git)
    cd checkpoint4-cyber-sast-platform
    ```

2.  **Suba os containers com o Docker Compose**
    ```bash
    docker-compose up --build -d
    ```

3.  **Valide o funcionamento**
    - Acesse `http://localhost:8000/docs` para visualizar o **Swagger UI**.

---

## 💡 Como Usar (Guia Básico)

1. Com a aplicação rodando, abra a documentação Swagger no navegador: `http://localhost:8000/docs`.
2. Expanda o endpoint **`POST /api/v1/analyze`** e clique em **"Try it out"**.
3. No corpo da requisição, envie o código Python que deseja auditar. Exemplo:
    ```json
    {
      "source_code": "db_password = 'senha_super_secreta'\n\nuser_input = 'print(\"Hackeado!\")'\neval(user_input)"
    }
    ```
4. Clique em **Execute**. A API retornará o JSON detalhando a severidade, linha e CWE das vulnerabilidades estruturais encontradas.

---

## 👥 Equipe de Desenvolvimento

Projeto desenvolvido para a disciplina de Cybersecurity na Engenharia de Software.

| Integrante | RM | Responsabilidade Principal |
| :--- | :--- | :--- |
| **João Victor Soave** | RM557595 | Arquiteto de Software e Desenvolvedor Backend |
| **Maria Alice Freitas Araújo** | RM557516 | QA e Especialista em Testes/Segurança |
| **Pedro Henrique Mendes dos Santos** | RM555332 | Desenvolvedor Backend / LLM Integration |
| **Rafael Teofilo Lucena** | RM555600 | Arquiteto de Infraestrutura e Diagramação (C4) |
| **Vinícius Fernandes Tavares Bittencourt** | RM558909 | Engenheiro DevOps / Docker |

---

## 📄 Licença

Projeto acadêmico. Este repositório está licenciado sob a **MIT License**.

<div align="center">
  <sub>Desenvolvido de forma ética para fins de educação e segurança defensiva.</sub>
</div>
