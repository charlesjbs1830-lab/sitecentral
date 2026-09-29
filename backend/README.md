# EDV Jr. — Backend de Segurança & RBAC (Custo Zero)

Este módulo implementa a camada de autenticação, proteção criptográfica e controle de acesso baseado em papéis (**RBAC**) para o Painel Executivo da **EDV Jr.** utilizando exclusivamente tecnologias de código aberto e execução de **custo zero**.

---

## 🏛️ Arquitetura & Tecnologias

| Componente | Tecnologia | Função | Custo |
| :--- | :--- | :--- | :--- |
| **Framework API** | [FastAPI](https://fastapi.tiangolo.com/) | API assíncrona de alto desempenho e rotas seguras | **R$ 0,00** (Open Source) |
| **Banco de Dados** | SQLite 3 | Base local embutida (`backend/auth.db`) | **R$ 0,00** (Sem servidor pago) |
| **Criptografia** | `bcrypt` | Hashing com salt e derivação de chaves | **R$ 0,00** (Padrão ouro de segurança) |
| **Sessão & Tokens** | `PyJWT` | Emissão de tokens de acesso HMAC-SHA256 | **R$ 0,00** (Autenticação stateless) |
| **Servidor ASGI** | `uvicorn` | Execução local e escalável para produção | **R$ 0,00** (Leve e rápido) |

---

## 🔐 Matriz de Controle de Acesso (RBAC)

O sistema inicializa automaticamente a base com os **23 membros oficiais da Whitelist da Gestão 2026**:

* **ADMIN (Presidência / VPGG):** Acesso irrestrito a todos os dados operacionais, auditoria de segurança e simulação de perfis.
* **MANAGER (Diretorias e Gerências):** Acesso a métricas consolidadas, dados de projetos (INPI), CRM de vendas e tesouraria.
* **ANALYST (Assessores e Consultores):** Acesso operacional à prospecção de leads, registros de acompanhamento e consultas ao INPI.

> **Credenciais Padrão:**
> * **E-mails:** cadastrados conforme a Whitelist oficial (`nome.sobrenome@edvjr.com.br`)
> * **Senha inicial de membro:** `edv2026!`

---

## 🚀 Como Executar o Servidor Localmente

### 1. Pré-requisitos
Certifique-se de possuir Python 3.10+ instalado.

### 2. Instalação das dependências
```bash
pip install -r backend/requirements.txt
```

### 3. Inicialização do servidor
Execute diretamente o script launcher:
```bash
python backend/run_server.py
```
Ou via Uvicorn no terminal:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

* **URL Base da API:** `http://127.0.0.1:8000`
* **Documentação Interativa (Swagger UI):** `http://127.0.0.1:8000/docs`
* **Documentação ReDoc:** `http://127.0.0.1:8000/redoc`

---

## 🛡️ Endpoints Principais

* **`POST /api/auth/login`**: Valida credenciais via `bcrypt` e emite o token JWT com perfil RBAC.
* **`GET /api/auth/me`**: Retorna dados do usuário autenticado no token Bearer.
* **`GET /api/data/operational`**: **Endpoint protegido**. Entrega o payload completo dos dados operacionais (`legacy_data.json`) exclusivamente a portadores de token válido.
* **`GET /api/admin/audit`**: Restrito a perfis `ADMIN` e `MANAGER`.
* **`GET /api/health`**: Verificação de disponibilidade e telemetria da API.

---

## 🌐 Compatibilidade com GitHub Pages (Contingência Inteligente)

O frontend (`app.js`) foi adaptado com uma **camada de contingência automática**:
1. Ao carregar, tenta autenticar via API FastAPI em `http://127.0.0.1:8000`.
2. Se o servidor local estiver offline (por exemplo, quando visualizado diretamente na nuvem estática do GitHub Pages), o sistema ativa o modo seguro de contingência com a Whitelist embutida, preservando 100% da usabilidade sem quebrar a interface nem incorrer em custos de hospedagem.
