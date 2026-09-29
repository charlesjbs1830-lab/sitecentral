"""
EDV Jr. - Sistema Operacional Unificado (EDbrain)
Backend em FastAPI com Persistência SQLite (Custo Zero), Proteção JWT,
Controle de Acesso Baseado em Papéis e Áreas (RBAC),
Módulo Financeiro com Blindagem Indireta, Mural de Avisos Institucionais,
Bloqueio de Auto-Promoção e Módulo de PDIs para a VPGG com Geração de Trilhas.
"""

import os
import json
import re
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List

import httpx

from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from database import (
    init_db,
    get_user_by_email,
    get_user_by_id,
    get_all_users,
    get_followup_by_id,
    get_connection,
    VALID_ROLES
)
from auth import (
    verify_password,
    create_access_token,
    get_current_user,
    require_role,
    verify_area_access,
    check_area_access,
    verify_vpgg_access,
    check_vpgg_access
)

# Caminho para o payload operacional oficial
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY_DATA_PATH = os.path.join(BASE_DIR, "data", "legacy_data.json")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializa tabelas SQLite e sincroniza Whitelist oficial
    init_db()
    yield

app = FastAPI(
    title="EDV Jr. - EDbrain Security & Core Backend",
    version="2.3.0",
    description="Backend oficial da EDV Jr. com SQLite, JWT, RBAC, Módulo Financeiro, Mural de Avisos, PDIs (VPGG) e CRM Comercial.",
    lifespan=lifespan
)

# Habilitar CORS irrestrito para consumo local e GitHub Pages
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# SCHEMAS PYDANTIC
# ==============================================================================

class LoginRequest(BaseModel):
    email: str
    password: str

class UserProfile(BaseModel):
    id: int
    email: str
    nome: str
    area: str
    role: str
    setor: Optional[str] = None
    cargo: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile

class SelfProfileUpdate(BaseModel):
    nome: Optional[str] = None
    role: Optional[str] = None
    area: Optional[str] = None
    setor: Optional[str] = None
    cargo: Optional[str] = None

class AdminUserUpdate(BaseModel):
    role: Optional[str] = None
    area: Optional[str] = None
    cargo: Optional[str] = None
    setor: Optional[str] = None
    nome: Optional[str] = None

class TransactionCreate(BaseModel):
    area: str = Field(..., description="Área da transação (ex: Projetos, Comercial, Tesouraria, VPGG, Marketing)")
    type: str = Field(..., description="Tipo da movimentação: 'receita' ou 'despesa'")
    category: str = Field(..., description="Categoria da movimentação (ex: Registro de Marca, Treinamento, Infraestrutura)")
    amount: float = Field(..., gt=0, description="Valor positivo da movimentação em Reais")
    description: Optional[str] = Field("", description="Descrição opcional ou justificativa")
    date: Optional[str] = Field(None, description="Data da transação (formato YYYY-MM-DD)")

class TransactionResponse(BaseModel):
    id: int
    area: str
    type: str
    category: str
    amount: float
    description: Optional[str] = None
    created_by: str
    date: str
    created_at: Optional[str] = None

class NoticeCreate(BaseModel):
    title: str = Field(..., min_length=1, description="Título do comunicado")
    content: str = Field(..., min_length=1, description="Conteúdo do comunicado")
    target_area: Optional[str] = Field(None, description="Área alvo. Nulo ou vazio para comunicado geral/institucional")

class NoticeResponse(BaseModel):
    id: int
    target_area: Optional[str] = None
    title: str
    content: str
    author: str
    created_at: Optional[str] = None

class PDICreate(BaseModel):
    user_email: str = Field(..., description="E-mail do membro colaborador avaliado")
    area: Optional[str] = Field("VPGG", description="Área do PDI")
    objectives: str = Field(..., min_length=3, description="Objetivos e metas de desenvolvimento")
    development_ideas: str = Field(..., min_length=3, description="Ações práticas, ideias e entregáveis de evolução")
    deadline: str = Field(..., description="Data limite para conclusão (YYYY-MM-DD)")
    status: Optional[str] = Field("em_andamento", description="Status do PDI ('planejado', 'em_andamento', 'concluido', 'pausado')")

class PDIUpdate(BaseModel):
    objectives: Optional[str] = None
    development_ideas: Optional[str] = None
    deadline: Optional[str] = None
    status: Optional[str] = None

class PDIResponse(BaseModel):
    id: int
    user_email: str
    area: str
    objectives: str
    development_ideas: str
    deadline: str
    status: str
    created_at: Optional[str] = None

class PDIGenerateRequest(BaseModel):
    member_email: str = Field(..., description="E-mail corporativo do membro para geração da trilha")
    foco_adicional: Optional[str] = Field(None, description="Foco customizado opcional (ex: liderança, oratória, vendas)")

VALID_CRM_STATUSES = {"prospeccao", "negociacao", "fechado", "perdido"}

class ClientFollowupCreate(BaseModel):
    client_name: str = Field(..., min_length=1, description="Nome da empresa ou cliente (OBRIGATÓRIO)")
    contact_person: Optional[str] = Field(None, description="Nome do contato principal")
    status: Optional[str] = Field("prospeccao", description="Status do ciclo comercial ('prospeccao', 'negociacao', 'fechado', 'perdido')")
    interaction_type: Optional[str] = Field(None, description="Tipo de interação (ex: Reunião, WhatsApp, Email, Proposta Enviada)")
    notes: Optional[str] = Field(None, description="Observações detalhadas sobre o andamento")
    next_followup_date: Optional[str] = Field(None, description="Data agendada para o próximo contato (YYYY-MM-DD)")
    area: Optional[str] = Field(None, description="Área responsável pelo lead/projeto")
    cnpj: Optional[str] = Field(None, description="CNPJ da empresa para enriquecimento automático via BrasilAPI")
    cnae: Optional[str] = Field(None, description="CNAE principal da empresa")
    company_size: Optional[str] = Field(None, description="Porte da empresa (ex: ME, EPP, DEMAIS)")
    address: Optional[str] = Field(None, description="Endereço comercial completo")
    score: Optional[int] = Field(None, description="Lead Score preditivo (0 a 100)")
    estimated_value: Optional[float] = Field(0.0, description="Valor estimado da oportunidade comercial em Reais")
    tags: Optional[str] = Field(None, description="Tags comerciais separadas por vírgula (ex: #quente, #marca)")

class ClientFollowupUpdate(BaseModel):
    client_name: Optional[str] = None
    contact_person: Optional[str] = None
    status: Optional[str] = None
    interaction_type: Optional[str] = None
    notes: Optional[str] = None
    next_followup_date: Optional[str] = None
    area: Optional[str] = None
    cnpj: Optional[str] = None
    cnae: Optional[str] = None
    company_size: Optional[str] = None
    address: Optional[str] = None
    score: Optional[int] = None
    estimated_value: Optional[float] = None
    tags: Optional[str] = None

class ClientFollowupResponse(BaseModel):
    id: int
    client_name: str
    contact_person: Optional[str] = None
    status: str
    interaction_type: Optional[str] = None
    notes: Optional[str] = None
    next_followup_date: Optional[str] = None
    area: str
    cnpj: Optional[str] = None
    cnae: Optional[str] = None
    company_size: Optional[str] = None
    address: Optional[str] = None
    score: Optional[int] = 50
    estimated_value: Optional[float] = 0.0
    tags: Optional[str] = None
    created_by: str
    created_at: Optional[str] = None
    days_stagnant: Optional[int] = 0
    is_stagnant: Optional[bool] = False

# ==============================================================================
# 1. AUTENTICAÇÃO, PERFIL E BLOQUEIO DE AUTO-PROMOÇÃO (RBAC SHIELD)
# ==============================================================================

@app.post("/api/auth/login", response_model=LoginResponse, summary="Autenticação com e-mail e senha")
async def login(credentials: LoginRequest):
    email = credentials.email.lower().strip()
    user = get_user_by_email(email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail não autorizado na Whitelist da EDV Jr. Verifique com a VPGG ou Presidência.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Senha incorreta. A senha padrão inicial de membro é 'edv2026!'.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Criar Token JWT com dados essenciais do usuário e papel RBAC
    token_payload = {
        "sub": user["email"],
        "nome": user["nome"],
        "area": user["area"],
        "role": user["role"],
        "setor": user.get("setor", user["area"])
    }
    access_token = create_access_token(data=token_payload)
    
    user_profile = UserProfile(
        id=user["id"],
        email=user["email"],
        nome=user["nome"],
        area=user["area"],
        role=user["role"],
        setor=user.get("setor"),
        cargo=user.get("cargo")
    )
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_profile
    )

@app.get("/api/auth/me", response_model=UserProfile, summary="Verificação de sessão e perfil RBAC")
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserProfile(
        id=current_user["id"],
        email=current_user["email"],
        nome=current_user["nome"],
        area=current_user["area"],
        role=current_user["role"],
        setor=current_user.get("setor"),
        cargo=current_user.get("cargo")
    )

@app.put(
    "/api/auth/me",
    response_model=UserProfile,
    summary="Atualização de perfil próprio com bloqueio estrito de auto-promoção"
)
@app.patch(
    "/api/auth/me",
    response_model=UserProfile,
    include_in_schema=False
)
async def update_my_profile(
    payload: SelfProfileUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Permite atualizar atributos cadastrais pessoais permitidos (nome),
    mas BLOQUEIA estritamente qualquer tentativa do colaborador de alterar
    seu próprio papel (role), área, setor ou cargo (Bloqueio de Auto-Promoção).
    """
    # 1. Bloqueio de auto-alteração de Role
    if payload.role is not None and payload.role.lower().strip() != current_user["role"].lower().strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bloqueio de auto-promoção: Colaboradores não têm permissão para alterar seu próprio papel (role). Esta operação é restrita à Presidência e Diretorias."
        )

    # 2. Bloqueio de auto-alteração de Área
    if payload.area is not None and payload.area.lower().strip() != current_user["area"].lower().strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bloqueio de alteração de área: Colaboradores não têm permissão para alterar sua própria área. Esta operação é restrita à Presidência e Diretorias."
        )

    # 3. Bloqueio de auto-alteração de Setor
    user_setor = current_user.get("setor") or ""
    if payload.setor is not None and payload.setor.lower().strip() != user_setor.lower().strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bloqueio de alteração de setor: Modificação de setor hierárquico é restrita à Presidência e Diretorias."
        )

    # 4. Bloqueio de auto-alteração de Cargo
    user_cargo = current_user.get("cargo") or ""
    if payload.cargo is not None and payload.cargo.lower().strip() != user_cargo.lower().strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bloqueio de alteração de cargo: Modificação de cargo hierárquico é restrita à Presidência e Diretorias."
        )

    # Atualização permitida (ex: nome cadastral)
    novo_nome = payload.nome.strip() if payload.nome and payload.nome.strip() else current_user["nome"]

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET nome = ? WHERE id = ?;", (novo_nome, current_user["id"]))
    conn.commit()
    cursor.execute("SELECT * FROM users WHERE id = ?;", (current_user["id"],))
    updated_user = cursor.fetchone()
    conn.close()

    return dict(updated_user)

# ==============================================================================
# 2. CONTROLE ADMINISTRATIVO HIERÁRQUICO (EXCLUSIVO: PRESIDENTE E DIRETOR)
# ==============================================================================

@app.get(
    "/api/admin/users",
    response_model=List[UserProfile],
    summary="Listar todos os membros com perfis hierárquicos (Exclusivo: Presidente e Diretor)"
)
@app.get("/admin/users", response_model=List[UserProfile], include_in_schema=False)
async def admin_list_users(admin_user: dict = Depends(require_role(["presidente", "diretor"]))):
    return get_all_users()

@app.put(
    "/api/admin/users/{user_identifier}",
    response_model=UserProfile,
    summary="Alteração administrativa de cargo, setor, área e role (Exclusivo: Presidente e Diretor)"
)
@app.put("/admin/users/{user_identifier}", response_model=UserProfile, include_in_schema=False)
async def admin_update_user(
    user_identifier: str,
    payload: AdminUserUpdate,
    admin_user: dict = Depends(require_role(["presidente", "diretor"]))
):
    conn = get_connection()
    cursor = conn.cursor()
    
    # Busca por ID numérico ou por e-mail corporativo
    if user_identifier.isdigit():
        cursor.execute("SELECT * FROM users WHERE id = ?;", (int(user_identifier),))
    else:
        cursor.execute("SELECT * FROM users WHERE email = ?;", (user_identifier.lower().strip(),))
        
    target_user = cursor.fetchone()
    if not target_user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Membro '{user_identifier}' não encontrado na base corporativa da EDV Jr."
        )

    target_id = target_user["id"]
    updates = []
    params = []

    if payload.role is not None:
        r_clean = payload.role.lower().strip()
        if r_clean not in VALID_ROLES:
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Papel (role) inválido. Valores aceitos estritamente: {list(VALID_ROLES)}"
            )
        updates.append("role = ?")
        params.append(r_clean)

    if payload.area is not None:
        updates.append("area = ?")
        params.append(payload.area.strip())

    if payload.cargo is not None:
        updates.append("cargo = ?")
        params.append(payload.cargo.strip())

    if payload.setor is not None:
        updates.append("setor = ?")
        params.append(payload.setor.strip())

    if payload.nome is not None:
        updates.append("nome = ?")
        params.append(payload.nome.strip())

    if updates:
        params.append(target_id)
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?;", params)
        conn.commit()

    cursor.execute("SELECT * FROM users WHERE id = ?;", (target_id,))
    updated_user = cursor.fetchone()
    conn.close()

    return dict(updated_user)

# ==============================================================================
# 3. MÓDULO FINANCEIRO COM ATUALIZAÇÃO INDIRETA (BLINDAGEM E TETO DE ALÇADA)
# ==============================================================================

@app.post(
    "/finance/transactions",
    response_model=TransactionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar nova movimentação financeira (Blindagem Indireta)"
)
@app.post(
    "/api/finance/transactions",
    response_model=TransactionResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False
)
async def create_transaction(
    payload: TransactionCreate,
    current_user: dict = Depends(get_current_user)
):
    # 1. Validação de tipo de transação
    tx_type = payload.type.lower().strip()
    if tx_type not in ("receita", "despesa"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de transação inválido. Deve ser estritamente 'receita' ou 'despesa'."
        )

    # 2. Validação de valor positivo
    if payload.amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O valor da transação deve ser positivo e superior a R$ 0,00."
        )

    # 3. Validação de Escopo de Área (RBAC)
    verify_area_access(payload.area, current_user)

    # 4. Validação de Teto de Alçada (Assessor capped at R$ 1.000,00)
    user_role = (current_user.get("role") or "").lower().strip()
    if user_role == "assessor" and payload.amount > 1000.0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Teto de alçada excedido: Lançamentos de R$ {payload.amount:,.2f} realizados por assessores "
                f"excedem o teto permitido de R$ 1.000,00 e exigem aprovação de gerência ou diretoria."
            )
        )

    # 5. Formatação da Data
    tx_date = payload.date.strip() if payload.date and payload.date.strip() else datetime.now().strftime("%Y-%m-%d")

    # 6. Gravação segura no SQLite (Blindagem contra edição direta da planilha original)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO transactions (area, type, category, amount, description, created_by, date)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (
        payload.area.strip(),
        tx_type,
        payload.category.strip(),
        payload.amount,
        (payload.description or "").strip(),
        current_user.get("email") or current_user.get("nome"),
        tx_date
    ))
    conn.commit()
    tx_id = cursor.lastrowid
    cursor.execute("SELECT * FROM transactions WHERE id = ?;", (tx_id,))
    row = cursor.fetchone()
    conn.close()

    return dict(row)

@app.get(
    "/finance/transactions",
    response_model=List[TransactionResponse],
    summary="Listar transações financeiras com escopo RBAC"
)
@app.get(
    "/api/finance/transactions",
    response_model=List[TransactionResponse],
    include_in_schema=False
)
async def list_transactions(
    area: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_role = (current_user.get("role") or "").lower().strip()
    user_area = current_user.get("area") or current_user.get("setor")
    
    conn = get_connection()
    cursor = conn.cursor()
    
    if user_role in {"presidente", "diretor"}:
        if area:
            cursor.execute("SELECT * FROM transactions WHERE LOWER(area) = LOWER(?) ORDER BY id DESC;", (area.strip(),))
        else:
            cursor.execute("SELECT * FROM transactions ORDER BY id DESC;")
    else:
        cursor.execute("SELECT * FROM transactions WHERE LOWER(area) = LOWER(?) ORDER BY id DESC;", (user_area,))
        
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ==============================================================================
# 4. MÓDULO DE AVISOS INSTITUCIONAIS (MURAL DE AVISOS)
# ==============================================================================

@app.post(
    "/notices",
    response_model=NoticeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Publicar aviso institucional (Restrito à Liderança: Presidente, Diretor, Gerente)"
)
@app.post(
    "/api/notices",
    response_model=NoticeResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False
)
async def create_notice(
    payload: NoticeCreate,
    current_user: dict = Depends(get_current_user)
):
    # 1. Validação estrita de papel: apenas presidente, diretor ou gerente podem publicar
    user_role = (current_user.get("role") or "").lower().strip()
    if user_role not in {"presidente", "diretor", "gerente"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Acesso negado: Publicação de comunicados é restrita à liderança (presidente, diretor, gerente). Seu perfil é '{user_role}'."
        )

    # 2. Validação de conteúdo não vazio
    if not payload.title.strip() or not payload.content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Título e conteúdo do comunicado não podem ser vazios."
        )

    target_area = payload.target_area.strip() if payload.target_area and payload.target_area.strip() else None

    # 3. Persistência na tabela notices
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notices (target_area, title, content, author)
        VALUES (?, ?, ?, ?);
    """, (
        target_area,
        payload.title.strip(),
        payload.content.strip(),
        current_user.get("nome") or current_user.get("email")
    ))
    conn.commit()
    notice_id = cursor.lastrowid
    cursor.execute("SELECT * FROM notices WHERE id = ?;", (notice_id,))
    row = cursor.fetchone()
    conn.close()

    return dict(row)

@app.get(
    "/notices",
    response_model=List[NoticeResponse],
    summary="Listar comunicados filtrados (Gerais + Área do Usuário)"
)
@app.get(
    "/api/notices",
    response_model=List[NoticeResponse],
    include_in_schema=False
)
async def get_notices(
    all_notices: bool = Query(False, description="Exibir todos os comunicados (exclusivo para presidente e diretores)"),
    current_user: dict = Depends(get_current_user)
):
    user_role = (current_user.get("role") or "").lower().strip()
    user_area = (current_user.get("area") or current_user.get("setor") or "").lower().strip()

    conn = get_connection()
    cursor = conn.cursor()

    if all_notices and user_role in {"presidente", "diretor"}:
        cursor.execute("SELECT * FROM notices ORDER BY id DESC;")
    else:
        cursor.execute("""
            SELECT * FROM notices
            WHERE target_area IS NULL
               OR TRIM(target_area) = ''
               OR LOWER(target_area) = ?
            ORDER BY id DESC;
        """, (user_area,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ==============================================================================
# 5. MÓDULO DE PDIS PARA A VPGG (PLANO DE DESENVOLVIMENTO INDIVIDUAL) & TRILHAS
# ==============================================================================

def generate_pdi_trail(member: dict, foco_adicional: Optional[str] = None) -> dict:
    """
    Motor de Geração de PDIs:
    Gera trilhas estruturadas de ideias de desenvolvimento, competências técnicas e comportamentais
    com base estrita no cargo, área e nível hierárquico atual do membro avaliado.
    """
    role = (member.get("role") or "assessor").lower().strip()
    area = (member.get("area") or "Geral").strip()
    cargo = member.get("cargo") or f"{role.capitalize()} de {area}"

    trilhas_por_area = {
        "Projetos": {
            "hard_skills": [
                "Classificação de Nice (NCL) e busca de anterioridade fonética e figurativa no INPI",
                "Análise de colidência de marcas e elaboração de oposições e recursos administrativos",
                "Monitoramento de despachos na RPI e gestão rigorosa do prazo fatal de 60 dias"
            ],
            "soft_skills": [
                "Atenção aos detalhes jurídicos e rigor processual analítico",
                "Comunicação técnica clara com titulares de marcas e clientes",
                "Organização e gestão de múltiplos processos em paralelo"
            ],
            "acoes_edv": [
                "Conduzir no mínimo 5 buscas de anterioridade com emissão de parecer formal de viabilidade",
                "Apresentar na Ágora semanal um caso prático de despacho de exigência do INPI",
                "Contribuir para a revisão e melhoria contínua do POP de depósito de marcas da EDV Jr."
            ]
        },
        "Comercial": {
            "hard_skills": [
                "Metodologia SPIN Selling e qualificação consultiva de leads B2B",
                "Triagem fiscal rápida de CNPJs na Receita Federal via BrasilAPI",
                "Elaboração de propostas comerciais de registro de marca e condução de negociações"
            ],
            "soft_skills": [
                "Escuta ativa e contorno consultivo de objeções de clientes",
                "Resiliência e ritmo acelerado de cadência de follow-up",
                "Persuasão ética fundamentada em valor jurídico de proteção de ativos"
            ],
            "acoes_edv": [
                "Atingir meta individual de abordagens qualificadas semanais via Radar",
                "Converter no mínimo 2 contratos de registro de marca no ciclo de gestão",
                "Gravar simulação de pitch de vendas de marcas para capacitação de novos membros"
            ]
        },
        "VPGG": {
            "hard_skills": [
                "Desenho, acompanhamento e revisão de PDIs e metas individuais",
                "Estruturação de processos seletivos, entrevistas por competências e onboarding",
                "Análise de métricas de clima, assiduidade em Ágoras e cálculo de eNPS"
            ],
            "soft_skills": [
                "Empatia e condução estruturada de conversas de alinhamento e feedbacks 1-on-1",
                "Comunicação institucional inspiradora e acolhimento de membros",
                "Visão sistêmica de desenvolvimento humano e liderança"
            ],
            "acoes_edv": [
                "Realizar rodadas mensais de One-on-One com 100% dos membros atribuídos",
                "Implementar diagnóstico de clima trimestral e plano de ação correspondente",
                "Organizar uma oficina interna de oratória e autogestão para a empresa"
            ]
        },
        "Marketing": {
            "hard_skills": [
                "Estratégia de Inbound Marketing jurídico em conformidade com o Provimento OAB",
                "Copywriting persuasivo e criação de narrativas institucionais para Reels/LinkedIn",
                "Análise de métricas de alcance, engajamento e CPL de campanhas"
            ],
            "soft_skills": [
                "Criatividade orientada a resultados e metas de geração de leads",
                "Alinhamento estratégico contínuo com o time comercial",
                "Gestão de cronograma editorial e consistência de postagens"
            ],
            "acoes_edv": [
                "Criar e publicar 3 carrosséis educativos sobre riscos de marcas não registradas",
                "Apoiar a campanha 'Maré de Vendas' com criativos visuais de alta conversão",
                "Otimizar o fluxo de captação de leads inbound pelo Instagram institucional"
            ]
        },
        "Jurídico": {
            "hard_skills": [
                "Análise estatutária e conformidade com critérios do Selo EJ (Brasil Júnior)",
                "Redação e revisão de minutas contratuais de prestação de serviços e parcerias",
                "Gestão de compliance, governança e certidões negativas corporativas"
            ],
            "soft_skills": [
                "Raciocínio jurídico analítico e precisão terminológica",
                "Pensamento preventivo de riscos contratuais e societários",
                "Postura ética e sigilo profissional estrito"
            ],
            "acoes_edv": [
                "Garantir a vigência e homologação de 100% dos critérios do Selo EJ 2026",
                "Revisar o modelo padrão de contrato de honorários de consultoria da EDV Jr.",
                "Elaborar parecer sobre adequação às normas da LGPD no tratamento de dados de leads"
            ]
        },
        "Tesouraria": {
            "hard_skills": [
                "Metodologia de Orçamento Base Zero (OBZ) e conciliação bancária Cora/CJA",
                "Projeção de fluxo de caixa, controle de inadimplência e emissão de notas fiscais",
                "Análise de viabilidade financeira e precificação de serviços"
            ],
            "soft_skills": [
                "Disciplina financeira e rigor contábil",
                "Transparência na prestação de contas à Diretoria Executiva",
                "Pensamento analítico de otimização de recursos"
            ],
            "acoes_edv": [
                "Realizar conciliação bancária semanal do Livro Caixa",
                "Elaborar o relatório financeiro consolidado mensal para apresentação nas Ágoras",
                "Acompanhar pagamentos de custas de GRU do INPI para evitar perda de prazos"
            ]
        },
        "Presidência": {
            "hard_skills": [
                "Planejamento Estratégico trienal (PE 25-27) e governança executiva",
                "Negociação de parcerias com entidades federadas e patrocinadores",
                "Gestão de crises e representação institucional da empresa"
            ],
            "soft_skills": [
                "Liderança servidora e visão macro de futuro",
                "Capacidade de tomada de decisão sob incerteza",
                "Oratória institucional e alinhamento de propósito"
            ],
            "acoes_edv": [
                "Conduzir as reuniões de Diretoria Executiva e Assembleias Gerais",
                "Garantir o atingimento das metas de faturamento e projetos de alto impacto",
                "Fortalecer a conexão da EDV Jr. com o ecossistema do MEJ capixaba e nacional"
            ]
        }
    }

    if role == "presidente":
        diretriz_hierarquica = "Liderança de conselho, representação institucional no MEJ nacional e governança executiva."
    elif role == "diretor":
        diretriz_hierarquica = "Liderança de diretoria, gestão de equipes, metas globais do PE e alinhamento cross-area."
    elif role == "gerente":
        diretriz_hierarquica = "Gestão tática direta de projetos, garantia de prazos críticos, delegação e condução de 1-on-1s."
    else:
        diretriz_hierarquica = "Execução de excelência operacional, protagonismo na área e desenvolvimento de liderança para o ciclo 2026."

    trilha_base = trilhas_por_area.get(area, trilhas_por_area["Projetos"])

    acoes = list(trilha_base["acoes_edv"])
    if foco_adicional:
        acoes.append(f"Projeto de foco especial: {foco_adicional.strip()}")

    return {
        "membro": {
            "nome": member.get("nome"),
            "email": member.get("email"),
            "area": area,
            "cargo": cargo,
            "role": role
        },
        "diretriz_hierarquica": diretriz_hierarquica,
        "objetivos_sugeridos": [
            f"Consolidar domínio das rotinas técnicas e padrões operacionais da área de {area}",
            f"Alcançar 100% de pontualidade nas entregas e compromissos corporativos da EDV Jr.",
            f"Desenvolver competências de liderança e comunicação para evolução de nível no ciclo 2026"
        ],
        "hard_skills_prioritarias": trilha_base["hard_skills"],
        "soft_skills_essenciais": trilha_base["soft_skills"],
        "acoes_praticas_edv": acoes,
        "metas_com_prazos": [
            {"marco": "Diagnóstico inicial e alinhamento com VPGG", "prazo_dias": 15},
            {"marco": "Execução da primeira ação prática de alto impacto", "prazo_dias": 45},
            {"marco": "Avaliação intermediária de evolução e ajustes no plano", "prazo_dias": 60},
            {"marco": "Apresentação de resultados e conclusão formal do ciclo do PDI", "prazo_dias": 90}
        ]
    }

@app.post(
    "/vpgg/pdis",
    response_model=PDIResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar novo PDI (Restrito a VPGG, Presidente e Diretores)"
)
@app.post(
    "/api/vpgg/pdis",
    response_model=PDIResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False
)
async def create_pdi(
    payload: PDICreate,
    current_user: dict = Depends(verify_vpgg_access)
):
    target_email = payload.user_email.lower().strip()
    target_user = get_user_by_email(target_email)
    
    # Se o membro existir, podemos herdar a área dele caso payload.area seja padrão
    area_final = payload.area.strip() if payload.area else (target_user["area"] if target_user else "VPGG")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO pdis (user_email, area, objectives, development_ideas, deadline, status)
        VALUES (?, ?, ?, ?, ?, ?);
    """, (
        target_email,
        area_final,
        payload.objectives.strip(),
        payload.development_ideas.strip(),
        payload.deadline.strip(),
        payload.status.strip() if payload.status else "em_andamento"
    ))
    conn.commit()
    pdi_id = cursor.lastrowid
    cursor.execute("SELECT * FROM pdis WHERE id = ?;", (pdi_id,))
    row = cursor.fetchone()
    conn.close()

    return dict(row)

@app.get(
    "/vpgg/pdis",
    response_model=List[PDIResponse],
    summary="Listar PDIs cadastrados (Restrito a VPGG, Presidente e Diretores)"
)
@app.get(
    "/api/vpgg/pdis",
    response_model=List[PDIResponse],
    include_in_schema=False
)
async def list_pdis(
    user_email: Optional[str] = Query(None, description="Filtrar por e-mail do colaborador"),
    status: Optional[str] = Query(None, description="Filtrar por status do PDI"),
    current_user: dict = Depends(verify_vpgg_access)
):
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM pdis WHERE 1=1"
    params = []

    if user_email:
        query += " AND LOWER(user_email) = ?"
        params.append(user_email.lower().strip())
    if status:
        query += " AND LOWER(status) = ?"
        params.append(status.lower().strip())

    query += " ORDER BY id DESC;"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]

@app.put(
    "/vpgg/pdis/{pdi_id}",
    response_model=PDIResponse,
    summary="Atualizar status ou metas de um PDI existente (Restrito a VPGG, Presidente e Diretores)"
)
@app.put(
    "/api/vpgg/pdis/{pdi_id}",
    response_model=PDIResponse,
    include_in_schema=False
)
async def update_pdi(
    pdi_id: int,
    payload: PDIUpdate,
    current_user: dict = Depends(verify_vpgg_access)
):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pdis WHERE id = ?;", (pdi_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PDI com identificador #{pdi_id} não encontrado."
        )

    updates = []
    params = []

    if payload.objectives is not None:
        updates.append("objectives = ?")
        params.append(payload.objectives.strip())
    if payload.development_ideas is not None:
        updates.append("development_ideas = ?")
        params.append(payload.development_ideas.strip())
    if payload.deadline is not None:
        updates.append("deadline = ?")
        params.append(payload.deadline.strip())
    if payload.status is not None:
        updates.append("status = ?")
        params.append(payload.status.strip())

    if updates:
        params.append(pdi_id)
        cursor.execute(f"UPDATE pdis SET {', '.join(updates)} WHERE id = ?;", params)
        conn.commit()

    cursor.execute("SELECT * FROM pdis WHERE id = ?;", (pdi_id,))
    row = cursor.fetchone()
    conn.close()

    return dict(row)

def _build_pdi_analytics_and_trail(target_email: str, foco: Optional[str] = None) -> dict:
    target_member = get_user_by_email(target_email)
    if not target_member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Membro '{target_email}' não encontrado na base corporativa da EDV Jr."
        )

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM pdis;")
    total_pdis = cursor.fetchone()[0]

    cursor.execute("SELECT status, COUNT(*) FROM pdis GROUP BY status;")
    status_counts = dict(cursor.fetchall())

    cursor.execute("SELECT * FROM pdis WHERE LOWER(user_email) = ? ORDER BY id DESC;", (target_email,))
    membro_pdis = [dict(r) for r in cursor.fetchall()]
    conn.close()

    sugestoes_trilha = generate_pdi_trail(target_member, foco)

    return {
        "status": "success",
        "consolidado_geral": {
            "total_pdis_cadastrados": total_pdis,
            "distribuicao_status": status_counts,
            "taxa_conclusao_pct": round((status_counts.get("concluido", 0) / total_pdis * 100), 1) if total_pdis > 0 else 0.0
        },
        "membro_avaliado": {
            "nome": target_member["nome"],
            "email": target_member["email"],
            "area": target_member["area"],
            "cargo": target_member["cargo"],
            "role": target_member["role"],
            "total_pdis_anteriores": len(membro_pdis)
        },
        "plano_estruturado_sugerido": sugestoes_trilha,
        "historico_pdis_membro": membro_pdis
    }

@app.post(
    "/vpgg/pdis/generate",
    summary="Motor de Geração de PDIs e Análise de Trilhas por Nível Hierárquico"
)
@app.post(
    "/api/vpgg/pdis/generate",
    include_in_schema=False
)
async def generate_pdi_endpoint(
    payload: PDIGenerateRequest,
    current_user: dict = Depends(verify_vpgg_access)
):
    """
    Consolida as métricas de PDIs disponíveis no SQLite e retorna sugestões estruturadas
    de ideias de desenvolvimento (Hard & Soft Skills, Ações Práticas, Metas)
    com base no cargo, área e nível hierárquico atual do membro avaliado.
    """
    target_email = payload.member_email.lower().strip() if payload.member_email else current_user["email"]
    foco = payload.foco_adicional
    return _build_pdi_analytics_and_trail(target_email, foco)

@app.get(
    "/vpgg/pdis/analytics",
    summary="Consolidado Analítico de PDIs da VPGG"
)
@app.get(
    "/api/vpgg/pdis/analytics",
    include_in_schema=False
)
async def get_pdi_analytics_endpoint(
    member_email: Optional[str] = Query(None, description="Filtrar por e-mail do colaborador"),
    current_user: dict = Depends(verify_vpgg_access)
):
    """
    Retorna o consolidado analítico de PDIs e trilha sugerida por e-mail (ou do usuário autenticado).
    """
    target_email = member_email.lower().strip() if member_email else current_user["email"]
    return _build_pdi_analytics_and_trail(target_email, None)

# ==============================================================================
# 6. MÓDULO DE INTELIGÊNCIA COMERCIAL, ENRIQUECIMENTO BRASILAPI & RADAR (EDbrain)
# ==============================================================================

def format_cnpj(clean_cnpj: str) -> str:
    """Formata CNPJ limpo de 14 dígitos no padrão oficial XX.XXX.XXX/YYYY-ZZ"""
    if len(clean_cnpj) == 14:
        return f"{clean_cnpj[:2]}.{clean_cnpj[2:5]}.{clean_cnpj[5:8]}/{clean_cnpj[8:12]}-{clean_cnpj[12:]}"
    return clean_cnpj

async def fetch_brasilapi_cnpj(clean_cnpj: str) -> Optional[dict]:
    """
    Consulta assíncrona e gratuita à BrasilAPI (v1/cnpj).
    Retorna os dados cadastrais da Receita Federal ou None em caso de falha/timeout.
    """
    clean = re.sub(r"\D", "", clean_cnpj)
    if len(clean) != 14:
        return None
    url = f"https://brasilapi.com.br/api/cnpj/v1/{clean}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 EDbrain/2.3"
    }
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=5.0, headers=headers) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 404:
                    return None
        except Exception as e:
            if attempt == 0:
                await asyncio.sleep(0.3)
                continue
            print(f"[BrasilAPI] Aviso: Falha de conexão ou timeout para CNPJ {clean}: {e}")
    return None

def calculate_days_stagnant(created_at: Optional[str]) -> int:
    """Calcula o tempo de estagnação do lead em dias desde a criação ou último registro"""
    if not created_at:
        return 0
    try:
        dt_str = str(created_at).replace("Z", "").split(".")[0]
        if "T" in dt_str:
            dt = datetime.fromisoformat(dt_str)
        else:
            dt = datetime.strptime(dt_str[:10], "%Y-%m-%d")
        return max(0, (datetime.now().date() - dt.date()).days)
    except Exception:
        return 0

def calculate_lead_score(
    status: str,
    created_at: Optional[str] = None,
    next_followup_date: Optional[str] = None,
    company_size: Optional[str] = None,
    estimated_value: Optional[float] = 0.0,
    has_cnpj: bool = False,
    tags: Optional[str] = None
) -> int:
    """
    Motor Preditivo de Lead Scoring da EDV Jr. (Escala de 0 a 100):
    Pondera recência do follow-up, tempo de estagnação, estágio no funil, porte corporativo e valor potencial.
    """
    st = (status or "").lower().strip()
    if st == "fechado":
        return 100
    if st == "perdido":
        return 10

    score = 40  # Base para leads ativos

    # 1. Estágio no funil
    if st == "negociacao":
        score += 30
    elif st == "prospeccao":
        score += 10

    # 2. Recência e tempo de estagnação
    days = calculate_days_stagnant(created_at)
    if days <= 3:
        score += 15
    elif days <= 7:
        score += 10
    elif days <= 14:
        score += 5
    elif days > 30:
        score -= 20  # Penalidade severa por estagnação superior a 30 dias
    elif days > 14:
        score -= 10  # Penalidade por estagnação moderada

    # Agendamento de próximo contato
    if next_followup_date:
        try:
            nxt = datetime.strptime(next_followup_date[:10], "%Y-%m-%d").date()
            diff = (nxt - datetime.now().date()).days
            if diff >= 0:
                score += 10  # Contato futuro planejado
            elif diff < -3:
                score -= 10  # Follow-up atrasado
        except Exception:
            pass

    # 3. Porte Corporativo
    size = (company_size or "").upper()
    if any(k in size for k in ["DEMAIS", "GRANDE", "MEDIO", "MÉDIO"]):
        score += 15
    elif any(k in size for k in ["EPP", "PEQUENO"]):
        score += 10
    elif any(k in size for k in ["ME", "MICRO"]):
        score += 5

    # 4. Dados Cadastrais e Valor Estimado
    if has_cnpj:
        score += 5

    if estimated_value and estimated_value > 0:
        if estimated_value >= 5000:
            score += 10
        elif estimated_value >= 2000:
            score += 7
        else:
            score += 4

    # 5. Tags estratégicas
    if tags:
        t_low = tags.lower()
        if any(w in t_low for w in ["quente", "prioridade", "decisor", "urgente"]):
            score += 5

    return max(0, min(100, score))

def enrich_lead_dict(row: dict) -> dict:
    """Preenche campos dinâmicos calculados (days_stagnant, is_stagnant, score default)"""
    d = dict(row)
    created_at = d.get("created_at")
    days_stagnant = calculate_days_stagnant(created_at)
    st = (d.get("status") or "").lower()
    is_stagnant = days_stagnant >= 14 and st in ("prospeccao", "negociacao")
    d["days_stagnant"] = days_stagnant
    d["is_stagnant"] = is_stagnant
    if d.get("score") is None:
        d["score"] = calculate_lead_score(
            status=d.get("status") or "prospeccao",
            created_at=created_at,
            next_followup_date=d.get("next_followup_date"),
            company_size=d.get("company_size"),
            estimated_value=d.get("estimated_value") or 0.0,
            has_cnpj=bool(d.get("cnpj")),
            tags=d.get("tags")
        )
    return d

@app.get(
    "/crm/radar/cnpj/{cnpj}",
    summary="Consulta e pré-visualização de CNPJ via BrasilAPI"
)
@app.get(
    "/api/crm/radar/cnpj/{cnpj}",
    include_in_schema=False
)
async def query_cnpj_brasilapi(cnpj: str, current_user: dict = Depends(get_current_user)):
    """
    Consulta assíncrona gratuita na BrasilAPI para enriquecer ou validar dados fiscais
    (Razão Social, CNAE, Porte, Endereço) antes ou durante a criação de um lead comercial.
    """
    clean = re.sub(r"\D", "", cnpj)
    if len(clean) != 14:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CNPJ inválido. Forneça exatamente 14 dígitos numéricos."
        )
    data = await fetch_brasilapi_cnpj(clean)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CNPJ {format_cnpj(clean)} não encontrado na base da BrasilAPI ou serviço temporariamente inacessível."
        )

    addr_parts = []
    if data.get("logradouro"):
        l = data.get("logradouro")
        if data.get("numero"):
            l += f", {data.get('numero')}"
        if data.get("complemento"):
            l += f" ({data.get('complemento')})"
        addr_parts.append(l)
    if data.get("bairro"):
        addr_parts.append(data.get("bairro"))
    if data.get("municipio") and data.get("uf"):
        addr_parts.append(f"{data.get('municipio')} - {data.get('uf')}")
    if data.get("cep"):
        addr_parts.append(f"CEP {data.get('cep')}")
    address = " • ".join(addr_parts) if addr_parts else None

    cnae = f"{data.get('cnae_fiscal', '')} - {data.get('cnae_fiscal_descricao', '')}".strip(" -")
    company_size = data.get("descricao_porte") or data.get("porte") or ""

    return {
        "status": "success",
        "cnpj": format_cnpj(clean),
        "clean_cnpj": clean,
        "razao_social": data.get("razao_social"),
        "nome_fantasia": data.get("nome_fantasia"),
        "situacao_cadastral": data.get("descricao_situacao_cadastral"),
        "cnae": cnae,
        "company_size": company_size,
        "address": address
    }

@app.post(
    "/crm/followups",
    response_model=ClientFollowupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar interação/follow-up de cliente com enriquecimento automático via BrasilAPI"
)
@app.post(
    "/api/crm/followups",
    response_model=ClientFollowupResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False
)
async def create_client_followup(
    payload: ClientFollowupCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Cadastra um novo follow-up no pipeline comercial com persistência no SQLite.
    Se o CNPJ for fornecido, dispara consulta assíncrona automática à BrasilAPI
    para enriquecer Razão Social, CNAE, Porte Corporativo e Endereço Comercial.
    Calcula preditivamente o Lead Score (0 a 100).
    Aplica validação de escopo de área (RBAC).
    """
    # 1. Validação de nome do cliente
    if not payload.client_name or not payload.client_name.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O nome do cliente é obrigatório para registrar o follow-up."
        )

    # 2. Validação estrita de status do ciclo comercial
    raw_status = (payload.status or "prospeccao").lower().strip()
    if raw_status not in VALID_CRM_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Status '{payload.status}' inválido. Valores permitidos: {sorted(list(VALID_CRM_STATUSES))}."
        )

    # 3. Validação de Escopo de Área (RBAC)
    target_area = payload.area.strip() if payload.area and payload.area.strip() else (current_user.get("area") or current_user.get("setor") or "Comercial")
    verify_area_access(target_area, current_user)

    # 4. Enriquecimento Automático via BrasilAPI se CNPJ fornecido
    clean_cnpj = re.sub(r"\D", "", payload.cnpj) if payload.cnpj else None
    formatted_cnpj = format_cnpj(clean_cnpj) if clean_cnpj else None

    final_cnae = payload.cnae
    final_company_size = payload.company_size
    final_address = payload.address
    final_client_name = payload.client_name.strip()

    if clean_cnpj and len(clean_cnpj) == 14:
        cnpj_data = await fetch_brasilapi_cnpj(clean_cnpj)
        if cnpj_data:
            if not final_cnae and (cnpj_data.get("cnae_fiscal") or cnpj_data.get("cnae_fiscal_descricao")):
                final_cnae = f"{cnpj_data.get('cnae_fiscal', '')} - {cnpj_data.get('cnae_fiscal_descricao', '')}".strip(" -")
            if not final_company_size and (cnpj_data.get("descricao_porte") or cnpj_data.get("porte")):
                final_company_size = cnpj_data.get("descricao_porte") or cnpj_data.get("porte")
            if not final_address:
                addr_parts = []
                if cnpj_data.get("logradouro"):
                    l = cnpj_data.get("logradouro")
                    if cnpj_data.get("numero"):
                        l += f", {cnpj_data.get('numero')}"
                    if cnpj_data.get("complemento"):
                        l += f" ({cnpj_data.get('complemento')})"
                    addr_parts.append(l)
                if cnpj_data.get("bairro"):
                    addr_parts.append(cnpj_data.get("bairro"))
                if cnpj_data.get("municipio") and cnpj_data.get("uf"):
                    addr_parts.append(f"{cnpj_data.get('municipio')} - {cnpj_data.get('uf')}")
                if cnpj_data.get("cep"):
                    addr_parts.append(f"CEP {cnpj_data.get('cep')}")
                if addr_parts:
                    final_address = " • ".join(addr_parts)
            if final_client_name.lower().startswith("lead") and cnpj_data.get("razao_social"):
                final_client_name = cnpj_data.get("razao_social")

    # 5. Cálculo preditivo do Lead Score
    if payload.score is not None:
        final_score = max(0, min(100, payload.score))
    else:
        final_score = calculate_lead_score(
            status=raw_status,
            created_at=datetime.now().strftime("%Y-%m-%d"),
            next_followup_date=payload.next_followup_date,
            company_size=final_company_size,
            estimated_value=payload.estimated_value or 0.0,
            has_cnpj=bool(formatted_cnpj),
            tags=payload.tags
        )

    # 6. Inserção segura na base relacional SQLite
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO client_followups (
            client_name, contact_person, status, interaction_type, notes,
            next_followup_date, area, cnpj, cnae, company_size, address,
            score, estimated_value, tags, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        final_client_name,
        payload.contact_person.strip() if payload.contact_person else None,
        raw_status,
        payload.interaction_type.strip() if payload.interaction_type else None,
        payload.notes.strip() if payload.notes else None,
        payload.next_followup_date.strip() if payload.next_followup_date else None,
        target_area,
        formatted_cnpj,
        final_cnae.strip() if final_cnae else None,
        final_company_size.strip() if final_company_size else None,
        final_address.strip() if final_address else None,
        final_score,
        float(payload.estimated_value or 0.0),
        payload.tags.strip() if payload.tags else None,
        current_user.get("email") or current_user.get("nome")
    ))
    conn.commit()
    followup_id = cursor.lastrowid
    cursor.execute("SELECT * FROM client_followups WHERE id = ?;", (followup_id,))
    row = cursor.fetchone()
    conn.close()

    return enrich_lead_dict(row)

@app.get(
    "/crm/followups",
    response_model=List[ClientFollowupResponse],
    summary="Listar interações comerciais com escopo por área (ou visão global para diretoria/presidência)"
)
@app.get(
    "/api/crm/followups",
    response_model=List[ClientFollowupResponse],
    include_in_schema=False
)
async def list_client_followups(
    area: Optional[str] = Query(None, description="Filtrar por área (ex: Comercial, Projetos)"),
    status: Optional[str] = Query(None, description="Filtrar por status do ciclo comercial"),
    client_name: Optional[str] = Query(None, description="Filtrar por nome do cliente ou empresa"),
    current_user: dict = Depends(get_current_user)
):
    """
    Retorna o histórico de follow-ups filtrado conforme o escopo RBAC do colaborador.
    - Presidente e Diretores: Acesso global irrestrito transversal a todas as áreas.
    - Gerentes e Assessores: Visualização restrita estritamente à sua área corporativa.
    """
    user_role = (current_user.get("role") or "").lower().strip()
    user_area = (current_user.get("area") or current_user.get("setor") or "").strip()

    if user_role in {"presidente", "diretor"}:
        effective_area = area.strip() if area and area.strip() else None
    else:
        if area and not check_area_access(area, current_user):
            verify_area_access(area, current_user)  # Dispara 403 Forbidden se tentar ver outra área
        effective_area = user_area

    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM client_followups WHERE 1=1"
    params = []

    if effective_area:
        query += " AND LOWER(area) = LOWER(?)"
        params.append(effective_area)

    if status:
        query += " AND LOWER(status) = LOWER(?)"
        params.append(status.lower().strip())

    if client_name:
        query += " AND LOWER(client_name) LIKE LOWER(?)"
        params.append(f"%{client_name.strip()}%")

    query += " ORDER BY id DESC;"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [enrich_lead_dict(r) for r in rows]

@app.get(
    "/crm/radar/search",
    response_model=List[ClientFollowupResponse],
    summary="Radar Avançado: Busca multicritério de leads com filtros dinâmicos compostos e Lead Scoring"
)
@app.get(
    "/api/crm/radar/search",
    response_model=List[ClientFollowupResponse],
    include_in_schema=False
)
async def search_radar_leads(
    date_from: Optional[str] = Query(None, description="Data inicial de cadastro ou próximo contato (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="Data final de cadastro ou próximo contato (YYYY-MM-DD)"),
    days_stagnant: Optional[int] = Query(None, description="Filtrar leads com estagnação maior ou igual a X dias"),
    cnae: Optional[str] = Query(None, description="Filtro por código ou descrição do CNAE"),
    min_score: Optional[int] = Query(None, description="Lead score mínimo (0 a 100)"),
    tags: Optional[str] = Query(None, description="Filtro por tags (ex: #quente)"),
    status: Optional[str] = Query(None, description="Status do funil comercial"),
    area: Optional[str] = Query(None, description="Área responsável"),
    search_query: Optional[str] = Query(None, description="Busca textual livre (cliente, contato, notas, CNPJ, CNAE)"),
    sort_by: Optional[str] = Query("score", description="Campo de ordenação ('score', 'estimated_value', 'created_at', 'client_name')"),
    order: Optional[str] = Query("desc", description="Sentido da ordenação ('desc' ou 'asc')"),
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint do Radar Comercial Avançado:
    Permite cruzamento multicritério de datas, tempo de estagnação, CNAE, score mínimo,
    tags e busca livre indexada em FTS5, com isolamento estrito de área por RBAC.
    """
    user_role = (current_user.get("role") or "").lower().strip()
    user_area = (current_user.get("area") or current_user.get("setor") or "").strip()

    if user_role in {"presidente", "diretor"}:
        effective_area = area.strip() if area and area.strip() else None
    else:
        if area and not check_area_access(area, current_user):
            verify_area_access(area, current_user)
        effective_area = user_area

    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM client_followups WHERE 1=1"
    params = []

    if effective_area:
        query += " AND LOWER(area) = LOWER(?)"
        params.append(effective_area)

    if status:
        query += " AND LOWER(status) = LOWER(?)"
        params.append(status.lower().strip())

    if min_score is not None:
        query += " AND score >= ?"
        params.append(min_score)

    if cnae:
        query += " AND LOWER(cnae) LIKE LOWER(?)"
        params.append(f"%{cnae.strip()}%")

    if tags:
        query += " AND LOWER(tags) LIKE LOWER(?)"
        params.append(f"%{tags.strip()}%")

    if date_from:
        query += " AND (date(created_at) >= date(?) OR (next_followup_date IS NOT NULL AND next_followup_date >= ?))"
        params.append(date_from.strip())
        params.append(date_from.strip())

    if date_to:
        query += " AND (date(created_at) <= date(?) OR (next_followup_date IS NOT NULL AND next_followup_date <= ?))"
        params.append(date_to.strip())
        params.append(date_to.strip())

    if search_query:
        sq = search_query.strip()
        fts_applied = False
        try:
            cursor.execute("SELECT 1 FROM client_followups_fts LIMIT 1;")
            query += " AND id IN (SELECT rowid FROM client_followups_fts WHERE client_followups_fts MATCH ?)"
            params.append(f'"{sq}"*')
            fts_applied = True
        except Exception:
            pass

        if not fts_applied:
            query += " AND (LOWER(client_name) LIKE LOWER(?) OR LOWER(contact_person) LIKE LOWER(?) OR LOWER(notes) LIKE LOWER(?) OR LOWER(cnpj) LIKE LOWER(?) OR LOWER(cnae) LIKE LOWER(?) OR LOWER(tags) LIKE LOWER(?))"
            p = f"%{sq}%"
            params.extend([p, p, p, p, p, p])

    order_dir = "ASC" if (order or "").lower() == "asc" else "DESC"
    if sort_by == "estimated_value":
        query += f" ORDER BY estimated_value {order_dir}, id DESC;"
    elif sort_by == "created_at":
        query += f" ORDER BY id {order_dir};"
    elif sort_by == "client_name":
        query += f" ORDER BY client_name {order_dir};"
    else:
        query += f" ORDER BY score {order_dir}, id DESC;"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    enriched_leads = [enrich_lead_dict(r) for r in rows]

    if days_stagnant is not None and days_stagnant > 0:
        enriched_leads = [l for l in enriched_leads if l.get("days_stagnant", 0) >= days_stagnant]

    return enriched_leads

@app.put(
    "/crm/followups/{followup_id}",
    response_model=ClientFollowupResponse,
    summary="Atualizar follow-up comercial existente"
)
@app.put(
    "/api/crm/followups/{followup_id}",
    response_model=ClientFollowupResponse,
    include_in_schema=False
)
async def update_client_followup(
    followup_id: int,
    payload: ClientFollowupUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Atualiza status, observações ou metadados de um follow-up existente,
    respeitando as regras de escopo por área.
    Se o CNPJ for atualizado, enriquece automaticamente via BrasilAPI.
    Recalcula preditivamente o Lead Score.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM client_followups WHERE id = ?;", (followup_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Follow-up #{followup_id} não encontrado."
        )

    # Verificar permissão sobre a área do registro existente
    verify_area_access(existing["area"], current_user)

    updates = []
    params = []

    if payload.client_name is not None:
        if not payload.client_name.strip():
            conn.close()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nome do cliente não pode ser vazio.")
        updates.append("client_name = ?")
        params.append(payload.client_name.strip())

    if payload.contact_person is not None:
        updates.append("contact_person = ?")
        params.append(payload.contact_person.strip())

    if payload.status is not None:
        st = payload.status.lower().strip()
        if st not in VALID_CRM_STATUSES:
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Status '{payload.status}' inválido. Permitidos: {sorted(list(VALID_CRM_STATUSES))}."
            )
        updates.append("status = ?")
        params.append(st)

    if payload.interaction_type is not None:
        updates.append("interaction_type = ?")
        params.append(payload.interaction_type.strip())

    if payload.notes is not None:
        updates.append("notes = ?")
        params.append(payload.notes.strip())

    if payload.next_followup_date is not None:
        updates.append("next_followup_date = ?")
        params.append(payload.next_followup_date.strip())

    if payload.area is not None:
        new_area = payload.area.strip()
        verify_area_access(new_area, current_user)
        updates.append("area = ?")
        params.append(new_area)

    # Enriquecimento via BrasilAPI em caso de novo CNPJ
    if payload.cnpj is not None:
        clean_c = re.sub(r"\D", "", payload.cnpj)
        formatted_c = format_cnpj(clean_c) if clean_c else None
        updates.append("cnpj = ?")
        params.append(formatted_c)

        if clean_c and len(clean_c) == 14 and (payload.cnae is None or payload.address is None):
            cnpj_data = await fetch_brasilapi_cnpj(clean_c)
            if cnpj_data:
                if payload.cnae is None and cnpj_data.get("cnae_fiscal"):
                    cnae_fmt = f"{cnpj_data.get('cnae_fiscal', '')} - {cnpj_data.get('cnae_fiscal_descricao', '')}".strip(" -")
                    updates.append("cnae = ?")
                    params.append(cnae_fmt)
                if payload.company_size is None and (cnpj_data.get("descricao_porte") or cnpj_data.get("porte")):
                    porte_val = cnpj_data.get("descricao_porte") or cnpj_data.get("porte")
                    updates.append("company_size = ?")
                    params.append(porte_val)
                if payload.address is None:
                    addr_parts = []
                    if cnpj_data.get("logradouro"):
                        l = cnpj_data.get("logradouro")
                        if cnpj_data.get("numero"):
                            l += f", {cnpj_data.get('numero')}"
                        if cnpj_data.get("complemento"):
                            l += f" ({cnpj_data.get('complemento')})"
                        addr_parts.append(l)
                    if cnpj_data.get("bairro"):
                        addr_parts.append(cnpj_data.get("bairro"))
                    if cnpj_data.get("municipio") and cnpj_data.get("uf"):
                        addr_parts.append(f"{cnpj_data.get('municipio')} - {cnpj_data.get('uf')}")
                    if cnpj_data.get("cep"):
                        addr_parts.append(f"CEP {cnpj_data.get('cep')}")
                    if addr_parts:
                        updates.append("address = ?")
                        params.append(" • ".join(addr_parts))

    if payload.cnae is not None:
        updates.append("cnae = ?")
        params.append(payload.cnae.strip())

    if payload.company_size is not None:
        updates.append("company_size = ?")
        params.append(payload.company_size.strip())

    if payload.address is not None:
        updates.append("address = ?")
        params.append(payload.address.strip())

    if payload.estimated_value is not None:
        updates.append("estimated_value = ?")
        params.append(float(payload.estimated_value))

    if payload.tags is not None:
        updates.append("tags = ?")
        params.append(payload.tags.strip())

    # Recalcular Lead Score se não for fornecido explicitamente
    if payload.score is not None:
        updates.append("score = ?")
        params.append(max(0, min(100, payload.score)))
    else:
        new_st = payload.status or existing["status"]
        new_val = payload.estimated_value if payload.estimated_value is not None else existing["estimated_value"]
        new_size = payload.company_size if payload.company_size is not None else existing["company_size"]
        new_cnpj = payload.cnpj if payload.cnpj is not None else existing["cnpj"]
        new_tags = payload.tags if payload.tags is not None else existing["tags"]
        recalculated_score = calculate_lead_score(
            status=new_st,
            created_at=existing["created_at"],
            next_followup_date=payload.next_followup_date or existing["next_followup_date"],
            company_size=new_size,
            estimated_value=new_val or 0.0,
            has_cnpj=bool(new_cnpj),
            tags=new_tags
        )
        updates.append("score = ?")
        params.append(recalculated_score)

    if updates:
        params.append(followup_id)
        cursor.execute(f"UPDATE client_followups SET {', '.join(updates)} WHERE id = ?;", params)
        conn.commit()

    cursor.execute("SELECT * FROM client_followups WHERE id = ?;", (followup_id,))
    row = cursor.fetchone()
    conn.close()
    return enrich_lead_dict(row)

# ==============================================================================
# 7. DADOS OPERACIONAIS E AUDITORIA
# ==============================================================================

@app.get("/api/data/operational", summary="Entrega protegida dos dados operacionais (Google Drive Sync)")
async def get_operational_data(current_user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Entrega os dados de RMs, Fluxo de Caixa, Leads CRM, VPGG e Selo EJ
    exclusivamente a usuários que possuam token JWT válido emitido pelo backend.
    """
    if not os.path.exists(LEGACY_DATA_PATH):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Arquivo de dados legados (legacy_data.json) não encontrado no servidor."
        )
    
    try:
        with open(LEGACY_DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao carregar dados operacionais: {str(e)}"
        )
    
    user_role = current_user.get("role", "assessor")
    response_data = {
        "timestamp": data.get("timestamp"),
        "authenticated_as": {
            "nome": current_user.get("nome"),
            "email": current_user.get("email"),
            "role": user_role,
            "area": current_user.get("area"),
            "setor": current_user.get("setor")
        },
        "rms": data.get("rms", []),
        "crm_leads": data.get("crm_leads", []),
        "fluxo": data.get("fluxo", []),
        "totais_financeiro": data.get("totais_financeiro", {}),
        "vpgg": data.get("vpgg", []),
        "selo_ej": data.get("selo_ej", [])
    }
    
    return response_data

@app.get("/api/admin/audit", summary="Auditoria de segurança restrita à Presidência e Diretorias")
async def get_audit_log(admin_user: dict = Depends(require_role(["presidente", "diretor"]))):
    return {
        "status": "authorized",
        "auditor": admin_user["nome"],
        "area": admin_user["area"],
        "role": admin_user["role"],
        "security_level": "RESTRICTED",
        "message": "Acesso concedido à telemetria de segurança e registros de auditoria corporativa."
    }

@app.get("/api/health", summary="Status do servidor FastAPI")
async def health_check():
    return {
        "status": "online",
        "service": "EDV Jr. EDbrain API",
        "version": "2.3.0",
        "cost": "0.00 BRL (Custo Zero - Open Source / Local SQLite)",
        "security": "BCrypt + JWT + Strict RBAC + Self-Promotion Shield + VPGG PDIs + CRM Follow-up"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
