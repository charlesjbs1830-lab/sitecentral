"""
EDV Jr. - Sistema Operacional Unificado (EDbrain)
Backend em FastAPI com Persistência SQLite (Custo Zero), Proteção JWT,
Controle de Acesso Baseado em Papéis e Áreas (RBAC),
Módulo Financeiro com Blindagem Indireta e Mural de Avisos Institucionais.
"""

import os
import json
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# Correção: Uso de importações relativas para o pacote backend
from database import init_db, get_user_by_email
from database import init_db, get_user_by_email, get_connection, VALID_ROLES
feature/auth-backend
from auth import (
    verify_password,
    create_access_token,
    get_current_user,
    require_role,
    verify_area_access
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
    version="2.1.0",
    description="Backend oficial da EDV Jr. com SQLite, JWT, RBAC, Módulo Financeiro e Mural de Avisos.",
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

# ==============================================================================
# 1. AUTENTICAÇÃO E PERFIL DO USUÁRIO
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

# ==============================================================================
# 2. MÓDULO FINANCEIRO COM ATUALIZAÇÃO INDIRETA (BLINDAGEM E TETO DE ALÇADA)
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
# 3. MÓDULO DE AVISOS INSTITUCIONAIS (MURAL DE AVISOS)
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
# 4. DADOS OPERACIONAIS E AUDITORIA
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
        "cost": "0.00 BRL (Custo Zero - Open Source / Local SQLite)",
        "security": "BCrypt + JWT + RBAC + Financial Shield"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
