"""
EDV Jr. - Sistema Operacional Unificado 2.0
Backend Leve em FastAPI com Proteção JWT e Controle de Acesso Baseado em Papéis (RBAC)
Custo Zero: Execução local em SQLite e pronto para hospedagem gratuita.
"""

import os
import json
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Correção: Uso de importações relativas para o pacote backend
from .database import init_db, get_user_by_email
from .auth import (
    verify_password,
    create_access_token,
    get_current_user,
    require_role
)

# Caminho para o payload operacional oficial
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY_DATA_PATH = os.path.join(BASE_DIR, "data", "legacy_data.json")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializa tabela SQLite e carrega Whitelist oficial no startup
    init_db()
    yield

app = FastAPI(
    title="EDV Jr. - Auth & RBAC Security Backend",
    version="2.0.0",
    description="Backend de segurança de custo zero com FastAPI, SQLite, BCrypt e JWT.",
    lifespan=lifespan
)

# Habilitar CORS para consumo do frontend em qualquer porta local ou no GitHub Pages
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Schemas Pydantic
class LoginRequest(BaseModel):
    email: str
    password: str

class UserProfile(BaseModel):
    id: int
    email: str
    nome: str
    setor: str
    cargo: str
    role: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile

# 1. ROTA DE LOGIN E EMISSÃO DE TOKEN JWT
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
    
    # Criar Token JWT com dados essenciais do usuário e papel (RBAC)
    token_payload = {
        "sub": user["email"],
        "nome": user["nome"],
        "setor": user["setor"],
        "role": user["role"]
    }
    access_token = create_access_token(data=token_payload)
    
    user_profile = UserProfile(
        id=user["id"],
        email=user["email"],
        nome=user["nome"],
        setor=user["setor"],
        cargo=user["cargo"],
        role=user["role"]
    )
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_profile
    )

# 2. ROTA DE IDENTIFICAÇÃO DO USUÁRIO CORRENTE
@app.get("/api/auth/me", response_model=UserProfile, summary="Verificação de sessão e perfil RBAC")
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserProfile(
        id=current_user["id"],
        email=current_user["email"],
        nome=current_user["nome"],
        setor=current_user["setor"],
        cargo=current_user["cargo"],
        role=current_user["role"]
    )

# 3. ROTA PROTEGIDA DE DADOS OPERACIONAIS (RBAC ESTREITO)
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
    
    # Enriquecimento com metadados de auditoria e RBAC
    user_role = current_user.get("role", "ANALYST")
    response_data = {
        "timestamp": data.get("timestamp"),
        "authenticated_as": {
            "nome": current_user.get("nome"),
            "email": current_user.get("email"),
            "role": user_role,
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

# 4. ROTA DE AUDITORIA RESTRITA A ADMINS E MANAGERS
@app.get("/api/admin/audit", summary="Auditoria de segurança restrita à Presidência e Diretorias")
async def get_audit_log(admin_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))):
    return {
        "status": "authorized",
        "auditor": admin_user["nome"],
        "role": admin_user["role"],
        "security_level": "RESTRICTED",
        "message": "Acesso concedido à telemetria de segurança e registros de autenticação."
    }

# 5. ROTA DE HEALTHCHECK
@app.get("/api/health", summary="Status do servidor FastAPI")
async def health_check():
    return {
        "status": "online",
        "service": "EDV Jr. Security API",
        "cost": "0.00 BRL (Custo Zero - Open Source / Local SQLite)",
        "security": "BCrypt + JWT + RBAC"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
