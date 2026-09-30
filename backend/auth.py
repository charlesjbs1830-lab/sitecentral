"""
EDV Jr. - Módulo de Autenticação, Criptografia Bcrypt, JWT e Controle de Acesso (RBAC)
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
try:
    from database import get_user_by_email, VALID_ROLES
except ImportError:
    from backend.database import get_user_by_email, VALID_ROLES

SECRET_KEY = os.getenv("EDV_JWT_SECRET", "edv_junior_secure_jwt_token_secret_key_gestao_2026_enterprise_rbac_sig")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 horas de sessão

security = HTTPBearer(auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acesso expirado. Por favor, faça login novamente.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou adulterado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais de autenticação não fornecidas (Bearer token ausente).",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_access_token(credentials.credentials)
    email: str = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido: sujeito ausente.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário do token não encontrado na base corporativa.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_copy = dict(user)
    user_copy.pop("hashed_password", None)
    return user_copy

def require_role(allowed_roles: List[str]):
    """
    Dependência que restringe a rota aos papéis estritos informados
    (ex: 'presidente', 'diretor', 'gerente', 'assessor').
    """
    normalized_allowed = {r.lower().strip() for r in allowed_roles}
    def role_checker(user: dict = Depends(get_current_user)):
        user_role = (user.get("role") or "").lower().strip()
        if user_role not in normalized_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acesso negado: Perfil '{user_role}' não tem permissão para este recurso. Permitidos: {list(normalized_allowed)}"
            )
        return user
    return role_checker

def check_area_access(target_area: Optional[str], user: dict) -> bool:
    """
    Retorna True se o usuário possuir acesso operacional à área solicitada.
    - 'presidente' e 'diretor' possuem privilégios cross-area irrestritos.
    - 'gerente' e 'assessor' têm escopo restrito exclusivamente à sua própria área.
    """
    if not user:
        return False
    role = (user.get("role") or "").lower().strip()
    if role in {"presidente", "diretor"}:
        return True
    
    if not target_area:
        return False
        
    user_area = (user.get("area") or user.get("setor") or "").lower().strip()
    target = target_area.lower().strip()
    
    return (
        user_area == target
        or user_area.startswith(target)
        or target.startswith(user_area)
    )

def verify_area_access(target_area: str, user: Optional[dict] = None):
    """
    Validação de Escopo de Área (RBAC).
    Suporta tanto uso direto como função:
        verify_area_access("Projetos", current_user)
    quanto uso declarativo como Factory de Dependência FastAPI:
        Depends(verify_area_access("Projetos"))
    """
    if user is None:
        def dependency(current_user: dict = Depends(get_current_user)):
            return verify_area_access(target_area, current_user)
        return dependency

    if not check_area_access(target_area, user):
        role = user.get("role", "desconhecido")
        area = user.get("area", user.get("setor", "indefinida"))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Acesso negado: Perfil '{role}' da área '{area}' não possui permissão "
                f"para operar sobre a área '{target_area}'. Privilégios cross-area são restritos à Presidência e Diretorias."
            )
        )
    return True

def check_vpgg_access(user: dict) -> bool:
    """
    Retorna True se o usuário pertencer à área VPGG (assessor, gerente, diretor de VPGG)
    ou possuir liderança global (presidente ou diretor).
    """
    if not user:
        return False
    role = (user.get("role") or "").lower().strip()
    if role in {"presidente", "diretor"}:
        return True
    area = (user.get("area") or user.get("setor") or "").lower().strip()
    return "vpgg" in area

def verify_vpgg_access(current_user: dict = Depends(get_current_user)) -> dict:
    """
    Validação de Escopo VPGG (RBAC).
    Restringe operações de PDIs e gestão de pessoas estritamente à equipe VPGG
    ou à liderança executiva (Presidente e Diretores).
    """
    if not current_user or not check_vpgg_access(current_user):
        role = current_user.get("role", "desconhecido") if current_user else "anônimo"
        area = current_user.get("area", current_user.get("setor", "indefinida")) if current_user else "indefinida"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Acesso negado: Perfil '{role}' da área '{area}' não possui permissão para acessar o módulo de PDIs da VPGG. "
                f"Recurso exclusivo para colaboradores da área de VPGG e liderança global (Presidente e Diretores)."
            )
        )
    return current_user

def check_marketing_access(user: dict) -> bool:
    """
    Retorna True se o usuário pertencer à área Marketing (assessor, gerente, diretor de Marketing)
    ou possuir liderança executiva global (presidente ou diretor).
    """
    if not user:
        return False
    role = (user.get("role") or "").lower().strip()
    if role in {"presidente", "diretor"}:
        return True
    area = (user.get("area") or user.get("setor") or "").lower().strip()
    return "marketing" in area

def verify_marketing_access(current_user: dict = Depends(get_current_user)) -> dict:
    """
    Validação de Escopo de Marketing (RBAC).
    Restringe operações estratégicas de campanhas e Brand Kit a colaboradores de Marketing
    e liderança executiva (Presidente e Diretores).
    """
    if not current_user or not check_marketing_access(current_user):
        role = current_user.get("role", "desconhecido") if current_user else "anônimo"
        area = current_user.get("area", current_user.get("setor", "indefinida")) if current_user else "indefinida"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Acesso negado: Perfil '{role}' da área '{area}' não possui permissão para gerenciar o módulo de Marketing e Campanhas. "
                f"Operação restrita à equipe de Marketing e liderança institucional (Presidente e Diretores)."
            )
        )
    return current_user

def check_psel_management_access(user: dict) -> bool:
    """
    Retorna True se o usuário tiver permissão para gerenciar candidatos do Processo Seletivo (PSEL):
    Liderança executiva (Presidente/Diretor) ou integrantes das áreas de Marketing e VPGG (Gente & Gestão).
    """
    if not user:
        return False
    role = (user.get("role") or "").lower().strip()
    if role in {"presidente", "diretor"}:
        return True
    area = (user.get("area") or user.get("setor") or "").lower().strip()
    return "marketing" in area or "vpgg" in area

def verify_psel_access(current_user: dict = Depends(get_current_user)) -> dict:
    """
    Validação de Acesso ao Funil de Recrutamento PSEL (RBAC).
    Permite acesso a membros do Marketing, VPGG e Diretoria Executiva.
    """
    if not current_user or not check_psel_management_access(current_user):
        role = current_user.get("role", "desconhecido") if current_user else "anônimo"
        area = current_user.get("area", current_user.get("setor", "indefinida")) if current_user else "indefinida"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Acesso negado: Perfil '{role}' da área '{area}' não possui permissão para gerenciar o Funil de Recrutamento (PSEL). "
                f"Acesso restrito às áreas de Marketing, VPGG (Gente & Gestão) e Diretoria Executiva."
            )
        )
    return current_user

