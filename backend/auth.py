"""
EDV Jr. - Módulo de Autenticação, Criptografia Bcrypt, JWT e Controle de Acesso (RBAC)
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Tuple
import threading
import time
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
try:
    from database import get_user_by_email, VALID_ROLES
except ImportError:
    from backend.database import get_user_by_email, VALID_ROLES

SECRET_KEY = os.getenv("EDV_JWT_SECRET", "edv_junior_secure_jwt_token_secret_key_gestao_2026_enterprise_rbac_sig")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", str(60 * 24 * 7)))  # 7 dias de sessão contínua para evitar expirações abruptas

security = HTTPBearer(auto_error=False)

# ==============================================================================
# MOTOR DE RATE LIMITING POR IP (PROTEÇÃO ATIVA CONTRA FORÇA BRUTA)
# ==============================================================================
class LoginRateLimiter:
    """
    Controlador de taxa de requisições por IP na rota de autenticação.
    Implementa janela deslizante para mitigação de ataques de força bruta e credential stuffing.
    - Bloqueia após FAILED_LIMIT tentativas incorretas em WINDOW_SECONDS (5 min).
    - Limita requisições globais por minuto por IP (BURST_LIMIT).
    """
    def __init__(self, max_failed: int = 5, window_seconds: int = 300, max_requests_per_minute: int = 20):
        self.max_failed = max_failed
        self.window_seconds = window_seconds
        self.max_requests_per_minute = max_requests_per_minute
        self.failed_attempts: Dict[str, List[float]] = {}
        self.request_timestamps: Dict[str, List[float]] = {}
        self.lock = threading.Lock()

    def get_client_ip(self, request: Request) -> str:
        # Verifica cabeçalhos de proxy reverso (Render, Cloudflare, Nginx)
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            # Primeiro IP na cadeia é o cliente real
            ip = x_forwarded_for.split(",")[0].strip()
            if ip:
                return ip
        x_real_ip = request.headers.get("x-real-ip")
        if x_real_ip:
            return x_real_ip.strip()
        if request.client and request.client.host:
            return request.client.host.strip()
        return "127.0.0.1"

    def is_ip_rate_limited(self, ip: str) -> Tuple[bool, int]:
        now = time.time()
        with self.lock:
            # 1. Verificar tentativas com falha (Força bruta de senhas)
            failed = self.failed_attempts.get(ip, [])
            # Limpar tentativas fora da janela deslizante
            valid_failed = [t for t in failed if now - t < self.window_seconds]
            self.failed_attempts[ip] = valid_failed

            if len(valid_failed) >= self.max_failed:
                oldest_in_window = valid_failed[0]
                retry_after = max(1, int(oldest_in_window + self.window_seconds - now))
                return True, retry_after

            # 2. Verificar rajada excessiva de requisições por minuto
            reqs = self.request_timestamps.get(ip, [])
            valid_reqs = [t for t in reqs if now - t < 60]
            self.request_timestamps[ip] = valid_reqs

            if len(valid_reqs) >= self.max_requests_per_minute:
                oldest_req = valid_reqs[0]
                retry_after = max(1, int(oldest_req + 60 - now))
                return True, retry_after

            # Registra requisição atual
            self.request_timestamps[ip].append(now)
            return False, 0

    def record_attempt(self, ip: str, success: bool):
        now = time.time()
        with self.lock:
            if success:
                # Login bem-sucedido zera o contador de falhas para o IP
                self.failed_attempts.pop(ip, None)
            else:
                if ip not in self.failed_attempts:
                    self.failed_attempts[ip] = []
                self.failed_attempts[ip].append(now)

    def reset(self, ip: Optional[str] = None):
        with self.lock:
            if ip:
                self.failed_attempts.pop(ip, None)
                self.request_timestamps.pop(ip, None)
            else:
                self.failed_attempts.clear()
                self.request_timestamps.clear()

login_rate_limiter = LoginRateLimiter()

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

def get_current_user(
    request: Request = None,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif request and request.cookies:
        token = request.cookies.get("access_token") or request.cookies.get("token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais de autenticação não fornecidas (Bearer token ou Cookie HttpOnly ausente).",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_access_token(token)
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


def check_compliance_access(user: dict) -> bool:
    """
    Retorna True se o usuário tiver permissão para gerenciar Estatutos, Selo EJ e Compliance:
    Presidência, Diretoria Executiva ou membros do Jurídico.
    """
    if not user:
        return False
    role = (user.get("role") or "").lower().strip()
    if role in {"presidente", "diretor", "vice_presidente"}:
        return True
    area = (user.get("area") or user.get("setor") or "").lower().strip()
    return "jurídico" in area or "juridico" in area or "presid" in area


def verify_compliance_access(current_user: dict = Depends(get_current_user)) -> dict:
    """
    Validação de Acesso a Estatutos e Compliance MEJ (RBAC).
    Restrito à Presidência, Diretoria Executiva e setor Jurídico.
    """
    if not current_user or not check_compliance_access(current_user):
        role = current_user.get("role", "desconhecido") if current_user else "anônimo"
        area = current_user.get("area", current_user.get("setor", "indefinida")) if current_user else "indefinida"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Acesso negado: Perfil '{role}' da área '{area}' não possui permissão para gerenciar o Módulo de Estatutos e Compliance MEJ. "
                f"Acesso restrito à Presidência, Diretoria Executiva e setor Jurídico."
            )
        )
    return current_user


def check_rm_staging_approval_access(user: dict) -> bool:
    """
    Retorna True se o usuário puder atuar como revisor/aprovador (Checker) em RM Staging:
    Exclusivo para Presidente ou Diretores Executivos.
    """
    if not user:
        return False
    role = (user.get("role") or "").lower().strip()
    return role in {"presidente", "diretor", "vice_presidente"}


def verify_rm_staging_approval_access(current_user: dict = Depends(get_current_user)) -> dict:
    """
    Validação de Permissão para Aprovação Maker-Checker no Staging de Marcas.
    """
    if not current_user or not check_rm_staging_approval_access(current_user):
        role = current_user.get("role", "desconhecido") if current_user else "anônimo"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Acesso negado: Perfil '{role}' não possui autoridade executiva para aprovar ou rejeitar alterações no Staging de RM. "
                f"Prerrogativa exclusiva de Diretores e Presidência."
            )
        )
    return current_user


