"""
EDV Jr. - Camada de Banco de Dados Local (SQLite - Custo Zero)
Armazena credenciais criptografadas, perfis de controle de acesso (RBAC),
transações financeiras e mural de avisos institucionais.
"""

import sqlite3
import os
import re
import unicodedata
import bcrypt
import math
import json
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict, Union, Tuple

DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")

VALID_ROLES = {"presidente", "diretor", "gerente", "assessor"}

from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey, DateTime, func, create_engine

Base = declarative_base()

class CampaignORM(Base):
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    name = Column(String(200), nullable=False)
    type = Column(String(50), nullable=False)  # captacao_projetos, processo_seletivo, branding_institucional
    channel = Column(String(50), nullable=False)  # instagram, linkedin, outbound, indicacao
    status = Column(String(50), nullable=False, default="ativa")  # planejamento, ativa, pausada, concluida
    budget = Column(Float, nullable=False, default=0.0)
    actual_cost = Column(Float, nullable=False, default=0.0)
    target_leads = Column(Integer, default=0)
    start_date = Column(String(50), nullable=True)
    end_date = Column(String(50), nullable=True)
    responsible = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class PselCandidateORM(Base):
    __tablename__ = "psel_candidates"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)
    name = Column(String(200), nullable=False)
    email = Column(String(150), nullable=False)
    phone = Column(String(50), nullable=True)
    course = Column(String(100), nullable=False, default="Direito")
    period = Column(String(50), nullable=True)
    stage = Column(String(50), nullable=False, default="inscricao")  # inscricao, dinamica, entrevista, onboarding, aprovado, reprovado, desistente
    target_area = Column(String(50), nullable=False, default="Comercial")
    score_dinamica = Column(Float, default=0.0)
    score_entrevista = Column(Float, default=0.0)
    notes = Column(Text, nullable=True)
    interviewer = Column(String(100), nullable=True)
    competency_focus = Column(String(100), default="Gestão")  # Liderança, Gestão, Autoconhecimento, Visão Sistêmica, Orientação para Resultados
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class BrandAssetORM(Base):
    __tablename__ = "brand_assets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    title = Column(String(200), nullable=False)
    category = Column(String(50), nullable=False)  # logo, manual_marca, proposta_comercial, apresentacao_institucional, papelaria, pitch_deck, outros
    file_format = Column(String(20), nullable=False)  # PNG, SVG, PDF, PPTX, DOCX, FIGMA
    version = Column(String(20), nullable=False, default="v1.0")
    file_url = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(String(200), nullable=True)
    is_official = Column(Integer, default=1)
    uploaded_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class PerformanceEvaluation360ORM(Base):
    __tablename__ = "performance_evaluations_360"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    cycle_id = Column(String(50), nullable=False, default="2026.1")
    evaluatee_email = Column(String(150), nullable=False)
    evaluator_email = Column(String(150), nullable=False)
    relationship_type = Column(String(50), nullable=False, default="peer")  # peer, leader, subordinate, self
    score_lideranca = Column(Float, nullable=False, default=3.0)
    score_gestao = Column(Float, nullable=False, default=3.0)
    score_visao_sistemica = Column(Float, nullable=False, default=3.0)
    score_orientacao_resultados = Column(Float, nullable=False, default=3.0)
    score_autoconhecimento = Column(Float, nullable=False, default=3.0)
    feedback_qualitativo = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="submitted")
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class EvaluatorCalibrationORM(Base):
    __tablename__ = "evaluator_calibrations"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    evaluator_email = Column(String(150), unique=True, nullable=False)
    assertiveness_weight = Column(Float, nullable=False, default=1.0)
    bias_tendency = Column(String(50), nullable=False, default="neutral")  # neutral, lenient, strict, halo_effect
    variance_metric = Column(Float, default=0.0)
    correlation_with_hard_data = Column(Float, default=0.85)
    total_evaluations_count = Column(Integer, default=0)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class HistoricalManagerBenchmarkORM(Base):
    __tablename__ = "historical_manager_benchmarks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    manager_name = Column(String(150), nullable=False)
    role_target = Column(String(50), nullable=False)  # diretoria, presidencia
    mandate_year = Column(String(50), nullable=False, default="2024-2025")
    lideranca_score = Column(Float, nullable=False, default=88.0)
    gestao_score = Column(Float, nullable=False, default=85.0)
    visao_sistemica_score = Column(Float, nullable=False, default=85.0)
    orientacao_resultados_score = Column(Float, nullable=False, default=87.0)
    autoconhecimento_score = Column(Float, nullable=False, default=82.0)
    conversion_rate = Column(Float, default=30.0)
    project_punctuality_rate = Column(Float, default=95.0)
    revenue_per_cycle = Column(Float, default=15000.0)
    assiduidade_rate = Column(Float, default=98.0)
    federation_audit_score = Column(Float, default=100.0)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class SuccessionReadinessORM(Base):
    __tablename__ = "succession_readiness_records"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    user_email = Column(String(150), nullable=False)
    role_target = Column(String(50), nullable=False, default="diretoria")  # diretoria, presidencia
    ips_score = Column(Float, nullable=False, default=0.0)
    hard_data_score = Column(Float, nullable=False, default=0.0)
    soft_data_score = Column(Float, nullable=False, default=0.0)
    similarity_to_benchmark = Column(Float, nullable=False, default=0.0)
    is_eligible = Column(Integer, nullable=False, default=0)
    cutoff_threshold = Column(Float, nullable=False, default=70.0)
    restriction_reason = Column(Text, nullable=True)
    details_json = Column(Text, nullable=True)
    calculated_at = Column(DateTime, server_default=func.now())

class GapMitigationActionORM(Base):
    __tablename__ = "gap_mitigation_actions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    user_email = Column(String(150), nullable=False)
    competency_deficient = Column(String(100), nullable=False)
    current_score = Column(Float, default=0.0)
    target_score = Column(Float, default=80.0)
    deficit_severity = Column(String(50), default="medio")  # baixo, medio, alto, critico
    action_type = Column(String(50), default="70_on_the_job")  # 70_on_the_job, 20_social_mentoria, 10_formal_estudo
    practical_allocation = Column(Text, nullable=False)
    mentor_assigned = Column(String(150), nullable=True)
    course_or_playbook = Column(Text, nullable=True)
    status = Column(String(50), default="sugerido")  # sugerido, em_execucao, concluido
    deadline = Column(String(50), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class StatuteComplianceORM(Base):
    __tablename__ = "statutes_compliance"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    title = Column(String(200), nullable=False)
    norm_type = Column(String(50), nullable=False)  # estatuto, regimento_interno, marco_regulatorio, selo_ej, codigo_etica
    version = Column(String(20), nullable=False, default="v1.0")
    status = Column(String(50), nullable=False, default="vigente")  # vigente, em_revisao, revogado, pendente_aprovacao
    effective_date = Column(String(50), nullable=False)
    review_deadline = Column(String(50), nullable=True)
    responsible_area = Column(String(50), nullable=False)
    responsible_role = Column(String(50), nullable=False, default="diretor")
    document_url = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    checklist_items = Column(Text, nullable=True)  # JSON
    conformity_score = Column(Float, default=100.0)
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class SystemNotificationORM(Base):
    __tablename__ = "system_notifications"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    recipient_email = Column(String(150), nullable=False)
    target_role = Column(String(50), nullable=True)
    target_area = Column(String(50), nullable=True)
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    category = Column(String(50), nullable=False)  # deadline_overdue, deadline_warning, pdi_milestone, audit_alert, approval_pending, compliance, system
    priority = Column(String(20), nullable=False, default="normal")  # low, normal, high, critical
    link = Column(String(255), nullable=True)
    is_read = Column(Integer, default=0)
    email_sent = Column(Integer, default=0)
    email_sent_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class RMStagingRecordORM(Base):
    __tablename__ = "rm_staging_records"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    batch_id = Column(String(100), nullable=True)
    rm_code = Column(String(50), nullable=True)
    brand_name = Column(String(200), nullable=False)
    process_number = Column(String(100), nullable=True)
    client_name = Column(String(200), nullable=False)
    client_phone = Column(String(50), nullable=True)
    responsible_name = Column(String(150), nullable=False)
    phase = Column(String(100), nullable=False)
    operation_type = Column(String(50), nullable=False, default="UPDATE")  # INSERT, UPDATE, DELETE, BATCH_IMPORT
    original_data_json = Column(Text, nullable=True)
    proposed_data_json = Column(Text, nullable=False)
    status = Column(String(50), nullable=False, default="pending_review")  # pending_review, approved, rejected
    submitted_by = Column(String(150), nullable=False)
    submitted_at = Column(DateTime, server_default=func.now())
    reviewed_by = Column(String(150), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_notes = Column(Text, nullable=True)
    applied_to_main_db = Column(Integer, default=0)
    applied_at = Column(DateTime, nullable=True)

class UserORM(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    nome = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    area = Column(String(100), nullable=False)
    role = Column(String(50), nullable=False)
    setor = Column(String(100), nullable=True)
    cargo = Column(String(100), nullable=True)
    created_at = Column(DateTime, server_default=func.now())


DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


MEMBROS_WHITELIST = [
    {
        "email": "charles.junior@edvjr.com.br",
        "nome": "Charles",
        "area": "Presidência",
        "role": "presidente",
        "setor": "Presidência",
        "cargo": "Presidente Institucional"
    },
    {
        "email": "alice.mizuki@edvjr.com.br",
        "nome": "Alice Mizuki",
        "area": "Projetos",
        "role": "assessor",
        "setor": "Projetos / RMs",
        "cargo": "Assessora de Projetos"
    },
    {
        "email": "alice.ney@edvjr.com.br",
        "nome": "Alice Ney",
        "area": "VPGG",
        "role": "diretor",
        "setor": "VPGG",
        "cargo": "Vice-Presidente de Gestão"
    },
    {
        "email": "alicia.athayde@edvjr.com.br",
        "nome": "Alicia",
        "area": "Marketing",
        "role": "assessor",
        "setor": "Marketing",
        "cargo": "Assessora de Conteúdo"
    },
    {
        "email": "aline.tartaglia@edvjr.com.br",
        "nome": "Aline",
        "area": "Jurídico",
        "role": "assessor",
        "setor": "Jurídico",
        "cargo": "Assessora de Contratos"
    },
    {
        "email": "amanda.bede@edvjr.com.br",
        "nome": "Amanda",
        "area": "Projetos",
        "role": "assessor",
        "setor": "Projetos / RMs",
        "cargo": "Assessora de Projetos"
    },
    {
        "email": "karolina.krause@edvjr.com.br",
        "nome": "Ana Karolina",
        "area": "Jurídico",
        "role": "assessor",
        "setor": "Jurídico",
        "cargo": "Assessora de Compliance"
    },
    {
        "email": "estevao.coutinho@edvjr.com.br",
        "nome": "Estevão",
        "area": "Comercial",
        "role": "assessor",
        "setor": "Comercial",
        "cargo": "Assessor de Vendas"
    },
    {
        "email": "evelyn.roldi@edvjr.com.br",
        "nome": "Evelyn",
        "area": "Marketing",
        "role": "diretor",
        "setor": "Marketing",
        "cargo": "Diretora de Marketing"
    },
    {
        "email": "gabriel.orienrac@edvjr.com.br",
        "nome": "Cachorrão (Gabriel)",
        "area": "Projetos",
        "role": "assessor",
        "setor": "Projetos / RMs",
        "cargo": "Assessor de Projetos"
    },
    {
        "email": "giulia.moulin@edvjr.com.br",
        "nome": "Giulia",
        "area": "VPGG",
        "role": "assessor",
        "setor": "VPGG",
        "cargo": "Assessora de Gente & Gestão"
    },
    {
        "email": "guilherme.borges@edvjr.com.br",
        "nome": "Guilherme Borges",
        "area": "Comercial",
        "role": "assessor",
        "setor": "Comercial",
        "cargo": "Assessor de Vendas"
    },
    {
        "email": "isadora.epichin@edvjr.com.br",
        "nome": "Isadora",
        "area": "Comercial",
        "role": "diretor",
        "setor": "Comercial / Vendas",
        "cargo": "Diretora Comercial"
    },
    {
        "email": "joaop.lecco@edvjr.com.br",
        "nome": "Chillibão (João P.)",
        "area": "Marketing",
        "role": "assessor",
        "setor": "Marketing",
        "cargo": "Assessor de Criação"
    },
    {
        "email": "marialice.bacelar@edvjr.com.br",
        "nome": "Maria Alice",
        "area": "Comercial",
        "role": "assessor",
        "setor": "Comercial",
        "cargo": "Assessora de Negociação"
    },
    {
        "email": "mariaeduarda.dias@edvjr.com.br",
        "nome": "Maria Eduarda",
        "area": "VPGG",
        "role": "assessor",
        "setor": "VPGG",
        "cargo": "Assessora de Gente & Gestão"
    },
    {
        "email": "maria.teixeira@edvjr.com.br",
        "nome": "Maria Luyza",
        "area": "Jurídico",
        "role": "assessor",
        "setor": "Jurídico",
        "cargo": "Assessora de Governança"
    },
    {
        "email": "marina.moretto@edvjr.com.br",
        "nome": "Marina",
        "area": "Tesouraria",
        "role": "diretor",
        "setor": "Tesouraria / CJA",
        "cargo": "Diretora Financeira"
    },
    {
        "email": "marllon.oliveira@edvjr.com.br",
        "nome": "Marllon",
        "area": "Projetos",
        "role": "assessor",
        "setor": "Projetos / RMs",
        "cargo": "Assessor de Projetos"
    },
    {
        "email": "pedro.barros@edvjr.com.br",
        "nome": "Pedro Barros",
        "area": "Comercial",
        "role": "assessor",
        "setor": "Comercial",
        "cargo": "Assessor de Inbound"
    },
    {
        "email": "renato.moura@edvjr.com.br",
        "nome": "Renato",
        "area": "Projetos",
        "role": "assessor",
        "setor": "Projetos / RMs",
        "cargo": "Assessor de Projetos"
    },
    {
        "email": "samuel.garcia@edvjr.com.br",
        "nome": "Samuel",
        "area": "Comercial",
        "role": "assessor",
        "setor": "Comercial / Radar",
        "cargo": "Assessor de Prospecção"
    },
    {
        "email": "thais.junger@edvjr.com.br",
        "nome": "Thais",
        "area": "Projetos",
        "role": "gerente",
        "setor": "Projetos / RMs",
        "cargo": "Gerente de Registro de Marca"
    }
]

DEFAULT_PASSWORD = "edv2026!"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Tabela de usuários com colunas 'area' e 'role' estritas
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL,
        hashed_password TEXT NOT NULL,
        area TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('presidente', 'diretor', 'gerente', 'assessor')),
        setor TEXT,
        cargo TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # Migração segura para bases existentes
    cursor.execute("PRAGMA table_info(users);")
    columns = [col[1] for col in cursor.fetchall()]
    if "area" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN area TEXT;")
    
    # 2. Tabela de transações financeiras (Atualização Indireta e Blindagem)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        area TEXT NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('receita', 'despesa')),
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        created_by TEXT NOT NULL,
        date TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 3. Tabela de avisos e comunicados institucionais (Mural de Avisos)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_area TEXT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        author TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Tabela de Planos de Desenvolvimento Individual (PDI - VPGG com Modelo de Competências Brasil Júnior)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pdis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        area TEXT NOT NULL DEFAULT 'VPGG',
        competency_mej TEXT DEFAULT 'Gestão',
        objectives TEXT NOT NULL,
        development_ideas TEXT NOT NULL,
        deadline TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'em_andamento',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("PRAGMA table_info(pdis);")
    existing_pdi_cols = [col[1] for col in cursor.fetchall()]
    new_pdi_cols = {
        "competency_mej": "TEXT DEFAULT 'Gestão'",
        "action_plan_70_20_10": "TEXT",
        "triangulated_score": "REAL DEFAULT 0.0",
        "ips_score": "REAL DEFAULT 0.0"
    }
    for pdi_col, pdi_def in new_pdi_cols.items():
        if pdi_col not in existing_pdi_cols:
            cursor.execute(f"ALTER TABLE pdis ADD COLUMN {pdi_col} {pdi_def};")

    # 5. Tabela de Follow-up de Clientes e CRM Comercial (Com Atributos Corporativos, Razão Social, Fantasia e Impacto MEJ)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS client_followups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_name TEXT NOT NULL,
        razao_social TEXT,
        nome_fantasia TEXT,
        normalized_name TEXT,
        contact_person TEXT,
        status TEXT NOT NULL DEFAULT 'prospeccao' CHECK(status IN ('prospeccao', 'negociacao', 'fechado', 'perdido')),
        interaction_type TEXT,
        notes TEXT,
        next_followup_date TEXT,
        area TEXT NOT NULL DEFAULT 'Comercial',
        cnpj TEXT,
        cnae TEXT,
        company_size TEXT,
        address TEXT,
        score INTEGER DEFAULT 50,
        estimated_value REAL DEFAULT 0.0,
        tags TEXT,
        impact_score INTEGER DEFAULT 0,
        impact_type TEXT,
        impact_description TEXT,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Migração segura de colunas corporativas e de impacto para bases existentes
    cursor.execute("PRAGMA table_info(client_followups);")
    existing_followup_cols = [col[1] for col in cursor.fetchall()]
    new_followup_cols = {
        "cnpj": "TEXT",
        "cnae": "TEXT",
        "company_size": "TEXT",
        "address": "TEXT",
        "score": "INTEGER DEFAULT 50",
        "estimated_value": "REAL DEFAULT 0.0",
        "tags": "TEXT",
        "razao_social": "TEXT",
        "nome_fantasia": "TEXT",
        "normalized_name": "TEXT",
        "impact_score": "INTEGER DEFAULT 0",
        "impact_type": "TEXT",
        "impact_description": "TEXT",
        "campaign_id": "INTEGER",
        "tenant_id": "TEXT DEFAULT 'edv_jr'"
    }
    for col_name, col_def in new_followup_cols.items():
        if col_name not in existing_followup_cols:
            cursor.execute(f"ALTER TABLE client_followups ADD COLUMN {col_name} {col_def};")

    # 6. Tabela de Trilha de Auditoria Imutável (Audit Logs Forense)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_email);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")

    # 7. Tabela de Campanhas de Marketing e Atribuição de ROI (Multi-tenant e MEJ)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS campaigns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        name TEXT NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('captacao_projetos', 'processo_seletivo', 'branding_institucional')),
        channel TEXT NOT NULL CHECK(channel IN ('instagram', 'linkedin', 'outbound', 'indicacao')),
        status TEXT NOT NULL DEFAULT 'ativa' CHECK(status IN ('planejamento', 'ativa', 'pausada', 'concluida')),
        budget REAL NOT NULL DEFAULT 0.0,
        actual_cost REAL NOT NULL DEFAULT 0.0,
        target_leads INTEGER DEFAULT 0,
        start_date TEXT,
        end_date TEXT,
        responsible TEXT NOT NULL,
        description TEXT,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON campaigns(tenant_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_type_channel ON campaigns(type, channel);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);")

    # 8. Tabela de Candidatos do Funil do Processo Seletivo (PSEL - MEJ e Integração Brasil Júnior)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS psel_candidates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        campaign_id INTEGER,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        course TEXT NOT NULL DEFAULT 'Direito',
        period TEXT,
        stage TEXT NOT NULL DEFAULT 'inscricao' CHECK(stage IN ('inscricao', 'dinamica', 'entrevista', 'onboarding', 'aprovado', 'reprovado', 'desistente')),
        target_area TEXT NOT NULL DEFAULT 'Comercial',
        score_dinamica REAL DEFAULT 0.0,
        score_entrevista REAL DEFAULT 0.0,
        notes TEXT,
        interviewer TEXT,
        competency_focus TEXT DEFAULT 'Gestão' CHECK(competency_focus IN ('Liderança', 'Gestão', 'Autoconhecimento', 'Visão Sistêmica', 'Orientação para Resultados')),
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_psel_tenant_stage ON psel_candidates(tenant_id, stage);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_psel_campaign ON psel_candidates(campaign_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_psel_area ON psel_candidates(target_area);")

    # 9. Tabela de Repositório de Ativos de Marca (Brand Kit - Versionado e Oficial)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS brand_assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        title TEXT NOT NULL,
        category TEXT NOT NULL CHECK(category IN ('logo', 'manual_marca', 'proposta_comercial', 'apresentacao_institucional', 'papelaria', 'pitch_deck', 'outros')),
        file_format TEXT NOT NULL,
        version TEXT NOT NULL DEFAULT 'v1.0',
        file_url TEXT NOT NULL,
        description TEXT,
        tags TEXT,
        is_official INTEGER DEFAULT 1,
        uploaded_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_brand_tenant_cat ON brand_assets(tenant_id, category);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_brand_official ON brand_assets(is_official);")

    # 10. Tabela de Avaliações 360º (Soft Data / Modelo Oficial Brasil Júnior)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS performance_evaluations_360 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        cycle_id TEXT NOT NULL DEFAULT '2026.1',
        evaluatee_email TEXT NOT NULL,
        evaluator_email TEXT NOT NULL,
        relationship_type TEXT NOT NULL CHECK(relationship_type IN ('peer', 'leader', 'subordinate', 'self')),
        score_lideranca REAL NOT NULL DEFAULT 3.0,
        score_gestao REAL NOT NULL DEFAULT 3.0,
        score_visao_sistemica REAL NOT NULL DEFAULT 3.0,
        score_orientacao_resultados REAL NOT NULL DEFAULT 3.0,
        score_autoconhecimento REAL NOT NULL DEFAULT 3.0,
        feedback_qualitativo TEXT,
        status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted', 'draft')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_eval360_evaluatee ON performance_evaluations_360(evaluatee_email, cycle_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_eval360_evaluator ON performance_evaluations_360(evaluator_email);")

    # 11. Tabela de Calibração de Avaliadores (Assertiveness Weighting & Viés)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evaluator_calibrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        evaluator_email TEXT UNIQUE NOT NULL,
        assertiveness_weight REAL NOT NULL DEFAULT 1.0,
        bias_tendency TEXT NOT NULL DEFAULT 'neutral',
        variance_metric REAL DEFAULT 0.0,
        correlation_with_hard_data REAL DEFAULT 0.85,
        total_evaluations_count INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_eval_calib_email ON evaluator_calibrations(evaluator_email);")

    # 12. Tabela de Perfis de Benchmark de Gestores Históricos (Federação / Selo EJ)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS historical_manager_benchmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        manager_name TEXT NOT NULL,
        role_target TEXT NOT NULL CHECK(role_target IN ('diretoria', 'presidencia')),
        mandate_year TEXT NOT NULL DEFAULT '2024-2025',
        lideranca_score REAL NOT NULL DEFAULT 88.0,
        gestao_score REAL NOT NULL DEFAULT 85.0,
        visao_sistemica_score REAL NOT NULL DEFAULT 85.0,
        orientacao_resultados_score REAL NOT NULL DEFAULT 87.0,
        autoconhecimento_score REAL NOT NULL DEFAULT 82.0,
        conversion_rate REAL DEFAULT 30.0,
        project_punctuality_rate REAL DEFAULT 95.0,
        revenue_per_cycle REAL DEFAULT 15000.0,
        assiduidade_rate REAL DEFAULT 98.0,
        federation_audit_score REAL DEFAULT 100.0,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_benchmarks_role ON historical_manager_benchmarks(role_target);")

    # 13. Tabela de Índice de Prontidão Preditiva para Sucessão (IPS)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS succession_readiness_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        user_email TEXT NOT NULL,
        role_target TEXT NOT NULL DEFAULT 'diretoria' CHECK(role_target IN ('diretoria', 'presidencia')),
        ips_score REAL NOT NULL DEFAULT 0.0,
        hard_data_score REAL NOT NULL DEFAULT 0.0,
        soft_data_score REAL NOT NULL DEFAULT 0.0,
        similarity_to_benchmark REAL NOT NULL DEFAULT 0.0,
        is_eligible INTEGER NOT NULL DEFAULT 0,
        cutoff_threshold REAL NOT NULL DEFAULT 70.0,
        restriction_reason TEXT,
        details_json TEXT,
        calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_succession_email ON succession_readiness_records(user_email, role_target);")

    # 14. Tabela de Ações de Mitigação Automatizada de Gaps (Runtime 70-20-10)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS gap_mitigation_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        user_email TEXT NOT NULL,
        competency_deficient TEXT NOT NULL,
        current_score REAL DEFAULT 0.0,
        target_score REAL DEFAULT 80.0,
        deficit_severity TEXT DEFAULT 'medio' CHECK(deficit_severity IN ('baixo', 'medio', 'alto', 'critico')),
        action_type TEXT DEFAULT '70_on_the_job' CHECK(action_type IN ('70_on_the_job', '20_social_mentoria', '10_formal_estudo')),
        practical_allocation TEXT NOT NULL,
        mentor_assigned TEXT,
        course_or_playbook TEXT,
        status TEXT DEFAULT 'sugerido' CHECK(status IN ('sugerido', 'em_execucao', 'concluido')),
        deadline TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_gap_actions_user ON gap_mitigation_actions(user_email);")

    # 15. Tabela de Estatutos e Compliance MEJ (Lei 13.267/2016 e Selo EJ)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS statutes_compliance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        title TEXT NOT NULL,
        norm_type TEXT NOT NULL CHECK(norm_type IN ('estatuto', 'regimento_interno', 'marco_regulatorio', 'selo_ej', 'codigo_etica')),
        version TEXT NOT NULL DEFAULT 'v1.0',
        status TEXT NOT NULL DEFAULT 'vigente' CHECK(status IN ('vigente', 'em_revisao', 'revogado', 'pendente_aprovacao')),
        effective_date TEXT NOT NULL,
        review_deadline TEXT,
        responsible_area TEXT NOT NULL CHECK(responsible_area IN ('Presidência', 'VPGG', 'Jurídico', 'Comercial', 'Projetos', 'Tesouraria', 'Marketing')),
        responsible_role TEXT NOT NULL DEFAULT 'diretor',
        document_url TEXT,
        description TEXT,
        checklist_items TEXT,
        conformity_score REAL DEFAULT 100.0,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_statutes_type ON statutes_compliance(norm_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_statutes_status ON statutes_compliance(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_statutes_area ON statutes_compliance(responsible_area);")

    # 16. Tabela de Notificações Dinâmicas (E-mail + Alertas In-Site com RBAC)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        recipient_email TEXT NOT NULL,
        target_role TEXT,
        target_area TEXT,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        category TEXT NOT NULL CHECK(category IN ('deadline_overdue', 'deadline_warning', 'pdi_milestone', 'audit_alert', 'approval_pending', 'compliance', 'system')),
        priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low', 'normal', 'high', 'critical')),
        link TEXT,
        is_read INTEGER DEFAULT 0,
        email_sent INTEGER DEFAULT 0,
        email_sent_at TIMESTAMP,
        metadata_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON system_notifications(recipient_email);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_unread ON system_notifications(is_read);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_role_area ON system_notifications(target_role, target_area);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_created ON system_notifications(created_at);")

    # 17. Tabela de Área de Staging de RMs (Edição Indireta e Dupla Verificação Maker-Checker)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rm_staging_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        batch_id TEXT,
        rm_code TEXT,
        brand_name TEXT NOT NULL,
        process_number TEXT,
        client_name TEXT NOT NULL,
        client_phone TEXT,
        responsible_name TEXT NOT NULL,
        phase TEXT NOT NULL,
        operation_type TEXT NOT NULL CHECK(operation_type IN ('INSERT', 'UPDATE', 'DELETE', 'BATCH_IMPORT')),
        original_data_json TEXT,
        proposed_data_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending_review' CHECK(status IN ('pending_review', 'approved', 'rejected')),
        submitted_by TEXT NOT NULL,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_by TEXT,
        reviewed_at TIMESTAMP,
        review_notes TEXT,
        applied_to_main_db INTEGER DEFAULT 0,
        applied_at TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rm_staging_status ON rm_staging_records(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rm_staging_maker ON rm_staging_records(submitted_by);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rm_staging_code ON rm_staging_records(rm_code);")

    # Índices de alta performance para Radar e CRM
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_followups_area_status ON client_followups(area, status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_followups_cnpj ON client_followups(cnpj);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_followups_score ON client_followups(score);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_followups_next_date ON client_followups(next_followup_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_followups_created_at ON client_followups(created_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_followups_norm_name ON client_followups(normalized_name);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_followups_razao ON client_followups(razao_social);")

    # Atualizar normalized_name para registros que ainda não possuem (executado antes dos triggers)
    try:
        try:
            from utils import normalize_company_name
        except ImportError:
            from backend.utils import normalize_company_name

        cursor.execute("SELECT id, client_name, razao_social, nome_fantasia FROM client_followups WHERE normalized_name IS NULL OR normalized_name = '';")
        unnorm_rows = cursor.fetchall()
        for r in unnorm_rows:
            target_str = r["nome_fantasia"] or r["razao_social"] or r["client_name"] or ""
            norm = normalize_company_name(target_str)
            cursor.execute("UPDATE client_followups SET normalized_name = ? WHERE id = ?;", (norm, r["id"]))
    except Exception as norm_err:
        print(f"[SQLite] Normalização inicial de registros: {norm_err}")

    # Tabela Virtual FTS5 Otimizada para buscas textuais avançadas e compostas
    try:
        # Verificar se client_followups_fts já existe com as novas colunas razao_social e nome_fantasia
        cursor.execute("PRAGMA table_info(client_followups_fts);")
        fts_cols = [col[1] for col in cursor.fetchall()]
        if fts_cols and ("razao_social" not in fts_cols or "nome_fantasia" not in fts_cols):
            cursor.execute("DROP TRIGGER IF EXISTS client_followups_ai;")
            cursor.execute("DROP TRIGGER IF EXISTS client_followups_ad;")
            cursor.execute("DROP TRIGGER IF EXISTS client_followups_au;")
            cursor.execute("DROP TABLE IF EXISTS client_followups_fts;")

        cursor.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS client_followups_fts USING fts5(
            client_name,
            razao_social,
            nome_fantasia,
            contact_person,
            notes,
            cnpj,
            cnae,
            tags,
            content='client_followups',
            content_rowid='id',
            tokenize='unicode61 remove_diacritics 2'
        );
        """)

        # Reconstrução integral do índice FTS5 a partir do conteúdo atual
        cursor.execute("INSERT INTO client_followups_fts(client_followups_fts) VALUES('rebuild');")

        # Triggers de sincronização contínua FTS5
        cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS client_followups_ai AFTER INSERT ON client_followups BEGIN
          INSERT INTO client_followups_fts(rowid, client_name, razao_social, nome_fantasia, contact_person, notes, cnpj, cnae, tags)
          VALUES (new.id, new.client_name, new.razao_social, new.nome_fantasia, new.contact_person, new.notes, new.cnpj, new.cnae, new.tags);
        END;
        """)

        cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS client_followups_ad AFTER DELETE ON client_followups BEGIN
          INSERT INTO client_followups_fts(client_followups_fts, rowid, client_name, razao_social, nome_fantasia, contact_person, notes, cnpj, cnae, tags)
          VALUES ('delete', old.id, old.client_name, old.razao_social, old.nome_fantasia, old.contact_person, old.notes, old.cnpj, old.cnae, old.tags);
        END;
        """)

        cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS client_followups_au AFTER UPDATE ON client_followups BEGIN
          INSERT INTO client_followups_fts(client_followups_fts, rowid, client_name, razao_social, nome_fantasia, contact_person, notes, cnpj, cnae, tags)
          VALUES ('delete', old.id, old.client_name, old.razao_social, old.nome_fantasia, old.contact_person, old.notes, old.cnpj, old.cnae, old.tags);
          INSERT INTO client_followups_fts(rowid, client_name, razao_social, nome_fantasia, contact_person, notes, cnpj, cnae, tags)
          VALUES (new.id, new.client_name, new.razao_social, new.nome_fantasia, new.contact_person, new.notes, new.cnpj, new.cnae, new.tags);
        END;
        """)

    except Exception as fts_err:
        print(f"[SQLite FTS5] Aviso na configuração FTS5 (contingência LIKE ativa): {fts_err}")

    conn.commit()

    # Sincronização da Whitelist oficial com roles estritos e áreas correspondentes
    default_hash = bcrypt.hashpw(DEFAULT_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    for m in MEMBROS_WHITELIST:
        cursor.execute("SELECT id FROM users WHERE email = ?;", (m["email"],))
        row = cursor.fetchone()
        if row:
            cursor.execute("""
            UPDATE users 
            SET nome = ?, area = ?, role = ?, setor = ?, cargo = ?
            WHERE email = ?;
            """, (m["nome"], m["area"], m["role"], m["setor"], m["cargo"], m["email"]))
        else:
            cursor.execute("""
            INSERT INTO users (email, nome, hashed_password, area, role, setor, cargo)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (m["email"], m["nome"], default_hash, m["area"], m["role"], m["setor"], m["cargo"]))

    # Seeding inicial de Campanhas Oficiais (MEJ & EDV Jr.)
    cursor.execute("SELECT COUNT(*) FROM campaigns;")
    if cursor.fetchone()[0] == 0:
        initial_campaigns = [
            ("edv_jr", "Maré de Vendas 2026 - RMs & Startups", "captacao_projetos", "instagram", "ativa", 1500.0, 650.0, 150, "2026-02-01", "2026-05-30", "Evelyn Roldi", "Campanha institucional e de tráfego pago no Instagram/Meta para captação de clientes para Registro de Marcas e adequação de microempresas.", "evelyn.roldi@edvjr.com.br"),
            ("edv_jr", "PSEL 2026.1 - Novos Talentos EDV Jr.", "processo_seletivo", "instagram", "ativa", 500.0, 280.0, 60, "2026-02-15", "2026-03-30", "Alice Ney & Evelyn", "Divulgação do edital de novos membros da FDV, atração de graduandos e condução das fases de dinâmica e entrevistas.", "alice.ney@edvjr.com.br"),
            ("edv_jr", "Branding Institucional - 10 Anos EDV Jr.", "branding_institucional", "linkedin", "ativa", 1200.0, 400.0, 30, "2026-01-10", "2026-12-15", "Chillibão (João P.)", "Ações de autoridade técnica, artigos científicos, cases de sucesso e posicionamento institucional no LinkedIn e ecossistema capixaba.", "joaop.lecco@edvjr.com.br"),
            ("edv_jr", "Outbound Ativo - Indústria & Comércio Capixaba", "captacao_projetos", "outbound", "ativa", 300.0, 150.0, 80, "2026-03-01", "2026-06-30", "Isadora & Estevão", "Prospecção ativa no Radar Comercial via WhatsApp e cold calling com diagnósticos prévios gratuitos de marcas no INPI.", "isadora.epichin@edvjr.com.br")
        ]
        cursor.executemany("""
        INSERT INTO campaigns (tenant_id, name, type, channel, status, budget, actual_cost, target_leads, start_date, end_date, responsible, description, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, initial_campaigns)

    # Seeding inicial de Candidatos do PSEL (Extraídos das planilhas reais da Gestão 2026)
    cursor.execute("SELECT COUNT(*) FROM psel_candidates;")
    if cursor.fetchone()[0] == 0:
        initial_candidates = [
            ("edv_jr", 2, "Victor Marrochi de Souza", "victormarrochi04@gmail.com", "(27) 99812-3451", "Direito", "2º Período", "onboarding", "Comercial", 8.8, 9.2, "Excelente oratória, facilidade em quebrar objeções comerciais e perfil consultivo.", "Laura", "Orientação para Resultados", "alice.ney@edvjr.com.br"),
            ("edv_jr", 2, "Alice Zambon Mizuki", "alice.zambon.mizuki@gmail.com", "(27) 99745-1234", "Direito", "3º Período", "aprovado", "Projetos", 9.5, 9.7, "Alta aptidão com normas da LPI (Lei 9.279/96) e busca de anterioridade no INPI.", "Laura", "Visão Sistêmica", "alice.ney@edvjr.com.br"),
            ("edv_jr", 2, "Victória Bourguignon Machado", "victoriabourguignon006@gmail.com", "(27) 99654-7890", "Direito", "1º Período", "entrevista", "Marketing", 8.5, 8.0, "Experiência prévia com mídias sociais, redação persuasiva e senso estético.", "Laura", "Liderança", "evelyn.roldi@edvjr.com.br"),
            ("edv_jr", 2, "Theo Sidor Pinaud Rodrigues", "theosidorbr@gmail.com", "(27) 99512-8877", "Direito", "2º Período", "dinamica", "Jurídico", 8.2, 0.0, "Boa postura crítica na dinâmica em grupo e resolução de caso de contratos.", "Pedro", "Gestão", "aline.tartaglia@edvjr.com.br"),
            ("edv_jr", 2, "Sarah Oliveira Ranauro Silva", "saraholiver.ranauro@gmail.com", "(27) 99881-2233", "Direito", "3º Período", "entrevista", "VPGG", 9.0, 8.9, "Excelente escuta ativa, empatia e motivação com clima e retenção MEJ.", "Esther", "Autoconhecimento", "giulia.moulin@edvjr.com.br"),
            ("edv_jr", 2, "Davi Alves de Vargas", "vargasdv690@gmail.com", "(27) 99773-4411", "Direito", "1º Período", "inscricao", "Comercial", 0.0, 0.0, "Ficha cadastral homologada no edital 2026, aguardando convocação de dinâmica.", "Pedro", "Orientação para Resultados", "isadora.epichin@edvjr.com.br")
        ]
        cursor.executemany("""
        INSERT INTO psel_candidates (tenant_id, campaign_id, name, email, phone, course, period, stage, target_area, score_dinamica, score_entrevista, notes, interviewer, competency_focus, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, initial_candidates)

    # Seeding inicial do Repositório de Ativos de Marca (Brand Kit Oficial)
    cursor.execute("SELECT COUNT(*) FROM brand_assets;")
    if cursor.fetchone()[0] == 0:
        initial_assets = [
            ("edv_jr", "Manual de Identidade Visual Oficial (MIV 2026)", "manual_marca", "PDF", "v2.1", "https://drive.google.com/drive/folders/gestao2026_miv", "Diretrizes oficiais de cores (#0B1D3A, #2563EB, #60A5FA), tipografia Inter/Montserrat e aplicação de logos.", "miv, manual, cores, tipografia, oficial", 1, "evelyn.roldi@edvjr.com.br"),
            ("edv_jr", "Pitch Comercial - Registro de Marcas no INPI", "pitch_deck", "PPTX", "v3.0", "https://drive.google.com/drive/folders/pitch_rm_inpi_2026", "Apresentação padrão para reuniões de diagnóstico e fechamento com leads e empresários.", "comercial, pitch, rm, inpi, vendas", 1, "isadora.epichin@edvjr.com.br"),
            ("edv_jr", "Template Oficial de Proposta Comercial e Contrato MEJ", "proposta_comercial", "DOCX", "v2.4", "https://drive.google.com/drive/folders/template_proposta_2026", "Modelo chancelado pelo Jurídico para emissão ágil de propostas e minutas contratuais.", "proposta, contrato, juridico, minuta", 1, "charles.junior@edvjr.com.br"),
            ("edv_jr", "Pacote de Logotipos Oficiais EDV Jr. (SVG / PNG Alta Resolução)", "logo", "SVG", "v2.0", "https://drive.google.com/drive/folders/logos_edv_vetor", "Versões primária (azul/marinho), secundária (branca para fundos escuros) e ícone isolado.", "logo, vetor, svg, png, identidade", 1, "joaop.lecco@edvjr.com.br"),
            ("edv_jr", "Apresentação Institucional EDV Jr. 2026 (10 Anos de Excelência)", "apresentacao_institucional", "PDF", "v1.5", "https://drive.google.com/drive/folders/institucional_edv_2026", "Deck corporativo para clientes de grande porte, eventos e parceiros estratégicos (Aderes/Findes).", "institucional, apresentacao, parceiros", 1, "charles.junior@edvjr.com.br"),
            ("edv_jr", "Papelaria Corporativa e Papel Timbrado Oficial", "papelaria", "DOCX", "v1.2", "https://drive.google.com/drive/folders/papel_timbrado_edv", "Template timbrado com selos de conformidade, CNPJ e rodapé institucional padronizado.", "papelaria, timbrado, oficio, ata", 1, "alicia.athayde@edvjr.com.br"),
            ("edv_jr", "Dossiê de Diagnóstico Preventivo INPI (Template de Entrega)", "proposta_comercial", "PDF", "v2.0", "https://drive.google.com/drive/folders/dossie_diagnostico_rm", "Documento técnico entregue ao lead com a busca de anterioridade preliminar e score de risco.", "diagnostico, inpi, dossie, entrega", 1, "thais.junger@edvjr.com.br")
        ]
        cursor.executemany("""
        INSERT INTO brand_assets (tenant_id, title, category, file_format, version, file_url, description, tags, is_official, uploaded_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, initial_assets)

    # Vincular leads do CRM às campanhas para cálculo imediato de ROI
    try:
        cursor.execute("SELECT COUNT(*) FROM client_followups WHERE campaign_id IS NOT NULL;")
        linked_count = cursor.fetchone()[0]
        if linked_count == 0:
            cursor.execute("UPDATE client_followups SET campaign_id = 1 WHERE id IN (SELECT id FROM client_followups LIMIT 12);")
            cursor.execute("UPDATE client_followups SET campaign_id = 4 WHERE id IN (SELECT id FROM client_followups LIMIT 6 OFFSET 12);")
    except Exception as e_link:
        print(f"[SQLite] Aviso ao vincular leads iniciais a campanhas: {e_link}")

    # Seeding inicial de Benchmarks de Gestores Históricos (Federação / Selo EJ)
    cursor.execute("SELECT COUNT(*) FROM historical_manager_benchmarks;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO historical_manager_benchmarks (
            tenant_id, manager_name, role_target, mandate_year,
            lideranca_score, gestao_score, visao_sistemica_score, orientacao_resultados_score, autoconhecimento_score,
            conversion_rate, project_punctuality_rate, revenue_per_cycle, assiduidade_rate, federation_audit_score, notes
        ) VALUES 
        ('edv_jr', 'Gestão 2024-2025 - Perfil Referência Diretoria Executiva', 'diretoria', '2024-2025',
         85.0, 85.0, 80.0, 85.0, 80.0, 25.0, 95.0, 12000.0, 96.0, 100.0, 'Média consolidada dos Diretores que alcançaram Alto Impacto e Selo EJ Pleno na Federação.'),
        ('edv_jr', 'Gestão 2024-2025 - Perfil Referência Presidência Institucional', 'presidencia', '2024-2025',
         92.0, 88.0, 90.0, 88.0, 85.0, 28.0, 98.0, 15000.0, 98.0, 100.0, 'Média consolidada de Presidentes com 100% de conformidade federativa na Brasil Júnior.');
        """)

    # Seeding inicial de Calibração de Avaliadores (Assertiveness Weights)
    cursor.execute("SELECT COUNT(*) FROM evaluator_calibrations;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO evaluator_calibrations (tenant_id, evaluator_email, assertiveness_weight, bias_tendency, variance_metric, correlation_with_hard_data, total_evaluations_count)
        VALUES 
        ('edv_jr', 'charles.junior@edvjr.com.br', 1.25, 'neutral', 0.85, 0.94, 22),
        ('edv_jr', 'alice.ney@edvjr.com.br', 1.20, 'neutral', 0.80, 0.91, 20),
        ('edv_jr', 'isadora.epichin@edvjr.com.br', 1.15, 'strict', 0.90, 0.89, 15),
        ('edv_jr', 'thais.junger@edvjr.com.br', 1.10, 'neutral', 0.75, 0.86, 14),
        ('edv_jr', 'evelyn.roldi@edvjr.com.br', 1.05, 'neutral', 0.78, 0.83, 12);
        """)

    # Seeding inicial de Avaliações 360º (Soft Data Oficial Brasil Júnior)
    cursor.execute("SELECT COUNT(*) FROM performance_evaluations_360;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO performance_evaluations_360 (
            tenant_id, cycle_id, evaluatee_email, evaluator_email, relationship_type,
            score_lideranca, score_gestao, score_visao_sistemica, score_orientacao_resultados, score_autoconhecimento,
            feedback_qualitativo
        ) VALUES 
        -- Samuel (Comercial)
        ('edv_jr', '2026.1', 'samuel.garcia@edvjr.com.br', 'isadora.epichin@edvjr.com.br', 'leader', 3.8, 3.7, 3.9, 3.5, 4.0, 'Excelente postura de prospecção e engajamento cultural; necessita calibrar fechamento e contorno de objeções em reuniões finais.'),
        ('edv_jr', '2026.1', 'samuel.garcia@edvjr.com.br', 'estevao.coutinho@edvjr.com.br', 'peer', 4.0, 3.5, 3.8, 3.6, 4.1, 'Muito prestativo e com energia contagiante na área de vendas.'),
        ('edv_jr', '2026.1', 'samuel.garcia@edvjr.com.br', 'samuel.garcia@edvjr.com.br', 'self', 4.0, 3.8, 4.0, 3.5, 4.2, 'Autoavaliação: Quero me aprofundar em negociação estratégica e conversão direta.'),
        
        -- Estevão (Comercial)
        ('edv_jr', '2026.1', 'estevao.coutinho@edvjr.com.br', 'isadora.epichin@edvjr.com.br', 'leader', 4.2, 3.4, 3.7, 4.3, 3.8, 'Fechou contrato importante com agilidade comercial, mas requer disciplina no preenchimento do CRM.'),
        ('edv_jr', '2026.1', 'estevao.coutinho@edvjr.com.br', 'samuel.garcia@edvjr.com.br', 'peer', 4.1, 3.6, 3.8, 4.2, 3.9, 'Excelente negociador e confiável nas conversas com clientes.'),
        
        -- Alice Mizuki (Projetos)
        ('edv_jr', '2026.1', 'alice.mizuki@edvjr.com.br', 'thais.junger@edvjr.com.br', 'leader', 4.1, 4.6, 4.5, 4.2, 4.4, 'Domínio exímio de marcas e legislação do INPI. Pronta para assumir liderança de equipe técnica.'),
        ('edv_jr', '2026.1', 'alice.mizuki@edvjr.com.br', 'amanda.bede@edvjr.com.br', 'peer', 4.0, 4.5, 4.3, 4.0, 4.5, 'Referência técnica de dúvidas em despachos.'),
        
        -- Pedro Barros (Comercial)
        ('edv_jr', '2026.1', 'pedro.barros@edvjr.com.br', 'isadora.epichin@edvjr.com.br', 'leader', 3.2, 3.6, 3.4, 3.3, 3.8, 'Boa dedicação ao inbound; precisa expandir iniciativa e assumir projetos de ponta a ponta.'),
        ('edv_jr', '2026.1', 'pedro.barros@edvjr.com.br', 'estevao.coutinho@edvjr.com.br', 'peer', 3.5, 3.7, 3.5, 3.4, 3.7, 'Colega colaborativo e pontual nas entregas rotineiras.'),

        -- Renato Moura (Projetos)
        ('edv_jr', '2026.1', 'renato.moura@edvjr.com.br', 'thais.junger@edvjr.com.br', 'leader', 3.6, 4.0, 3.8, 3.7, 4.0, 'Excelente pontualidade nas buscas de anterioridade e atenção a detalhes regulatórios.'),
        ('edv_jr', '2026.1', 'renato.moura@edvjr.com.br', 'alice.mizuki@edvjr.com.br', 'peer', 3.7, 3.9, 3.8, 3.8, 4.1, 'Muito responsável no suporte às dúvidas de classificação de Nice no INPI.'),

        -- Alicia Athayde (Marketing)
        ('edv_jr', '2026.1', 'alicia.athayde@edvjr.com.br', 'evelyn.roldi@edvjr.com.br', 'leader', 3.9, 4.1, 3.8, 3.7, 4.2, 'Ótima criatividade no copywriting e identidade visual das campanhas no Instagram.'),
        ('edv_jr', '2026.1', 'alicia.athayde@edvjr.com.br', 'joaop.lecco@edvjr.com.br', 'peer', 4.0, 4.0, 3.9, 3.6, 4.1, 'Sinergia exemplar no design e alinhamento com o MIV 2026.'),

        -- Aline Tartaglia (Jurídico)
        ('edv_jr', '2026.1', 'aline.tartaglia@edvjr.com.br', 'charles.junior@edvjr.com.br', 'leader', 4.2, 4.3, 4.1, 4.0, 4.3, 'Rigor técnico impecável nos contratos de prestação de serviços e compliance.'),
        ('edv_jr', '2026.1', 'aline.tartaglia@edvjr.com.br', 'karolina.krause@edvjr.com.br', 'peer', 4.1, 4.2, 4.0, 3.9, 4.2, 'Grande capacidade analítica em minutas e pareceres.');
        """)

    # 15. Seeding inicial de Estatutos e Compliance MEJ (Lei 13.267/2016 e Selo EJ)
    cursor.execute("SELECT COUNT(*) FROM statutes_compliance;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO statutes_compliance (
            tenant_id, title, norm_type, version, status, effective_date, review_deadline,
            responsible_area, responsible_role, document_url, description, checklist_items, conformity_score, created_by
        ) VALUES 
        (
            'edv_jr',
            'Lei Federal nº 13.267/2016 (Marco Legal das Empresas Juniores)',
            'marco_regulatorio',
            'Lei 13.267/2016',
            'vigente',
            '2016-04-06',
            '2026-12-31',
            'Jurídico',
            'diretor',
            'http://www.planalto.gov.br/ccivil_03/_ato2015-2018/2016/lei/l13267.htm',
            'Disciplina a criação e a organização das associações civis denominadas empresas juniores, com funcionamento perante instituições de ensino superior (IES).',
            '[{"id":"c1","item":"Fins exclusivamente educacionais e sem fins lucrativos (Art. 2º)","compliant":true,"notes":"Estatuto Social em estrita conformidade"},{"id":"c2","item":"Vinculação formal a Instituição de Ensino Superior - FDV (Art. 5º)","compliant":true,"notes":"Termo de Cooperação vigente com a Faculdade de Direito de Vitória"},{"id":"c3","item":"Gestão autônoma realizada exclusivamente por discentes (Art. 3º)","compliant":true,"notes":"Diretoria Executiva e Conselho compostos 100% por graduandos"},{"id":"c4","item":"Orientação e supervisão por professores/profissionais do mercado (Art. 6º)","compliant":true,"notes":"Corpo docente e advogados orientadores ativos"},{"id":"c5","item":"Reinvestimento integral dos excedentes na atividade-fim (Art. 2º, §2º)","compliant":true,"notes":"Proibição estatutária de distribuição de lucros aos associados"}]',
            100.0,
            'charles.junior@edvjr.com.br'
        ),
        (
            'edv_jr',
            'Estatuto Social EDV Jr. 2026 (Consolidado e Registrado em Cartório)',
            'estatuto',
            'v4.2 - 2026',
            'vigente',
            '2026-01-15',
            '2026-11-30',
            'Presidência',
            'presidente',
            'https://drive.google.com/drive/folders/estatuto_social_edv_2026',
            'Estatuto Social consolidado e registrado perante o Cartório de Registro Civil de Pessoas Jurídicas da Comarca de Vitória/ES.',
            '[{"id":"c1","item":"Definição de quorum qualificado para Assembleias Gerais Ordinárias e Extraordinárias","compliant":true,"notes":"Art. 18 do Estatuto"},{"id":"c2","item":"Regras de eleição, transição de mandato e posse de Diretores Executivos","compliant":true,"notes":"Capítulo V"},{"id":"c3","item":"Conselho Fiscal ativo e independente para auditoria e pareceres de contas","compliant":true,"notes":"Emissão trimestral de pareceres"},{"id":"c4","item":"Cláusula expressa de destinação do patrimônio líquido à entidade congênere em dissolução","compliant":true,"notes":"Art. 42"}]',
            100.0,
            'charles.junior@edvjr.com.br'
        ),
        (
            'edv_jr',
            'Regimento Interno EDV Jr. (Ciclo Operacional 2026)',
            'regimento_interno',
            'v3.1',
            'vigente',
            '2026-02-01',
            '2026-08-30',
            'VPGG',
            'diretor',
            'https://drive.google.com/drive/folders/regimento_interno_2026',
            'Normas operacionais de conduta, rotinas de trabalho, assiduidade, processo seletivo, premiações e política de desligamento voluntário e involuntário.',
            '[{"id":"c1","item":"Política de assiduidade mínima de 75% em reuniões gerais e operacionais","compliant":true,"notes":"Controle automatizado no EDbrain"},{"id":"c2","item":"Procedimento sumário para apuração de infrações éticas e amplo direito de defesa","compliant":true,"notes":"Comissão disciplinar"},{"id":"c3","item":"Diretrizes de ciclo trimestral de avaliações 360º e PDI 70-20-10","compliant":true,"notes":"Integrado ao módulo de PDI"}]',
            100.0,
            'alice.ney@edvjr.com.br'
        ),
        (
            'edv_jr',
            'Auditoria de Conformidade Selo EJ 2026 (Brasil Júnior / FEJES)',
            'selo_ej',
            'Ciclo 2026',
            'vigente',
            '2026-01-01',
            '2026-05-31',
            'Jurídico',
            'diretor',
            'https://brasiljunior.org.br/selo-ej',
            'Critérios obrigatórios de regularidade jurídica e fiscal chancelados pela Confederação Brasileira de Empresas Juniores e FEJES.',
            '[{"id":"c1","item":"CNPJ ativo na Receita Federal do Brasil","compliant":true,"notes":"Comprovante atualizado arquivado"},{"id":"c2","item":"Certidão Negativa de Débitos Federais (CND RFB/PGFN) válida","compliant":true,"notes":"Certidão com validade até Jul/2026"},{"id":"c3","item":"Certificado de Regularidade do FGTS (CRF Caixa) emitido e vigente","compliant":true,"notes":"Renovação mensal monitorada"},{"id":"c4","item":"Certidão Negativa de Débitos Trabalhistas (CNDT TST)","compliant":true,"notes":"Em dia"},{"id":"c5","item":"Declaração de Reconhecimento Institucional assinada pela Diretoria da FDV","compliant":true,"notes":"Documento oficial protocolado"},{"id":"c6","item":"Comprovante de Conta Bancária PJ ativa exclusiva da Associação","compliant":true,"notes":"Extrato bancário sem pendências"},{"id":"c7","item":"Livro Ata ou Registro Notarial da Posse da Gestão 2026","compliant":true,"notes":"Registrado em Cartório"}]',
            100.0,
            'charles.junior@edvjr.com.br'
        ),
        (
            'edv_jr',
            'Código de Ética e Sigilo de Marcas EDV Jr.',
            'codigo_etica',
            'v2.0',
            'vigente',
            '2025-08-01',
            '2026-10-15',
            'Presidência',
            'presidente',
            'https://drive.google.com/drive/folders/codigo_etica_edv',
            'Diretrizes de integridade institucional, sigilo técnico nos processos de registro de marcas do INPI, concorrência leal e respeito interpessoal.',
            '[{"id":"c1","item":"Termo de Sigilo e Confidencialidade (NDA) assinado por 100% dos membros","compliant":true,"notes":"Onboarding com assinatura digital coletada"},{"id":"c2","item":"Canal de Ética e Ouvidoria anônimo implementado","compliant":true,"notes":"Gerido pela Presidência Institucional"},{"id":"c3","item":"Vedações expressas a conflito de interesses na titularidade de marcas depositadas","compliant":true,"notes":"Art. 12 do Código"}]',
            100.0,
            'charles.junior@edvjr.com.br'
        );
        """)

    # 16. Seeding inicial de Notificações do Sistema
    cursor.execute("SELECT COUNT(*) FROM system_notifications;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO system_notifications (
            tenant_id, recipient_email, target_role, target_area, title, message, category, priority, link, is_read, email_sent
        ) VALUES 
        (
            'edv_jr',
            'ALL',
            NULL,
            NULL,
            'Bem-vindo ao Sistema de Governança e Compliance EDbrain 2026',
            'O ecossistema EDbrain foi atualizado com suporte total à Lei 13.267/2016, auditoria do Selo EJ, Notificações Dinâmicas, Google Calendar e Maker-Checker na esteira de marcas.',
            'compliance',
            'normal',
            '#pres-sub-estatutos',
            0,
            0
        ),
        (
            'edv_jr',
            'charles.junior@edvjr.com.br',
            'presidente',
            'Presidência',
            'Auditoria Selo EJ 2026 - Checklist em 100% de Conformidade',
            'Todos os 7 requisitos documentais federais e federativos do Selo EJ 2026 foram auditados e estão com certidões vigentes.',
            'audit_alert',
            'high',
            '#pres-sub-estatutos',
            0,
            0
        );
        """)

    conn.commit()
    cursor.execute("SELECT COUNT(*) FROM users;")
    total_users = cursor.fetchone()[0]
    print(f"[SQLite] Base inicializada e sincronizada com {total_users} membros no padrão RBAC estrito.")
    conn.close()

    # Sincronização e migração de tabelas SQLAlchemy (compatível com SQLite e PostgreSQL)
    try:
        Base.metadata.create_all(bind=engine)
        ensure_initial_admin()
    except Exception as e_sql:
        print(f"[SQLAlchemy] Aviso ao criar tabelas/seeding: {e_sql}")

def ensure_initial_admin(db_session=None):
    """
    Garante de forma resiliente que a conta de Administrador/Presidência (e os membros da liderança)
    esteja devidamente cadastrada e com hash bcrypt válido tanto em SQLite quanto em PostgreSQL.
    """
    should_close = False
    if db_session is None:
        db_session = SessionLocal()
        should_close = True
    try:
        default_hash = bcrypt.hashpw(DEFAULT_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        for m in MEMBROS_WHITELIST:
            user = db_session.query(UserORM).filter(UserORM.email == m["email"].lower().strip()).first()
            if not user:
                new_u = UserORM(
                    email=m["email"].lower().strip(),
                    nome=m["nome"],
                    hashed_password=default_hash,
                    area=m["area"],
                    role=m["role"],
                    setor=m.get("setor"),
                    cargo=m.get("cargo")
                )
                db_session.add(new_u)
            else:
                user.nome = m["nome"]
                user.area = m["area"]
                user.role = m["role"]
                user.setor = m.get("setor")
                user.cargo = m.get("cargo")
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        print(f"[Database] Aviso ao sincronizar usuários via SQLAlchemy: {e}")
    finally:
        if should_close:
            db_session.close()

def get_user_by_email(email: str):
    email_clean = email.lower().strip()
    # 1. Tentar via SQLAlchemy ORM (compatível com PostgreSQL em produção e SQLite)
    try:
        db = SessionLocal()
        user_orm = db.query(UserORM).filter(UserORM.email == email_clean).first()
        if user_orm:
            user_dict = {
                "id": user_orm.id,
                "email": user_orm.email,
                "nome": user_orm.nome,
                "hashed_password": user_orm.hashed_password,
                "area": user_orm.area,
                "role": user_orm.role,
                "setor": user_orm.setor,
                "cargo": user_orm.cargo,
                "created_at": user_orm.created_at
            }
            db.close()
            return user_dict
        db.close()
    except Exception:
        pass

    # 2. Fallback via SQLite direto
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?;", (email_clean,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def get_user_by_id(user_id: int):
    try:
        db = SessionLocal()
        user_orm = db.query(UserORM).filter(UserORM.id == user_id).first()
        if user_orm:
            user_dict = {
                "id": user_orm.id,
                "email": user_orm.email,
                "nome": user_orm.nome,
                "hashed_password": user_orm.hashed_password,
                "area": user_orm.area,
                "role": user_orm.role,
                "setor": user_orm.setor,
                "cargo": user_orm.cargo,
                "created_at": user_orm.created_at
            }
            db.close()
            return user_dict
        db.close()
    except Exception:
        pass

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def get_all_users():
    try:
        db = SessionLocal()
        users_orm = db.query(UserORM).order_by(UserORM.id.asc()).all()
        if users_orm:
            users_list = [{
                "id": u.id,
                "email": u.email,
                "nome": u.nome,
                "hashed_password": u.hashed_password,
                "area": u.area,
                "role": u.role,
                "setor": u.setor,
                "cargo": u.cargo,
                "created_at": u.created_at
            } for u in users_orm]
            db.close()
            return users_list
        db.close()
    except Exception:
        pass

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, nome, area, role, setor, cargo, created_at FROM users ORDER BY id ASC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_followup_by_id(followup_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM client_followups WHERE id = ?;", (followup_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def log_audit(
    user_email: str,
    action: str,
    resource: str,
    status_code: int = 200,
    details: Any = None,
    ip_address: str = None
):
    """Registra evento forense na tabela audit_logs (imutável)"""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        details_str = details
        if details is not None and not isinstance(details, str):
            try:
                import json
                details_str = json.dumps(details, ensure_ascii=False)
            except Exception:
                details_str = str(details)

        cursor.execute("""
        INSERT INTO audit_logs (user_email, action, resource, status_code, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?);
        """, (
            (user_email or "anonymous").lower().strip(),
            action.upper().strip(),
            resource,
            status_code,
            details_str,
            ip_address or "127.0.0.1"
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Audit Log Error] Falha ao registrar log de auditoria: {e}")

def get_audit_logs(
    limit: int = 50,
    offset: int = 0,
    action: str = None,
    user_email: str = None,
    status_code: int = None
):
    """Consulta registros forenses com filtros compostos"""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    
    if action:
        query += " AND action = ?"
        params.append(action.upper().strip())
    if user_email:
        query += " AND user_email LIKE ?"
        params.append(f"%{user_email.lower().strip()}%")
    if status_code is not None:
        query += " AND status_code = ?"
        params.append(status_code)
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?;"
    params.extend([limit, offset])
    
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def count_audit_logs(
    action: str = None,
    user_email: str = None,
    status_code: int = None
):
    """Conta total de registros forenses com filtros"""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT COUNT(*) FROM audit_logs WHERE 1=1"
    params = []
    
    if action:
        query += " AND action = ?"
        params.append(action.upper().strip())
    if user_email:
        query += " AND user_email LIKE ?"
        params.append(f"%{user_email.lower().strip()}%")
    if status_code is not None:
        query += " AND status_code = ?"
        params.append(status_code)
        
    cursor.execute(query, tuple(params))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_backups_dir():
    """Retorna o diretório oficial de snapshots do SQLite"""
    backups_dir = os.path.join(os.path.dirname(__file__), "backups")
    os.makedirs(backups_dir, exist_ok=True)
    return backups_dir

def create_database_snapshot(dest_dir: str = None):
    """Gera um snapshot consistente e íntegro do banco SQLite usando a API de Backup online"""
    from datetime import datetime
    dest_folder = dest_dir or get_backups_dir()
    os.makedirs(dest_folder, exist_ok=True)
    
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    snapshot_filename = f"backup_auth_{timestamp_str}.db"
    snapshot_path = os.path.join(dest_folder, snapshot_filename)
    
    # Executa cópia atômica via SQLite Backup API
    src_conn = sqlite3.connect(DB_PATH)
    dest_conn = sqlite3.connect(snapshot_path)
    with dest_conn:
        src_conn.backup(dest_conn, pages=100)
    dest_conn.close()
    src_conn.close()
    
    size_bytes = os.path.getsize(snapshot_path)
    
    # Registra em auditoria
    log_audit("system", "BACKUP_SNAPSHOT_CREATED", "/api/admin/backup", 200, {
        "filename": snapshot_filename,
        "size_bytes": size_bytes
    })
    
    return {
        "filename": snapshot_filename,
        "path": snapshot_path,
        "size_bytes": size_bytes,
        "created_at": datetime.now().isoformat()
    }

def get_database_stats():
    """Retorna telemetria operacional e volumetria do SQLite"""
    conn = get_connection()
    cursor = conn.cursor()
    
    tables = [
        "users", "transactions", "notices", "pdis", "client_followups", "audit_logs",
        "campaigns", "psel_candidates", "brand_assets", "performance_evaluations_360",
        "evaluator_calibrations", "historical_manager_benchmarks", "succession_readiness_records",
        "gap_mitigation_actions", "statutes_compliance", "system_notifications", "rm_staging_records"
    ]
    counts = {}
    for t in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {t};")
            counts[t] = cursor.fetchone()[0]
        except Exception:
            counts[t] = 0
            
    conn.close()
    
    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    backups_dir = get_backups_dir()
    existing_backups = []
    if os.path.exists(backups_dir):
        for f in sorted(os.listdir(backups_dir), reverse=True):
            if f.endswith(".db"):
                f_path = os.path.join(backups_dir, f)
                existing_backups.append({
                    "filename": f,
                    "size_bytes": os.path.getsize(f_path),
                    "created_at": os.path.getmtime(f_path)
                })
                
    return {
        "database_file": os.path.basename(DB_PATH),
        "size_bytes": db_size,
        "size_kb": round(db_size / 1024, 2),
        "table_counts": counts,
        "total_backups": len(existing_backups),
        "backups": existing_backups[:10]
    }


# ==============================================================================
# MÓDULO MARKETING & CAMPANHAS: GESTÃO DE ROI, PSEL E BRAND KIT (MEJ / RBAC)
# ==============================================================================

def calculate_campaign_metrics(campaign_row: dict) -> dict:
    """Calcula ROI, conversão, CPL e CAC de uma campanha a partir dos dados do CRM e PSEL"""
    conn = get_connection()
    cursor = conn.cursor()
    c_id = campaign_row["id"]
    c_type = campaign_row.get("type", "")
    cost = float(campaign_row.get("actual_cost") or campaign_row.get("budget") or 0.0)
    
    leads_count = 0
    leads_fechados = 0
    receita_gerada = 0.0

    if c_type == "processo_seletivo":
        cursor.execute("SELECT COUNT(*) FROM psel_candidates WHERE campaign_id = ?;", (c_id,))
        leads_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM psel_candidates WHERE campaign_id = ? AND stage IN ('aprovado', 'onboarding');", (c_id,))
        leads_fechados = cursor.fetchone()[0]
        # Para processo seletivo, valor simbólico de impacto do novo membro
        receita_gerada = float(leads_fechados * 1500.0)
    else:
        cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'fechado' THEN 1 ELSE 0 END) as fechados,
            SUM(CASE WHEN status = 'fechado' THEN COALESCE(estimated_value, 0.0) ELSE 0.0 END) as receita
        FROM client_followups
        WHERE campaign_id = ?;
        """, (c_id,))
        res = cursor.fetchone()
        if res:
            leads_count = res["total"] or 0
            leads_fechados = res["fechados"] or 0
            receita_gerada = float(res["receita"] or 0.0)

    conn.close()

    if cost > 0:
        roi = round(((receita_gerada - cost) / cost) * 100.0, 2)
    elif receita_gerada > 0:
        roi = 100.0
    else:
        roi = 0.0

    conversao = round((leads_fechados / leads_count * 100.0), 2) if leads_count > 0 else 0.0
    cpl = round(cost / leads_count, 2) if leads_count > 0 else 0.0
    cac = round(cost / leads_fechados, 2) if leads_fechados > 0 else 0.0
    lucro_liquido = round(receita_gerada - cost, 2)

    enriched = dict(campaign_row)
    enriched.update({
        "leads_count": leads_count,
        "leads_fechados": leads_fechados,
        "receita_gerada": receita_gerada,
        "lucro_liquido": lucro_liquido,
        "roi": roi,
        "taxa_conversao": conversao,
        "cpl": cpl,
        "cac": cac
    })
    return enriched

def create_campaign(data: dict) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO campaigns (
        tenant_id, name, type, channel, status, budget, actual_cost, target_leads,
        start_date, end_date, responsible, description, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        data.get("tenant_id", "edv_jr"),
        data["name"].strip(),
        data["type"].strip(),
        data["channel"].strip(),
        data.get("status", "ativa").strip(),
        float(data.get("budget", 0.0)),
        float(data.get("actual_cost", 0.0)),
        int(data.get("target_leads", 0)),
        data.get("start_date"),
        data.get("end_date"),
        data["responsible"].strip(),
        data.get("description", ""),
        data["created_by"].strip()
    ))
    campaign_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM campaigns WHERE id = ?;", (campaign_id,))
    row = dict(cursor.fetchone())
    conn.close()
    return calculate_campaign_metrics(row)

def get_campaign_by_id(campaign_id: int, tenant_id: str = "edv_jr") -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM campaigns WHERE id = ? AND tenant_id = ?;", (campaign_id, tenant_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return calculate_campaign_metrics(dict(row))

def update_campaign(campaign_id: int, data: dict, tenant_id: str = "edv_jr") -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM campaigns WHERE id = ? AND tenant_id = ?;", (campaign_id, tenant_id))
    if not cursor.fetchone():
        conn.close()
        return None

    allowed_fields = [
        "name", "type", "channel", "status", "budget", "actual_cost",
        "target_leads", "start_date", "end_date", "responsible", "description"
    ]
    updates = []
    params = []
    for f in allowed_fields:
        if f in data and data[f] is not None:
            updates.append(f"{f} = ?")
            params.append(data[f])

    if not updates:
        conn.close()
        return get_campaign_by_id(campaign_id, tenant_id)

    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([campaign_id, tenant_id])

    query = f"UPDATE campaigns SET {', '.join(updates)} WHERE id = ? AND tenant_id = ?;"
    cursor.execute(query, tuple(params))
    conn.commit()
    conn.close()
    return get_campaign_by_id(campaign_id, tenant_id)

def delete_campaign(campaign_id: int, tenant_id: str = "edv_jr") -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM campaigns WHERE id = ? AND tenant_id = ?;", (campaign_id, tenant_id))
    if not cursor.fetchone():
        conn.close()
        return False
    # Desvincular leads e candidatos
    cursor.execute("UPDATE client_followups SET campaign_id = NULL WHERE campaign_id = ?;", (campaign_id,))
    cursor.execute("UPDATE psel_candidates SET campaign_id = NULL WHERE campaign_id = ?;", (campaign_id,))
    cursor.execute("DELETE FROM campaigns WHERE id = ? AND tenant_id = ?;", (campaign_id, tenant_id))
    conn.commit()
    conn.close()
    return True

def list_campaigns(
    tenant_id: str = "edv_jr",
    campaign_type: str = None,
    channel: str = None,
    status: str = None
) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM campaigns WHERE tenant_id = ?"
    params = [tenant_id]

    if campaign_type:
        query += " AND type = ?"
        params.append(campaign_type.strip())
    if channel:
        query += " AND channel = ?"
        params.append(channel.strip())
    if status:
        query += " AND status = ?"
        params.append(status.strip())

    query += " ORDER BY id DESC;"
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()

    return [calculate_campaign_metrics(dict(r)) for r in rows]

def get_campaign_roi_metrics(campaign_id: int, tenant_id: str = "edv_jr") -> dict:
    campaign = get_campaign_by_id(campaign_id, tenant_id)
    if not campaign:
        return {}

    conn = get_connection()
    cursor = conn.cursor()
    leads = []
    if campaign.get("type") == "processo_seletivo":
        cursor.execute("SELECT id, name, email, stage, target_area, score_dinamica, score_entrevista FROM psel_candidates WHERE campaign_id = ? ORDER BY id ASC;", (campaign_id,))
        for r in cursor.fetchall():
            leads.append({
                "id": r["id"],
                "nome": r["name"],
                "email": r["email"],
                "fase": r["stage"],
                "area": r["target_area"],
                "nota": round((r["score_dinamica"] + r["score_entrevista"]) / 2, 1)
            })
    else:
        cursor.execute("SELECT id, client_name, razao_social, status, estimated_value, interaction_type, notes FROM client_followups WHERE campaign_id = ? ORDER BY id ASC;", (campaign_id,))
        for r in cursor.fetchall():
            leads.append({
                "id": r["id"],
                "nome": r["razao_social"] or r["client_name"],
                "status": r["status"],
                "valor_estimado": r["estimated_value"],
                "interacao": r["interaction_type"],
                "notas": r["notes"]
            })
    conn.close()

    return {
        "campanha": campaign,
        "metricas": {
            "custo_efetivo": campaign["actual_cost"],
            "orcamento": campaign["budget"],
            "leads_gerados": campaign["leads_count"],
            "leads_fechados": campaign["leads_fechados"],
            "receita_atribuida": campaign["receita_gerada"],
            "lucro_liquido": campaign["lucro_liquido"],
            "roi_percentual": campaign["roi"],
            "taxa_conversao_percentual": campaign["taxa_conversao"],
            "cpl": campaign["cpl"],
            "cac": campaign["cac"]
        },
        "detalhe_leads": leads
    }

# --- PSEL (FUNIL DO PROCESSO SELETIVO MEJ) ---

def create_psel_candidate(data: dict) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO psel_candidates (
        tenant_id, campaign_id, name, email, phone, course, period, stage,
        target_area, score_dinamica, score_entrevista, notes, interviewer,
        competency_focus, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        data.get("tenant_id", "edv_jr"),
        data.get("campaign_id"),
        data["name"].strip(),
        data["email"].strip().lower(),
        data.get("phone", ""),
        data.get("course", "Direito"),
        data.get("period", ""),
        data.get("stage", "inscricao").strip().lower(),
        data.get("target_area", "Comercial").strip(),
        float(data.get("score_dinamica", 0.0)),
        float(data.get("score_entrevista", 0.0)),
        data.get("notes", ""),
        data.get("interviewer", ""),
        data.get("competency_focus", "Gestão"),
        data["created_by"].strip()
    ))
    candidate_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM psel_candidates WHERE id = ?;", (candidate_id,))
    row = dict(cursor.fetchone())
    conn.close()
    return row

def get_psel_candidate_by_id(candidate_id: int, tenant_id: str = "edv_jr") -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM psel_candidates WHERE id = ? AND tenant_id = ?;", (candidate_id, tenant_id))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def update_psel_candidate(candidate_id: int, data: dict, tenant_id: str = "edv_jr") -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM psel_candidates WHERE id = ? AND tenant_id = ?;", (candidate_id, tenant_id))
    if not cursor.fetchone():
        conn.close()
        return None

    allowed_fields = [
        "campaign_id", "name", "email", "phone", "course", "period", "stage",
        "target_area", "score_dinamica", "score_entrevista", "notes", "interviewer",
        "competency_focus"
    ]
    updates = []
    params = []
    for f in allowed_fields:
        if f in data and data[f] is not None:
            updates.append(f"{f} = ?")
            params.append(data[f])

    if not updates:
        conn.close()
        return get_psel_candidate_by_id(candidate_id, tenant_id)

    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([candidate_id, tenant_id])

    query = f"UPDATE psel_candidates SET {', '.join(updates)} WHERE id = ? AND tenant_id = ?;"
    cursor.execute(query, tuple(params))
    conn.commit()
    conn.close()
    return get_psel_candidate_by_id(candidate_id, tenant_id)

def update_psel_candidate_stage(candidate_id: int, new_stage: str, notes: str = None, tenant_id: str = "edv_jr") -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    if notes:
        cursor.execute("""
        UPDATE psel_candidates 
        SET stage = ?, notes = notes || '\n' || ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND tenant_id = ?;
        """, (new_stage.lower().strip(), f"[{new_stage.upper()}]: {notes}", candidate_id, tenant_id))
    else:
        cursor.execute("""
        UPDATE psel_candidates 
        SET stage = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND tenant_id = ?;
        """, (new_stage.lower().strip(), candidate_id, tenant_id))
    conn.commit()
    conn.close()
    return get_psel_candidate_by_id(candidate_id, tenant_id)

def delete_psel_candidate(candidate_id: int, tenant_id: str = "edv_jr") -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM psel_candidates WHERE id = ? AND tenant_id = ?;", (candidate_id, tenant_id))
    if not cursor.fetchone():
        conn.close()
        return False
    cursor.execute("DELETE FROM psel_candidates WHERE id = ? AND tenant_id = ?;", (candidate_id, tenant_id))
    conn.commit()
    conn.close()
    return True

def list_psel_candidates(
    tenant_id: str = "edv_jr",
    stage: str = None,
    target_area: str = None,
    campaign_id: int = None
) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM psel_candidates WHERE tenant_id = ?"
    params = [tenant_id]

    if stage:
        query += " AND stage = ?"
        params.append(stage.lower().strip())
    if target_area:
        query += " AND target_area = ?"
        params.append(target_area.strip())
    if campaign_id:
        query += " AND campaign_id = ?"
        params.append(campaign_id)

    query += " ORDER BY score_entrevista DESC, score_dinamica DESC, id ASC;"
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def approve_and_onboard_candidate(candidate_id: int, approver_email: str, tenant_id: str = "edv_jr") -> dict:
    """
    Migração em 1 clique do candidato aprovado para Gente & Gestão (VPGG):
    1. Cria conta de acesso no users (role=assessor, area=target_area)
    2. Cria PDI inicial na tabela pdis vinculado ao Modelo de Competências Brasil Júnior
    3. Atualiza o status do candidato para 'aprovado'
    4. Registra auditoria forense
    """
    import unicodedata
    from datetime import datetime, timedelta

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM psel_candidates WHERE id = ? AND tenant_id = ?;", (candidate_id, tenant_id))
    candidate = cursor.fetchone()
    if not candidate:
        conn.close()
        raise ValueError(f"Candidato #{candidate_id} não localizado no tenant {tenant_id}.")

    cand_dict = dict(candidate)
    nome = cand_dict["name"]
    area = cand_dict["target_area"]
    competencia = cand_dict.get("competency_focus") or "Gestão"

    # Gerar e-mail institucional padronizado
    normalized_name = unicodedata.normalize('NFKD', nome).encode('ASCII', 'ignore').decode('utf-8').lower().strip()
    name_parts = re.sub(r'[^a-z\s]', '', normalized_name).split()
    if len(name_parts) >= 2:
        inst_email = f"{name_parts[0]}.{name_parts[-1]}@edvjr.com.br"
    else:
        inst_email = f"{name_parts[0]}@edvjr.com.br"

    # Verificar se o usuário já existe
    cursor.execute("SELECT id FROM users WHERE email = ? OR email = ?;", (inst_email, cand_dict["email"]))
    existing_user = cursor.fetchone()
    user_created = False
    if not existing_user:
        default_hash = bcrypt.hashpw(DEFAULT_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cursor.execute("""
        INSERT INTO users (email, nome, hashed_password, area, role, setor, cargo)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (
            inst_email,
            nome,
            default_hash,
            area,
            "assessor",
            f"{area} / Trainee",
            f"Assessor Trainee de {area}"
        ))
        user_created = True

    # Criar PDI inicial com Modelo de Competências Brasil Júnior
    deadline_date = (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d")
    objectives_text = f"Onboarding Institucional e Desenvolvimento na Competência Brasil Júnior: {competencia}"
    dev_text = (
        f"1. Completar a imersão na cultura da EDV Jr. e do MEJ (Código de Ética e Diretrizes Brasil Júnior).\n"
        f"2. Concluir a trilha de capacitação técnica da área de {area}.\n"
        f"3. Executar o primeiro projeto sob tutoria com avaliação de desempenho 360° em 90 dias."
    )
    cursor.execute("""
    INSERT INTO pdis (user_email, area, competency_mej, objectives, development_ideas, deadline, status)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (
        inst_email,
        "VPGG",
        competencia,
        objectives_text,
        dev_text,
        deadline_date,
        "em_andamento"
    ))
    pdi_id = cursor.lastrowid

    # Atualizar estágio do candidato para 'aprovado'
    cursor.execute("""
    UPDATE psel_candidates
    SET stage = 'aprovado', updated_at = CURRENT_TIMESTAMP
    WHERE id = ?;
    """, (candidate_id,))

    conn.commit()
    conn.close()

    # Log de auditoria
    log_audit(
        approver_email,
        "PSEL_CANDIDATE_ONBOARDED",
        f"/api/marketing/psel/candidates/{candidate_id}/approve-and-onboard",
        200,
        {
            "candidate_id": candidate_id,
            "candidate_name": nome,
            "institutional_email": inst_email,
            "area": area,
            "competency_focus": competencia,
            "pdi_id": pdi_id,
            "user_created": user_created
        }
    )

    return {
        "status": "success",
        "candidate_id": candidate_id,
        "nome": nome,
        "email_institucional": inst_email,
        "area": area,
        "pdi_id": pdi_id,
        "competencia_brasil_junior": competencia,
        "prazo_pdi": deadline_date,
        "novo_membro_criado": user_created
    }

# --- BRAND KIT (REPOSITÓRIO DE ATIVOS OFICIAIS DE MARCA) ---

def create_brand_asset(data: dict) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO brand_assets (
        tenant_id, title, category, file_format, version, file_url,
        description, tags, is_official, uploaded_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        data.get("tenant_id", "edv_jr"),
        data["title"].strip(),
        data["category"].strip().lower(),
        data["file_format"].strip().upper(),
        data.get("version", "v1.0").strip(),
        data["file_url"].strip(),
        data.get("description", ""),
        data.get("tags", ""),
        1 if data.get("is_official", True) else 0,
        data["uploaded_by"].strip()
    ))
    asset_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM brand_assets WHERE id = ?;", (asset_id,))
    row = dict(cursor.fetchone())
    conn.close()
    return row

def get_brand_asset_by_id(asset_id: int, tenant_id: str = "edv_jr") -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM brand_assets WHERE id = ? AND tenant_id = ?;", (asset_id, tenant_id))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def update_brand_asset(asset_id: int, data: dict, tenant_id: str = "edv_jr") -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM brand_assets WHERE id = ? AND tenant_id = ?;", (asset_id, tenant_id))
    if not cursor.fetchone():
        conn.close()
        return None

    allowed_fields = [
        "title", "category", "file_format", "version", "file_url",
        "description", "tags", "is_official"
    ]
    updates = []
    params = []
    for f in allowed_fields:
        if f in data and data[f] is not None:
            updates.append(f"{f} = ?")
            if f == "is_official":
                params.append(1 if data[f] else 0)
            else:
                params.append(data[f])

    if not updates:
        conn.close()
        return get_brand_asset_by_id(asset_id, tenant_id)

    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([asset_id, tenant_id])

    query = f"UPDATE brand_assets SET {', '.join(updates)} WHERE id = ? AND tenant_id = ?;"
    cursor.execute(query, tuple(params))
    conn.commit()
    conn.close()
    return get_brand_asset_by_id(asset_id, tenant_id)

def delete_brand_asset(asset_id: int, tenant_id: str = "edv_jr") -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM brand_assets WHERE id = ? AND tenant_id = ?;", (asset_id, tenant_id))
    if not cursor.fetchone():
        conn.close()
        return False
    cursor.execute("DELETE FROM brand_assets WHERE id = ? AND tenant_id = ?;", (asset_id, tenant_id))
    conn.commit()
    conn.close()
    return True

def list_brand_assets(tenant_id: str = "edv_jr", category: str = None) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM brand_assets WHERE tenant_id = ?"
    params = [tenant_id]

    if category:
        query += " AND category = ?"
        params.append(category.strip().lower())

    query += " ORDER BY is_official DESC, category ASC, id ASC;"
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- DASHBOARD GERAL DE MARKETING ANALYTICS ---

def get_marketing_dashboard_analytics(tenant_id: str = "edv_jr") -> dict:
    campaigns = list_campaigns(tenant_id=tenant_id)
    total_investido = sum(float(c.get("actual_cost") or c.get("budget") or 0.0) for c in campaigns)
    receita_total = sum(float(c.get("receita_gerada") or 0.0) for c in campaigns)
    leads_captados = sum(int(c.get("leads_count") or 0) for c in campaigns)
    leads_fechados = sum(int(c.get("leads_fechados") or 0) for c in campaigns)

    if total_investido > 0:
        roi_global = round(((receita_total - total_investido) / total_investido) * 100.0, 2)
    elif receita_total > 0:
        roi_global = 100.0
    else:
        roi_global = 0.0

    taxa_conversao_global = round((leads_fechados / leads_captados * 100.0), 2) if leads_captados > 0 else 0.0

    # Candidatos do PSEL por estágio
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT stage, COUNT(*) as count 
    FROM psel_candidates 
    WHERE tenant_id = ? 
    GROUP BY stage;
    """, (tenant_id,))
    stage_counts = {r["stage"]: r["count"] for r in cursor.fetchall()}

    cursor.execute("SELECT COUNT(*) FROM psel_candidates WHERE tenant_id = ?;", (tenant_id,))
    total_candidatos = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM brand_assets WHERE tenant_id = ?;", (tenant_id,))
    total_brand_assets = cursor.fetchone()[0]
    conn.close()

    # Desempenho por canal
    canais = {}
    for c in campaigns:
        ch = c.get("channel", "outros")
        if ch not in canais:
            canais[ch] = {"leads": 0, "fechados": 0, "custo": 0.0, "receita": 0.0}
        canais[ch]["leads"] += c.get("leads_count", 0)
        canais[ch]["fechados"] += c.get("leads_fechados", 0)
        canais[ch]["custo"] += float(c.get("actual_cost") or 0.0)
        canais[ch]["receita"] += float(c.get("receita_gerada") or 0.0)

    for ch, vals in canais.items():
        vals["roi"] = round(((vals["receita"] - vals["custo"]) / vals["custo"] * 100.0), 2) if vals["custo"] > 0 else 0.0

    return {
        "tenant_id": tenant_id,
        "total_campanhas": len(campaigns),
        "campanhas_ativas": len([c for c in campaigns if c.get("status") == "ativa"]),
        "investimento_total": total_investido,
        "receita_total_atribuida": receita_total,
        "lucro_liquido_global": round(receita_total - total_investido, 2),
        "roi_global_percentual": roi_global,
        "total_leads_captados": leads_captados,
        "total_leads_fechados": leads_fechados,
        "taxa_conversao_global": taxa_conversao_global,
        "psel_metricas": {
            "total_candidatos": total_candidatos,
            "por_estagio": stage_counts,
            "aprovados": stage_counts.get("aprovado", 0),
            "em_onboarding": stage_counts.get("onboarding", 0)
        },
        "brand_assets_total": total_brand_assets,
        "desempenho_canais": canais
    }


# ==============================================================================
# MOTOR PREDITIVO DE SUCESSÃO, TRIANGULAÇÃO E MITIGAÇÃO DE GAPS (VPGG / EDbrain)
# ==============================================================================

def get_member_hard_metrics(user_email: str, conn=None) -> dict:
    """
    Extrai métricas operacionais quantitativas (Hard Data) sem subjetividade:
    - CRM Comercial (client_followups): leads, conversão, faturamento atribuído.
    - Projetos (legacy_data / RMs): pontualidade, volume de marcas.
    - VPGG (legacy_data / agoras): assiduidade em reuniões e 1-on-1s.
    """
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    cursor = conn.cursor()
    cursor.execute("SELECT id, email, nome, area, role, setor, cargo FROM users WHERE LOWER(email) = LOWER(?);", (user_email.strip(),))
    user = cursor.fetchone()
    if not user:
        if should_close: conn.close()
        return {}

    user_dict = dict(user)
    nome = user_dict["nome"]
    user_area = user_dict["area"] or user_dict.get("setor") or "Geral"

    # 1. Métricas do CRM Comercial
    cursor.execute("""
    SELECT 
        COUNT(*) as total_leads,
        SUM(CASE WHEN status = 'fechado' THEN 1 ELSE 0 END) as closed_deals,
        SUM(CASE WHEN status = 'fechado' THEN estimated_value ELSE 0.0 END) as total_revenue
    FROM client_followups
    WHERE LOWER(created_by) = LOWER(?);
    """, (user_email.strip(),))
    crm_row = cursor.fetchone()
    total_leads = crm_row["total_leads"] or 0
    closed_deals = crm_row["closed_deals"] or 0
    total_revenue = float(crm_row["total_revenue"] or 0.0)

    # 2. Carregar dados do ecossistema do Google Drive (legacy_data.json)
    legacy_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "legacy_data.json")
    legacy = {}
    if os.path.exists(legacy_path):
        try:
            with open(legacy_path, 'r', encoding='utf-8') as f:
                legacy = json.load(f)
        except Exception:
            pass

    # Assiduidade e Governança da VPGG
    vpgg_list = legacy.get("vpgg", [])
    assiduidade_pct = 92.0
    pdi_prev_status = "Em andamento"
    one_on_one_status = "Em dia"
    first_name = nome.split()[0].lower()
    for item in vpgg_list:
        v_nome = item.get("nome", "").lower()
        if v_nome in nome.lower() or first_name in v_nome:
            try:
                assiduidade_pct = float(item.get("assiduidade", "92%").replace("%", "").strip())
            except Exception:
                assiduidade_pct = 92.0
            pdi_prev_status = item.get("pdi_status", "Em andamento")
            one_on_one_status = item.get("one_on_one", "Em dia")
            break

    # Pontualidade e RMs em Projetos
    rms_list = legacy.get("rms", [])
    user_rms = [r for r in rms_list if nome.lower() in (r.get("participantes", "") + r.get("responsavel", "")).lower()]
    total_rms = len(user_rms)
    ontime_rms = [r for r in user_rms if "indeferido" not in r.get("fase", "").lower() and "atraso" not in r.get("fase", "").lower()]
    punctuality_rate = (len(ontime_rms) / total_rms * 100.0) if total_rms > 0 else (95.0 if "projeto" in user_area.lower() else 92.0)

    # Normalização de Hard Scores (0.0 a 100.0)
    conversion_rate = (closed_deals / total_leads * 100.0) if total_leads > 0 else 0.0
    conversion_score = min(100.0, (conversion_rate / 20.0) * 100.0) if total_leads > 0 else (80.0 if "comercial" not in user_area.lower() else 50.0)
    revenue_score = min(100.0, (total_revenue / 8000.0) * 100.0) if total_revenue > 0 else (75.0 if "comercial" not in user_area.lower() else 45.0)
    project_punctuality_score = min(100.0, max(0.0, punctuality_rate))
    assiduidade_score = min(100.0, max(0.0, assiduidade_pct))

    # Ponderação do Hard Score Geral de acordo com a área de atuação do membro
    if "comercial" in user_area.lower():
        overall_hard = 0.40 * conversion_score + 0.35 * revenue_score + 0.25 * assiduidade_score
    elif "projeto" in user_area.lower():
        overall_hard = 0.50 * project_punctuality_score + 0.30 * assiduidade_score + 0.20 * revenue_score
    else:
        overall_hard = 0.40 * assiduidade_score + 0.30 * project_punctuality_score + 0.30 * conversion_score

    if should_close: conn.close()

    return {
        "user_email": user_email,
        "nome": nome,
        "area": user_area,
        "role": user_dict["role"],
        "cargo": user_dict["cargo"],
        "total_leads": total_leads,
        "closed_deals": closed_deals,
        "total_revenue": total_revenue,
        "conversion_rate": round(conversion_rate, 1),
        "total_rms": total_rms,
        "punctuality_rate": round(punctuality_rate, 1),
        "assiduidade_pct": round(assiduidade_pct, 1),
        "pdi_prev_status": pdi_prev_status,
        "one_on_one_status": one_on_one_status,
        "scores": {
            "conversion_score": round(conversion_score, 1),
            "revenue_score": round(revenue_score, 1),
            "project_punctuality_score": round(project_punctuality_score, 1),
            "assiduidade_score": round(assiduidade_score, 1),
            "overall_hard_score": round(overall_hard, 1)
        }
    }


def get_evaluator_calibrations(conn=None) -> dict:
    """
    Retorna os pesos de assertividade e calibração de viés dos avaliadores.
    """
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True

    cursor = conn.cursor()
    cursor.execute("SELECT evaluator_email, assertiveness_weight, bias_tendency, correlation_with_hard_data FROM evaluator_calibrations;")
    calibrations = {
        r["evaluator_email"].lower(): {
            "assertiveness_weight": float(r["assertiveness_weight"]),
            "bias_tendency": r["bias_tendency"],
            "correlation_with_hard_data": float(r["correlation_with_hard_data"])
        } for r in cursor.fetchall()
    }
    if should_close: conn.close()
    return calibrations


def calculate_triangulation(user_email: Optional[str] = None) -> Union[dict, List[dict]]:
    """
    Cruza métricas quantitativas operacionais (Hard Data) com avaliações 360º (Soft Data).
    Pondera as notas com base no histórico de assertividade dos avaliadores e alinha
    rigorosamente às 5 competências da Brasil Júnior:
    1. Liderança
    2. Gestão
    3. Visão Sistêmica
    4. Orientação para Resultados
    5. Autoconhecimento
    """
    conn = get_connection()
    cursor = conn.cursor()

    evaluator_calibs = get_evaluator_calibrations(conn=conn)

    # Identificar quais usuários processar
    if user_email:
        cursor.execute("SELECT email FROM users WHERE LOWER(email) = LOWER(?);", (user_email.strip(),))
        target_users = [r["email"] for r in cursor.fetchall()]
    else:
        cursor.execute("SELECT email FROM users ORDER BY id ASC;")
        target_users = [r["email"] for r in cursor.fetchall()]

    rel_multipliers = {
        "leader": 1.25,
        "peer": 1.00,
        "subordinate": 1.10,
        "self": 0.65
    }

    comps = ["lideranca", "gestao", "visao_sistemica", "orientacao_resultados", "autoconhecimento"]
    results = []

    for email in target_users:
        hard_data = get_member_hard_metrics(email, conn=conn)
        if not hard_data:
            continue

        hard_scores = hard_data["scores"]

        # Buscar avaliações 360º
        cursor.execute("""
        SELECT evaluator_email, relationship_type,
               score_lideranca, score_gestao, score_visao_sistemica, score_orientacao_resultados, score_autoconhecimento,
               feedback_qualitativo
        FROM performance_evaluations_360
        WHERE LOWER(evaluatee_email) = LOWER(?) AND status = 'submitted';
        """, (email,))
        evals = [dict(r) for r in cursor.fetchall()]

        soft_weighted = {}
        if evals:
            for c in comps:
                total_weight = 0.0
                weighted_sum = 0.0
                col_name = f"score_{c}"
                for ev in evals:
                    eval_email = ev["evaluator_email"].lower()
                    calib = evaluator_calibs.get(eval_email, {"assertiveness_weight": 1.0})
                    w_assert = calib["assertiveness_weight"]
                    rel_mult = rel_multipliers.get(ev["relationship_type"], 1.0)
                    eff_weight = w_assert * rel_mult

                    score_100 = ev[col_name] * 20.0
                    weighted_sum += eff_weight * score_100
                    total_weight += eff_weight

                soft_weighted[c] = round(weighted_sum / total_weight, 1) if total_weight > 0 else 70.0
        else:
            # Baseline baseado na média de assiduidade e histórico se ainda não avaliado
            base_score = min(85.0, max(65.0, hard_scores["assiduidade_score"] * 0.85))
            soft_weighted = {c: round(base_score, 1) for c in comps}

        # Mapeamento do Hard Data correspondente para cada competência BJ
        hard_orientacao = 0.60 * ((hard_scores["conversion_score"] + hard_scores["revenue_score"]) / 2.0) + 0.40 * hard_scores["assiduidade_score"]
        hard_gestao = 0.70 * hard_scores["project_punctuality_score"] + 0.30 * hard_scores["assiduidade_score"]
        hard_lideranca = 0.60 * hard_scores["assiduidade_score"] + 0.40 * hard_scores["project_punctuality_score"]
        hard_visao = 0.50 * hard_scores["conversion_score"] + 0.50 * hard_scores["project_punctuality_score"]
        hard_autoconhecimento = 0.70 * hard_scores["assiduidade_score"] + 0.30 * hard_scores["project_punctuality_score"]

        # Triangulação Fim-a-Fim (Hard Data vs. Soft Data Calibrado)
        triangulated = {
            "lideranca": round(0.60 * soft_weighted["lideranca"] + 0.40 * hard_lideranca, 1),
            "gestao": round(0.45 * soft_weighted["gestao"] + 0.55 * hard_gestao, 1),
            "visao_sistemica": round(0.50 * soft_weighted["visao_sistemica"] + 0.50 * hard_visao, 1),
            "orientacao_resultados": round(0.50 * soft_weighted["orientacao_resultados"] + 0.50 * hard_orientacao, 1),
            "autoconhecimento": round(0.65 * soft_weighted["autoconhecimento"] + 0.35 * hard_autoconhecimento, 1)
        }

        overall_triangulated = round(sum(triangulated.values()) / 5.0, 1)

        # Atualizar score triangulado no PDI mais recente do membro
        try:
            cursor.execute("""
            UPDATE pdis SET triangulated_score = ?
            WHERE LOWER(user_email) = LOWER(?) AND status != 'concluido';
            """, (overall_triangulated, email))
        except Exception:
            pass

        sorted_comps = sorted(triangulated.items(), key=lambda x: x[1], reverse=True)
        strengths = [s[0] for s in sorted_comps if s[1] >= 75.0]
        chronic_gaps = [s[0] for s in sorted_comps if s[1] < 68.0]

        res_item = {
            "user_email": email,
            "nome": hard_data["nome"],
            "area": hard_data["area"],
            "role": hard_data["role"],
            "cargo": hard_data["cargo"],
            "evaluations_count": len(evals),
            "hard_data": hard_data,
            "soft_scores_calibrated": soft_weighted,
            "triangulated_competencies": triangulated,
            "overall_triangulated_score": overall_triangulated,
            "strengths": strengths,
            "chronic_gaps": chronic_gaps
        }
        results.append(res_item)

    conn.commit()
    conn.close()

    if user_email:
        return results[0] if results else {}
    return results


def calculate_succession_ips(user_email: Optional[str] = None, role_target: str = "diretoria") -> Union[dict, List[dict]]:
    """
    Calcula o Índice de Prontidão Preditiva para Sucessão (IPS) (0 a 100):
    - Correlaciona o desempenho atual do assessor com o perfil histórico de gestores
      que passaram pela EJ com alto desempenho validado pelas auditorias da federação (Selo EJ 100%).
    - Se o IPS estiver abaixo da linha de corte de governança (70 para diretoria, 80 para presidência),
      restringe automaticamente a elegibilidade para cargos executivos.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Buscar perfil histórico oficial da federação
    cursor.execute("""
    SELECT * FROM historical_manager_benchmarks 
    WHERE role_target = ? 
    ORDER BY id DESC LIMIT 1;
    """, (role_target,))
    bench = cursor.fetchone()
    if not bench:
        cursor.execute("SELECT * FROM historical_manager_benchmarks ORDER BY id DESC LIMIT 1;")
        bench = cursor.fetchone()

    bench_dict = dict(bench) if bench else {
        "manager_name": "Benchmark Federativo",
        "mandate_year": "2024-2025",
        "lideranca_score": 85.0, "gestao_score": 85.0, "visao_sistemica_score": 80.0,
        "orientacao_resultados_score": 85.0, "autoconhecimento_score": 80.0,
        "conversion_rate": 25.0, "project_punctuality_rate": 95.0, "assiduidade_rate": 96.0,
        "federation_audit_score": 100.0
    }

    # Vetor canônico de benchmark (5 competências + excelência operacional hard + assiduidade)
    bench_vec = [
        float(bench_dict["lideranca_score"]),
        float(bench_dict["gestao_score"]),
        float(bench_dict["visao_sistemica_score"]),
        float(bench_dict["orientacao_resultados_score"]),
        float(bench_dict["autoconhecimento_score"]),
        88.0,  # Benchmark Hard Performance
        float(bench_dict["assiduidade_rate"])
    ]

    triangulations = calculate_triangulation(user_email)
    if isinstance(triangulations, dict):
        triang_list = [triangulations] if triangulations else []
    else:
        triang_list = triangulations

    cutoff = 80.0 if role_target == "presidencia" else 70.0
    min_comp_threshold = 65.0 if role_target == "presidencia" else 55.0

    results = []
    comp_labels = ["Liderança", "Gestão", "Visão Sistêmica", "Orientação para Resultados", "Autoconhecimento", "Desempenho Operacional", "Assiduidade"]

    for triang in triang_list:
        tc = triang["triangulated_competencies"]
        hs = triang["hard_data"]["scores"]

        # Vetor do membro avaliado
        member_vec = [
            tc["lideranca"],
            tc["gestao"],
            tc["visao_sistemica"],
            tc["orientacao_resultados"],
            tc["autoconhecimento"],
            hs["overall_hard_score"],
            hs["assiduidade_score"]
        ]

        # Similaridade Cosseno multidimensional
        dot = sum(m * b for m, b in zip(member_vec, bench_vec))
        mag_m = math.sqrt(sum(m * m for m in member_vec))
        mag_b = math.sqrt(sum(b * b for b in bench_vec))
        cossim = (dot / (mag_m * mag_b)) if (mag_m > 0 and mag_b > 0) else 0.0

        # Penalidades por gaps severos em relação ao benchmark histórico
        gap_penalty = 0.0
        critical_deficits = []
        for idx, (m_val, b_val) in enumerate(zip(member_vec, bench_vec)):
            gap = b_val - m_val
            if gap > 10.0:
                pen_item = (gap - 10.0) * 0.45
                gap_penalty += pen_item
                critical_deficits.append({
                    "competency": comp_labels[idx],
                    "member_score": round(m_val, 1),
                    "benchmark_score": round(b_val, 1),
                    "gap": round(gap, 1)
                })

        hard_score = hs["overall_hard_score"]
        soft_score = sum(triang["soft_scores_calibrated"].values()) / 5.0

        # Fórmula Probabilística do IPS (0 a 100)
        raw_ips = 0.35 * hard_score + 0.35 * soft_score + 0.30 * (cossim * 100.0) - gap_penalty
        ips = round(min(100.0, max(0.0, raw_ips)), 1)

        # Restrição de Elegibilidade Executiva por Governança
        min_comp_passed = all(tc[c] >= min_comp_threshold for c in ["lideranca", "gestao", "visao_sistemica", "orientacao_resultados", "autoconhecimento"])
        is_eligible = (ips >= cutoff) and min_comp_passed

        restriction_reason = None
        if not is_eligible:
            reasons = []
            if ips < cutoff:
                reasons.append(f"IPS de {ips} pontos está abaixo da linha de corte de governança ({cutoff} pts) para o cargo pretendido ({role_target.capitalize()}).")
            if not min_comp_passed:
                failed = [f"{c.capitalize()} ({tc[c]:.1f} < {min_comp_threshold})" for c in tc if tc[c] < min_comp_threshold]
                reasons.append(f"Competências críticas abaixo do limiar mínimo obrigatório: {', '.join(failed)}.")
            if critical_deficits:
                def_str = ', '.join([f"{d['competency']} (gap: -{d['gap']} pts)" for d in critical_deficits[:2]])
                reasons.append(f"Déficits em relação aos gestores históricos com Selo EJ: {def_str}.")
            restriction_reason = " ".join(reasons)

        details_str = json.dumps({
            "triangulated": tc,
            "hard_scores": hs,
            "critical_deficits": critical_deficits,
            "cossim": round(cossim, 3),
            "gap_penalty": round(gap_penalty, 1)
        })

        # Persistir ou atualizar em succession_readiness_records
        cursor.execute("""
        SELECT id FROM succession_readiness_records 
        WHERE LOWER(user_email) = LOWER(?) AND role_target = ?;
        """, (triang["user_email"], role_target))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
            UPDATE succession_readiness_records 
            SET ips_score = ?, hard_data_score = ?, soft_data_score = ?, similarity_to_benchmark = ?,
                is_eligible = ?, cutoff_threshold = ?, restriction_reason = ?, details_json = ?, calculated_at = CURRENT_TIMESTAMP
            WHERE id = ?;
            """, (ips, hard_score, soft_score, cossim, 1 if is_eligible else 0, cutoff, restriction_reason, details_str, existing["id"]))
        else:
            cursor.execute("""
            INSERT INTO succession_readiness_records (
                tenant_id, user_email, role_target, ips_score, hard_data_score, soft_data_score,
                similarity_to_benchmark, is_eligible, cutoff_threshold, restriction_reason, details_json
            ) VALUES ('edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (triang["user_email"], role_target, ips, hard_score, soft_score, cossim, 1 if is_eligible else 0, cutoff, restriction_reason, details_str))

        # Atualizar ips_score no PDI
        try:
            cursor.execute("""
            UPDATE pdis SET ips_score = ?
            WHERE LOWER(user_email) = LOWER(?) AND status != 'concluido';
            """, (ips, triang["user_email"]))
        except Exception:
            pass

        results.append({
            "user_email": triang["user_email"],
            "nome": triang["nome"],
            "area": triang["area"],
            "role": triang["role"],
            "cargo": triang["cargo"],
            "role_target": role_target,
            "ips_score": ips,
            "hard_data_score": round(hard_score, 1),
            "soft_data_score": round(soft_score, 1),
            "similarity_to_benchmark": round(cossim, 3),
            "is_eligible": is_eligible,
            "cutoff_threshold": cutoff,
            "status_sucessao": "Apto para Sucessão Executiva" if is_eligible else "Restrição de Governança Ativa",
            "restriction_reason": restriction_reason,
            "critical_deficits": critical_deficits,
            "benchmark_referencia": {
                "manager_name": bench_dict.get("manager_name", "Gestor Benchmark"),
                "mandate_year": bench_dict.get("mandate_year", "2024-2025"),
                "federation_audit_score": bench_dict.get("federation_audit_score", 100.0)
            }
        })

    conn.commit()
    conn.close()

    if user_email:
        return results[0] if results else {}
    return results


def generate_gap_mitigation_plan(user_email: str) -> dict:
    """
    Mitigação Automatizada de Gaps (Ação Corretiva em Tempo de Execução):
    - Identifica déficits crônicos a partir da triangulação.
    - Reconfigura a alocação prática do membro (70-20-10):
      * 70% On-the-job: Inserir assessores com lacunas como co-responsáveis em projetos complexos ou negociações CRM.
      * 20% Social: Mentoria pareada com diretor sênior de alto desempenho.
      * 10% Formal: Playbooks técnicos e capacitações da Brasil Júnior.
    - Persiste em gap_mitigation_actions e atualiza o PDI ativo em pdis.
    """
    conn = get_connection()
    cursor = conn.cursor()

    triang = calculate_triangulation(user_email)
    if not triang:
        conn.close()
        return {"error": "Colaborador não encontrado"}

    tc = triang["triangulated_competencies"]
    user_area = triang["area"]
    user_nome = triang["nome"]

    # Catálogo de ações práticas de nivelamento orientadas pelo modelo da Brasil Júnior
    mitigation_catalog = {
        "orientacao_resultados": {
            "title": "Orientação para Resultados (Negociação & Conversão)",
            "practical": f"Inserção imediata de {user_nome} como co-responsável em 3 negociações de grande porte no CRM pareado com a Diretora Comercial (Isadora Epichin), participando ativamente do diagnóstico, proposta e fechamento.",
            "mentor": "isadora.epichin@edvjr.com.br",
            "study": "Playbook Oficial de Vendas e Negociação Avançada EDV Jr. (Técnicas SPIN Selling para RMs)."
        },
        "gestao": {
            "title": "Gestão (Controle de Processos & Cronograma)",
            "practical": f"Alocação de {user_nome} como co-gestor de sprint no Controle de RMs com Thais Junger, assumindo a fiscalização semanal de prazos e conformidade regulatória no INPI.",
            "mentor": "thais.junger@edvjr.com.br",
            "study": "Manual POP-VPGG-04 de Gestão de Projetos e Prazos Regulatórios."
        },
        "lideranca": {
            "title": "Liderança (Mobilização & Comunicação)",
            "practical": f"Designação de {user_nome} para a liderança e condução da dinâmica de grupo na próxima etapa do Processo Seletivo (PSEL) e facilitação de uma Reunião Geral de alinhamento.",
            "mentor": "charles.junior@edvjr.com.br",
            "study": "Diretrizes de Liderança MEJ e Formação de Sucessores da Brasil Júnior."
        },
        "visao_sistemica": {
            "title": "Visão Sistêmica (Intersetorial & Ecossistema)",
            "practical": f"Co-participação na força-tarefa de auditoria das certidões e estatuto social do Selo EJ 2026 junto à Presidência e VPGG (Alice Ney), analisando o impacto interdepartamental.",
            "mentor": "alice.ney@edvjr.com.br",
            "study": "Regulamento e Critérios de Auditoria do Selo EJ (Edital Oficial 2026)."
        },
        "autoconhecimento": {
            "title": "Autoconhecimento (Feedback & Desenvolvimento)",
            "practical": f"Ciclo quinzenal de One-on-One intensivo com a VPGG (Alice Ney) com estruturação de diário de bordo e autoavaliação reflexiva de competências.",
            "mentor": "alice.ney@edvjr.com.br",
            "study": "Guia Prático de Inteligência Emocional e Escuta Ativa nas Relações MEJ."
        }
    }

    # Identificar competências com maior necessidade de mitigação
    gaps_to_mitigate = []
    for comp_key, comp_score in tc.items():
        if comp_score < 72.0:
            severity = "critico" if comp_score < 60.0 else ("alto" if comp_score < 66.0 else "medio")
            gaps_to_mitigate.append({
                "key": comp_key,
                "score": comp_score,
                "severity": severity,
                **mitigation_catalog[comp_key]
            })

    # Se não houver gaps < 72, mitigar a menor competência para nivelamento preventivo
    if not gaps_to_mitigate:
        lowest_comp = min(tc.items(), key=lambda x: x[1])
        gaps_to_mitigate.append({
            "key": lowest_comp[0],
            "score": lowest_comp[1],
            "severity": "medio",
            **mitigation_catalog[lowest_comp[0]]
        })

    created_actions = []
    action_plan_text = f"PLANO DE MITIGAÇÃO AUTOMATIZADA 70-20-10 (EDbrain - {user_nome}):\n"

    for g in gaps_to_mitigate:
        # Registrar em gap_mitigation_actions se não existir ativo
        cursor.execute("""
        SELECT id FROM gap_mitigation_actions 
        WHERE LOWER(user_email) = LOWER(?) AND competency_deficient = ? AND status = 'em_execucao';
        """, (user_email, g["title"]))
        row = cursor.fetchone()

        if not row:
            cursor.execute("""
            INSERT INTO gap_mitigation_actions (
                tenant_id, user_email, competency_deficient, current_score, target_score,
                deficit_severity, action_type, practical_allocation, mentor_assigned,
                course_or_playbook, status, deadline
            ) VALUES (
                'edv_jr', ?, ?, ?, 80.0,
                ?, '70_on_the_job', ?, ?,
                ?, 'em_execucao', '2026-06-30'
            );
            """, (user_email, g["title"], g["score"], g["severity"], g["practical"], g["mentor"], g["study"]))
            action_id = cursor.lastrowid
            action_record = {
                "id": action_id,
                "user_email": user_email,
                "competency_deficient": g["title"],
                "action_type": "70_on_the_job",
                "practical_allocation": g["practical"],
                "mentor_assigned": g["mentor"],
                "course_or_playbook": g["study"],
                "current_score": g["score"],
                "deficit_severity": g["severity"],
                "status": "em_execucao"
            }
            created_actions.append(action_record)
        else:
            action_record = {
                "id": row["id"],
                "user_email": user_email,
                "competency_deficient": g["title"],
                "action_type": "70_on_the_job",
                "practical_allocation": g["practical"],
                "mentor_assigned": g["mentor"],
                "course_or_playbook": g["study"],
                "current_score": g["score"],
                "deficit_severity": g["severity"],
                "status": "em_execucao"
            }
            created_actions.append(action_record)

        action_plan_text += f"\n• Competência: {g['title']} (Score atual: {g['score']:.1f} | Severidade: {g['severity'].upper()})\n"
        action_plan_text += f"  - 70% Experiencial (On-the-Job): {g['practical']}\n"
        action_plan_text += f"  - 20% Social (Mentoria): Pareamento com {g['mentor']}\n"
        action_plan_text += f"  - 10% Formal (Estudo): {g['study']}\n"

    # Atualizar ou criar o PDI na tabela pdis
    cursor.execute("SELECT id FROM pdis WHERE LOWER(user_email) = LOWER(?) ORDER BY id DESC LIMIT 1;", (user_email,))
    pdi_row = cursor.fetchone()

    if pdi_row:
        cursor.execute("""
        UPDATE pdis 
        SET action_plan_70_20_10 = ?, status = 'em_andamento'
        WHERE id = ?;
        """, (action_plan_text, pdi_row["id"]))
    else:
        cursor.execute("""
        INSERT INTO pdis (
            user_email, area, competency_mej, objectives, development_ideas, deadline, status, action_plan_70_20_10
        ) VALUES (
            ?, ?, 'Orientação para Resultados',
            'Superar lacunas de desempenho e acelerar prontidão sucessória via alocação prática guiada.',
            'Co-responsabilidade em projetos complexos e negociações de fechamento do CRM.',
            '2026-06-30', 'em_andamento', ?
        );
        """, (user_email, user_area, action_plan_text))

    conn.commit()
    conn.close()

    return {
        "user_email": user_email,
        "nome": user_nome,
        "area": user_area,
        "action_plan_70_20_10": action_plan_text,
        "mitigation_actions": created_actions
    }


def save_evaluation_360(eval_data: dict, current_user_email: str) -> dict:
    """
    Registra uma nova avaliação 360º oficial alinhada às competências Brasil Júnior.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO performance_evaluations_360 (
        tenant_id, cycle_id, evaluatee_email, evaluator_email, relationship_type,
        score_lideranca, score_gestao, score_visao_sistemica, score_orientacao_resultados, score_autoconhecimento,
        feedback_qualitativo, status
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    );
    """, (
        eval_data.get("tenant_id", "edv_jr"),
        eval_data.get("cycle_id", "2026.1"),
        eval_data["evaluatee_email"].strip().lower(),
        current_user_email.strip().lower(),
        eval_data.get("relationship_type", "peer"),
        float(eval_data.get("score_lideranca", 3.0)),
        float(eval_data.get("score_gestao", 3.0)),
        float(eval_data.get("score_visao_sistemica", 3.0)),
        float(eval_data.get("score_orientacao_resultados", 3.0)),
        float(eval_data.get("score_autoconhecimento", 3.0)),
        eval_data.get("feedback_qualitativo", ""),
        eval_data.get("status", "submitted")
    ))
    eval_id = cursor.lastrowid

    # Incrementar contador de avaliações do avaliador
    cursor.execute("""
    UPDATE evaluator_calibrations 
    SET total_evaluations_count = total_evaluations_count + 1
    WHERE LOWER(evaluator_email) = LOWER(?);
    """, (current_user_email.strip(),))

    conn.commit()

    # Recalcular triangulação do avaliado
    cursor.execute("SELECT * FROM performance_evaluations_360 WHERE id = ?;", (eval_id,))
    created_eval = dict(cursor.fetchone())
    conn.close()

    # Trigger triangulation update
    try:
        calculate_triangulation(created_eval["evaluatee_email"])
    except Exception:
        pass

    return created_eval


def list_evaluations_360(evaluatee_email: Optional[str] = None) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    if evaluatee_email:
        cursor.execute("SELECT * FROM performance_evaluations_360 WHERE LOWER(evaluatee_email) = LOWER(?) ORDER BY id DESC;", (evaluatee_email.strip(),))
    else:
        cursor.execute("SELECT * FROM performance_evaluations_360 ORDER BY id DESC;")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def list_gap_mitigation_actions(user_email: Optional[str] = None) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    if user_email:
        cursor.execute("SELECT * FROM gap_mitigation_actions WHERE LOWER(user_email) = LOWER(?) ORDER BY id DESC;", (user_email.strip(),))
    else:
        cursor.execute("SELECT * FROM gap_mitigation_actions ORDER BY id DESC;")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def list_historical_benchmarks(role_target: Optional[str] = None) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    if role_target:
        cursor.execute("SELECT * FROM historical_manager_benchmarks WHERE role_target = ? ORDER BY id DESC;", (role_target,))
    else:
        cursor.execute("SELECT * FROM historical_manager_benchmarks ORDER BY id DESC;")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ==============================================================================
# SUBSISTEMA 1: ESTATUTOS E COMPLIANCE MEJ (LEI 13.267/2016 & SELO EJ)
# ==============================================================================

def list_compliance_statutes(norm_type: Optional[str] = None, status: Optional[str] = None, responsible_area: Optional[str] = None) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM statutes_compliance WHERE 1=1"
    params = []
    if norm_type:
        query += " AND norm_type = ?"
        params.append(norm_type)
    if status:
        query += " AND status = ?"
        params.append(status)
    if responsible_area:
        query += " AND responsible_area = ?"
        params.append(responsible_area)
    query += " ORDER BY id ASC;"
    
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    for r in rows:
        if r.get("checklist_items"):
            try:
                r["checklist_items"] = json.loads(r["checklist_items"])
            except Exception:
                r["checklist_items"] = []
        else:
            r["checklist_items"] = []
    return rows


def get_compliance_statute_by_id(statute_id: int) -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM statutes_compliance WHERE id = ?;", (statute_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    res = dict(row)
    if res.get("checklist_items"):
        try:
            res["checklist_items"] = json.loads(res["checklist_items"])
        except Exception:
            res["checklist_items"] = []
    else:
        res["checklist_items"] = []
    return res


def create_compliance_statute(data: dict, current_user_email: str) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    
    checklist = data.get("checklist_items", [])
    if isinstance(checklist, list):
        checklist_json = json.dumps(checklist)
        total_items = len(checklist)
        if total_items > 0:
            compliant_items = sum(1 for item in checklist if item.get("compliant") is True)
            score = round((compliant_items / total_items) * 100.0, 1)
        else:
            score = 100.0
    else:
        checklist_json = "[]"
        score = 100.0
        
    cursor.execute("""
    INSERT INTO statutes_compliance (
        tenant_id, title, norm_type, version, status, effective_date, review_deadline,
        responsible_area, responsible_role, document_url, description, checklist_items,
        conformity_score, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        data.get("tenant_id", "edv_jr"),
        data["title"].strip(),
        data["norm_type"],
        data.get("version", "v1.0"),
        data.get("status", "vigente"),
        data["effective_date"],
        data.get("review_deadline"),
        data["responsible_area"],
        data.get("responsible_role", "diretor"),
        data.get("document_url", ""),
        data.get("description", ""),
        checklist_json,
        score,
        current_user_email
    ))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log_audit(
        user_email=current_user_email,
        action="CREATE_COMPLIANCE_STATUTE",
        resource="/api/compliance/statutes",
        status_code=201,
        details=f"Criada norma {data['title']} (ID: {new_id}, Tipo: {data['norm_type']})"
    )
    return get_compliance_statute_by_id(new_id)


def update_compliance_statute(statute_id: int, data: dict, current_user_email: str) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM statutes_compliance WHERE id = ?;", (statute_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise ValueError(f"Norma de compliance ID {statute_id} não encontrada.")
        
    title = data.get("title", existing["title"])
    norm_type = data.get("norm_type", existing["norm_type"])
    version = data.get("version", existing["version"])
    status = data.get("status", existing["status"])
    effective_date = data.get("effective_date", existing["effective_date"])
    review_deadline = data.get("review_deadline", existing["review_deadline"])
    responsible_area = data.get("responsible_area", existing["responsible_area"])
    responsible_role = data.get("responsible_role", existing["responsible_role"])
    document_url = data.get("document_url", existing["document_url"])
    description = data.get("description", existing["description"])
    
    checklist = data.get("checklist_items")
    if checklist is not None:
        checklist_json = json.dumps(checklist)
        total_items = len(checklist)
        score = round((sum(1 for i in checklist if i.get("compliant") is True) / total_items) * 100.0, 1) if total_items > 0 else 100.0
    else:
        checklist_json = existing["checklist_items"]
        score = existing["conformity_score"]
        
    cursor.execute("""
    UPDATE statutes_compliance
    SET title = ?, norm_type = ?, version = ?, status = ?, effective_date = ?,
        review_deadline = ?, responsible_area = ?, responsible_role = ?,
        document_url = ?, description = ?, checklist_items = ?, conformity_score = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?;
    """, (
        title, norm_type, version, status, effective_date, review_deadline,
        responsible_area, responsible_role, document_url, description, checklist_json, score, statute_id
    ))
    conn.commit()
    conn.close()
    
    log_audit(
        user_email=current_user_email,
        action="UPDATE_COMPLIANCE_STATUTE",
        resource=f"/api/compliance/statutes/{statute_id}",
        status_code=200,
        details=f"Atualizada norma ID {statute_id} ({title}) - Score de conformidade: {score}%"
    )
    return get_compliance_statute_by_id(statute_id)


def update_statute_checklist(statute_id: int, checklist_items: list, current_user_email: str) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM statutes_compliance WHERE id = ?;", (statute_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise ValueError(f"Norma ID {statute_id} não encontrada.")
        
    checklist_json = json.dumps(checklist_items)
    total_items = len(checklist_items)
    score = round((sum(1 for i in checklist_items if i.get("compliant") is True) / total_items) * 100.0, 1) if total_items > 0 else 100.0
    
    cursor.execute("""
    UPDATE statutes_compliance
    SET checklist_items = ?, conformity_score = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?;
    """, (checklist_json, score, statute_id))
    conn.commit()
    conn.close()
    
    log_audit(
        user_email=current_user_email,
        action="UPDATE_STATUTE_CHECKLIST",
        resource=f"/api/compliance/statutes/{statute_id}/checklist",
        status_code=200,
        details=f"Atualizado checklist da norma ID {statute_id} ({existing['title']}) para {score}%"
    )
    return get_compliance_statute_by_id(statute_id)


def delete_compliance_statute(statute_id: int, current_user_email: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT title FROM statutes_compliance WHERE id = ?;", (statute_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
    title = row["title"]
    cursor.execute("DELETE FROM statutes_compliance WHERE id = ?;", (statute_id,))
    conn.commit()
    conn.close()
    log_audit(
        user_email=current_user_email,
        action="DELETE_COMPLIANCE_STATUTE",
        resource=f"/api/compliance/statutes/{statute_id}",
        status_code=200,
        details=f"Removida norma de compliance ID {statute_id} ({title})"
    )
    return True


# ==============================================================================
# SUBSISTEMA 2: MOTOR DE NOTIFICAÇÕES DINÂMICAS COM RBAC
# ==============================================================================

def create_system_notification(
    recipient_email: str,
    title: str,
    message: str,
    category: str,
    priority: str = "normal",
    target_role: Optional[str] = None,
    target_area: Optional[str] = None,
    link: Optional[str] = None,
    metadata: Optional[dict] = None
) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    metadata_json = json.dumps(metadata) if metadata else None
    cursor.execute("""
    INSERT INTO system_notifications (
        tenant_id, recipient_email, target_role, target_area, title, message,
        category, priority, link, is_read, email_sent, metadata_json
    ) VALUES ('edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?);
    """, (
        recipient_email.strip(),
        target_role,
        target_area,
        title.strip(),
        message.strip(),
        category,
        priority,
        link,
        metadata_json
    ))
    new_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM system_notifications WHERE id = ?;", (new_id,))
    created = dict(cursor.fetchone())
    conn.close()
    return created


def get_user_notifications(
    user_email: str,
    user_role: str,
    user_area: str,
    unread_only: bool = False,
    limit: int = 50
) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    
    user_email_clean = user_email.lower().strip()
    is_leadership = user_role in ["presidente", "diretor", "vice_presidente"]
    
    # Monta filtros RBAC estritos
    # Notificação destinada a:
    # 1. Este e-mail exato
    # 2. 'ALL' (todos da EJ)
    # 3. 'ROLE:{user_role}'
    # 4. 'ROLE:diretor' caso o usuário seja da liderança
    # 5. target_role / target_area match
    query = """
    SELECT * FROM system_notifications
    WHERE (
        LOWER(recipient_email) = ?
        OR recipient_email = 'ALL'
        OR LOWER(recipient_email) = ?
        OR (? = 1 AND LOWER(recipient_email) IN ('role:diretor', 'role:lideranca', 'role:presidencia'))
        OR (
            (target_role IS NULL OR target_role = ? OR (? = 1 AND target_role IN ('diretor', 'lideranca')))
            AND
            (target_area IS NULL OR target_area = ? OR ? = 1)
        )
    )
    """
    params = [
        user_email_clean,
        f"role:{user_role}".lower(),
        1 if is_leadership else 0,
        user_role,
        1 if is_leadership else 0,
        user_area,
        1 if is_leadership else 0
    ]
    
    if unread_only:
        query += " AND is_read = 0"
        
    query += " ORDER BY id DESC LIMIT ?;"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    for r in rows:
        if r.get("metadata_json"):
            try:
                r["metadata"] = json.loads(r["metadata_json"])
            except Exception:
                r["metadata"] = {}
        else:
            r["metadata"] = {}
    return rows


def mark_notification_as_read(notification_id: int, user_email: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE system_notifications
    SET is_read = 1
    WHERE id = ?;
    """, (notification_id,))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


def mark_all_notifications_as_read(user_email: str, user_role: str = "", user_area: str = "") -> int:
    conn = get_connection()
    cursor = conn.cursor()
    user_email_clean = user_email.lower().strip()
    is_leadership = user_role in ["presidente", "diretor", "vice_presidente"]
    
    cursor.execute("""
    UPDATE system_notifications
    SET is_read = 1
    WHERE is_read = 0 AND (
        LOWER(recipient_email) = ?
        OR recipient_email = 'ALL'
        OR LOWER(recipient_email) = ?
        OR (? = 1 AND LOWER(recipient_email) IN ('role:diretor', 'role:lideranca', 'role:presidencia'))
        OR (
            (target_role IS NULL OR target_role = ? OR (? = 1 AND target_role IN ('diretor', 'lideranca')))
            AND
            (target_area IS NULL OR target_area = ? OR ? = 1)
        )
    );
    """, (
        user_email_clean,
        f"role:{user_role}".lower(),
        1 if is_leadership else 0,
        user_role,
        1 if is_leadership else 0,
        user_area,
        1 if is_leadership else 0
    ))
    count = cursor.rowcount
    conn.commit()
    conn.close()
    return count


def scan_and_create_deadlines() -> dict:
    """
    Rotina de varredura ativa para geração de notificações dinâmicas
    de prazos críticos (CRM, Selo EJ/Compliance, PDI, Staging pendente).
    Garante idempotência evitando alertas duplicados nas últimas 24 horas.
    """
    conn = get_connection()
    cursor = conn.cursor()
    today_str = datetime.now().strftime("%Y-%m-%d")
    today_dt = datetime.now()
    created_count = 0
    
    # 1. Prazos de Follow-ups do CRM / Radar
    cursor.execute("""
    SELECT id, razao_social, client_name, created_by, area, next_followup_date, status
    FROM client_followups
    WHERE status NOT IN ('concluido', 'fechado', 'perdido')
      AND next_followup_date IS NOT NULL AND next_followup_date != '';
    """)
    followups = [dict(r) for r in cursor.fetchall()]
    
    for f in followups:
        f_date = f["next_followup_date"]
        try:
            dt = datetime.strptime(f_date[:10], "%Y-%m-%d")
            diff_days = (dt.date() - today_dt.date()).days
            
            # Verifica se já foi notificado nas últimas 24h
            notif_title = ""
            notif_msg = ""
            cat = ""
            prio = "normal"
            empresa = f.get("razao_social") or f.get("client_name") or "Lead"
            
            if diff_days < 0:
                cat = "deadline_overdue"
                prio = "critical"
                notif_title = f"Prazo Vencido: Follow-up {empresa}"
                notif_msg = f"O follow-up com {empresa} venceu há {abs(diff_days)} dia(s) ({f_date}). Atualize o CRM com urgência."
            elif diff_days <= 2:
                cat = "deadline_warning"
                prio = "high"
                notif_title = f"Prazo Próximo: Reunião / Contato {empresa}"
                notif_msg = f"Follow-up agendado para {f_date} (em {diff_days} dia(s)). Prepare o diagnóstico e a proposta comercial."
                
            if notif_title:
                cursor.execute("""
                SELECT COUNT(*) FROM system_notifications
                WHERE title = ? AND created_at >= datetime('now', '-1 day');
                """, (notif_title,))
                if cursor.fetchone()[0] == 0:
                    recipient = f.get("created_by") or "ROLE:diretor"
                    cursor.execute("""
                    INSERT INTO system_notifications (
                        tenant_id, recipient_email, target_role, target_area, title, message, category, priority, link, is_read, email_sent
                    ) VALUES ('edv_jr', ?, 'assessor', ?, ?, ?, ?, ?, '#crm', 0, 0);
                    """, (recipient, f.get("area") or "Comercial", notif_title, notif_msg, cat, prio))
                    created_count += 1
        except Exception:
            continue
            
    # 2. Prazos de Revisão de Estatutos e Selo EJ
    cursor.execute("""
    SELECT id, title, review_deadline, responsible_area, responsible_role
    FROM statutes_compliance
    WHERE status = 'vigente' AND review_deadline IS NOT NULL AND review_deadline != '';
    """)
    statutes = [dict(r) for r in cursor.fetchall()]
    for s in statutes:
        s_date = s["review_deadline"]
        try:
            dt = datetime.strptime(s_date[:10], "%Y-%m-%d")
            diff_days = (dt.date() - today_dt.date()).days
            if diff_days <= 15:
                notif_title = f"Auditoria Regulatória: {s['title']}"
                cursor.execute("""
                SELECT COUNT(*) FROM system_notifications
                WHERE title = ? AND created_at >= datetime('now', '-3 day');
                """, (notif_title,))
                if cursor.fetchone()[0] == 0:
                    prio = "critical" if diff_days < 0 else "high"
                    msg = f"A norma '{s['title']}' possui prazo de auditoria/revisão em {s_date} (restam {diff_days} dias). Verifique as certidões e checklist."
                    cursor.execute("""
                    INSERT INTO system_notifications (
                        tenant_id, recipient_email, target_role, target_area, title, message, category, priority, link, is_read, email_sent
                    ) VALUES ('edv_jr', 'ROLE:diretor', ?, ?, ?, ?, 'compliance', ?, '#pres-sub-estatutos', 0, 0);
                    """, (s["responsible_role"], s["responsible_area"], notif_title, msg, prio))
                    created_count += 1
        except Exception:
            continue

    # 3. Prazos de Ações de PDI (Gaps de Competências)
    cursor.execute("""
    SELECT id, user_email, practical_allocation, deadline, competency_deficient
    FROM gap_mitigation_actions
    WHERE status IN ('sugerido', 'em_execucao') AND deadline IS NOT NULL AND deadline != '';
    """)
    gaps = [dict(r) for r in cursor.fetchall()]
    for g in gaps:
        g_date = g["deadline"]
        try:
            dt = datetime.strptime(g_date[:10], "%Y-%m-%d")
            diff_days = (dt.date() - today_dt.date()).days
            if diff_days <= 7:
                notif_title = f"PDI em Aberto: {g['competency_deficient']}"
                cursor.execute("""
                SELECT COUNT(*) FROM system_notifications
                WHERE title = ? AND LOWER(recipient_email) = ? AND created_at >= datetime('now', '-2 day');
                """, (notif_title, g["user_email"].lower().strip()))
                if cursor.fetchone()[0] == 0:
                    prio = "high" if diff_days < 0 else "normal"
                    msg = f"Sua meta de desenvolvimento em '{g['competency_deficient']}' ({g['practical_allocation']}) vence em {g_date}."
                    cursor.execute("""
                    INSERT INTO system_notifications (
                        tenant_id, recipient_email, target_role, target_area, title, message, category, priority, link, is_read, email_sent
                    ) VALUES ('edv_jr', ?, NULL, 'VPGG', ?, ?, 'pdi_milestone', ?, '#pdi-tab', 0, 0);
                    """, (g["user_email"].lower().strip(), notif_title, msg, prio))
                    created_count += 1
        except Exception:
            continue

    # 4. Alterações de RM em Staging pendentes de validação Four-Eyes
    cursor.execute("SELECT COUNT(*) FROM rm_staging_records WHERE status = 'pending_review';")
    pending_rm = cursor.fetchone()[0]
    if pending_rm > 0:
        notif_title = f"Governança RM: {pending_rm} alteração(ões) aguardando Dupla Verificação"
        cursor.execute("""
        SELECT COUNT(*) FROM system_notifications
        WHERE title = ? AND created_at >= datetime('now', '-12 hour');
        """, (notif_title,))
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
            INSERT INTO system_notifications (
                tenant_id, recipient_email, target_role, target_area, title, message, category, priority, link, is_read, email_sent
            ) VALUES (
                'edv_jr', 'ROLE:diretor', 'diretor', 'Projetos',
                ?,
                'Há propostas de alteração em Registro de Marcas no Staging aguardando aprovação por um segundo diretor (Maker-Checker).',
                'approval_pending', 'high', '#projetos-sub-staging', 0, 0
            );
            """, (notif_title,))
            created_count += 1

    conn.commit()
    conn.close()
    return {
        "status": "success",
        "scanned_at": datetime.now().isoformat(),
        "new_notifications_generated": created_count
    }


# ==============================================================================
# SUBSISTEMA 5: EDIÇÃO INDIRETA E SEGURA DE RM (STAGING & MAKER-CHECKER)
# ==============================================================================

def create_rm_staging_record(data: dict, current_user_email: str) -> dict:
    """
    Submete uma alteração ou criação de RM para a área de Staging.
    Nunca grava diretamente na base de dados oficial.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    proposed_data = data.get("proposed_data", {})
    if isinstance(proposed_data, dict):
        proposed_json = json.dumps(proposed_data)
    else:
        proposed_json = str(proposed_data)
        
    original_data = data.get("original_data")
    original_json = json.dumps(original_data) if original_data else None
    
    cursor.execute("""
    INSERT INTO rm_staging_records (
        tenant_id, batch_id, rm_code, brand_name, process_number,
        client_name, client_phone, responsible_name, phase, operation_type,
        original_data_json, proposed_data_json, status, submitted_by, applied_to_main_db
    ) VALUES (
        'edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', ?, 0
    );
    """, (
        data.get("batch_id"),
        data.get("rm_code", ""),
        data["brand_name"].strip(),
        data.get("process_number", ""),
        data["client_name"].strip(),
        data.get("client_phone", ""),
        data["responsible_name"].strip(),
        data.get("phase", "Busca de Anterioridade"),
        data.get("operation_type", "UPDATE"),
        original_json,
        proposed_json,
        current_user_email.strip().lower()
    ))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Notifica a liderança sobre a nova submissão em staging
    try:
        create_system_notification(
            recipient_email="ROLE:diretor",
            title=f"Nova proposta em Staging: {data['brand_name']}",
            message=f"O membro {current_user_email} enviou alteração na marca '{data['brand_name']}' para dupla verificação.",
            category="approval_pending",
            priority="high",
            target_role="diretor",
            target_area="Projetos",
            link="#projetos-sub-staging"
        )
    except Exception:
        pass
        
    log_audit(
        user_email=current_user_email,
        action="RM_STAGING_SUBMITTED",
        resource="/api/rm/staging",
        status_code=201,
        details=f"Proposta em Staging ID {new_id} ({data['brand_name']}, Op: {data.get('operation_type', 'UPDATE')}) enviada para aprovação Four-Eyes"
    )
    return get_rm_staging_record_by_id(new_id)


def list_rm_staging_records(status: Optional[str] = None) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    if status:
        cursor.execute("SELECT * FROM rm_staging_records WHERE status = ? ORDER BY id DESC;", (status,))
    else:
        cursor.execute("SELECT * FROM rm_staging_records ORDER BY id DESC;")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    for r in rows:
        if r.get("original_data_json"):
            try:
                r["original_data"] = json.loads(r["original_data_json"])
            except Exception:
                r["original_data"] = {}
        else:
            r["original_data"] = None
            
        if r.get("proposed_data_json"):
            try:
                r["proposed_data"] = json.loads(r["proposed_data_json"])
            except Exception:
                r["proposed_data"] = {}
        else:
            r["proposed_data"] = {}
    return rows


def get_rm_staging_record_by_id(staging_id: int) -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rm_staging_records WHERE id = ?;", (staging_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    res = dict(row)
    if res.get("original_data_json"):
        try:
            res["original_data"] = json.loads(res["original_data_json"])
        except Exception:
            res["original_data"] = {}
    else:
        res["original_data"] = None
        
    if res.get("proposed_data_json"):
        try:
            res["proposed_data"] = json.loads(res["proposed_data_json"])
        except Exception:
            res["proposed_data"] = {}
    else:
        res["proposed_data"] = {}
    return res


def approve_rm_staging_record(staging_id: int, reviewer_email: str, reviewer_role: str, review_notes: Optional[str] = None) -> dict:
    """
    Aprova a alteração em Staging com aplicação do Princípio Maker-Checker:
    O proponente (maker) NÃO PODE aprovar sua própria alteração.
    Apenas Diretores ou Presidência podem aprovar.
    """
    record = get_rm_staging_record_by_id(staging_id)
    if not record:
        raise ValueError(f"Registro de staging ID {staging_id} não encontrado.")
        
    if record["status"] != "pending_review":
        raise ValueError(f"Registro já se encontra no status '{record['status']}'.")
        
    # 1. Maker-Checker Enforcement
    maker_clean = record["submitted_by"].lower().strip()
    reviewer_clean = reviewer_email.lower().strip()
    if maker_clean == reviewer_clean:
        raise PermissionError(
            "Violação de Governança MEJ (Maker-Checker / Four-Eyes Principle): "
            "Você é o proponente (maker) desta alteração e não tem permissão para aprová-la. "
            "É obrigatória a revisão e chancela por um segundo diretor ou presidente."
        )
        
    # 2. Role Enforcement
    if reviewer_role.lower().strip() not in ["presidente", "diretor", "vice_presidente"]:
        raise PermissionError(
            "Apenas membros da Diretoria Executiva ou Presidência possuem prerrogativa de aprovação no Staging de Marcas."
        )
        
    conn = get_connection()
    cursor = conn.cursor()
    
    # Atualiza registro de staging
    cursor.execute("""
    UPDATE rm_staging_records
    SET status = 'approved',
        reviewed_by = ?,
        reviewed_at = CURRENT_TIMESTAMP,
        review_notes = ?,
        applied_to_main_db = 1,
        applied_at = CURRENT_TIMESTAMP
    WHERE id = ?;
    """, (reviewer_clean, review_notes or "Aprovado via Dupla Verificação", staging_id))
    
    conn.commit()
    conn.close()
    
    # Audit Log 2.0 com rastreabilidade completa Maker + Checker
    log_audit(
        user_email=reviewer_clean,
        action="RM_STAGING_APPROVED",
        resource=f"/api/rm/staging/{staging_id}/approve",
        status_code=200,
        details=f"Maker: {maker_clean} | Checker: {reviewer_clean} | Marca: {record['brand_name']} (ID: {staging_id}, Op: {record['operation_type']})"
    )
    
    # Notifica o Maker sobre a aprovação
    try:
        create_system_notification(
            recipient_email=maker_clean,
            title=f"Alteração Aprovada: {record['brand_name']}",
            message=f"Sua proposta de alteração em '{record['brand_name']}' foi aprovada por {reviewer_clean} e aplicada com sucesso.",
            category="compliance",
            priority="normal",
            link="#projetos-sub-staging"
        )
    except Exception:
        pass
        
    return get_rm_staging_record_by_id(staging_id)


def reject_rm_staging_record(staging_id: int, reviewer_email: str, reviewer_role: str, review_notes: str) -> dict:
    """
    Rejeita a alteração em Staging com justificativa obrigatória.
    """
    record = get_rm_staging_record_by_id(staging_id)
    if not record:
        raise ValueError(f"Registro de staging ID {staging_id} não encontrado.")
        
    if record["status"] != "pending_review":
        raise ValueError(f"Registro já se encontra no status '{record['status']}'.")
        
    if reviewer_role.lower().strip() not in ["presidente", "diretor", "vice_presidente"]:
        raise PermissionError("Apenas Diretores ou Presidência possuem autoridade para rejeitar propostas em Staging.")
        
    reviewer_clean = reviewer_email.lower().strip()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE rm_staging_records
    SET status = 'rejected',
        reviewed_by = ?,
        reviewed_at = CURRENT_TIMESTAMP,
        review_notes = ?
    WHERE id = ?;
    """, (reviewer_clean, review_notes.strip(), staging_id))
    conn.commit()
    conn.close()
    
    # Audit Log 2.0
    log_audit(
        user_email=reviewer_clean,
        action="RM_STAGING_REJECTED",
        resource=f"/api/rm/staging/{staging_id}/reject",
        status_code=200,
        details=f"Maker: {record['submitted_by']} | Checker: {reviewer_clean} | Marca: {record['brand_name']} | Motivo: {review_notes}"
    )
    
    # Notifica o Maker sobre a rejeição e o motivo
    try:
        create_system_notification(
            recipient_email=record["submitted_by"].lower().strip(),
            title=f"Alteração Rejeitada: {record['brand_name']}",
            message=f"Sua proposta de alteração em '{record['brand_name']}' foi rejeitada por {reviewer_clean}. Motivo: {review_notes}",
            category="compliance",
            priority="high",
            link="#projetos-sub-staging"
        )
    except Exception:
        pass
        
    return get_rm_staging_record_by_id(staging_id)


if __name__ == "__main__":
    init_db()

