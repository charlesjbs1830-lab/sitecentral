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
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, List, Dict, Union, Tuple

try:
    from learning_blocks_seed import INITIAL_LEARNING_MICROBLOCKS
except ImportError:
    from backend.learning_blocks_seed import INITIAL_LEARNING_MICROBLOCKS

DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")

VALID_ROLES = {"presidente", "diretor", "gerente", "assessor"}

from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey, DateTime, Boolean, func, create_engine

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

class MemberPDIBlockORM(Base):
    __tablename__ = "member_pdi_blocks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    user_email = Column(String(150), nullable=False, index=True)
    pdi_id = Column(Integer, nullable=True)
    microblock_code = Column(String(50), nullable=False)
    title = Column(String(200), nullable=False)
    competency_mej = Column(String(50), nullable=False)
    eixo = Column(String(50), nullable=False)
    area = Column(String(100), nullable=False)
    complexity = Column(Integer, default=1)
    description = Column(Text, nullable=False)
    deliverable_format = Column(String(100), nullable=True)
    evaluation_metric = Column(Text, nullable=True)
    sla_days = Column(Integer, default=30)
    deadline_date = Column(String(50), nullable=True)
    status = Column(String(50), nullable=False, default="pendente")  # pendente, em_andamento, concluido
    justificativa_algoritmica = Column(Text, nullable=True)
    singularidade_hash = Column(String(64), nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class ForumDuvidaORM(Base):
    __tablename__ = "forum_duvidas"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    author_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    author_email = Column(String(150), nullable=False)
    author_name = Column(String(150), nullable=False)
    author_area = Column(String(100), nullable=False)
    author_role = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), nullable=False, default="Geral")
    status = Column(String(50), nullable=False, default="aberta")  # aberta, em_andamento, resolvida
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    respostas = relationship("ForumRespostaORM", back_populates="duvida", cascade="all, delete-orphan")

class ForumRespostaORM(Base):
    __tablename__ = "forum_respostas"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    duvida_id = Column(Integer, ForeignKey("forum_duvidas.id"), nullable=False, index=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    author_email = Column(String(150), nullable=False)
    author_name = Column(String(150), nullable=False)
    author_area = Column(String(100), nullable=False)
    author_role = Column(String(50), nullable=False)
    content = Column(Text, nullable=False)
    is_solution = Column(Integer, default=0)
    created_at = Column(DateTime, server_default=func.now())
    duvida = relationship("ForumDuvidaORM", back_populates="respostas")

class LeadORM(Base):
    __tablename__ = "leads"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    client_name = Column(String(200), nullable=False)
    cnpj = Column(String(30), nullable=True)
    contact_person = Column(String(150), nullable=True)
    contact_email = Column(String(150), nullable=True)
    contact_phone = Column(String(50), nullable=True)
    estimated_value = Column(Float, nullable=False, default=0.0)
    etapa = Column(String(50), nullable=False, default="prospeccao")
    responsible = Column(String(150), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    contratos = relationship("ContratoRMORM", back_populates="lead", cascade="all, delete-orphan")

class ContratoRMORM(Base):
    __tablename__ = "contratos_rm"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="edv_jr")
    lead_id = Column(Integer, ForeignKey("leads.id"), nullable=False, index=True)
    brand_name = Column(String(200), nullable=False)
    client_name = Column(String(200), nullable=False)
    cnpj = Column(String(30), nullable=True)
    consultoria_escopo = Column(Text, nullable=False)
    prazo_dias = Column(Integer, default=60)
    prazo_entrega = Column(String(50), nullable=True)
    marcos_financeiros = Column(Text, nullable=True)
    valor_total = Column(Float, default=0.0)
    status_execucao = Column(String(50), nullable=False, default="ativo")
    responsavel_tecnico = Column(String(150), nullable=True)
    hash_integridade = Column(String(64), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    lead = relationship("LeadORM", back_populates="contratos")
    transacoes = relationship("TransacaoFinanceiraORM", back_populates="contrato")


class TransacaoFinanceiraORM(Base):
    __tablename__ = "transacoes_financeiras"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tipo = Column(String(20), nullable=False)
    categoria = Column(String(50), nullable=False)
    descricao = Column(Text, nullable=False)
    valor = Column(Float, nullable=False)
    data_vencimento = Column(String(20), nullable=False)
    data_pagamento = Column(String(20), nullable=True)
    status = Column(String(20), nullable=False, default="pendente")
    contrato_id = Column(Integer, ForeignKey("contratos_rm.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    contrato = relationship("ContratoRMORM", back_populates="transacoes")


class KBArtigoORM(Base):
    __tablename__ = "kb_artigos"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), default="edv_jr", nullable=False)
    titulo = Column(String(255), nullable=False)
    categoria = Column(String(50), nullable=False, index=True)
    conteudo = Column(Text, nullable=False)
    drive_url = Column(String(500), nullable=True)
    autor_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    autor_nome = Column(String(150), nullable=True)
    autor_email = Column(String(150), nullable=True)
    gerado_por_ia = Column(Boolean, default=False, nullable=False)
    trilha_derivada_id = Column(Integer, ForeignKey("pdis.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


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

    # 18. Tabela de Biblioteca de Micro-Entregáveis (Atomic Learning Blocks)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS learning_microblocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        code TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        competency_mej TEXT NOT NULL CHECK(competency_mej IN ('lideranca', 'gestao', 'visao_sistemica', 'orientacao_resultados', 'autoconhecimento')),
        eixo TEXT NOT NULL CHECK(eixo IN ('hard_skills', 'soft_skills')),
        area TEXT NOT NULL DEFAULT 'Cross-Setorial',
        hierarchical_level TEXT NOT NULL DEFAULT 'todos' CHECK(hierarchical_level IN ('assessor', 'gerente', 'diretor', 'presidente', 'todos')),
        complexity INTEGER NOT NULL DEFAULT 2 CHECK(complexity IN (1, 2, 3)),
        description TEXT NOT NULL,
        deliverable_format TEXT,
        evaluation_metric TEXT DEFAULT 'Aprovação formal e validação de conformidade técnica pela liderança',
        estimated_hours INTEGER DEFAULT 10,
        suggested_deadline_days INTEGER DEFAULT 30,
        keywords TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_microblocks_code ON learning_microblocks(code);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_microblocks_comp ON learning_microblocks(competency_mej);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_microblocks_eixo ON learning_microblocks(eixo);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_microblocks_area ON learning_microblocks(area);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_microblocks_level ON learning_microblocks(hierarchical_level);")

    # Migração defensiva para coluna evaluation_metric se tabela já existia
    try:
        cursor.execute("PRAGMA table_info(learning_microblocks);")
        mb_cols = [c[1] for c in cursor.fetchall()]
        if "evaluation_metric" not in mb_cols:
            cursor.execute("ALTER TABLE learning_microblocks ADD COLUMN evaluation_metric TEXT DEFAULT 'Aprovação formal e validação de conformidade técnica pela liderança';")
    except Exception:
        pass

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

    # 19. Tabela de Execução Individual de Micro-Blocos de PDI (Painel do Membro)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS member_pdi_blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        user_id INTEGER NOT NULL REFERENCES users(id),
        user_email TEXT NOT NULL,
        pdi_id INTEGER,
        microblock_code TEXT NOT NULL,
        title TEXT NOT NULL,
        competency_mej TEXT NOT NULL,
        eixo TEXT NOT NULL,
        area TEXT NOT NULL,
        complexity INTEGER NOT NULL DEFAULT 1,
        description TEXT NOT NULL,
        deliverable_format TEXT,
        evaluation_metric TEXT,
        sla_days INTEGER NOT NULL DEFAULT 30,
        deadline_date TEXT,
        status TEXT NOT NULL DEFAULT 'pendente' CHECK(status IN ('pendente', 'em_andamento', 'concluido')),
        justificativa_algoritmica TEXT,
        singularidade_hash TEXT,
        completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_member_pdi_user_id ON member_pdi_blocks(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_member_pdi_email ON member_pdi_blocks(user_email);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_member_pdi_status ON member_pdi_blocks(status);")

    # 20. Tabelas da Caixa de Dúvidas e Ajuda Coletiva (Fórum Colaborativo)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS forum_duvidas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        author_id INTEGER REFERENCES users(id),
        author_email TEXT NOT NULL,
        author_name TEXT NOT NULL,
        author_area TEXT NOT NULL,
        author_role TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'Geral',
        status TEXT NOT NULL DEFAULT 'aberta' CHECK(status IN ('aberta', 'em_andamento', 'resolvida')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_forum_duvidas_status ON forum_duvidas(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_forum_duvidas_category ON forum_duvidas(category);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_forum_duvidas_created ON forum_duvidas(created_at);")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS forum_respostas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        duvida_id INTEGER NOT NULL REFERENCES forum_duvidas(id) ON DELETE CASCADE,
        author_id INTEGER REFERENCES users(id),
        author_email TEXT NOT NULL,
        author_name TEXT NOT NULL,
        author_area TEXT NOT NULL,
        author_role TEXT NOT NULL,
        content TEXT NOT NULL,
        is_solution INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_forum_respostas_duvida ON forum_respostas(duvida_id);")

    # 21. Tabela de Leads do Funil Comercial (CRM & Pipeline de Vendas)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        client_name TEXT NOT NULL,
        cnpj TEXT,
        contact_person TEXT,
        contact_email TEXT,
        contact_phone TEXT,
        estimated_value REAL NOT NULL DEFAULT 0.0,
        etapa TEXT NOT NULL DEFAULT 'prospeccao' CHECK(etapa IN ('prospeccao', 'diagnostico', 'proposta', 'negociacao', 'fechado', 'perdido')),
        responsible TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_leads_etapa ON leads(etapa);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_leads_client_name ON leads(client_name);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_leads_cnpj ON leads(cnpj);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_leads_updated_at ON leads(updated_at);")

    # 22. Tabela de Contratos de Consultoria e Gestão de RMs Ativas
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS contratos_rm (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        brand_name TEXT NOT NULL,
        client_name TEXT NOT NULL,
        cnpj TEXT,
        consultoria_escopo TEXT NOT NULL,
        prazo_dias INTEGER NOT NULL DEFAULT 60,
        prazo_entrega TEXT,
        marcos_financeiros TEXT,
        valor_total REAL NOT NULL DEFAULT 0.0,
        status_execucao TEXT NOT NULL DEFAULT 'ativo' CHECK(status_execucao IN ('ativo', 'suspenso', 'concluido')),
        responsavel_tecnico TEXT,
        hash_integridade TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_contratos_rm_lead ON contratos_rm(lead_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_contratos_rm_status ON contratos_rm(status_execucao);")

    # Seeding inicial de Leads e Contratos de Consultoria
    cursor.execute("SELECT COUNT(*) FROM leads;")
    if cursor.fetchone()[0] == 0:
        initial_leads = [
            ("edv_jr", "Padaria & Confeitaria Pão Dourado Ltda", "12.345.678/0001-90", "Antônio Carlos", "antonio@paodourado.com.br", "(27) 99812-4433", 2440.0, "prospeccao", "estevao.coutinho@edvjr.com.br", "Identificada necessidade de registro de marca mista na classe 30 (panificação)."),
            ("edv_jr", "Café Especial Pedra Azul Eireli", "98.765.432/0001-11", "Mariana Siqueira", "mariana@pedraazulcafe.com.br", "(27) 99755-6677", 3200.0, "diagnostico", "samuel.garcia@edvjr.com.br", "Diagnóstico prévio no INPI: sem colidências fonéticas na classe 30."),
            ("edv_jr", "TechVix Soluções em Software S.A.", "45.123.890/0001-55", "Rodrigo Mendes", "rodrigo@techvix.io", "(27) 99234-8899", 4800.0, "proposta", "isadora.epichin@edvjr.com.br", "Proposta enviada para registro de marca nominativa classe 42 e adequação contratual."),
            ("edv_jr", "Clínica Odontológica Sorriso Real", "33.222.111/0001-44", "Dra. Camila Prado", "camila@sorrisoreal.com.br", "(27) 98111-2233", 2440.0, "negociacao", "pedro.barros@edvjr.com.br", "Reunião de alinhamento de cláusulas de pagamento em 2x sem juros."),
            ("edv_jr", "Indústria de Sucos da Mata Ltda", "22.333.444/0001-66", "Fernando Silveira", "fernando@sucosdamata.ind.br", "(27) 99988-7766", 2440.0, "fechado", "marialice.bacelar@edvjr.com.br", "Contrato assinado perante a EDV Jr. Registro de marca na classe 32."),
            ("edv_jr", "Restaurante e Chopperia Vila Velha", "77.888.999/0001-00", "Jorge Amaral", "jorge@restaurantevilavelha.com.br", "(27) 99677-1122", 1800.0, "perdido", "estevao.coutinho@edvjr.com.br", "Cliente optou por adiar o investimento para o próximo semestre.")
        ]
        cursor.executemany("""
        INSERT INTO leads (tenant_id, client_name, cnpj, contact_person, contact_email, contact_phone, estimated_value, etapa, responsible, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, initial_leads)

        # Seeding inicial de contratos_rm para o lead fechado
        cursor.execute("SELECT id, client_name, cnpj FROM leads WHERE etapa = 'fechado' LIMIT 1;")
        lead_row = cursor.fetchone()
        if lead_row:
            marcos = json.dumps([
                {"parcela": 1, "valor": 1220.0, "vencimento": "2026-10-15", "status": "pago", "descricao": "Entrada na assinatura"},
                {"parcela": 2, "valor": 1220.0, "vencimento": "2026-11-15", "status": "pendente", "descricao": "Protocolo inicial perante o INPI"}
            ], ensure_ascii=False)
            cursor.execute("""
            INSERT INTO contratos_rm (
                tenant_id, lead_id, brand_name, client_name, cnpj, consultoria_escopo,
                prazo_dias, prazo_entrega, marcos_financeiros, valor_total, status_execucao,
                responsavel_tecnico, hash_integridade
            ) VALUES (
                'edv_jr', ?, 'SUCOS DA MATA', ?, ?,
                'Consultoria técnica de registro de marca perante o INPI na classe 32 (bebidas não alcoólicas), com busca preliminar de anterioridade, elaboração do pedido e acompanhamento de despachos na RPI.',
                60, '2026-12-05', ?, 2440.0, 'ativo', 'thais.junger@edvjr.com.br',
                'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0'
            );
            """, (lead_row["id"], lead_row["client_name"], lead_row["cnpj"], marcos))

    # 23. Tabela de Transações Financeiras Corporativas (Módulo Financeiro e Controle de Caixa 2.0)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transacoes_financeiras (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tipo TEXT NOT NULL CHECK(tipo IN ('receita', 'despesa')),
        categoria TEXT NOT NULL,
        descricao TEXT NOT NULL,
        valor REAL NOT NULL CHECK(valor > 0),
        data_vencimento TEXT NOT NULL,
        data_pagamento TEXT,
        status TEXT NOT NULL DEFAULT 'pendente' CHECK(status IN ('pendente', 'pago', 'atrasado', 'cancelado')),
        contrato_id INTEGER REFERENCES contratos_rm(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_transacoes_fin_tipo ON transacoes_financeiras(tipo);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_transacoes_fin_status ON transacoes_financeiras(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_transacoes_fin_vencimento ON transacoes_financeiras(data_vencimento);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_transacoes_fin_contrato ON transacoes_financeiras(contrato_id);")

    # Seeding inicial de Transações Financeiras vinculadas a contratos
    cursor.execute("SELECT COUNT(*) FROM transacoes_financeiras;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("SELECT id FROM contratos_rm LIMIT 1;")
        c_row = cursor.fetchone()
        cid = c_row[0] if c_row else None
        curr_month = datetime.now().strftime("%Y-%m")
        initial_txs = [
            ("receita", "consultoria_rm", "1ª Parcela - Consultoria Registro de Marca INPI (Sucos da Mata)", 1220.0, f"{curr_month}-05", f"{curr_month}-05", "pago", cid),
            ("receita", "consultoria_rm", "2ª Parcela - Protocolo e Acompanhamento INPI (Sucos da Mata)", 1220.0, f"{curr_month}-28", None, "pendente", cid),
            ("receita", "consultoria_rm", "Diagnóstico de Anterioridade Marcária - Parcela Única", 800.0, "2026-08-10", None, "atrasado", None),
            ("despesa", "consultoria_rm", "Custas Federais INPI - Emissão de GRU Guia 389", 142.0, f"{curr_month}-06", f"{curr_month}-06", "pago", cid),
            ("despesa", "taxa_federativa", "Taxa Federativa Anual Brasil Júnior / FEJERS 2026", 450.0, f"{curr_month}-10", f"{curr_month}-10", "pago", None),
            ("despesa", "infraestrutura", "Servidor Cloud EDbrain & Hospedagem Render", 250.0, f"{curr_month}-25", None, "pendente", None),
            ("despesa", "capacitacao", "Treinamento Metodologia Ágil Scrum & OKRs para Assessores", 300.0, f"{curr_month}-30", None, "pendente", None),
        ]
        cursor.executemany("""
        INSERT INTO transacoes_financeiras (tipo, categoria, descricao, valor, data_vencimento, data_pagamento, status, contrato_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, initial_txs)

    # 24. Tabela de Base de Conhecimento e POPs (Wiki Interna & Continuidade)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS kb_artigos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'edv_jr',
        titulo TEXT NOT NULL,
        categoria TEXT NOT NULL CHECK(categoria IN ('juridico', 'financeiro', 'projetos', 'gestao_gente', 'ti', 'comercial', 'geral')),
        conteudo TEXT NOT NULL,
        drive_url TEXT,
        autor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        autor_nome TEXT,
        autor_email TEXT,
        gerado_por_ia BOOLEAN DEFAULT FALSE,
        trilha_derivada_id INTEGER REFERENCES pdis(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_kb_categoria ON kb_artigos(categoria);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_kb_created ON kb_artigos(created_at);")

    # Migração segura para colunas gerado_por_ia e trilha_derivada_id caso tabela já exista
    for col_def in [
        ("gerado_por_ia", "BOOLEAN DEFAULT FALSE"),
        ("trilha_derivada_id", "INTEGER REFERENCES pdis(id) ON DELETE SET NULL")
    ]:
        try:
            cursor.execute(f"ALTER TABLE kb_artigos ADD COLUMN {col_def[0]} {col_def[1]};")
        except Exception:
            pass

    # Injeção e atualização idempotente do Catálogo Oficial de POPs Técnicos (POP-01 a POP-08)
    seed_official_kb_pops(conn)

    ensure_learning_microblocks(conn)
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

def ensure_learning_microblocks(conn=None):
    """
    Popula de forma idempotente a Biblioteca de Micro-Entregáveis (Atomic Learning Blocks)
    com 48 micro-ações estruturadas por competência da Brasil Júnior, área e nível hierárquico.
    """
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM learning_microblocks;")
        if cursor.fetchone()[0] == 0:
            cursor.executemany("""
            INSERT INTO learning_microblocks (
                tenant_id, code, title, competency_mej, eixo, area,
                hierarchical_level, complexity, description, deliverable_format,
                estimated_hours, suggested_deadline_days, keywords
            ) VALUES ('edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, INITIAL_LEARNING_MICROBLOCKS)
            conn.commit()
    except Exception as e:
        print(f"[Learning Engine] Aviso ao semear micro-blocos: {e}")
    if should_close:
        conn.close()

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


def list_learning_microblocks(
    competency_mej: Optional[str] = None,
    area: Optional[str] = None,
    hierarchical_level: Optional[str] = None,
    eixo: Optional[str] = None
) -> List[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM learning_microblocks WHERE 1=1"
    params = []
    if competency_mej:
        query += " AND competency_mej = ?"
        params.append(competency_mej)
    if area and area != "Cross-Setorial":
        query += " AND (area = ? OR area = 'Cross-Setorial')"
        params.append(area)
    if hierarchical_level and hierarchical_level != "todos":
        query += " AND (hierarchical_level = ? OR hierarchical_level = 'todos')"
        params.append(hierarchical_level)
    if eixo:
        query += " AND eixo = ?"
        params.append(eixo)
    query += " ORDER BY complexity ASC, id ASC;"
    cursor.execute(query, tuple(params))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_microblock_by_code(code: str) -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM learning_microblocks WHERE code = ?;", (code.strip().upper(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


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

# ==============================================================================
# 19. SUBSISTEMA DE EXECUÇÃO INDIVIDUAL DO PDI & FÓRUM COLABORATIVO DE DÚVIDAS
# ==============================================================================

def get_user_by_id_or_email(user_identifier: Union[int, str]) -> Optional[Dict[str, Any]]:
    """Busca usuário de forma flexível por ID numérico ou endereço de e-mail institucional."""
    conn = get_connection()
    cursor = conn.cursor()
    user = None
    ident_str = str(user_identifier).strip()
    if ident_str.isdigit():
        cursor.execute("SELECT * FROM users WHERE id = ?;", (int(ident_str),))
        row = cursor.fetchone()
        if row:
            user = dict(row)
    if not user:
        cursor.execute("SELECT * FROM users WHERE LOWER(email) = ?;", (ident_str.lower(),))
        row = cursor.fetchone()
        if row:
            user = dict(row)
    conn.close()
    return user


def get_or_create_member_pdi_trail(user_identifier: Union[int, str], current_user: Optional[dict] = None) -> Optional[Dict[str, Any]]:
    """
    Retorna a trilha de micro-blocos atribuída ao colaborador com acompanhamento de SLA e status.
    Se o colaborador ainda não possuir blocos gravados, aciona a montagem algorítmica e persiste.
    """
    target_user = None
    if str(user_identifier).lower() == "me" and current_user:
        target_user = current_user
    else:
        target_user = get_user_by_id_or_email(user_identifier)
        
    if not target_user:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM member_pdi_blocks WHERE user_id = ? ORDER BY id ASC;", (target_user["id"],))
    rows = cursor.fetchall()

    if not rows:
        # Geração autônoma e calibrada da primeira trilha
        try:
            try:
                from semantic_nlp import montar_trilha_algoritmica
            except ImportError:
                from backend.semantic_nlp import montar_trilha_algoritmica
            triang = {}
            try:
                triang = calculate_triangulation(target_user["email"])
            except Exception:
                triang = {}
            trilha_data = montar_trilha_algoritmica(member=target_user, triangulacao=triang)
            sig_hash = trilha_data.get("singularidade_hash", "")
            
            for b in trilha_data.get("micro_blocos_selecionados", []):
                sla = int(b.get("suggested_deadline_days") or 30)
                deadline = (datetime.now() + timedelta(days=sla)).strftime("%Y-%m-%d")
                cursor.execute("""
                INSERT INTO member_pdi_blocks (
                    tenant_id, user_id, user_email, microblock_code, title, competency_mej,
                    eixo, area, complexity, description, deliverable_format, evaluation_metric,
                    sla_days, deadline_date, status, justificativa_algoritmica, singularidade_hash
                ) VALUES ('edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pendente', ?, ?);
                """, (
                    target_user["id"],
                    target_user["email"].lower().strip(),
                    b.get("code", "MB-GER-00"),
                    b.get("title", "Micro-bloco Operacional"),
                    b.get("competency_mej", "gestao"),
                    b.get("eixo", "hard_skills"),
                    b.get("area", target_user.get("area", "VPGG")),
                    int(b.get("complexity") or 1),
                    b.get("description", ""),
                    b.get("deliverable_format", "Entregável"),
                    b.get("evaluation_metric", "Aprovação formal pela liderança"),
                    sla,
                    deadline,
                    b.get("justificativa_algoritmica", "Alinhamento com competências Brasil Júnior"),
                    sig_hash
                ))
            conn.commit()
            cursor.execute("SELECT * FROM member_pdi_blocks WHERE user_id = ? ORDER BY id ASC;", (target_user["id"],))
            rows = cursor.fetchall()
        except Exception as err:
            print(f"[PDI Trail] Erro ao semear blocos para {target_user['email']}: {err}")

    blocks = []
    today = datetime.now().date()
    for r in rows:
        b_dict = dict(r)
        dias_rest = b_dict.get("sla_days", 30)
        d_str = b_dict.get("deadline_date")
        if d_str:
            try:
                d_obj = datetime.strptime(d_str, "%Y-%m-%d").date()
                dias_rest = (d_obj - today).days if b_dict.get("status") != "concluido" else 0
            except Exception:
                dias_rest = b_dict.get("sla_days", 30)
        elif b_dict.get("status") == "concluido":
            dias_rest = 0
            
        b_dict["dias_restantes"] = dias_rest
        blocks.append(b_dict)

    conn.close()

    total = len(blocks)
    concluidos = sum(1 for b in blocks if b["status"] == "concluido")
    em_andamento = sum(1 for b in blocks if b["status"] == "em_andamento")
    pendentes = sum(1 for b in blocks if b["status"] == "pendente")
    progresso_pct = round((concluidos / total * 100), 1) if total > 0 else 0.0
    sig_hash = blocks[0]["singularidade_hash"] if blocks else ""

    return {
        "user": {
            "id": target_user["id"],
            "nome": target_user["nome"],
            "email": target_user["email"],
            "area": target_user["area"],
            "role": target_user["role"],
            "cargo": target_user.get("cargo", "")
        },
        "trilha": {
            "singularidade_hash": sig_hash,
            "progresso_percentual": progresso_pct,
            "total_blocos": total,
            "concluidos": concluidos,
            "em_andamento": em_andamento,
            "pendentes": pendentes,
            "blocos": blocks
        }
    }


def update_microblock_status(bloco_id: int, new_status: str, current_user: dict) -> Dict[str, Any]:
    """
    Atualiza o status operacional do micro-bloco e recalcula o progresso percentual da trilha.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM member_pdi_blocks WHERE id = ?;", (bloco_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise ValueError(f"Micro-bloco ID #{bloco_id} não encontrado.")
        
    block = dict(row)
    c_email = current_user["email"].lower().strip()
    c_role = current_user.get("role", "assessor").lower()
    c_area = current_user.get("area", "").lower()
    
    is_owner = (c_email == block["user_email"].lower().strip())
    is_leader = (c_role in ["presidente", "diretor"] or "vpgg" in c_area)
    if not is_owner and not is_leader:
        conn.close()
        raise PermissionError("Você não possui permissão para modificar o status deste micro-bloco.")
        
    st_clean = new_status.lower().strip()
    if st_clean not in ["pendente", "em_andamento", "concluido"]:
        conn.close()
        raise ValueError(f"Status '{new_status}' inválido. Permitidos: pendente, em_andamento, concluido.")
        
    completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if st_clean == "concluido" else None
    
    cursor.execute("""
    UPDATE member_pdi_blocks
    SET status = ?, completed_at = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?;
    """, (st_clean, completed_at, bloco_id))
    conn.commit()
    
    # Recalcular avanço percentual da trilha do usuário
    cursor.execute("SELECT * FROM member_pdi_blocks WHERE user_id = ? ORDER BY id ASC;", (block["user_id"],))
    user_blocks = [dict(b) for b in cursor.fetchall()]
    total = len(user_blocks)
    concluidos = sum(1 for b in user_blocks if b["status"] == "concluido")
    em_andamento = sum(1 for b in user_blocks if b["status"] == "em_andamento")
    pendentes = sum(1 for b in user_blocks if b["status"] == "pendente")
    progresso_pct = round((concluidos / total * 100), 1) if total > 0 else 0.0

    cursor.execute("SELECT * FROM member_pdi_blocks WHERE id = ?;", (bloco_id,))
    updated_block = dict(cursor.fetchone())
    conn.close()
    
    return {
        "status": "success",
        "micro_bloco": updated_block,
        "trilha_progresso": {
            "total_blocos": total,
            "concluidos": concluidos,
            "em_andamento": em_andamento,
            "pendentes": pendentes,
            "progresso_percentual": progresso_pct
        }
    }


def create_forum_duvida(author: dict, title: str, description: str, category: str = "Geral") -> Dict[str, Any]:
    """Registra uma nova dúvida pública no Fórum Colaborativo."""
    if not title or not title.strip():
        raise ValueError("O título da dúvida não pode ser vazio.")
    if not description or not description.strip():
        raise ValueError("A descrição da dúvida não pode ser vazia.")
        
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO forum_duvidas (
        tenant_id, author_id, author_email, author_name, author_area, author_role,
        title, description, category, status
    ) VALUES ('edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, 'aberta');
    """, (
        author.get("id"),
        author["email"].lower().strip(),
        author.get("nome", "Membro"),
        author.get("area", "Cross-Setorial"),
        author.get("role", "assessor"),
        title.strip(),
        description.strip(),
        (category or "Geral").strip()
    ))
    duvida_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM forum_duvidas WHERE id = ?;", (duvida_id,))
    created = dict(cursor.fetchone())
    conn.close()
    created["total_respostas"] = 0
    created["respostas"] = []
    return created


def list_forum_duvidas(status_filter: Optional[str] = None, category_filter: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retorna o feed público de dúvidas com dados dos autores e respectivas respostas em thread."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM forum_duvidas WHERE 1=1"
    params = []
    
    if status_filter and status_filter.lower() != "todas":
        query += " AND status = ?"
        params.append(status_filter.lower().strip())
    if category_filter and category_filter.lower() != "todas":
        query += " AND LOWER(category) = ?"
        params.append(category_filter.lower().strip())
    if search and search.strip():
        query += " AND (title LIKE ? OR description LIKE ?)"
        s_term = f"%{search.strip()}%"
        params.extend([s_term, s_term])
        
    query += " ORDER BY id DESC;"
    cursor.execute(query, tuple(params))
    duvidas = [dict(r) for r in cursor.fetchall()]
    
    for d in duvidas:
        cursor.execute("SELECT * FROM forum_respostas WHERE duvida_id = ? ORDER BY id ASC;", (d["id"],))
        respostas = [dict(r) for r in cursor.fetchall()]
        d["total_respostas"] = len(respostas)
        d["respostas"] = respostas
        
    conn.close()
    return duvidas


def add_forum_resposta(duvida_id: int, author: dict, content: str) -> Dict[str, Any]:
    """Adiciona resposta/comentário/diretriz colaborativa em uma dúvida existente."""
    if not content or not content.strip():
        raise ValueError("O conteúdo da resposta não pode ser vazio.")
        
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forum_duvidas WHERE id = ?;", (duvida_id,))
    duvida = cursor.fetchone()
    if not duvida:
        conn.close()
        raise ValueError(f"Dúvida ID #{duvida_id} não encontrada.")
        
    cursor.execute("""
    INSERT INTO forum_respostas (
        tenant_id, duvida_id, author_id, author_email, author_name, author_area, author_role, content, is_solution
    ) VALUES ('edv_jr', ?, ?, ?, ?, ?, ?, ?, 0);
    """, (
        duvida_id,
        author.get("id"),
        author["email"].lower().strip(),
        author.get("nome", "Membro"),
        author.get("area", "Cross-Setorial"),
        author.get("role", "assessor"),
        content.strip()
    ))
    resp_id = cursor.lastrowid
    cursor.execute("UPDATE forum_duvidas SET updated_at = CURRENT_TIMESTAMP WHERE id = ?;", (duvida_id,))
    conn.commit()
    cursor.execute("SELECT * FROM forum_respostas WHERE id = ?;", (resp_id,))
    res_dict = dict(cursor.fetchone())
    conn.close()
    return res_dict


def resolve_forum_duvida(duvida_id: int, current_user: dict, new_status: str = "resolvida") -> Dict[str, Any]:
    """Alterna o status de uma dúvida para resolvida (ou reaberta)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forum_duvidas WHERE id = ?;", (duvida_id,))
    duvida = cursor.fetchone()
    if not duvida:
        conn.close()
        raise ValueError(f"Dúvida ID #{duvida_id} não encontrada.")
        
    c_email = current_user["email"].lower().strip()
    c_role = current_user.get("role", "assessor").lower()
    is_author = (c_email == duvida["author_email"].lower().strip())
    is_leader = (c_role in ["presidente", "diretor", "gerente"])
    if not is_author and not is_leader:
        conn.close()
        raise PermissionError("Apenas o autor da dúvida ou a liderança possuem permissão para alterar o status.")
        
    st_clean = new_status.lower().strip()
    cursor.execute("UPDATE forum_duvidas SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;", (st_clean, duvida_id))
    conn.commit()
    cursor.execute("SELECT * FROM forum_duvidas WHERE id = ?;", (duvida_id,))
    updated = dict(cursor.fetchone())
    conn.close()
    return updated


# ==============================================================================
# 20. SUBSISTEMA DE CRM, GESTÃO DE RMS & CONTRATOS DE CONSULTORIA
# ==============================================================================

VALID_ETAPAS = {"prospeccao", "diagnostico", "proposta", "negociacao", "fechado", "perdido"}
VALID_CONTRATO_STATUS = {"ativo", "suspenso", "concluido"}

def create_lead(data: dict, current_user: Optional[dict] = None) -> dict:
    """Cadastra nova oportunidade comercial no pipeline de vendas."""
    client_name = data.get("client_name")
    if not client_name or not client_name.strip():
        raise ValueError("O nome do cliente/empresa é obrigatório.")
        
    etapa = data.get("etapa", "prospeccao").lower().strip()
    if etapa not in VALID_ETAPAS:
        raise ValueError(f"Etapa inválida '{etapa}'. Deve ser uma de: {', '.join(sorted(VALID_ETAPAS))}.")
        
    estimated_value = float(data.get("estimated_value", 0.0) or 0.0)
    responsible = data.get("responsible")
    if not responsible and current_user:
        responsible = current_user.get("email")
        
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO leads (
        tenant_id, client_name, cnpj, contact_person, contact_email,
        contact_phone, estimated_value, etapa, responsible, notes
    ) VALUES (
        'edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, ?
    );
    """, (
        client_name.strip(),
        (data.get("cnpj") or "").strip() or None,
        (data.get("contact_person") or "").strip() or None,
        (data.get("contact_email") or "").strip() or None,
        (data.get("contact_phone") or "").strip() or None,
        estimated_value,
        etapa,
        (responsible or "").strip() or None,
        (data.get("notes") or "").strip() or None
    ))
    new_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM leads WHERE id = ?;", (new_id,))
    lead = dict(cursor.fetchone())
    conn.close()
    return lead


def get_lead_by_id(lead_id: int) -> Optional[dict]:
    """Retorna detalhes do lead pelo ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM leads WHERE id = ?;", (lead_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_lead(lead_id: int, updates: dict, current_user: Optional[dict] = None) -> Optional[dict]:
    """Atualiza dados e/ou transiciona a etapa do lead no funil."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM leads WHERE id = ?;", (lead_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise ValueError(f"Lead ID #{lead_id} não encontrado.")
        
    allowed_fields = [
        "client_name", "cnpj", "contact_person", "contact_email",
        "contact_phone", "estimated_value", "etapa", "responsible", "notes"
    ]
    set_clauses = []
    params = []
    
    for f in allowed_fields:
        if f in updates and updates[f] is not None:
            val = updates[f]
            if f == "etapa":
                val = str(val).lower().strip()
                if val not in VALID_ETAPAS:
                    conn.close()
                    raise ValueError(f"Etapa inválida '{val}'. Deve ser uma de: {', '.join(sorted(VALID_ETAPAS))}.")
            elif f == "estimated_value":
                val = float(val)
            set_clauses.append(f"{f} = ?")
            params.append(val)
            
    if not set_clauses:
        conn.close()
        return dict(existing)
        
    set_clauses.append("updated_at = CURRENT_TIMESTAMP")
    params.append(lead_id)
    query = f"UPDATE leads SET {', '.join(set_clauses)} WHERE id = ?;"
    cursor.execute(query, tuple(params))
    conn.commit()
    cursor.execute("SELECT * FROM leads WHERE id = ?;", (lead_id,))
    updated = dict(cursor.fetchone())
    conn.close()
    return updated


def get_crm_pipeline() -> dict:
    """Retorna o panorama completo do funil de vendas segmentado pelas 6 etapas e métricas consolidadas."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM leads ORDER BY updated_at DESC, id DESC;")
    rows = cursor.fetchall()
    conn.close()
    
    pipeline = {
        "prospeccao": [],
        "diagnostico": [],
        "proposta": [],
        "negociacao": [],
        "fechado": [],
        "perdido": []
    }
    
    total_pipeline_val = 0.0
    total_fechado_val = 0.0
    
    for r in rows:
        lead_dict = dict(r)
        st = lead_dict.get("etapa", "prospeccao")
        if st in pipeline:
            pipeline[st].append(lead_dict)
        else:
            pipeline["prospeccao"].append(lead_dict)
            
        val = float(lead_dict.get("estimated_value", 0.0) or 0.0)
        if st in ["prospeccao", "diagnostico", "proposta", "negociacao"]:
            total_pipeline_val += val
        elif st == "fechado":
            total_fechado_val += val
            
    total_leads = len(rows)
    total_fechados = len(pipeline["fechado"])
    conversion_rate = round((total_fechados / total_leads * 100.0), 1) if total_leads > 0 else 0.0
    
    resumo_etapas = {
        k: {
            "count": len(pipeline[k]),
            "total_value": round(sum(float(x.get("estimated_value", 0.0) or 0.0) for x in pipeline[k]), 2)
        }
        for k in pipeline
    }
    
    return {
        "status": "success",
        "etapas": pipeline,
        "resumo_etapas": resumo_etapas,
        "total_leads_count": total_leads,
        "total_pipeline_value": round(total_pipeline_val, 2),
        "total_fechado_value": round(total_fechado_val, 2),
        "conversion_rate": conversion_rate
    }


def create_contrato_rm(data: dict, current_user: Optional[dict] = None) -> dict:
    """Cria e vincula um contrato de consultoria / RM a um lead existente."""
    lead_id = data.get("lead_id")
    if not lead_id:
        raise ValueError("O campo 'lead_id' é obrigatório para formalizar o contrato de consultoria.")
        
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM leads WHERE id = ?;", (lead_id,))
    lead = cursor.fetchone()
    if not lead:
        conn.close()
        raise ValueError(f"Lead ID #{lead_id} não encontrado no CRM.")
        
    brand_name = data.get("brand_name") or data.get("client_name") or lead["client_name"]
    client_name = data.get("client_name") or lead["client_name"]
    cnpj = data.get("cnpj") or lead["cnpj"]
    consultoria_escopo = data.get("consultoria_escopo")
    if not consultoria_escopo or not consultoria_escopo.strip():
        consultoria_escopo = "Consultoria técnica de registro de marca e proteção marcária perante o INPI."
        
    status_exec = data.get("status_execucao", "ativo").lower().strip()
    if status_exec not in VALID_CONTRATO_STATUS:
        conn.close()
        raise ValueError(f"Status de execução inválido '{status_exec}'. Deve ser: {', '.join(sorted(VALID_CONTRATO_STATUS))}.")
        
    marcos = data.get("marcos_financeiros")
    if isinstance(marcos, (list, dict)):
        marcos_str = json.dumps(marcos, ensure_ascii=False)
    else:
        marcos_str = str(marcos) if marcos else None
        
    valor_total = float(data.get("valor_total", lead["estimated_value"]) or 0.0)
    prazo_dias = int(data.get("prazo_dias", 60) or 60)
    prazo_entrega = data.get("prazo_entrega")
    if not prazo_entrega:
        prazo_entrega = (datetime.now() + timedelta(days=prazo_dias)).strftime("%Y-%m-%d")
        
    resp_tec = data.get("responsavel_tecnico")
    if not resp_tec and current_user:
        resp_tec = current_user.get("email")
        
    hash_integ = data.get("hash_integridade")
    
    cursor.execute("""
    INSERT INTO contratos_rm (
        tenant_id, lead_id, brand_name, client_name, cnpj, consultoria_escopo,
        prazo_dias, prazo_entrega, marcos_financeiros, valor_total, status_execucao,
        responsavel_tecnico, hash_integridade
    ) VALUES (
        'edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    );
    """, (
        lead_id,
        brand_name.strip(),
        client_name.strip(),
        cnpj,
        consultoria_escopo.strip(),
        prazo_dias,
        prazo_entrega,
        marcos_str,
        valor_total,
        status_exec,
        resp_tec,
        hash_integ
    ))
    new_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM contratos_rm WHERE id = ?;", (new_id,))
    contrato = dict(cursor.fetchone())
    conn.close()
    return contrato


def list_contratos_rm(status_filter: Optional[str] = None) -> List[dict]:
    """Lista contratos de consultoria / RMs ativas com metadados do lead."""
    conn = get_connection()
    cursor = conn.cursor()
    query = """
    SELECT c.*, l.contact_person, l.contact_email, l.contact_phone
    FROM contratos_rm c
    LEFT JOIN leads l ON c.lead_id = l.id
    """
    params = []
    if status_filter and status_filter.strip():
        query += " WHERE c.status_execucao = ?"
        params.append(status_filter.lower().strip())
    query += " ORDER BY c.id DESC;"
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        d = dict(r)
        if d.get("marcos_financeiros"):
            try:
                d["marcos_financeiros_parsed"] = json.loads(d["marcos_financeiros"])
            except Exception:
                d["marcos_financeiros_parsed"] = []
        results.append(d)
    return results


def get_contrato_rm_by_id(contrato_id: int) -> Optional[dict]:
    """Retorna detalhes de um contrato de RM pelo ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT c.*, l.contact_person, l.contact_email, l.contact_phone
    FROM contratos_rm c
    LEFT JOIN leads l ON c.lead_id = l.id
    WHERE c.id = ?;
    """, (contrato_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("marcos_financeiros"):
        try:
            d["marcos_financeiros_parsed"] = json.loads(d["marcos_financeiros"])
        except Exception:
            d["marcos_financeiros_parsed"] = []
    return d


def update_contrato_rm_status(contrato_id: int, status: str, current_user: Optional[dict] = None) -> Optional[dict]:
    """Atualiza o status de execução de um contrato de consultoria."""
    st_clean = status.lower().strip()
    if st_clean not in VALID_CONTRATO_STATUS:
        raise ValueError(f"Status inválido '{status}'. Deve ser: {', '.join(sorted(VALID_CONTRATO_STATUS))}.")
        
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM contratos_rm WHERE id = ?;", (contrato_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise ValueError(f"Contrato ID #{contrato_id} não encontrado.")
        
    cursor.execute("""
    UPDATE contratos_rm 
    SET status_execucao = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?;
    """, (st_clean, contrato_id))
    conn.commit()
    cursor.execute("SELECT * FROM contratos_rm WHERE id = ?;", (contrato_id,))
    updated = dict(cursor.fetchone())
    conn.close()
    return updated


# ==============================================================================
# 21. SUBSISTEMA FINANCEIRO E CONTROLE DE CAIXA 2.0 (TRANSAÇÕES & KPIS)
# ==============================================================================

VALID_TX_TIPO = {"receita", "despesa"}
VALID_TX_STATUS = {"pendente", "pago", "atrasado", "cancelado"}

def create_transacao_financeira(data: dict) -> dict:
    """Cria uma nova transação financeira no fluxo de caixa corporativo."""
    tipo = (data.get("tipo") or "").lower().strip()
    if tipo not in VALID_TX_TIPO:
        raise ValueError(f"Tipo de transação inválido '{tipo}'. Deve ser 'receita' ou 'despesa'.")
        
    valor = float(data.get("valor") or 0.0)
    if valor <= 0:
        raise ValueError("O valor da movimentação financeira deve ser superior a R$ 0,00.")
        
    categoria = (data.get("categoria") or "").strip()
    if not categoria:
        raise ValueError("A categoria contábil é obrigatória.")
        
    descricao = (data.get("descricao") or "").strip()
    if not descricao:
        raise ValueError("A descrição da movimentação é obrigatória.")
        
    data_vencimento = (data.get("data_vencimento") or "").strip()
    if not data_vencimento:
        raise ValueError("A data de vencimento da movimentação é obrigatória (YYYY-MM-DD).")
        
    status = (data.get("status") or "pendente").lower().strip()
    if status not in VALID_TX_STATUS:
        raise ValueError(f"Status inválido '{status}'. Deve ser: {', '.join(sorted(VALID_TX_STATUS))}.")
        
    data_pagamento = data.get("data_pagamento")
    if status == "pago" and not data_pagamento:
        data_pagamento = datetime.now().strftime("%Y-%m-%d")
        
    contrato_id = data.get("contrato_id")
    if contrato_id is not None:
        try:
            contrato_id = int(contrato_id)
        except (ValueError, TypeError):
            raise ValueError(f"ID do contrato inválido: {data.get('contrato_id')}")

    conn = get_connection()
    cursor = conn.cursor()
    
    if contrato_id is not None:
        cursor.execute("SELECT id FROM contratos_rm WHERE id = ?;", (contrato_id,))
        if not cursor.fetchone():
            conn.close()
            raise ValueError(f"Contrato de consultoria ID #{contrato_id} não encontrado.")

    cursor.execute("""
    INSERT INTO transacoes_financeiras (
        tipo, categoria, descricao, valor, data_vencimento, data_pagamento, status, contrato_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (tipo, categoria, descricao, valor, data_vencimento, data_pagamento, status, contrato_id))
    conn.commit()
    tx_id = cursor.lastrowid
    conn.close()
    
    return get_transacao_financeira_by_id(tx_id)


def get_transacao_financeira_by_id(tx_id: int) -> Optional[dict]:
    """Retorna detalhes de uma transação financeira pelo ID com dados do contrato vinculado."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT t.*, c.brand_name as contrato_brand_name, c.client_name as contrato_client_name, c.status_execucao as contrato_status
    FROM transacoes_financeiras t
    LEFT JOIN contratos_rm c ON t.contrato_id = c.id
    WHERE t.id = ?;
    """, (tx_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def list_transacoes_financeiras(filtros: Optional[dict] = None) -> List[dict]:
    """Lista transações financeiras com filtros avançados."""
    filtros = filtros or {}
    query = """
    SELECT t.*, c.brand_name as contrato_brand_name, c.client_name as contrato_client_name, c.status_execucao as contrato_status
    FROM transacoes_financeiras t
    LEFT JOIN contratos_rm c ON t.contrato_id = c.id
    WHERE 1=1
    """
    params = []
    
    if filtros.get("tipo"):
        query += " AND t.tipo = ?"
        params.append(filtros["tipo"].lower().strip())
        
    if filtros.get("status"):
        query += " AND t.status = ?"
        params.append(filtros["status"].lower().strip())
        
    if filtros.get("categoria"):
        query += " AND t.categoria = ?"
        params.append(filtros["categoria"].strip())
        
    if filtros.get("contrato_id"):
        query += " AND t.contrato_id = ?"
        params.append(int(filtros["contrato_id"]))
        
    if filtros.get("data_inicio"):
        query += " AND t.data_vencimento >= ?"
        params.append(filtros["data_inicio"].strip())
        
    if filtros.get("data_fim"):
        query += " AND t.data_vencimento <= ?"
        params.append(filtros["data_fim"].strip())
        
    if filtros.get("busca"):
        busca = f"%{filtros['busca'].strip()}%"
        query += " AND (t.descricao LIKE ? OR t.categoria LIKE ? OR c.brand_name LIKE ? OR c.client_name LIKE ?)"
        params.extend([busca, busca, busca, busca])
        
    query += " ORDER BY t.data_vencimento ASC, t.id DESC;"
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_transacao_financeira_status(tx_id: int, novo_status: str, data_pagamento: Optional[str] = None) -> Optional[dict]:
    """Atualiza o status de liquidação de uma transação financeira."""
    st_clean = novo_status.lower().strip()
    if st_clean not in VALID_TX_STATUS:
        raise ValueError(f"Status inválido '{novo_status}'. Deve ser: {', '.join(sorted(VALID_TX_STATUS))}.")
        
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transacoes_financeiras WHERE id = ?;", (tx_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise ValueError(f"Transação financeira ID #{tx_id} não encontrada.")
        
    if st_clean == "pago":
        if not data_pagamento:
            data_pagamento = datetime.now().strftime("%Y-%m-%d")
    else:
        if data_pagamento is None and st_clean != "pago":
            data_pagamento = None
            
    cursor.execute("""
    UPDATE transacoes_financeiras
    SET status = ?, data_pagamento = ?
    WHERE id = ?;
    """, (st_clean, data_pagamento, tx_id))
    conn.commit()
    conn.close()
    
    return get_transacao_financeira_by_id(tx_id)


def get_financeiro_kpis(mes_referencia: Optional[str] = None) -> dict:
    """Calcula indicadores consolidados de caixa, projeção e inadimplência em tempo real."""
    if not mes_referencia:
        mes_referencia = datetime.now().strftime("%Y-%m")
        
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Total Receitas Pagas e Despesas Pagas (Saldo Caixa)
    cursor.execute("""
    SELECT 
        COALESCE(SUM(CASE WHEN tipo = 'receita' AND status = 'pago' THEN valor ELSE 0 END), 0.0) as rec_pagas,
        COALESCE(SUM(CASE WHEN tipo = 'despesa' AND status = 'pago' THEN valor ELSE 0 END), 0.0) as desp_pagas
    FROM transacoes_financeiras;
    """)
    row_saldo = cursor.fetchone()
    rec_pagas = float(row_saldo["rec_pagas"])
    desp_pagas = float(row_saldo["desp_pagas"])
    saldo_caixa = rec_pagas - desp_pagas
    
    # 2. Total a Receber no Mês Corrente (receitas pendentes ou atrasadas com vencimento no mês)
    cursor.execute("""
    SELECT COALESCE(SUM(valor), 0.0) as total_receber
    FROM transacoes_financeiras
    WHERE tipo = 'receita' 
      AND status IN ('pendente', 'atrasado')
      AND strftime('%Y-%m', data_vencimento) = ?;
    """, (mes_referencia,))
    total_receber_mes = float(cursor.fetchone()["total_receber"])
    
    # 3. Total a Pagar no Mês Corrente (despesas pendentes ou atrasadas com vencimento no mês)
    cursor.execute("""
    SELECT COALESCE(SUM(valor), 0.0) as total_pagar
    FROM transacoes_financeiras
    WHERE tipo = 'despesa'
      AND status IN ('pendente', 'atrasado')
      AND strftime('%Y-%m', data_vencimento) = ?;
    """, (mes_referencia,))
    total_pagar_mes = float(cursor.fetchone()["total_pagar"])
    
    # 4. Índice de Inadimplência
    cursor.execute("""
    SELECT 
        COALESCE(SUM(valor), 0.0) as total_atrasadas,
        COUNT(*) as qtd_atrasadas
    FROM transacoes_financeiras
    WHERE tipo = 'receita' 
      AND status NOT IN ('pago', 'cancelado')
      AND (status = 'atrasado' OR data_vencimento < ?);
    """, (today_str,))
    row_atraso = cursor.fetchone()
    total_atrasadas = float(row_atraso["total_atrasadas"])
    qtd_atrasadas = int(row_atraso["qtd_atrasadas"])
    
    # Base de vencidos: receitas pagas com vencimento <= today_str + receitas atrasadas
    cursor.execute("""
    SELECT COALESCE(SUM(valor), 0.0) as total_vencido
    FROM transacoes_financeiras
    WHERE tipo = 'receita'
      AND status != 'cancelado'
      AND (status = 'pago' OR status = 'atrasado' OR data_vencimento < ?);
    """, (today_str,))
    total_vencido = float(cursor.fetchone()["total_vencido"])
    
    taxa_inadimplencia = 0.0
    if total_vencido > 0:
        taxa_inadimplencia = round((total_atrasadas / total_vencido) * 100, 2)
        
    # Contagem geral
    cursor.execute("SELECT COUNT(*) as total FROM transacoes_financeiras;")
    total_tx = int(cursor.fetchone()["total"])
    
    conn.close()
    
    return {
        "saldo_caixa": round(saldo_caixa, 2),
        "total_receber_mes": round(total_receber_mes, 2),
        "total_pagar_mes": round(total_pagar_mes, 2),
        "taxa_inadimplencia": taxa_inadimplencia,
        "total_receitas_pagas": round(rec_pagas, 2),
        "total_despesas_pagas": round(desp_pagas, 2),
        "total_receitas_atrasadas": round(total_atrasadas, 2),
        "qtd_faturas_atrasadas": qtd_atrasadas,
        "total_transacoes": total_tx,
        "mes_referencia": mes_referencia
    }


# ==============================================================================
# 22. BI EXECUTIVO DA PRESIDÊNCIA & DIRETORIA (KPIs CONSOLIDADOS)
# ==============================================================================

def get_executivo_kpis_consolidados() -> dict:
    """
    Retorna o panorama macro de inteligência de negócios (BI) unificando:
    1. Saúde Financeira (saldo em caixa, valores a receber no mês, taxa de inadimplência)
    2. Funil Comercial & RMs (pipeline aberto, leads em negociação, contratos de RM ativos)
    3. Gestão de Talentos / PDI (avanço médio da equipe, micro-blocos concluídos vs pendentes)
    4. Governança Operacional (dúvidas abertas no fórum, estatutos vigentes)
    5. Alertas de Gargalos Críticos e Score de Saúde Organizacional
    """
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    # 1. Métricas Financeiras
    fin_kpis = get_financeiro_kpis()
    saldo_caixa = fin_kpis.get("saldo_caixa", 0.0)
    total_receber_mes = fin_kpis.get("total_receber_mes", 0.0)
    total_pagar_mes = fin_kpis.get("total_pagar_mes", 0.0)
    taxa_inadimplencia = fin_kpis.get("taxa_inadimplencia", 0.0)
    total_receitas_atrasadas = fin_kpis.get("total_receitas_atrasadas", 0.0)
    qtd_faturas_atrasadas = fin_kpis.get("qtd_faturas_atrasadas", 0)

    # 2. Métricas Comerciais & RMs
    crm_pipeline = get_crm_pipeline()
    vol_pipeline_aberto = crm_pipeline.get("total_pipeline_value", 0.0)
    vol_fechado = crm_pipeline.get("total_fechado_value", 0.0)
    leads_em_negociacao = crm_pipeline.get("resumo_etapas", {}).get("negociacao", {}).get("count", 0)
    total_leads = crm_pipeline.get("total_leads_count", 0)
    taxa_conversao = crm_pipeline.get("conversion_rate", 0.0)
    
    contratos_ativos_lista = list_contratos_rm(status_filter="ativo")
    contratos_rm_ativos = len(contratos_ativos_lista)

    # 3. Métricas de Pessoas & PDI
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM member_pdi_blocks;")
    total_micro_blocos = int(cursor.fetchone()["total"])

    cursor.execute("SELECT COUNT(*) as c FROM member_pdi_blocks WHERE status = 'concluido';")
    micro_blocos_concluidos = int(cursor.fetchone()["c"])

    cursor.execute("SELECT COUNT(*) as e FROM member_pdi_blocks WHERE status = 'em_andamento';")
    micro_blocos_em_andamento = int(cursor.fetchone()["e"])

    cursor.execute("SELECT COUNT(*) as p FROM member_pdi_blocks WHERE status = 'pendente';")
    micro_blocos_pendentes = int(cursor.fetchone()["p"])

    cursor.execute("""
    SELECT COUNT(*) as a 
    FROM member_pdi_blocks 
    WHERE status != 'concluido' AND deadline_date < ?;
    """, (today_str,))
    micro_blocos_atrasados = int(cursor.fetchone()["a"])

    cursor.execute("SELECT COUNT(DISTINCT user_id) as u FROM member_pdi_blocks;")
    colaboradores_com_trilha = int(cursor.fetchone()["u"])

    cursor.execute("""
    SELECT user_id, 
           COUNT(*) as total_m,
           SUM(CASE WHEN status = 'concluido' THEN 1 ELSE 0 END) as concluidos_m
    FROM member_pdi_blocks
    GROUP BY user_id;
    """)
    member_rows = cursor.fetchall()
    if member_rows:
        member_pcts = [(float(r["concluidos_m"]) / float(r["total_m"]) * 100.0) for r in member_rows if r["total_m"] > 0]
        media_avanco_global_pct = round(sum(member_pcts) / len(member_pcts), 1) if member_pcts else 0.0
    elif total_micro_blocos > 0:
        media_avanco_global_pct = round((micro_blocos_concluidos / total_micro_blocos) * 100.0, 1)
    else:
        media_avanco_global_pct = 0.0

    # 4. Métricas de Governança Operacional
    cursor.execute("SELECT COUNT(*) as abertas FROM forum_duvidas WHERE status = 'aberta';")
    duvidas_forum_abertas = int(cursor.fetchone()["abertas"])

    cursor.execute("SELECT COUNT(*) as resolvidas FROM forum_duvidas WHERE status = 'resolvida';")
    duvidas_forum_resolvidas = int(cursor.fetchone()["resolvidas"])

    cursor.execute("SELECT COUNT(*) as total_d FROM forum_duvidas;")
    duvidas_totais = int(cursor.fetchone()["total_d"])

    # Estatutos vigentes
    try:
        cursor.execute("SELECT COUNT(*) as vig FROM compliance_statutes WHERE status = 'vigente';")
        estatutos_vigentes = int(cursor.fetchone()["vig"])
    except Exception:
        estatutos_vigentes = 5

    conn.close()

    # 5. Destaques de Alertas & Gargalos Críticos
    alertas_atencao = []

    # Alerta Financeiro
    if taxa_inadimplencia > 10.0 or total_receitas_atrasadas > 0:
        nivel_fin = "danger" if (taxa_inadimplencia > 15.0 or total_receitas_atrasadas >= 2000.0) else "warning"
        alertas_atencao.append({
            "id": "alerta-inadimplencia",
            "tipo": "financeiro",
            "nivel": nivel_fin,
            "titulo": "Risco de Inadimplência ou Recebíveis em Atraso",
            "mensagem": f"Inadimplência em {taxa_inadimplencia}% com {qtd_faturas_atrasadas} título(s) pendente(s) totalizando R$ {total_receitas_atrasadas:,.2f}.",
            "acao_texto": "Auditar Fluxo de Caixa",
            "acao_link": "financeiro"
        })

    # Alerta Governança (Fórum)
    if duvidas_forum_abertas > 0:
        alertas_atencao.append({
            "id": "alerta-forum-duvidas",
            "tipo": "governanca",
            "nivel": "warning",
            "titulo": "Demandas Operacionais Sem Resolução no Fórum",
            "mensagem": f"Há {duvidas_forum_abertas} dúvida(s) aberta(s) de membros aguardando parecer ou diretriz da liderança.",
            "acao_texto": "Responder Dúvidas",
            "acao_link": "painel_membro"
        })

    # Alerta PDI (Micro-blocos Atrasados)
    if micro_blocos_atrasados > 0:
        alertas_atencao.append({
            "id": "alerta-pdi-atraso",
            "tipo": "pessoas",
            "nivel": "danger",
            "titulo": "Atraso no Cumprimento de Trilhas de PDI",
            "mensagem": f"{micro_blocos_atrasados} micro-bloco(s) de capacitação estão com SLA/data limite expirada na equipe.",
            "acao_texto": "Intervir no PDI",
            "acao_link": "vpgg"
        })

    # Alerta Comercial (Oportunidades em Negociação)
    if leads_em_negociacao > 0:
        alertas_atencao.append({
            "id": "alerta-crm-negociacao",
            "tipo": "comercial",
            "nivel": "info",
            "titulo": "Propostas Comerciais em Fase Decisiva",
            "mensagem": f"{leads_em_negociacao} oportunidade(s) quente(s) em etapa de negociação no CRM. Priorize o contato com os clientes.",
            "acao_texto": "Ver Funil Kanban",
            "acao_link": "comercial"
        })

    # 6. Score Sintético de Saúde Organizacional (0 a 100)
    score_fin = max(0.0, 30.0 - (taxa_inadimplencia * 0.5))
    score_crm = min(25.0, 10.0 + (taxa_conversao * 0.3) + (contratos_rm_ativos * 2.0))
    score_pdi = min(25.0, (media_avanco_global_pct * 0.25) - (micro_blocos_atrasados * 2.0))
    score_gov = max(5.0, 20.0 - (duvidas_forum_abertas * 2.0))
    score_total = round(max(10.0, min(100.0, score_fin + score_crm + score_pdi + score_gov)), 1)

    if score_total >= 75.0:
        status_geral = "saudavel"
    elif score_total >= 50.0:
        status_geral = "atencao"
    else:
        status_geral = "critico"

    return {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "financeiro": {
            "saldo_caixa": round(saldo_caixa, 2),
            "total_receber_mes": round(total_receber_mes, 2),
            "total_pagar_mes": round(total_pagar_mes, 2),
            "taxa_inadimplencia": taxa_inadimplencia,
            "total_receitas_atrasadas": round(total_receitas_atrasadas, 2),
            "qtd_faturas_atrasadas": qtd_faturas_atrasadas
        },
        "comercial": {
            "volume_pipeline_aberto": round(vol_pipeline_aberto, 2),
            "volume_fechado": round(vol_fechado, 2),
            "leads_em_negociacao": leads_em_negociacao,
            "leads_totais": total_leads,
            "contratos_rm_ativos": contratos_rm_ativos,
            "taxa_conversao": taxa_conversao
        },
        "pessoas_pdi": {
            "media_avanco_global_pct": media_avanco_global_pct,
            "total_micro_blocos": total_micro_blocos,
            "micro_blocos_concluidos": micro_blocos_concluidos,
            "micro_blocos_em_andamento": micro_blocos_em_andamento,
            "micro_blocos_pendentes": micro_blocos_pendentes,
            "micro_blocos_atrasados": micro_blocos_atrasados,
            "colaboradores_com_trilha": colaboradores_com_trilha
        },
        "governanca_operacional": {
            "duvidas_forum_abertas": duvidas_forum_abertas,
            "duvidas_forum_resolvidas": duvidas_forum_resolvidas,
            "duvidas_totais": duvidas_totais,
            "estatutos_vigentes": estatutos_vigentes
        },
        "alertas_atencao": alertas_atencao,
        "resumo_executivo": {
            "score_saude_organizacional": score_total,
            "status_geral": status_geral
        }
    }


# ==============================================================================
# 23. BASE DE CONHECIMENTO & POPs (WIKI CORPORATIVA & MITIGAÇÃO DE ROTATIVIDADE)
# ==============================================================================

VALID_KB_CATEGORIAS = {'juridico', 'financeiro', 'projetos', 'gestao_gente', 'ti', 'comercial', 'geral'}

OFFICIAL_KB_POPS = [
    {
        "codigo": "POP-01",
        "titulo": "POP-01: Utilização do Dashboard Executivo (BI Consolidado)",
        "categoria": "juridico",
        "drive_url": "https://drive.google.com/drive/folders/edv-bi-governanca",
        "autor_id": 1,
        "autor_nome": "Charles Junior (Presidência)",
        "autor_email": "charles.junior@edvjr.com.br",
        "conteudo": (
            "# POP-01 - Utilização do Dashboard Executivo (BI Consolidado)\n"
            "**Área Responsável**: Estratégico & Governança\n"
            "**Nível de Acesso**: Presidência e Diretorias (Roles: presidente, diretor)\n\n"
            "## 1. Objetivo Operacional\n"
            "Centralizar o monitoramento estratégico da EDV Jr. em um único painel executivo de inteligência de negócios, "
            "integrando telemetria em tempo real sobre liquidez de caixa, tração comercial do funil CRM, avanço das competências "
            "da equipe no PDI e governança sob a Lei Federal nº 13.267/2016.\n\n"
            "## 2. Pré-requisitos Sistêmicos\n"
            "* Usuário autenticado com credencial de Diretor ou Presidente (token JWT ativo).\n"
            "* Sincronização prévia das planilhas de Fluxo de Caixa e CRM do Google Drive.\n"
            "* Módulos Financeiro, CRM e VPGG inicializados com dados operacionais vigentes.\n\n"
            "## 3. Passo a Passo na Interface do EDbrain\n"
            "1. Localize o menu lateral correspondente e clique na aba **Presidência & BI** (`#view-presidencia`).\n"
            "2. Acesse a sub-aba **Dashboard Executivo (BI)** (`#subtab-pres-bi`), posicionada como visualização primária da liderança.\n"
            "3. Analise o **Score de Saúde Organizacional** (0 a 100), inspecionando os 4 quadrantes oficiais:\n"
            "   - **Quadrante 1 (Financeiro & Caixa)**: Saldo Bruto em Caixa, Previsão a Receber/Pagar e Taxa de Inadimplência.\n"
            "   - **Quadrante 2 (Comercial & RMs)**: Volume em Aberto no Pipeline, Leads em Negociação e Contratos Ativos.\n"
            "   - **Quadrante 3 (Desenvolvimento PDI)**: Média de Avanço das Trilhas e Taxa de Conclusão de Micro-Blocos.\n"
            "   - **Quadrante 4 (Governança & Selo EJ)**: Chamados no Fórum aguardando diretriz e Conformidade Selo BJ.\n"
            "4. Caso surjam alertas de gargalos críticos no banner superior, clique nos botões de atalho contextual para navegar diretamente ao módulo afetado.\n"
            "5. Para forçar a consolidação instantânea dos dados, clique no botão **Atualizar BI**.\n\n"
            "## 4. Tratamento de Exceções & Suporte Coletivo\n"
            "Caso o painel retorne erro `403 Forbidden`, verifique se o seu perfil de usuário possui a prerrogativa estatutária necessária. "
            "Se os indicadores apresentarem discrepância em relação às contas bancárias ou ao Drive, acione a rotina de ressincronização em "
            "**Central de Planilhas** ou reporte a ocorrência no Fórum Coletivo com a tag `#governanca-bi`."
        )
    },
    {
        "codigo": "POP-02",
        "titulo": "POP-02: Gestão de Acessos e Controle RBAC",
        "categoria": "ti",
        "drive_url": "https://drive.google.com/drive/folders/edv-ti-seguranca",
        "autor_id": 1,
        "autor_nome": "Charles Junior (Presidência)",
        "autor_email": "charles.junior@edvjr.com.br",
        "conteudo": (
            "# POP-02 - Gestão de Acessos e Controle RBAC\n"
            "**Área Responsável**: Estratégico & Governança\n"
            "**Nível de Acesso**: Presidência e TI (Roles: presidente, diretor, ti)\n\n"
            "## 1. Objetivo Operacional\n"
            "Garantir a integridade da segurança da informação, a confidencialidade dos dados de clientes e a segregação estrita de funções "
            "no EDbrain através do controle de acesso baseado em papéis (Role-Based Access Control - RBAC), prevenindo auto-promoção e vazamento de informações.\n\n"
            "## 2. Pré-requisitos Sistêmicos\n"
            "* Login efetuado com perfil de Administrador do Sistema (Presidência ou TI).\n"
            "* Cadastro prévio do colaborador na base corporativa com e-mail institucional `@edvjr.com.br`.\n"
            "* Termo de Confidencialidade e Adesão Estatutária assinado pelo membro.\n\n"
            "## 3. Passo a Passo na Interface do EDbrain\n"
            "1. Localize o menu lateral e acione a seção de **Auditoria & Segurança** ou a aba **Gestão de Gente (VPGG)**.\n"
            "2. Na listagem de membros ativos, selecione o usuário para validação ou alteração de privilégios.\n"
            "3. Configure o perfil de acesso adequado conforme a hierarquia do ecossistema:\n"
            "   - **Assessor**: Acesso restrito a preenchimento operacional de CRM, visualização de RMs atribuídos e Meu PDI.\n"
            "   - **Gerente**: Permissão de homologação operacional de projetos, gestão de follow-ups e avaliação de PDIs.\n"
            "   - **Diretor**: Acesso gerencial completo à sua respectiva diretoria e ao BI Executivo.\n"
            "   - **Presidente**: Acesso irrestrito a todos os módulos, parametrizações globais e exclusão de registros.\n"
            "4. Submeta a alteração e confirme o registro do log de auditoria com carimbo temporal e IP de origem.\n\n"
            "## 4. Tratamento de Exceções & Suporte Coletivo\n"
            "Tentativas de auto-elevação de privilégio disparam bloqueio imediato e geram notificação de segurança de nível crítico. "
            "Em caso de bloqueio acidental de credenciais da Diretoria, solicite reset criptográfico seguro via console de emergência do servidor "
            "ou abra chamado de contingência com a tag `#seguranca-rbac`."
        )
    },
    {
        "codigo": "POP-03",
        "titulo": "POP-03: Operação do Funil de Vendas CRM (6 Etapas)",
        "categoria": "comercial",
        "drive_url": "https://drive.google.com/drive/folders/edv-crm-vendas",
        "autor_id": 1,
        "autor_nome": "Charles Junior (Presidência)",
        "autor_email": "charles.junior@edvjr.com.br",
        "conteudo": (
            "# POP-03 - Operação do Funil de Vendas CRM (6 Etapas)\n"
            "**Área Responsável**: Comercial & Marketing\n"
            "**Nível de Acesso**: Equipe Comercial e RMs (Roles: assessor, gerente, diretor, presidente)\n\n"
            "## 1. Objetivo Operacional\n"
            "Padronizar a esteira de prospecção, qualificação e conversão de leads B2B interessados em Registro de Marcas (RMs) e consultoria jurídica, "
            "assegurando o cumprimento dos SLAs comerciais e a previsibilidade de faturamento da EDV Jr.\n\n"
            "## 2. Pré-requisitos Sistêmicos\n"
            "* Lead identificado com Razão Social, CNPJ válido (14 dígitos numéricos) e canal de origem mapeado.\n"
            "* Consultor comercial atribuído como responsável direto pela negociação.\n"
            "* Tabela de honorários e modelos de proposta vigentes parametrizados no sistema.\n\n"
            "## 3. Passo a Passo na Interface do EDbrain\n"
            "1. Localize o menu lateral e acione a aba **Comercial & CRM** (`#view-comercial`).\n"
            "2. No quadro Kanban oficial, cadastre ou selecione o lead e conduza-o pelas 6 etapas obrigatórias:\n"
            "   - **1. Prospecção**: Triagem inicial de empresas e verificação preliminar de marca no banco do INPI.\n"
            "   - **2. Contato Inicial**: Primeiro contato via WhatsApp/E-mail com aplicação do script de abordagem rápida.\n"
            "   - **3. Diagnóstico**: Reunião de alinhamento técnico para mapeamento de riscos e classes de Nice (NCL).\n"
            "   - **4. Proposta Enviada**: Envio formal da proposta comercial com honorários discriminados e link do Drive.\n"
            "   - **5. Negociação**: Alinhamento de condições de pagamento (Cora parcelado) e minutas jurídicas.\n"
            "   - **6. Fechado**: Conclusão da venda com upload do contrato assinado e conversão automática em Projeto RM.\n"
            "3. A cada interação com o cliente, adicione notas de follow-up detalhadas para manter o histórico unificado.\n\n"
            "## 4. Tratamento de Exceções & Suporte Coletivo\n"
            "Caso o validador de CNPJ aponte inconsistência cadastral, consulte a situação na Receita Federal via BrasilAPI ou portal Redesim. "
            "Se o cliente solicitar prorrogação de proposta por mais de 15 dias, sinalize a Diretoria Comercial ou submeta a dúvida na thread "
            "do Fórum Coletivo sob a tag `#comercial-negociacao`."
        )
    },
    {
        "codigo": "POP-04",
        "titulo": "POP-04: Automação e Emissão de Minutas Jurídicas com SHA-256",
        "categoria": "juridico",
        "drive_url": "https://drive.google.com/drive/folders/edv-juridico-contratos",
        "autor_id": 1,
        "autor_nome": "Charles Junior (Presidência)",
        "autor_email": "charles.junior@edvjr.com.br",
        "conteudo": (
            "# POP-04 - Automação e Emissão de Minutas Jurídicas com SHA-256\n"
            "**Área Responsável**: Comercial & Marketing\n"
            "**Nível de Acesso**: Projetos e Jurídico (Roles: assessor, gerente, diretor, presidente)\n\n"
            "## 1. Objetivo Operacional\n"
            "Automatizar a confecção de minutas de contratos de prestação de serviços de consultoria em conformidade com as diretrizes da "
            "Lei Federal nº 13.267/2016 (Lei das EJs), aplicando marca d'água institucional e autenticação por hash criptográfico SHA-256 "
            "para assegurar a idoneidade jurídica do instrumento.\n\n"
            "## 2. Pré-requisitos Sistêmicos\n"
            "* Lead no estágio de `negociacao` no CRM ou registro de consultoria homologado em Projetos.\n"
            "* Dados cadastrais completos do tomador do serviço (Razão Social, CNPJ, Endereço, Representante Legal e CPF).\n"
            "* Modelo de minuta contratual homologado pela Diretoria Jurídica disponível no catálogo do sistema.\n\n"
            "## 3. Passo a Passo na Interface do EDbrain\n"
            "1. Acesse a aba **Comercial** ou navegue até o **Painel de Contratos** na interface.\n"
            "2. Na linha correspondente à oportunidade contratada, clique na ação **Gerar Minuta Contratual**.\n"
            "3. Selecione o modelo adequado (ex: Contrato Padrão de Consultoria e Registro de Marca no INPI).\n"
            "4. O motor jurídico do EDbrain processará os campos dinâmicos, inserirá a marca d'água oficial da EDV Jr. e estampará o rodapé com a assinatura digital contendo o hash criptográfico SHA-256.\n"
            "5. Verifique a prévia do documento na tela e realize o download do arquivo PDF pronto para assinatura eletrônica (Gov.br, Clicksign ou Docusign).\n\n"
            "## 4. Tratamento de Exceções & Suporte Coletivo\n"
            "Se houver divergência entre as cláusulas padrão e exigências particulares do cliente, não edite o arquivo sem prévia autorização. "
            "Solicite parecer técnico da Diretoria Jurídica abrindo um chamado no Fórum Coletivo com a tag `#juridico-contratos`."
        )
    },
    {
        "codigo": "POP-05",
        "titulo": "POP-05: Acompanhamento de RMs e Marcos de Entrega",
        "categoria": "projetos",
        "drive_url": "https://drive.google.com/drive/folders/edv-projetos-rms",
        "autor_id": 1,
        "autor_nome": "Charles Junior (Presidência)",
        "autor_email": "charles.junior@edvjr.com.br",
        "conteudo": (
            "# POP-05 - Acompanhamento de RMs e Marcos de Entrega\n"
            "**Área Responsável**: Operação & Finanças\n"
            "**Nível de Acesso**: Gerentes de Projetos (Roles: gerente, diretor, presidente)\n\n"
            "## 1. Objetivo Operacional\n"
            "Monitorar a execução técnica das consultorias de Registro de Marcas (RMs), garantindo o cumprimento dos prazos legais do INPI "
            "(Lei nº 9.279/1996 - LPI), o controle de entregáveis por marcos e a mitigação de atrasos ou perdas de prazos decadenciais.\n\n"
            "## 2. Pré-requisitos Sistêmicos\n"
            "* Contrato de consultoria assinado e projeto registrado na base com código oficial de RM.\n"
            "* Gerente e consultores de projeto designados para o acompanhamento do prontuário.\n"
            "* Cadastro do número de processo ou protocolo do pedido perante o sistema e-INPI.\n\n"
            "## 3. Passo a Passo na Interface do EDbrain\n"
            "1. Localize o menu lateral e acione a aba **Projetos & RMs** (`#view-projetos`).\n"
            "2. Acesse a grade de controle operacional ou o quadro de marcos de entrega das consultorias ativas.\n"
            "3. Para cada projeto sob sua gestão, atualize o status conforme a evolução perante a autarquia federal:\n"
            "   - `ativo`: Consultoria em andamento regular dentro do cronograma contratado.\n"
            "   - `suspenso`: Processo sobrestado aguardando subsídios do cliente ou publicação oficial na RPI.\n"
            "   - `concluido`: Entrega técnica finalizada com protocolo deferido ou certificado expedido.\n"
            "4. Lance os despachos semanais da Revista da Propriedade Industrial (RPI), vinculando os links dos comprovantes oficiais salvos na pasta correspondente do Google Drive.\n\n"
            "## 4. Tratamento de Exceções & Suporte Coletivo\n"
            "Publicações de oposição (art. 158 da LPI) exigem manifestação em até 60 dias ininterruptos. Caso ocorra uma colidência de marcas ou "
            "notificação do INPI, notifique imediatamente o Diretor de Projetos e publique um tópico de alerta no Fórum Coletivo sob a tag `#projetos-inpi`."
        )
    },
    {
        "codigo": "POP-06",
        "titulo": "POP-06: Tesouraria, Fluxo de Caixa e Controle de Inadimplência",
        "categoria": "financeiro",
        "drive_url": "https://drive.google.com/drive/folders/edv-financeiro-cora",
        "autor_id": 1,
        "autor_nome": "Charles Junior (Presidência)",
        "autor_email": "charles.junior@edvjr.com.br",
        "conteudo": (
            "# POP-06 - Tesouraria, Fluxo de Caixa e Controle de Inadimplência\n"
            "**Área Responsável**: Operação & Finanças\n"
            "**Nível de Acesso**: Diretoria Financeira (Roles: diretor, presidente)\n\n"
            "## 1. Objetivo Operacional\n"
            "Garantir o rigor contábil, a solvência financeira e a conciliação bancária de receitas e despesas da EDV Jr., "
            "monitorando o faturamento oriundo de consultorias de RM, taxas federativas e controlando de forma ativa os índices de inadimplência.\n\n"
            "## 2. Pré-requisitos Sistêmicos\n"
            "* Autenticação autorizada com credenciais de Diretor Financeiro ou Presidente.\n"
            "* Extrato de conciliação bancária (Banco Cora) e notas fiscais de serviço (NFS-e) emitidas.\n"
            "* Base de contratos de consultoria associada aos respectivos planos de parcelamento.\n\n"
            "## 3. Passo a Passo na Interface do EDbrain\n"
            "1. Localize o menu lateral e selecione a aba **Financeiro** (`#view-financeiro`).\n"
            "2. Para lançar novos recebíveis ou custos operacionais, acione o botão **Nova Transação**:\n"
            "   - Defina o tipo contábil: `receita` ou `despesa`.\n"
            "   - Escolha a categoria oficial: `consultoria_rm`, `taxa_federativa`, `capacitacao`, `infraestrutura` ou `administrativo`.\n"
            "   - Preencha a descrição, valor monetário e data de vencimento.\n"
            "   - Em caso de consultorias, selecione o **Contrato RM Vinculado** para reconciliação automática.\n"
            "3. Monitore os indicadores de topo: Saldo em Caixa Consolidado, Previsão Mensal e Taxa de Inadimplência.\n"
            "4. Ao constatar a liquidação em conta corrente, clique em **Dar Baixa** e informe a data do efetivo pagamento.\n\n"
            "## 4. Tratamento de Exceções & Suporte Coletivo\n"
            "Títulos em atraso há mais de 15 dias disparam automaticamente alertas de risco no BI Executivo. Ao constatar inadimplência, "
            "inicie o protocolo de cobrança amigável em alinhamento com a equipe Comercial. Dúvidas tributárias ou de emissão de guias devem "
            "ser abertas no Fórum Coletivo com a tag `#financeiro-tesouraria`."
        )
    },
    {
        "codigo": "POP-07",
        "titulo": "POP-07: Geração e Execução do PDI Baseado no Motor Semântico",
        "categoria": "gestao_gente",
        "drive_url": "https://drive.google.com/drive/folders/edv-vpgg-pdi",
        "autor_id": 2,
        "autor_nome": "Alice Ney (VPGG)",
        "autor_email": "alice.ney@edvjr.com.br",
        "conteudo": (
            "# POP-07 - Geração e Execução do PDI Baseado no Motor Semântico\n"
            "**Área Responsável**: Pessoas & Conhecimento\n"
            "**Nível de Acesso**: Todos os Membros (Roles: assessor, gerente, diretor, presidente)\n\n"
            "## 1. Objetivo Operacional\n"
            "Acelerar a curva de maturidade técnica e comportamental dos membros da EDV Jr., fornecendo planos de desenvolvimento individual (PDI) "
            "dinâmicos gerados por inteligência semântica a partir da triangulação de gaps de competência, feedbacks 360º e objetivos estratégicos da gestão.\n\n"
            "## 2. Pré-requisitos Sistêmicos\n"
            "* Cadastro ativo do membro no ecossistema e perfil de acesso atribuído.\n"
            "* Participação no ciclo semestral de Avaliação de Desempenho 360º ou registro de entregas operacionais.\n"
            "* Definição da área de atuação e aspirações de liderança (sucessão) no módulo VPGG.\n\n"
            "## 3. Passo a Passo na Interface do EDbrain\n"
            "1. Localize o menu lateral e clique em **Meu PDI / Painel do Membro** (`#view-painel_membro`) ou acesse via **Gestão de Gente (VPGG)**.\n"
            "2. Acione o botão **Gerar Trilha Atômica com IA**. O motor semântico cruzará:\n"
            "   - Gaps de competências identificados pelos pares e liderança;\n"
            "   - Histórico de desempenho operacional em consultorias de RM;\n"
            "   - Foco individual declarado pelo colaborador.\n"
            "3. No Centro de Execução, examine os micro-blocos pedagógicos criados com títulos, ementas, materiais sugeridos e prazos de SLA (em dias).\n"
            "4. Ao concluir o estudo dos manuais ou capacitações gravadas correspondentes, clique em **Concluir Micro-Bloco** e registre a síntese do aprendizado para contabilizar o avanço percentual da trilha.\n\n"
            "## 4. Tratamento de Exceções & Suporte Coletivo\n"
            "Caso o motor semântico gere micro-blocos com SLA expirado ou fora do escopo funcional de sua diretoria, solicite a recalibração da trilha "
            "ao Gerente de Gente ou submeta uma solicitação de ajuste no Fórum Coletivo com a tag `#vpgg-pdi`."
        )
    },
    {
        "codigo": "POP-08",
        "titulo": "POP-08: Utilização do Fórum Coletivo de Dúvidas",
        "categoria": "geral",
        "drive_url": "https://drive.google.com/drive/folders/edv-forum-colaborativo",
        "autor_id": 1,
        "autor_nome": "Charles Junior (Presidência)",
        "autor_email": "charles.junior@edvjr.com.br",
        "conteudo": (
            "# POP-08 - Utilização do Fórum Coletivo de Dúvidas\n"
            "**Área Responsável**: Pessoas & Conhecimento\n"
            "**Nível de Acesso**: Todos os Membros (Roles: assessor, gerente, diretor, presidente)\n\n"
            "## 1. Objetivo Operacional\n"
            "Institucionalizar a gestão do conhecimento tácito da EDV Jr., fornecendo uma plataforma colaborativa assíncrona para resolução ágil de "
            "travas operacionais em consultorias, dúvidas jurídicas de PI e rotinas administrativas, mitigando o retrabalho entre diferentes gerações de membros.\n\n"
            "## 2. Pré-requisitos Sistêmicos\n"
            "* Acesso autenticado ao sistema EDbrain por qualquer membro da empresa júnior.\n"
            "* Consulta prévia aos artigos da Base de Conhecimento e POPs para verificar se o problema já possui solução documentada.\n\n"
            "## 3. Passo a Passo na Interface do EDbrain\n"
            "1. Localize o menu lateral e acione a seção de **Fórum Colaborativo**.\n"
            "2. Clique no botão **Nova Dúvida / Tópico**:\n"
            "   - Defina o título conciso do obstáculo enfrentado.\n"
            "   - Selecione a área temática (`juridico`, `comercial`, `projetos`, `financeiro`, `vpgg` ou `ti`).\n"
            "   - Detalhe o contexto, o número do processo/lead (se aplicável) e as tentativas de resolução já efetuadas.\n"
            "3. Acompanhe as respostas e debates colaborativos postados pelos pares, gerentes e diretores na thread.\n"
            "4. Assim que a dúvida for esclarecida, o autor ou um membro da Diretoria deve clicar em **Homologar Solução**, fixando a melhor resposta no topo como diretriz oficial para futuras consultas.\n\n"
            "## 4. Tratamento de Exceções & Suporte Coletivo\n"
            "Travas operacionais emergenciais que impactem prazos fatais perante terceiros (como defesas no INPI com vencimento em menos de 48 horas) "
            "devem ser sinalizadas com a flag de alta prioridade e comunicadas concomitantemente no canal de contingência da Presidência sob a tag `#forum-urgente`."
        )
    }
]

def seed_official_kb_pops(conn=None) -> dict:
    """
    Popula e atualiza de forma idempotente o Catálogo Oficial de Tutoriais e POPs Técnicos
    do EDbrain (POP-01 a POP-08), garantindo hierarquia Markdown estrita e metadados de autoria.
    """
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
    cursor = conn.cursor()
    try:
        inserted = 0
        updated = 0
        for pop in OFFICIAL_KB_POPS:
            codigo = pop.get("codigo", "")
            cursor.execute("SELECT id FROM kb_artigos WHERE titulo = ? OR titulo LIKE ?;", (pop["titulo"], f"{codigo}%"))
            existing = cursor.fetchone()
            if existing:
                artigo_id = existing[0]
                cursor.execute("""
                UPDATE kb_artigos
                SET titulo = ?, categoria = ?, conteudo = ?, drive_url = ?,
                    autor_id = ?, autor_nome = ?, autor_email = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
                """, (
                    pop["titulo"], pop["categoria"], pop["conteudo"], pop.get("drive_url"),
                    pop.get("autor_id", 1), pop.get("autor_nome", "Charles Junior (Presidência)"),
                    pop.get("autor_email", "charles.junior@edvjr.com.br"), artigo_id
                ))
                updated += 1
            else:
                cursor.execute("""
                INSERT INTO kb_artigos (tenant_id, titulo, categoria, conteudo, drive_url, autor_id, autor_nome, autor_email)
                VALUES ('edv_jr', ?, ?, ?, ?, ?, ?, ?);
                """, (
                    pop["titulo"], pop["categoria"], pop["conteudo"], pop.get("drive_url"),
                    pop.get("autor_id", 1), pop.get("autor_nome", "Charles Junior (Presidência)"),
                    pop.get("autor_email", "charles.junior@edvjr.com.br")
                ))
                inserted += 1
        conn.commit()
        return {"inserted": inserted, "updated": updated, "total": len(OFFICIAL_KB_POPS)}
    finally:
        if should_close:
            conn.close()


def create_kb_artigo(data: dict, current_user: Optional[dict] = None) -> dict:
    """Cadastra novo artigo ou Procedimento Operacional Padrão (POP) na base de conhecimento."""
    titulo = (data.get("titulo") or "").strip()
    if not titulo:
        raise ValueError("O título do artigo/POP é obrigatório.")

    categoria = (data.get("categoria") or "geral").strip().lower()
    if categoria not in VALID_KB_CATEGORIAS:
        raise ValueError(f"Categoria '{categoria}' inválida. Permitidas: {list(VALID_KB_CATEGORIAS)}")

    conteudo = (data.get("conteudo") or "").strip()
    if not conteudo:
        raise ValueError("O conteúdo descritivo em Markdown é obrigatório.")

    drive_url = (data.get("drive_url") or "").strip() or None

    autor_id = None
    autor_nome = "Equipe EDV Jr."
    autor_email = "contato@edvjr.com.br"
    if current_user:
        autor_id = current_user.get("id")
        autor_nome = current_user.get("nome") or current_user.get("name") or autor_nome
        autor_email = current_user.get("email") or autor_email

    gerado_por_ia = 1 if data.get("gerado_por_ia") else 0
    trilha_derivada_id = data.get("trilha_derivada_id")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO kb_artigos (tenant_id, titulo, categoria, conteudo, drive_url, autor_id, autor_nome, autor_email, gerado_por_ia, trilha_derivada_id)
    VALUES ('edv_jr', ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (titulo, categoria, conteudo, drive_url, autor_id, autor_nome, autor_email, gerado_por_ia, trilha_derivada_id))
    artigo_id = cursor.lastrowid
    conn.commit()

    cursor.execute("SELECT * FROM kb_artigos WHERE id = ?;", (artigo_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row)


def get_kb_artigo_by_id(artigo_id: int) -> Optional[dict]:
    """Recupera os detalhes completos de um artigo ou POP pelo ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM kb_artigos WHERE id = ?;", (artigo_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def list_kb_artigos(categoria: Optional[str] = None, search: Optional[str] = None) -> List[dict]:
    """Lista artigos com suporte a filtro por categoria e busca textual em título e conteúdo."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM kb_artigos WHERE 1=1"
    params = []

    if categoria and categoria.lower() not in ("todos", "todas", ""):
        query += " AND LOWER(categoria) = ?"
        params.append(categoria.lower().strip())

    if search and search.strip():
        s_term = f"%{search.strip()}%"
        query += " AND (titulo LIKE ? OR conteudo LIKE ?)"
        params.extend([s_term, s_term])

    query += " ORDER BY updated_at DESC, id DESC;"
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_kb_artigo(artigo_id: int) -> bool:
    """Exclui um artigo ou POP da base de conhecimento."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM kb_artigos WHERE id = ?;", (artigo_id,))
    if not cursor.fetchone():
        conn.close()
        return False

    cursor.execute("DELETE FROM kb_artigos WHERE id = ?;", (artigo_id,))
    conn.commit()
    conn.close()
    return True


def expand_kb_artigo_semantically(
    artigo_id: int,
    user_email: Optional[str] = None,
    vincular_ao_pdi: bool = False,
    area_foco: Optional[str] = None,
    contexto_adicional: Optional[str] = None,
    current_user: Optional[dict] = None
) -> dict:
    """
    Motor semântico autônomo do EDbrain que expande um POP em trilhas operacionais práticas,
    passos atômicos, checklists de validação e critérios de aceite vinculáveis ao Centro de Execução (PDI).
    """
    artigo = get_kb_artigo_by_id(artigo_id)
    if not artigo:
        raise ValueError(f"Artigo/POP com ID {artigo_id} não encontrado na Base de Conhecimento.")

    cat = (artigo.get("categoria") or "geral").lower()
    titulo = artigo.get("titulo") or "Procedimento Operacional"

    templates_por_categoria = {
        "projetos": {
            "trilha_titulo": f"Trilha Operacional de Execução: {titulo}",
            "vetor_demandas": "Prazos do INPI (Lei nº 9.279/1996 - LPI), prevenção de perda de prazos de 60 dias da RPI, garantia de satisfação do cliente e entrega tempestiva da consultoria de RM.",
            "etapas": [
                {
                    "etapa_num": 1,
                    "titulo": "Auditoria Prévia e Análise de Anterioridade Marcária",
                    "descricao": "Executar varredura aprofundada na base do INPI para identificação de marcas colidentes antes de qualquer manifestação ou depósito.",
                    "passos_praticos": [
                        "Acessar a base de marcas do portal do INPI com busca por radical e fonética;",
                        "Mapear todas as marcas com processo ativo ou deferido nas mesmas classes de Nice (NCL);",
                        "Elaborar relatório preliminar de viabilidade e risco com parecer consultivo."
                    ],
                    "checklist_validacao": [
                        "Busca exata e fonética concluída no INPI",
                        "Classes de Nice (NCL) confrontadas com o objeto social do cliente",
                        "Relatório anexado ao prontuário do projeto"
                    ],
                    "criterios_aceite": "Ausência de colidência direta nas classes primárias e aprovação formal do parecer pelo Gerente de Projetos.",
                    "sla_dias": 3,
                    "complexidade": "Média",
                    "entregavel_esperado": "Parecer de Anterioridade e Risco homologado"
                },
                {
                    "etapa_num": 2,
                    "titulo": "Preparação Documental e Emissão de GRU com Desconto MEJ",
                    "descricao": "Reunir o instrumental de mandato (procuração com poderes específicos) e emitir a Guia de Recolhimento da União com benefício de MEJ (código 389).",
                    "passos_praticos": [
                        "Colher procuração assinada digitalmente com poderes expressos perante o INPI;",
                        "Emitir a GRU sob código 389 no e-INPI aplicando desconto MEJ (Lei Complementar 123/2006);",
                        "Confirmar a compensação bancária da guia antes da submissão do protocolo."
                    ],
                    "checklist_validacao": [
                        "Procuração assinada com poderes específicos conferidos à EDV Jr.",
                        "GRU código 389 emitida no CPF/CNPJ do titular",
                        "Comprovante de pagamento bancário arquivado"
                    ],
                    "criterios_aceite": "Guia compensada no sistema e-INPI sem divergência cadastral de titularidade.",
                    "sla_dias": 2,
                    "complexidade": "Baixa",
                    "entregavel_esperado": "Dossiê com Procuração e Comprovante de GRU quitada"
                },
                {
                    "etapa_num": 3,
                    "titulo": "Protocolo Digital no e-INPI e Guarda do Comprovante de 9 Dígitos",
                    "descricao": "Submeter o formulário oficial no e-Marcas, anexando a logo em formato exigido (JPG/PNG alta definição) e salvando o número de processo.",
                    "passos_praticos": [
                        "Preencher o formulário no e-INPI com a especificação detalhada de produtos/serviços;",
                        "Realizar upload da arte visual conforme diretrizes de dimensão e resolução;",
                        "Baixar o recibo de protocolo contendo o número oficial de 9 dígitos e atualizar o prontuário no EDbrain."
                    ],
                    "checklist_validacao": [
                        "Formulário conferido e transmitido sem erros de validação",
                        "Recibo oficial de 9 dígitos salvo no diretório do projeto",
                        "Status do projeto atualizado para 'ativo' no módulo de RMs"
                    ],
                    "criterios_aceite": "Comprovante com carimbo temporal da autarquia e número de processo gerado com sucesso.",
                    "sla_dias": 1,
                    "complexidade": "Média",
                    "entregavel_esperado": "Recibo de Protocolo com Número de Processo INPI"
                },
                {
                    "etapa_num": 4,
                    "titulo": "Configuração da Esteira de Vigilância na RPI",
                    "descricao": "Cadastrar o número de processo na rotina semanal de leitura da Revista da Propriedade Industrial (RPI) para monitoramento de despachos e prazos.",
                    "passos_praticos": [
                        "Inserir o processo no radar de monitoramento da RPI do EDbrain;",
                        "Agendar alerta para publicação do pedido (início do prazo de oposição de 60 dias);",
                        "Emitir notificação informativa de conclusão da fase inicial para o cliente."
                    ],
                    "checklist_validacao": [
                        "Processo cadastrado no radar semanal da RPI",
                        "Alerta de 60 dias de oposição configurado",
                        "Relatório de protocolo enviado formalmente ao cliente"
                    ],
                    "criterios_aceite": "Processo rastreado no sistema e cliente cientificado com termo de protocolo formal.",
                    "sla_dias": 2,
                    "complexidade": "Baixa",
                    "entregavel_esperado": "Comunicação Formal de Depósito e Calendário de Acompanhamento"
                }
            ]
        },
        "financeiro": {
            "trilha_titulo": f"Trilha de Rigor Contábil e Liquidez: {titulo}",
            "vetor_demandas": "Conciliação bancária Cora, emissão de NFS-e sob Lei Municipal de Vitória, controle de inadimplência e preservação do índice de solvência da EDV Jr.",
            "etapas": [
                {
                    "etapa_num": 1,
                    "titulo": "Parametrização do Sacado e Emissão de Boletos no Banco Cora",
                    "descricao": "Cadastrar o cliente com dados tributários completos e programar os boletos das parcelas com incidência estatutária de juros e multa.",
                    "passos_praticos": [
                        "Inserir o CNPJ/CPF e razão social do contratante no Cora Banking;",
                        "Configurar o plano de parcelamento alinhado às cláusulas do Contrato de RM;",
                        "Vincular código da fatura à transação correspondente no Fluxo de Caixa do EDbrain."
                    ],
                    "checklist_validacao": [
                        "CNPJ validado sem restrições cadastrais",
                        "Datas de vencimento batendo com o contrato assinado",
                        "Chave de integração da cobrança salva no EDbrain"
                    ],
                    "criterios_aceite": "Carnê emitido e link de liquidação testado e funcional.",
                    "sla_dias": 2,
                    "complexidade": "Baixa",
                    "entregavel_esperado": "Boletos emitidos com QR Code PIX e código de barras"
                },
                {
                    "etapa_num": 2,
                    "titulo": "Emissão de Nota Fiscal de Serviços Eletrônica (NFS-e)",
                    "descricao": "Emitir a NFS-e oficial no portal da Prefeitura Municipal conforme o enquadramento de imunidade/isenção tributária de Empresa Júnior.",
                    "passos_praticos": [
                        "Acessar o portal fazendário municipal com certificado digital da EDV Jr.;",
                        "Discriminar os serviços de consultoria técnica prestados sem retenção indevida de ISS;",
                        "Fazer o download do XML e PDF da nota fiscal e arquivar na pasta financeira."
                    ],
                    "checklist_validacao": [
                        "Código de serviço compatível com consultoria jurídica e mercadológica",
                        "Valores e dados das partes conferidos",
                        "Nota Fiscal anexada ao registro financeiro do EDbrain"
                    ],
                    "criterios_aceite": "NFS-e transmitida com sucesso e número de autorização municipal gerado.",
                    "sla_dias": 3,
                    "complexidade": "Média",
                    "entregavel_esperado": "NFS-e autorizada e transmitida"
                },
                {
                    "etapa_num": 3,
                    "titulo": "Conciliação Bancária e Mitigação Ativa de Inadimplência",
                    "descricao": "Realizar o batimento do extrato bancário semanal com as previsões de caixa e executar cobrança amigável caso haja atraso superior a 5 dias.",
                    "passos_praticos": [
                        "Importar extrato OFX do Cora e verificar conciliação 100% de entradas;",
                        "Executar rotina de 'Dar Baixa' nas transações quitadas;",
                        "Acionar régua de comunicação para faturas em atraso antes do corte de 15 dias."
                    ],
                    "checklist_validacao": [
                        "Extrato conciliado com saldo bancário real",
                        "Transações marcadas como 'pago' com data efetiva",
                        "Alertas do BI Executivo atualizados"
                    ],
                    "criterios_aceite": "Divergência financeira zero entre extrato do Cora e o Fluxo de Caixa 2.0.",
                    "sla_dias": 2,
                    "complexidade": "Média",
                    "entregavel_esperado": "Relatório Semanal de Conciliação e Status de Recebíveis"
                }
            ]
        },
        "comercial": {
            "trilha_titulo": f"Esteira de Conversão e Tração Comercial: {titulo}",
            "vetor_demandas": "Metas de faturamento do Planejamento Estratégico, SLA de follow-ups no CRM em menos de 48h e fechamento de contratos de Registro de Marca.",
            "etapas": [
                {
                    "etapa_num": 1,
                    "titulo": "Qualificação B2B e Pesquisa Preliminar de Marca",
                    "descricao": "Triar o lead recém-chegado, verificar enquadramento no perfil de cliente ideal (ICP) e realizar checagem sumária no INPI.",
                    "passos_praticos": [
                        "Conferir situação cadastral do CNPJ via BrasilAPI;",
                        "Realizar checagem prévia no INPI para levar subsídios técnicos à reunião;",
                        "Mover o lead da etapa 'prospeccao' para 'contato_inicial' no CRM."
                    ],
                    "checklist_validacao": [
                        "CNPJ ativo e verificado",
                        "Dossiê preliminar de marca preenchido",
                        "Contato com tomador de decisão estabelecido"
                    ],
                    "criterios_aceite": "Abordagem realizada em menos de 24 horas após entrada do lead.",
                    "sla_dias": 1,
                    "complexidade": "Baixa",
                    "entregavel_esperado": "Dossiê de Qualificação Comercial do Lead"
                },
                {
                    "etapa_num": 2,
                    "titulo": "Condução de Reunião de Diagnóstico e Pitch de Valor",
                    "descricao": "Apresentar os riscos de operar sem registro de marca, explicar as vantagens do apoio da EDV Jr. e levantar necessidades específicas do cliente.",
                    "passos_praticos": [
                        "Conduzir alinhamento consultivo via Google Meet;",
                        "Apresentar casos de sucesso e a segurança da Lei 13.267/2016;",
                        "Mover oportunidade para 'diagnostico' e agendar envio de proposta."
                    ],
                    "checklist_validacao": [
                        "Dores e expectativas do tomador registradas no CRM",
                        "Número de classes estimadas acordado com o cliente",
                        "Data limite para apresentação da proposta fixada"
                    ],
                    "criterios_aceite": "Cliente engajado com confirmação de recebimento da proposta comercial formal.",
                    "sla_dias": 2,
                    "complexidade": "Média",
                    "entregavel_esperado": "Ata de Reunião de Diagnóstico Comercial"
                },
                {
                    "etapa_num": 3,
                    "titulo": "Envio de Proposta Comercial e Fechamento de Contrato",
                    "descricao": "Elaborar proposta personalizada com condições facilitadas no Cora e colher assinatura para conversão em projeto ativo.",
                    "passos_praticos": [
                        "Emitir minuta formal com hash SHA-256 e marca d'água oficial;",
                        "Negociar condições finais e encaminhar para assinatura digital Gov.br/Clicksign;",
                        "Mover oportunidade para 'fechado' e acionar a equipe de Projetos."
                    ],
                    "checklist_validacao": [
                        "Contrato assinado por ambas as partes arquivado",
                        "Receita lançada no módulo Financeiro",
                        "Kick-off agendado com o Gerente de Projetos"
                    ],
                    "criterios_aceite": "Contrato devidamente formalizado e registrado no Painel de Contratos do EDbrain.",
                    "sla_dias": 4,
                    "complexidade": "Alta",
                    "entregavel_esperado": "Contrato de Consultoria Assinado e Projeto Aberto"
                }
            ]
        },
        "juridico": {
            "trilha_titulo": f"Trilha de Governança, Compliance e Lei 13.267: {titulo}",
            "vetor_demandas": "Auditoria do Selo EJ Brasil Júnior, segurança documental com hash SHA-256, arquivamento de atas e regularidade fiscal e estatutária.",
            "etapas": [
                {
                    "etapa_num": 1,
                    "titulo": "Auditoria de Cláusulas Obrigatórias e Mitigação de Vícios Formais",
                    "descricao": "Conferir minutas e atos societários garantindo conformidade com a Lei Federal nº 13.267/2016 e as diretrizes do Conselho Nacional de Justiça (CNJ).",
                    "passos_praticos": [
                        "Checar qualificação completa das partes contratantes;",
                        "Garantir cláusula expressa de destinação não-lucrativa dos recursos para fins educacionais;",
                        "Verificar eleição de foro da Comarca de Vitória/ES."
                    ],
                    "checklist_validacao": [
                        "Conformidade com os arts. 2º e 3º da Lei 13.267/2016",
                        "Ausência de cláusulas abusivas ou de responsabilidade ilimitada",
                        "Aprovação do parecer pelo Diretor Jurídico"
                    ],
                    "criterios_aceite": "Parecer de conformidade com carimbo de aprovação da Diretoria Jurídica.",
                    "sla_dias": 2,
                    "complexidade": "Média",
                    "entregavel_esperado": "Parecer Jurídico de Regularidade Formal"
                },
                {
                    "etapa_num": 2,
                    "titulo": "Autenticação Criptográfica com Hash SHA-256 e Marca D'água",
                    "descricao": "Processar o documento no motor criptográfico do EDbrain para geração do carimbo de inviolabilidade digital.",
                    "passos_praticos": [
                        "Gerar PDF final com aplicação da marca d'água oficial da EDV Jr.;",
                        "Executar algoritmo SHA-256 para extração da chave única do arquivo;",
                        "Estampar hash no rodapé da minuta antes da colheita das assinaturas."
                    ],
                    "checklist_validacao": [
                        "Hash SHA-256 computado e registrado no banco de dados",
                        "Marca d'água institucional aplicada sem obstruir o texto",
                        "Arquivo disponibilizado para assinatura segura"
                    ],
                    "criterios_aceite": "Integridade criptográfica conferida contra adulteração textual posterior.",
                    "sla_dias": 1,
                    "complexidade": "Baixa",
                    "entregavel_esperado": "Instrumento Jurídico Autenticado com Assinatura SHA-256"
                },
                {
                    "etapa_num": 3,
                    "titulo": "Gestão de Certidões Negativas de Débitos (CNDs) e Selo EJ",
                    "descricao": "Verificar a regularidade contínua da empresa júnior emitindo mensalmente CND Federal, FGTS e CNDT perante a Receita Federal e TST.",
                    "passos_praticos": [
                        "Emitir CND Conjunta da Receita Federal e PGFN;",
                        "Emitir Certificado de Regularidade do FGTS (CRF) na Caixa Econômica;",
                        "Emitir CNDT perante a Justiça do Trabalho e anexar ao repositório Selo EJ."
                    ],
                    "checklist_validacao": [
                        "3 certidões negativas válidas e sem pendências fiscais",
                        "Documentos arquivados na pasta oficial do Selo EJ",
                        "Dashboard Executivo atualizado com status verde no Selo EJ"
                    ],
                    "criterios_aceite": "Todas as certidões com prazo de validade vigente e arquivadas no sistema.",
                    "sla_dias": 3,
                    "complexidade": "Média",
                    "entregavel_esperado": "Dossiê Mensal de Certidões Negativas (CNDs)"
                }
            ]
        },
        "gestao_gente": {
            "trilha_titulo": f"Trilha de Desenvolvimento e Aceleração de Membros: {titulo}",
            "vetor_demandas": "Mitigação de turnover, triangulação de gaps de desempenho 360º, retenção de talentos e formação de novas lideranças (plano de sucessão).",
            "etapas": [
                {
                    "etapa_num": 1,
                    "titulo": "Triangulação de Gaps e Diagnóstico 360º",
                    "descricao": "Cruzar as avaliações de pares com o histórico de entregas operacionais do membro para identificar prioridades de capacitação.",
                    "passos_praticos": [
                        "Consultar matriz de competências da Brasil Júnior no módulo VPGG;",
                        "Identificar competências com nota inferior a 3.5 em autoavaliação ou liderança;",
                        "Selecionar micro-blocos de aprendizagem correspondentes no catálogo."
                    ],
                    "checklist_validacao": [
                        "Triangulação executada com dados de avaliações ativas",
                        "Gaps classificados em Hard Skills e Soft Skills",
                        "Foco adicional acordado em reunião 1-on-1"
                    ],
                    "criterios_aceite": "Diagnóstico validado pelo membro e pelo Gerente de Gente.",
                    "sla_dias": 3,
                    "complexidade": "Média",
                    "entregavel_esperado": "Mapa Individual de Gaps de Competência"
                },
                {
                    "etapa_num": 2,
                    "titulo": "Execução de Micro-Ações Práticas e Estudo de POPs",
                    "descricao": "Cumprir a esteira pedagógica de micro-blocos, estudando a documentação oficial da Wiki e executando entregáveis práticos supervisionados.",
                    "passos_praticos": [
                        "Ler os POPs correspondentes à área de atuação na Base de Conhecimento;",
                        "Executar tarefas práticas simuladas sob mentoria de um membro sênior;",
                        "Registrar a síntese de aprendizado na plataforma."
                    ],
                    "checklist_validacao": [
                        "POPs obrigatórios concluídos e validados",
                        "Entregável prático submetido na esteira",
                        "SLA de conclusão do micro-bloco respeitado"
                    ],
                    "criterios_aceite": "Homologação do entregável pelo mentor com feedback descritivo.",
                    "sla_dias": 7,
                    "complexidade": "Média",
                    "entregavel_esperado": "Síntese Prática de Aprendizado Homologada"
                },
                {
                    "etapa_num": 3,
                    "titulo": "Avaliação de Impacto e Calibração Sucessória",
                    "descricao": "Medir a evolução do membro pós-trilha e posicioná-lo no pipeline de sucessão para cargos de gerência e diretoria.",
                    "passos_praticos": [
                        "Apurar ganho de maturidade nos indicadores de entrega;",
                        "Atualizar o score de prontidão para sucessão (IPS) no painel VPGG;",
                        "Emitir certificado de conclusão de ciclo de PDI."
                    ],
                    "checklist_validacao": [
                        "Avanço percentual do PDI atualizado para 100%",
                        "Score de sucessão recalculado automaticamente",
                        "Feedback final registrado na ata do membro"
                    ],
                    "criterios_aceite": "Membro calibrado e apto para novos desafios operacionais e estatutários.",
                    "sla_dias": 4,
                    "complexidade": "Média",
                    "entregavel_esperado": "Parecer de Evolução Individual e Prontidão de Sucessão"
                }
            ]
        },
        "ti": {
            "trilha_titulo": f"Trilha de Segurança, Auditoria e Governança Tecnológica: {titulo}",
            "vetor_demandas": "Blindagem de acessos RBAC, conformidade com a LGPD (Lei 13.709/2018), integridade dos logs de auditoria e alta disponibilidade do servidor.",
            "etapas": [
                {
                    "etapa_num": 1,
                    "titulo": "Auditoria de Matriz RBAC e Princípio do Menor Privilégio",
                    "descricao": "Conferir todas as credenciais ativas no banco de dados e revogar permissões sobressalentes ou perfis órfãos.",
                    "passos_praticos": [
                        "Executar varredura na tabela de usuários confrontando papéis atuais;",
                        "Validar isolamento de rotas de diretoria e presidência;",
                        "Garantir bloqueio de auto-promoção de assessores para diretores."
                    ],
                    "checklist_validacao": [
                        "Todos os membros com papéis estritamente mapeados",
                        "Nenhuma conta ativa sem e-mail institucional corporativo",
                        "Testes de bloqueio 403 validados com sucesso"
                    ],
                    "criterios_aceite": "Relatório de conformidade de acessos sem inconformidades críticas.",
                    "sla_dias": 2,
                    "complexidade": "Média",
                    "entregavel_esperado": "Relatório de Auditoria de Acessos e Papéis"
                },
                {
                    "etapa_num": 2,
                    "titulo": "Inspeção de Logs de Auditoria e Snapshot de Backup",
                    "descricao": "Verificar integridade da trilha de auditoria contínua e gerar snapshot seguro da base SQLite com hash de integridade.",
                    "passos_praticos": [
                        "Acessar módulo de auditoria e validar registros de operações críticas;",
                        "Executar rotina de snapshot de backup do arquivo auth.db;",
                        "Calcular hash SHA-256 da base de dados e arquivar cópia de contingência."
                    ],
                    "checklist_validacao": [
                        "Logs de auditoria ativos e sem gaps temporais",
                        "Backup gerado e testado com restauração em sandbox",
                        "Hash criptográfico do backup arquivado"
                    ],
                    "criterios_aceite": "Backup íntegro e base operacional pronta para contingência.",
                    "sla_dias": 1,
                    "complexidade": "Baixa",
                    "entregavel_esperado": "Snapshot de Contingência e Hash de Integridade"
                }
            ]
        }
    }

    template_default = {
        "trilha_titulo": f"Plano de Execução Autônoma: {titulo}",
        "vetor_demandas": "Continuidade institucional, mitigação de rotatividade entre gestões e retenção do saber operacional da EDV Jr.",
        "etapas": [
            {
                "etapa_num": 1,
                "titulo": "Revisão e Assimilação das Diretrizes do POP",
                "descricao": "Ler integralmente o manual oficial e identificar as conexões operacionais com a sua rotina semanal.",
                "passos_praticos": [
                    "Estudar as seções de objetivo e pré-requisitos sistêmicos;",
                    "Mapear os menus e botões correspondentes na interface do EDbrain;",
                    "Identificar pontos de atenção e possíveis travas operacionais."
                ],
                "checklist_validacao": [
                    "Leitura completa do POP realizada",
                    "Acesso aos módulos e ferramentas necessários testado",
                    "Dúvidas iniciais sanadas com a liderança"
                ],
                "criterios_aceite": "Compreensão clara do fluxo operacional sem bloqueios de procedimento.",
                "sla_dias": 2,
                "complexidade": "Baixa",
                "entregavel_esperado": "Confirmação de Leitura e Plano de Aplicação"
            },
            {
                "etapa_num": 2,
                "titulo": "Execução Prática Supervisionada com Checklist de Validação",
                "descricao": "Aplicar o procedimento operacional em um caso real ou projeto ativo sob acompanhamento de par ou gerente.",
                "passos_praticos": [
                    "Preencher os formulários oficiais na interface;",
                    "Submeter as ações cumprindo todos os critérios de validação;",
                    "Registrar a conclusão da atividade no sistema."
                ],
                "checklist_validacao": [
                    "Todos os campos obrigatórios validados",
                    "Evidências e anexos arquivados na base",
                    "Status da operação atualizado para concluído"
                ],
                "criterios_aceite": "Execução em conformidade com as regras do POP sem necessidade de retrabalho.",
                "sla_dias": 4,
                "complexidade": "Média",
                "entregavel_esperado": "Evidência de Execução Prática Homologada"
            },
            {
                "etapa_num": 3,
                "titulo": "Registro de Lições Aprendidas e Contribuição no Fórum",
                "descricao": "Documentar melhorias identificadas durante a rotina para aprimoramento contínuo da Base de Conhecimento.",
                "passos_praticos": [
                    "Anotar pontos de melhoria observados durante a execução;",
                    "Compartilhar dicas práticas com a equipe no Fórum Coletivo;",
                    "Sugerir atualizações nos manuais em caso de mudança de procedimentos externos."
                ],
                "checklist_validacao": [
                    "Lições aprendidas registradas",
                    "Tópico ou contribuição publicada no Fórum",
                    "Diretoria ciente de eventuais oportunidades de melhoria"
                ],
                "criterios_aceite": "Disseminação do saber técnico concluída com sucesso entre os membros.",
                "sla_dias": 3,
                "complexidade": "Baixa",
                "entregavel_esperado": "Registro de Contribuição Coletiva"
            }
        ]
    }

    ramificacao = templates_por_categoria.get(cat, template_default)

    checklist_consolidado = []
    for etapa in ramificacao["etapas"]:
        etapa["passo"] = etapa.get("etapa_num", 1)
        etapa["criterio_aceite"] = etapa.get("criterios_aceite", "")
        etapa["formato_entregavel"] = etapa.get("entregavel_esperado", "")
        for item in etapa["checklist_validacao"]:
            checklist_consolidado.append({
                "etapa_num": etapa["etapa_num"],
                "etapa_titulo": etapa["titulo"],
                "item": item,
                "concluido": False
            })

    markdown_linhas = [
        f"# [Trilha Autônoma] {ramificacao['trilha_titulo']}",
        f"**Documento Base**: {titulo}  ",
        f"**Categoria Operacional**: {cat.upper()}  ",
        f"**Vetor de Demandas**: {ramificacao['vetor_demandas']}  ",
        f"**Origem**: Gerado Autonomamente pelo Motor Semântico do EDbrain  \n",
        "## 1. Etapas Operacionais Deduzidas",
        f"Esta trilha prática desdobra o procedimento operacional padrão `{titulo}` em sub-etapas atômicas, checklists de validação e critérios objetivos de aceite para execução imediata pelos membros da EDV Jr.\n",
        "## 2. Checklist Executivo de Validação",
    ]
    for chk in checklist_consolidado:
        markdown_linhas.append(f"- [ ] **[Etapa {chk['etapa_num']}]** {chk['item']}")

    markdown_linhas.append("\n## 3. SLA Global & Governança\n")
    for etapa in ramificacao["etapas"]:
        markdown_linhas.append(f"### Etapa {etapa['etapa_num']}: {etapa['titulo']}")
        markdown_linhas.append(f"**SLA Estimado**: {etapa['sla_dias']} dias | **Complexidade**: {etapa['complexidade']}  ")
        markdown_linhas.append(f"**Entregável Esperado**: `{etapa['entregavel_esperado']}`\n")
        markdown_linhas.append(f"{etapa['descricao']}\n")
        markdown_linhas.append("**Passos Práticos de Execução**:")
        for p in etapa["passos_praticos"]:
            markdown_linhas.append(f"1. {p}")
        markdown_linhas.append("\n**Critérios de Aceite & Conformidade**:")
        markdown_linhas.append(f"> {etapa['criterios_aceite']}\n")

    markdown_linhas.append("## 4. Integração com o Centro de Execução")
    markdown_linhas.append(
        "Todas as sub-etapas desta trilha podem ser vinculadas ao seu PDI individual no menu **Meu PDI / VPGG**, "
        "gerando micro-blocos rastreáveis com contagem de SLA e pontuação para o plano de sucessão da empresa júnior."
    )

    markdown_derivado = "\n".join(markdown_linhas)

    novo_artigo_titulo = f"Trilha Prática: {titulo} (Ramificação Semântica)"
    artigo_derivado = create_kb_artigo({
        "titulo": novo_artigo_titulo,
        "categoria": cat,
        "conteudo": markdown_derivado,
        "drive_url": artigo.get("drive_url"),
        "gerado_por_ia": True,
        "trilha_derivada_id": artigo_id
    }, current_user={
        "id": (current_user.get("id") if current_user else None),
        "nome": "Motor Semântico EDbrain",
        "email": "ia@edvjr.com.br"
    })

    blocos_pdi_criados = []

    if vincular_ao_pdi:
        conn = get_connection()
        cursor = conn.cursor()
        try:
            target_user = None
            if user_email:
                cursor.execute("SELECT id, nome, email FROM users WHERE LOWER(email) = ?;", (user_email.lower().strip(),))
                target_user = cursor.fetchone()
            if not target_user and current_user and current_user.get("email"):
                cursor.execute("SELECT id, nome, email FROM users WHERE LOWER(email) = ?;", (current_user["email"].lower().strip(),))
                target_user = cursor.fetchone()
            if not target_user:
                cursor.execute("SELECT id, nome, email FROM users ORDER BY id ASC LIMIT 1;")
                target_user = cursor.fetchone()

            if target_user:
                u_id = target_user["id"]
                u_email = target_user["email"]

                for etapa in ramificacao["etapas"]:
                    micro_code = f"POP{artigo_id}-E{etapa['etapa_num']}"
                    cursor.execute("SELECT id FROM member_pdi_blocks WHERE user_id = ? AND microblock_code = ?;", (u_id, micro_code))
                    bloco_existente = cursor.fetchone()
                    if not bloco_existente:
                        cursor.execute("""
                        INSERT INTO member_pdi_blocks (
                            tenant_id, user_id, user_email, microblock_code, title,
                            competency_mej, eixo, area, complexity, description,
                            deliverable_format, evaluation_metric, sla_days, status,
                            justificativa_algoritmica
                        ) VALUES (
                            'edv_jr', ?, ?, ?, ?,
                            'Execução de Consultorias', 'Operação & Técnica', ?, ?, ?,
                            ?, 'Checklist 100% Homologado', ?, 'pendente',
                            ?
                        );
                        """, (
                            u_id, u_email, micro_code, f"[{cat.upper()}] {etapa['titulo']}",
                            cat, 2 if etapa['complexidade'] == 'Média' else (3 if etapa['complexidade'] == 'Alta' else 1),
                            etapa['descricao'], etapa['entregavel_esperado'], etapa['sla_dias'],
                            f"Ramificação semântica automática gerada do {titulo}"
                        ))
                        bloco_id = cursor.lastrowid
                        blocos_pdi_criados.append({
                            "id": bloco_id,
                            "code": micro_code,
                            "microblock_code": micro_code,
                            "title": etapa["titulo"],
                            "sla_days": etapa["sla_dias"],
                            "status": "pendente"
                        })
                conn.commit()

                if blocos_pdi_criados:
                    cursor.execute("UPDATE kb_artigos SET trilha_derivada_id = ? WHERE id = ?;", (blocos_pdi_criados[0]["id"], artigo_derivado["id"]))
                    conn.commit()
                    artigo_derivado["trilha_derivada_id"] = blocos_pdi_criados[0]["id"]
        finally:
            conn.close()

    checklist_simples = [item["item"] for item in checklist_consolidado]

    return {
        "status": "success",
        "success": True,
        "artigo_base_id": artigo_id,
        "artigo_base": {
            "id": artigo_id,
            "titulo": titulo,
            "categoria": cat
        },
        "artigo_base_titulo": titulo,
        "categoria": cat,
        "area_foco": area_foco or cat,
        "contexto_adicional": contexto_adicional or "",
        "vinculado_ao_pdi": bool(vincular_ao_pdi),
        "total_etapas": len(ramificacao["etapas"]),
        "etapas_autonomas": ramificacao["etapas"],
        "checklist_consolidado": checklist_simples,
        "checklist_detalhado": checklist_consolidado,
        "ramificacao_semantica": {
            "trilha_titulo": ramificacao["trilha_titulo"],
            "vetor_demandas_analisado": ramificacao["vetor_demandas"],
            "etapas_autonomas": ramificacao["etapas"],
            "checklist_consolidado": checklist_simples,
            "total_etapas": len(ramificacao["etapas"])
        },
        "artigo_derivado": artigo_derivado,
        "blocos_pdi_vinculados": blocos_pdi_criados
    }



if __name__ == "__main__":
    init_db()

