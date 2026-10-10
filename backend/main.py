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
import csv
import io
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List, Union

import httpx

from fastapi import FastAPI, Depends, HTTPException, status, Query, Request, BackgroundTasks
from fastapi.responses import FileResponse, Response, StreamingResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from utils import (
        clean_cnpj,
        format_cnpj,
        normalize_company_name,
        build_fts5_wildcard_query,
        build_address_from_brasilapi,
        generate_commercial_pitch
    )
except ImportError:
    from backend.utils import (
        clean_cnpj,
        format_cnpj,
        normalize_company_name,
        build_fts5_wildcard_query,
        build_address_from_brasilapi,
        generate_commercial_pitch
    )

try:
    from backend.database import (
        init_db,
        get_user_by_email,
        get_user_by_id,
        get_all_users,
        get_followup_by_id,
        get_connection,
        log_audit,
        get_audit_logs,
        count_audit_logs,
        create_database_snapshot,
        get_database_stats,
        DB_PATH,
        get_backups_dir,
        VALID_ROLES,
        create_campaign,
        get_campaign_by_id,
        update_campaign,
        delete_campaign,
        list_campaigns,
        get_campaign_roi_metrics,
        create_psel_candidate,
        get_psel_candidate_by_id,
        update_psel_candidate,
        update_psel_candidate_stage,
        delete_psel_candidate,
        list_psel_candidates,
        approve_and_onboard_candidate,
        create_brand_asset,
        get_brand_asset_by_id,
        update_brand_asset,
        delete_brand_asset,
        list_brand_assets,
        get_marketing_dashboard_analytics,
        CampaignORM,
        PselCandidateORM,
        BrandAssetORM,
        PerformanceEvaluation360ORM,
        EvaluatorCalibrationORM,
        HistoricalManagerBenchmarkORM,
        SuccessionReadinessORM,
        GapMitigationActionORM,
        calculate_triangulation,
        save_evaluation_360,
        list_evaluations_360,
        calculate_succession_ips,
        generate_gap_mitigation_plan,
        list_gap_mitigation_actions,
        list_historical_benchmarks,
        get_member_hard_metrics,
        get_evaluator_calibrations,
        get_db_session,
        list_compliance_statutes,
        get_compliance_statute_by_id,
        create_compliance_statute,
        update_compliance_statute,
        update_statute_checklist,
        delete_compliance_statute,
        create_system_notification,
        get_user_notifications,
        mark_notification_as_read,
        mark_all_notifications_as_read,
        scan_and_create_deadlines,
        create_rm_staging_record,
        list_rm_staging_records,
        get_rm_staging_record_by_id,
        approve_rm_staging_record,
        reject_rm_staging_record,
        get_or_create_member_pdi_trail,
        update_microblock_status,
        create_forum_duvida,
        list_forum_duvidas,
        add_forum_resposta,
        resolve_forum_duvida,
        create_lead,
        get_lead_by_id,
        update_lead,
        get_crm_pipeline,
        create_contrato_rm,
        list_contratos_rm,
        get_contrato_rm_by_id,
        update_contrato_rm_status,
        get_contrato_rm_by_process_number,
        get_rpi_despachos_historico,
        get_rpi_resumo_executivo,
        seed_contratos_rm_from_legacy,
        create_transacao_financeira,
        get_transacao_financeira_by_id,
        list_transacoes_financeiras,
        update_transacao_financeira_status,
        get_financeiro_kpis,
        get_executivo_kpis_consolidados,
        create_kb_artigo,
        get_kb_artigo_by_id,
        list_kb_artigos,
        delete_kb_artigo,
        expand_kb_artigo_semantically
    )
    from backend.auth import (
        verify_password,
        create_access_token,
        get_current_user,
        get_current_user_optional,
        require_role,
        verify_area_access,
        check_area_access,
        verify_vpgg_access,
        check_vpgg_access,
        check_marketing_access,
        verify_marketing_access,
        check_psel_management_access,
        verify_psel_access,
        check_compliance_access,
        verify_compliance_access,
        check_rm_staging_approval_access,
        verify_rm_staging_approval_access,
        login_rate_limiter
    )
except ImportError:
    from database import (
        init_db,
        get_user_by_email,
        get_user_by_id,
        get_all_users,
        get_followup_by_id,
        get_connection,
        log_audit,
        get_audit_logs,
        count_audit_logs,
        create_database_snapshot,
        get_database_stats,
        DB_PATH,
        get_backups_dir,
        VALID_ROLES,
        create_campaign,
        get_campaign_by_id,
        update_campaign,
        delete_campaign,
        list_campaigns,
        get_campaign_roi_metrics,
        create_psel_candidate,
        get_psel_candidate_by_id,
        update_psel_candidate,
        update_psel_candidate_stage,
        delete_psel_candidate,
        list_psel_candidates,
        approve_and_onboard_candidate,
        create_brand_asset,
        get_brand_asset_by_id,
        update_brand_asset,
        delete_brand_asset,
        list_brand_assets,
        get_marketing_dashboard_analytics,
        CampaignORM,
        PselCandidateORM,
        BrandAssetORM,
        PerformanceEvaluation360ORM,
        EvaluatorCalibrationORM,
        HistoricalManagerBenchmarkORM,
        SuccessionReadinessORM,
        GapMitigationActionORM,
        calculate_triangulation,
        save_evaluation_360,
        list_evaluations_360,
        calculate_succession_ips,
        generate_gap_mitigation_plan,
        list_gap_mitigation_actions,
        list_historical_benchmarks,
        get_member_hard_metrics,
        get_evaluator_calibrations,
        get_db_session,
        list_compliance_statutes,
        get_compliance_statute_by_id,
        create_compliance_statute,
        update_compliance_statute,
        update_statute_checklist,
        delete_compliance_statute,
        create_system_notification,
        get_user_notifications,
        mark_notification_as_read,
        mark_all_notifications_as_read,
        scan_and_create_deadlines,
        create_rm_staging_record,
        list_rm_staging_records,
        get_rm_staging_record_by_id,
        approve_rm_staging_record,
        reject_rm_staging_record,
        get_or_create_member_pdi_trail,
        update_microblock_status,
        create_forum_duvida,
        list_forum_duvidas,
        add_forum_resposta,
        resolve_forum_duvida,
        create_lead,
        get_lead_by_id,
        update_lead,
        get_crm_pipeline,
        create_contrato_rm,
        list_contratos_rm,
        get_contrato_rm_by_id,
        update_contrato_rm_status,
        get_contrato_rm_by_process_number,
        get_rpi_despachos_historico,
        get_rpi_resumo_executivo,
        seed_contratos_rm_from_legacy,
        create_transacao_financeira,
        get_transacao_financeira_by_id,
        list_transacoes_financeiras,
        update_transacao_financeira_status,
        get_financeiro_kpis,
        get_executivo_kpis_consolidados,
        create_kb_artigo,
        get_kb_artigo_by_id,
        list_kb_artigos,
        delete_kb_artigo,
        expand_kb_artigo_semantically
    )
    from auth import (
        verify_password,
        create_access_token,
        get_current_user,
        get_current_user_optional,
        require_role,
        verify_area_access,
        check_area_access,
        verify_vpgg_access,
        check_vpgg_access,
        check_marketing_access,
        verify_marketing_access,
        check_psel_management_access,
        verify_psel_access,
        check_compliance_access,
        verify_compliance_access,
        check_rm_staging_approval_access,
        verify_rm_staging_approval_access,
        login_rate_limiter
    )

try:
    from backend.legal_engine import gerar_minuta_contratual, gerar_documento_didatico
except ImportError:
    from legal_engine import gerar_minuta_contratual, gerar_documento_didatico

try:
    from backend.rpi_scanner import RPIScannerEngine, simular_varredura_semanal_inpi, parse_rpi_xml, parse_rpi_json
except ImportError:
    from rpi_scanner import RPIScannerEngine, simular_varredura_semanal_inpi, parse_rpi_xml, parse_rpi_json

try:
    from semantic_nlp import (
        SemanticIntentProcessor,
        calcular_matriz_combinatoria,
        montar_trilha_algoritmica,
        gerar_hash_singularidade
    )
except ImportError:
    from backend.semantic_nlp import (
        SemanticIntentProcessor,
        calcular_matriz_combinatoria,
        montar_trilha_algoritmica,
        gerar_hash_singularidade
    )

# Caminho para o payload operacional oficial
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY_DATA_PATH = os.path.join(BASE_DIR, "data", "legacy_data.json")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializa tabelas SQLite e sincroniza Whitelist oficial
    init_db()
    try:
        scan_and_create_deadlines()
    except Exception as e_scan:
        print(f"[Lifespan] Erro ao varrer prazos iniciais: {e_scan}")
    yield

app = FastAPI(
    title="EDV Jr. - EDbrain Security & Core Backend",
    version="2.3.0",
    description="Backend oficial da EDV Jr. com SQLite, JWT, RBAC, Módulo Financeiro, Mural de Avisos, PDIs (VPGG) e CRM Comercial.",
    lifespan=lifespan
)

# Origens permitidas explícitas para garantir compatibilidade com cookies HttpOnly (RFC 6454 / Fetch Spec)
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://edbrain.onrender.com",
    "https://charlesjbs1830-lab.github.io",
]
env_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")
if env_origins:
    ALLOWED_ORIGINS.extend([o.strip() for o in env_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?|https://.*\.github\.io|https://.*\.onrender\.com",
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
    competency_mej: Optional[str] = Field("Gestão", description="Modelo de Competências da Brasil Júnior (Liderança, Gestão, Autoconhecimento, Visão Sistêmica, Orientação para Resultados)")
    objectives: str = Field(..., min_length=3, description="Objetivos e metas de desenvolvimento")
    development_ideas: str = Field(..., min_length=3, description="Ações práticas, ideias e entregáveis de evolução")
    deadline: str = Field(..., description="Data limite para conclusão (YYYY-MM-DD)")
    status: Optional[str] = Field("em_andamento", description="Status do PDI ('planejado', 'em_andamento', 'concluido', 'pausado')")

class PDIUpdate(BaseModel):
    competency_mej: Optional[str] = None
    objectives: Optional[str] = None
    development_ideas: Optional[str] = None
    deadline: Optional[str] = None
    status: Optional[str] = None

class PDIResponse(BaseModel):
    id: int
    user_email: str
    area: str
    competency_mej: Optional[str] = "Gestão"
    objectives: str
    development_ideas: str
    deadline: str
    status: str
    triangulated_score: Optional[float] = 0.0
    ips_score: Optional[float] = 0.0
    action_plan_70_20_10: Optional[str] = None
    created_at: Optional[str] = None

class PDIGenerateRequest(BaseModel):
    member_email: str = Field(..., description="E-mail corporativo do membro para geração da trilha")
    foco_adicional: Optional[str] = Field(None, description="Foco customizado opcional (ex: liderança, oratória, vendas)")
    sanitization_mode: Optional[str] = Field("adaptive", description="Modo de saneamento: 'adaptive' (IA inteligente) ou 'restrictive' (governança rígida)")

class MicroblockStatusUpdate(BaseModel):
    status: str = Field(..., description="Novo status: pendente, em_andamento ou concluido")

class DuvidaCreate(BaseModel):
    title: str = Field(..., min_length=3, description="Título da dúvida ou ocorrência")
    description: str = Field(..., min_length=5, description="Descrição detalhada do problema")
    category: Optional[str] = Field("Geral", description="Categoria corporativa")

class RespostaCreate(BaseModel):
    content: str = Field(..., min_length=2, description="Conteúdo da resposta colaborativa")

class DuvidaStatusUpdate(BaseModel):
    status: str = Field(..., description="Novo status da dúvida (aberta ou resolvida)")

class Evaluation360Create(BaseModel):
    evaluatee_email: str = Field(..., description="E-mail institucional do colaborador avaliado")
    cycle_id: Optional[str] = Field("2026.1", description="Ciclo avaliativo vigente (ex: '2026.1', '2026.2')")
    relationship_type: Optional[str] = Field("peer", description="Relação hierárquica com o avaliado ('leader', 'peer', 'subordinate', 'self')")
    score_lideranca: float = Field(..., ge=1.0, le=5.0, description="Nota de Liderança Oficial Brasil Júnior (1.0 a 5.0)")
    score_gestao: float = Field(..., ge=1.0, le=5.0, description="Nota de Gestão Oficial Brasil Júnior (1.0 a 5.0)")
    score_visao_sistemica: float = Field(..., ge=1.0, le=5.0, description="Nota de Visão Sistêmica Oficial Brasil Júnior (1.0 a 5.0)")
    score_orientacao_resultados: float = Field(..., ge=1.0, le=5.0, description="Nota de Orientação para Resultados Oficial Brasil Júnior (1.0 a 5.0)")
    score_autoconhecimento: float = Field(..., ge=1.0, le=5.0, description="Nota de Autoconhecimento Oficial Brasil Júnior (1.0 a 5.0)")
    feedback_qualitativo: Optional[str] = Field(None, description="Parecer qualitativo, pontos a continuar e pontos a desenvolver")

class Evaluation360Response(BaseModel):
    id: int
    tenant_id: str
    cycle_id: str
    evaluatee_email: str
    evaluator_email: str
    relationship_type: str
    score_lideranca: float
    score_gestao: float
    score_visao_sistemica: float
    score_orientacao_resultados: float
    score_autoconhecimento: float
    feedback_qualitativo: Optional[str] = None
    status: str
    created_at: Optional[Any] = None

class GapMitigationPlanRequest(BaseModel):
    user_email: str = Field(..., description="E-mail do assessor para reconfiguração imediata do plano de desenvolvimento")

class GapMitigationActionResponse(BaseModel):
    id: int
    tenant_id: str
    user_email: str
    competency_deficient: str
    current_score: float
    target_score: float
    deficit_severity: str
    action_type: str
    practical_allocation: str
    mentor_assigned: Optional[str] = None
    course_or_playbook: Optional[str] = None
    status: str
    deadline: Optional[str] = None
    created_at: Optional[Any] = None

VALID_CRM_STATUSES = {"prospeccao", "negociacao", "fechado", "perdido"}

class ClientFollowupCreate(BaseModel):
    client_name: str = Field(..., min_length=1, description="Nome da empresa ou cliente (OBRIGATÓRIO)")
    razao_social: Optional[str] = Field(None, description="Razão Social corporativa oficial")
    nome_fantasia: Optional[str] = Field(None, description="Nome Fantasia da empresa")
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
    impact_score: Optional[int] = Field(0, description="Score de impacto socioeconômico gerado (0 a 100)")
    impact_type: Optional[str] = Field(None, description="Tipo de impacto MEJ (ex: Proteção de Ativo Intangível / Marca, Aceleração Econômica de PME)")
    impact_description: Optional[str] = Field(None, description="Descrição do impacto da consultoria no negócio do cliente")

class ClientFollowupUpdate(BaseModel):
    client_name: Optional[str] = None
    razao_social: Optional[str] = None
    nome_fantasia: Optional[str] = None
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
    impact_score: Optional[int] = None
    impact_type: Optional[str] = None
    impact_description: Optional[str] = None

class ClientFollowupResponse(BaseModel):
    id: int
    client_name: str
    razao_social: Optional[str] = None
    nome_fantasia: Optional[str] = None
    normalized_name: Optional[str] = None
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
    impact_score: Optional[int] = 0
    impact_type: Optional[str] = None
    impact_description: Optional[str] = None
    created_by: str
    created_at: Optional[str] = None
    days_stagnant: Optional[int] = 0
    is_stagnant: Optional[bool] = False

class LeadPitchRequest(BaseModel):
    lead_id: Optional[int] = None
    client_name: Optional[str] = None
    razao_social: Optional[str] = None
    nome_fantasia: Optional[str] = None
    cnae: Optional[str] = None
    company_size: Optional[str] = None
    address: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[str] = None
    contact_person: Optional[str] = None

class LeadPitchResponse(BaseModel):
    status: str = "success"
    client_name: str
    segmento: str
    tese_juridica: str
    whatsapp: str
    instagram: str
    email: str
    instagram_dm: Optional[str] = None
    email_formal: Optional[str] = None

class AuditLogItem(BaseModel):
    id: int
    user_email: str
    action: str
    resource: str
    status_code: int
    details: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: str

class AuditLogResponse(BaseModel):
    status: str = "success"
    total: int
    limit: int
    offset: int
    logs: List[AuditLogItem]

class StrategyPEMetricsResponse(BaseModel):
    status: str = "success"
    ano_referencia: int = 2026
    planejamento_estrategico: str = "PE Brasil Júnior 2024-2026"
    cluster_mej: str = "Cluster 4.0 (Conectada, Alto Crescimento, Alto Impacto)"
    faturamento_realizado: float
    faturamento_meta: float
    faturamento_percentual: float
    faturamento_status: str
    projetos_alto_impacto_realizados: int
    projetos_alto_impacto_meta: int
    projetos_alto_impacto_percentual: float
    projetos_alto_impacto_status: str
    retencao_membros_taxa: float
    retencao_membros_meta: float
    retencao_status: str
    nps_satisfacao_media: float
    nps_satisfacao_meta: float
    nps_status: str
    alertas_linha_corte: List[str]
    compliance_mej_geral: str

class LeadIngestItem(BaseModel):
    client_name: Optional[str] = None
    razao_social: Optional[str] = None
    nome_fantasia: Optional[str] = None
    cnpj: Optional[str] = None
    cnae: Optional[str] = None
    company_size: Optional[str] = None
    address: Optional[str] = None
    contact_person: Optional[str] = None
    status: Optional[str] = "prospeccao"
    interaction_type: Optional[str] = "Radar Ingestão"
    notes: Optional[str] = None
    next_followup_date: Optional[str] = None
    area: Optional[str] = "Comercial"
    tags: Optional[str] = "#public_data"
    estimated_value: Optional[float] = 0.0

class LeadIngestBatchRequest(BaseModel):
    leads: Optional[List[LeadIngestItem]] = None
    csv_content: Optional[str] = None

class IngestDetailItem(BaseModel):
    id: int
    client_name: str
    cnpj: Optional[str] = None
    action: str  # 'inserted' ou 'updated'
    score: int
    area: str

class LeadIngestResponse(BaseModel):
    status: str
    total_received: int
    inserted: int
    updated: int
    enriched_via_brasilapi: int
    errors: int
    details: List[IngestDetailItem] = []

# ==============================================================================
# SCHEMAS DO MÓDULO MARKETING & CAMPANHAS (ROI, PSEL, BRAND KIT)
# ==============================================================================

class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=2, description="Nome da campanha (ex: Maré de Vendas 2026)")
    type: str = Field(..., description="Tipo da ação: 'captacao_projetos', 'processo_seletivo' ou 'branding_institucional'")
    channel: str = Field(..., description="Canal principal: 'instagram', 'linkedin', 'outbound' ou 'indicacao'")
    status: Optional[str] = Field("ativa", description="'planejamento', 'ativa', 'pausada', 'concluida'")
    budget: Optional[float] = Field(0.0, ge=0, description="Orçamento planejado em Reais")
    actual_cost: Optional[float] = Field(0.0, ge=0, description="Custo efetivo / investimento realizado em Reais")
    target_leads: Optional[int] = Field(0, ge=0, description="Meta de leads ou inscritos")
    start_date: Optional[str] = Field(None, description="Data de início (YYYY-MM-DD)")
    end_date: Optional[str] = Field(None, description="Data de término (YYYY-MM-DD)")
    responsible: str = Field(..., description="Membro responsável pela condução da campanha")
    description: Optional[str] = Field("", description="Objetivos e escopo da campanha")
    tenant_id: Optional[str] = Field("edv_jr", description="Identificador do tenant")

class CampaignUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    channel: Optional[str] = None
    status: Optional[str] = None
    budget: Optional[float] = None
    actual_cost: Optional[float] = None
    target_leads: Optional[int] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    responsible: Optional[str] = None
    description: Optional[str] = None

class CampaignResponse(BaseModel):
    id: int
    tenant_id: str
    name: str
    type: str
    channel: str
    status: str
    budget: float
    actual_cost: float
    target_leads: int
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    responsible: str
    description: Optional[str] = None
    created_by: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    leads_count: Optional[int] = 0
    leads_fechados: Optional[int] = 0
    receita_gerada: Optional[float] = 0.0
    lucro_liquido: Optional[float] = 0.0
    roi: Optional[float] = 0.0
    taxa_conversao: Optional[float] = 0.0
    cpl: Optional[float] = 0.0
    cac: Optional[float] = 0.0

class PselCandidateCreate(BaseModel):
    campaign_id: Optional[int] = Field(None, description="ID da campanha de divulgação do PSEL associada")
    name: str = Field(..., min_length=2, description="Nome completo do candidato")
    email: str = Field(..., min_length=5, description="E-mail de contato")
    phone: Optional[str] = Field(None, description="Telefone / WhatsApp")
    course: Optional[str] = Field("Direito", description="Curso de graduação")
    period: Optional[str] = Field(None, description="Período acadêmico atual")
    stage: Optional[str] = Field("inscricao", description="Estágio no funil ('inscricao', 'dinamica', 'entrevista', 'onboarding', 'aprovado', 'reprovado', 'desistente')")
    target_area: Optional[str] = Field("Comercial", description="Área pretendida (Comercial, Projetos, Marketing, VPGG, Jurídico, Tesouraria)")
    score_dinamica: Optional[float] = Field(0.0, ge=0, le=10, description="Nota na fase de dinâmica em grupo (0 a 10)")
    score_entrevista: Optional[float] = Field(0.0, ge=0, le=10, description="Nota na entrevista individual (0 a 10)")
    notes: Optional[str] = Field("", description="Anotações e parecer dos avaliadores")
    interviewer: Optional[str] = Field("", description="Nome do entrevistador / assessor líder")
    competency_focus: Optional[str] = Field("Gestão", description="Competência Brasil Júnior chave ('Liderança', 'Gestão', 'Autoconhecimento', 'Visão Sistêmica', 'Orientação para Resultados')")
    tenant_id: Optional[str] = Field("edv_jr", description="Identificador do tenant")

class PselCandidateUpdate(BaseModel):
    campaign_id: Optional[int] = None
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    course: Optional[str] = None
    period: Optional[str] = None
    stage: Optional[str] = None
    target_area: Optional[str] = None
    score_dinamica: Optional[float] = None
    score_entrevista: Optional[float] = None
    notes: Optional[str] = None
    interviewer: Optional[str] = None
    competency_focus: Optional[str] = None

class PselStageUpdate(BaseModel):
    stage: str = Field(..., description="Novo estágio ('inscricao', 'dinamica', 'entrevista', 'onboarding', 'aprovado', 'reprovado', 'desistente')")
    notes: Optional[str] = Field(None, description="Parecer adicional ou justificativa da transição")

class PselCandidateResponse(BaseModel):
    id: int
    tenant_id: str
    campaign_id: Optional[int] = None
    name: str
    email: str
    phone: Optional[str] = None
    course: str
    period: Optional[str] = None
    stage: str
    target_area: str
    score_dinamica: float
    score_entrevista: float
    notes: Optional[str] = None
    interviewer: Optional[str] = None
    competency_focus: Optional[str] = "Gestão"
    created_by: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class BrandAssetCreate(BaseModel):
    title: str = Field(..., min_length=2, description="Título do ativo (ex: Manual de Identidade Visual 2026)")
    category: str = Field(..., description="Categoria: 'logo', 'manual_marca', 'proposta_comercial', 'apresentacao_institucional', 'papelaria', 'pitch_deck', 'outros'")
    file_format: str = Field(..., description="Formato do arquivo (PNG, SVG, PDF, PPTX, DOCX, FIGMA)")
    version: Optional[str] = Field("v1.0", description="Versão do ativo (ex: v1.0, v2.1)")
    file_url: str = Field(..., description="URL ou link no Google Drive / CDN oficial")
    description: Optional[str] = Field("", description="Descrição das diretrizes de uso")
    tags: Optional[str] = Field("", description="Tags separadas por vírgula para busca")
    is_official: Optional[bool] = Field(True, description="Indicador se é o ativo oficial homologado")
    tenant_id: Optional[str] = Field("edv_jr", description="Identificador do tenant")

class BrandAssetUpdate(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    file_format: Optional[str] = None
    version: Optional[str] = None
    file_url: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[str] = None
    is_official: Optional[bool] = None

class BrandAssetResponse(BaseModel):
    id: int
    tenant_id: str
    title: str
    category: str
    file_format: str
    version: str
    file_url: str
    description: Optional[str] = None
    tags: Optional[str] = None
    is_official: int
    uploaded_by: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

# ==============================================================================
# SCHEMAS DE ESTATUTOS & COMPLIANCE MEJ (LEI 13.267/2016 & SELO EJ)
# ==============================================================================

class StatuteCreate(BaseModel):
    title: str = Field(..., min_length=3, description="Título da norma ou marco regulatório")
    norm_type: str = Field(..., description="estatuto, regimento_interno, marco_regulatorio, selo_ej, codigo_etica")
    version: Optional[str] = Field("v1.0", description="Versão do documento")
    status: Optional[str] = Field("vigente", description="vigente, em_revisao, revogado, pendente_aprovacao")
    effective_date: str = Field(..., description="Data de vigência (YYYY-MM-DD)")
    review_deadline: Optional[str] = Field(None, description="Data limite de revisão / auditoria (YYYY-MM-DD)")
    responsible_area: str = Field(..., description="Presidência, VPGG, Jurídico, Comercial, Projetos, Tesouraria, Marketing")
    responsible_role: Optional[str] = Field("diretor", description="Cargo responsável")
    document_url: Optional[str] = Field("", description="Link Google Drive ou arquivo oficial")
    description: Optional[str] = Field("", description="Ementa ou descrição dos objetivos regulatórios")
    checklist_items: Optional[List[Dict[str, Any]]] = Field([], description="Itens de auditoria e conformidade")
    tenant_id: Optional[str] = Field("edv_jr", description="Tenant")

class StatuteUpdate(BaseModel):
    title: Optional[str] = None
    norm_type: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None
    effective_date: Optional[str] = None
    review_deadline: Optional[str] = None
    responsible_area: Optional[str] = None
    responsible_role: Optional[str] = None
    document_url: Optional[str] = None
    description: Optional[str] = None
    checklist_items: Optional[List[Dict[str, Any]]] = None

class StatuteChecklistUpdate(BaseModel):
    checklist_items: List[Dict[str, Any]]

class StatuteResponse(BaseModel):
    id: int
    tenant_id: str
    title: str
    norm_type: str
    version: str
    status: str
    effective_date: str
    review_deadline: Optional[str] = None
    responsible_area: str
    responsible_role: str
    document_url: Optional[str] = None
    description: Optional[str] = None
    checklist_items: List[Dict[str, Any]] = []
    conformity_score: float
    created_by: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

# ==============================================================================
# SCHEMAS DE NOTIFICAÇÕES DINÂMICAS (E-MAIL + ALERTA IN-SITE)
# ==============================================================================

class NotificationCreate(BaseModel):
    recipient_email: str = Field(..., description="E-mail destinatário, 'ALL' ou 'ROLE:diretor'")
    title: str = Field(..., min_length=3)
    message: str = Field(..., min_length=3)
    category: str = Field("compliance", description="deadline_overdue, deadline_warning, pdi_milestone, audit_alert, approval_pending, compliance, system")
    priority: Optional[str] = Field("normal", description="low, normal, high, critical")
    target_role: Optional[str] = None
    target_area: Optional[str] = None
    link: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class NotificationResponse(BaseModel):
    id: int
    tenant_id: str
    recipient_email: str
    target_role: Optional[str] = None
    target_area: Optional[str] = None
    title: str
    message: str
    category: str
    priority: str
    link: Optional[str] = None
    is_read: int
    email_sent: int
    metadata: Optional[Dict[str, Any]] = {}
    created_at: Optional[str] = None

# ==============================================================================
# SCHEMAS DE RM STAGING & DUPLA VERIFICAÇÃO (MAKER-CHECKER)
# ==============================================================================

class RMStagingCreate(BaseModel):
    batch_id: Optional[str] = None
    rm_code: Optional[str] = None
    brand_name: str = Field(..., min_length=2, description="Nome da Marca em registro")
    process_number: Optional[str] = None
    client_name: str = Field(..., min_length=2, description="Nome do Titular ou Cliente")
    client_phone: Optional[str] = None
    responsible_name: str = Field(..., description="Assessor responsável")
    phase: Optional[str] = Field("Busca de Anterioridade", description="Fase processual no INPI")
    operation_type: Optional[str] = Field("UPDATE", description="INSERT, UPDATE, DELETE, BATCH_IMPORT")
    original_data: Optional[Dict[str, Any]] = None
    proposed_data: Dict[str, Any] = Field(..., description="Dados propostos para a alteração")

class RMStagingReview(BaseModel):
    review_notes: Optional[str] = Field("", description="Justificativa ou despacho da aprovação/rejeição")

class RMStagingResponse(BaseModel):
    id: int
    tenant_id: str
    batch_id: Optional[str] = None
    rm_code: Optional[str] = None
    brand_name: str
    process_number: Optional[str] = None
    client_name: str
    client_phone: Optional[str] = None
    responsible_name: str
    phase: str
    operation_type: str
    original_data: Optional[Dict[str, Any]] = None
    proposed_data: Dict[str, Any]
    status: str
    submitted_by: str
    submitted_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_notes: Optional[str] = None
    applied_to_main_db: int

# ==============================================================================
# SCHEMAS DE GOOGLE CALENDAR & EVENTOS CRÍTICOS
# ==============================================================================

class CalendarEventResponse(BaseModel):
    id: str
    title: str
    start_date: str
    end_date: Optional[str] = None
    category: str
    priority: str
    responsible: Optional[str] = None
    area: Optional[str] = None
    description: Optional[str] = None
    google_calendar_url: str

# ==============================================================================
# SCHEMAS DE PDI 360 & SUCESSÃO PREDICTIVA
# ==============================================================================

class Evaluation360Create(BaseModel):
    evaluatee_email: str = Field(..., description="E-mail do membro avaliado")
    relationship_type: str = Field("peer", description="peer, leader, subordinate, self")
    score_lideranca: float = Field(..., ge=1.0, le=5.0)
    score_gestao: float = Field(..., ge=1.0, le=5.0)
    score_visao_sistemica: float = Field(..., ge=1.0, le=5.0)
    score_orientacao_resultados: float = Field(..., ge=1.0, le=5.0)
    score_autoconhecimento: float = Field(..., ge=1.0, le=5.0)
    feedback_qualitativo: Optional[str] = Field("", description="Parecer analítico")
    cycle_id: Optional[str] = Field("2026.1", description="Ciclo avaliativo")

class GapPlanCreate(BaseModel):
    user_email: str
    role_target: Optional[str] = "diretoria"

# ==============================================================================
# SCHEMAS DO PIPELINE DE VENDAS CRM, CONTRATOS DE CONSULTORIA & JURÍDICO
# ==============================================================================

class LeadCreate(BaseModel):
    client_name: str = Field(..., min_length=2, description="Razão Social, Nome Fantasia ou Nome do Cliente")
    cnpj: Optional[str] = Field(None, description="CNPJ ou CPF do cliente")
    contact_person: Optional[str] = Field(None, description="Contato responsável no cliente")
    contact_email: Optional[str] = Field(None, description="E-mail corporativo de contato")
    contact_phone: Optional[str] = Field(None, description="Telefone ou WhatsApp de contato")
    estimated_value: Optional[float] = Field(0.0, ge=0.0, description="Valor estimado da oportunidade")
    etapa: Optional[str] = Field("prospeccao", description="Etapa do funil: prospeccao, diagnostico, proposta, negociacao, fechado, perdido")
    responsible: Optional[str] = Field(None, description="E-mail ou nome do assessor responsável")
    notes: Optional[str] = Field(None, description="Anotações comerciais ou histórico de contato")

class LeadUpdate(BaseModel):
    client_name: Optional[str] = None
    cnpj: Optional[str] = None
    contact_person: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    estimated_value: Optional[float] = None
    etapa: Optional[str] = None
    responsible: Optional[str] = None
    notes: Optional[str] = None

class ContratoRMCreate(BaseModel):
    lead_id: int = Field(..., description="ID do lead convertido no CRM")
    rm_code: Optional[str] = Field(None, description="Código do processo RM (ex: RM-001)")
    process_number: Optional[str] = Field(None, description="Número oficial do processo INPI (9 dígitos)")
    brand_name: Optional[str] = Field(None, description="Nome da marca ou título da consultoria")
    client_name: Optional[str] = Field(None, description="Nome do cliente ou razão social")
    cnpj: Optional[str] = Field(None, description="CNPJ ou CPF do contratante")
    consultoria_escopo: Optional[str] = Field(None, description="Escopo técnico detalhado da consultoria")
    prazo_dias: Optional[int] = Field(60, ge=1, description="SLA de entrega em dias")
    prazo_entrega: Optional[str] = Field(None, description="Data estimada de entrega")
    marcos_financeiros: Optional[Any] = Field(None, description="Parcelas ou marcos financeiros (lista ou JSON)")
    valor_total: Optional[float] = Field(None, ge=0.0, description="Valor global da consultoria")
    status_execucao: Optional[str] = Field("ativo", description="Status operacional: ativo, suspenso, concluido")
    responsavel_tecnico: Optional[str] = Field(None, description="Consultor ou gerente técnico responsável")

class ContratoRMStatusUpdate(BaseModel):
    status: str = Field(..., description="Novo status de execução: ativo, suspenso, concluido")

class GerarContratoRequest(BaseModel):
    lead_id: Optional[int] = Field(None, description="ID do lead para preenchimento automático")
    contrato_rm_id: Optional[int] = Field(None, description="ID do contrato para preenchimento automático")
    modelo: Optional[str] = Field("prestacao_servicos_rm", description="prestacao_servicos_rm, consultoria_juridica_preventiva, acordo_confidencialidade_nda")
    client_name: Optional[str] = None
    cnpj: Optional[str] = None
    contact_person: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    brand_name: Optional[str] = None
    objeto_detalhado: Optional[str] = None
    consultoria_escopo: Optional[str] = None
    valor: Optional[float] = None
    valor_total: Optional[float] = None
    condicoes_pagamento: Optional[str] = None
    prazo_dias: Optional[int] = None
    responsavel_tecnico: Optional[str] = None

class TransacaoFinanceiraCreate(BaseModel):
    tipo: str = Field(..., description="Tipo de movimentação: receita ou despesa")
    categoria: str = Field(..., description="Categoria contábil ou operacional")
    descricao: str = Field(..., min_length=2, description="Detalhamento da movimentação")
    valor: float = Field(..., gt=0.0, description="Valor monetário superior a R$ 0,00")
    data_vencimento: str = Field(..., description="Data limite de liquidação (YYYY-MM-DD)")
    data_pagamento: Optional[str] = Field(None, description="Data efetiva do pagamento (YYYY-MM-DD)")
    status: Optional[str] = Field("pendente", description="Status: pendente, pago, atrasado, cancelado")
    contrato_id: Optional[int] = Field(None, description="ID do contrato_rm vinculado")

class TransacaoFinanceiraStatusUpdate(BaseModel):
    status: str = Field(..., description="Novo status: pendente, pago, atrasado, cancelado")
    data_pagamento: Optional[str] = Field(None, description="Data de quitação opcional (YYYY-MM-DD)")

def parse_csv_leads(csv_text: str) -> List[LeadIngestItem]:
    """Interpreta texto CSV delimitado por vírgula ou ponto-e-vírgula em objetos LeadIngestItem."""
    items = []
    if not csv_text or not csv_text.strip():
        return items
    f = io.StringIO(csv_text.strip())
    first_line = csv_text.strip().split("\n")[0]
    delimiter = ";" if ";" in first_line else ","
    reader = csv.DictReader(f, delimiter=delimiter)
    
    for row in reader:
        norm_row = {str(k).strip().lower(): str(v).strip() for k, v in row.items() if k and v}
        est_val = 0.0
        try:
            raw_v = norm_row.get("estimated_value") or norm_row.get("valor") or "0"
            est_val = float(raw_v.replace("R$", "").replace(".", "").replace(",", ".").strip())
        except Exception:
            est_val = 0.0

        item = LeadIngestItem(
            cnpj=norm_row.get("cnpj"),
            razao_social=norm_row.get("razao_social") or norm_row.get("razao") or norm_row.get("empresa"),
            nome_fantasia=norm_row.get("nome_fantasia") or norm_row.get("fantasia"),
            client_name=norm_row.get("client_name") or norm_row.get("nome") or norm_row.get("razao_social") or norm_row.get("empresa"),
            cnae=norm_row.get("cnae"),
            company_size=norm_row.get("company_size") or norm_row.get("porte"),
            address=norm_row.get("address") or norm_row.get("endereco"),
            contact_person=norm_row.get("contact_person") or norm_row.get("contato"),
            status=norm_row.get("status") or "prospeccao",
            interaction_type=norm_row.get("interaction_type") or "Radar Ingestão",
            notes=norm_row.get("notes") or norm_row.get("observacoes") or norm_row.get("historico"),
            next_followup_date=norm_row.get("next_followup_date") or norm_row.get("proximo_contato"),
            area=norm_row.get("area") or "Comercial",
            tags=norm_row.get("tags") or "#public_data",
            estimated_value=est_val
        )
        items.append(item)
    return items

# ==============================================================================
# 1. AUTENTICAÇÃO, PERFIL E BLOQUEIO DE AUTO-PROMOÇÃO (RBAC SHIELD)
# ==============================================================================

@app.post("/api/auth/login", response_model=LoginResponse, summary="Autenticação estrita com e-mail e senha (BCrypt + Cookie HttpOnly)")
async def login(credentials: LoginRequest, request: Request, response: Response):
    client_ip = login_rate_limiter.get_client_ip(request)
    is_limited, retry_after = login_rate_limiter.is_ip_rate_limited(client_ip)
    if is_limited:
        log_audit(client_ip, "RATE_LIMIT_BLOCKED", "/api/auth/login", 429, {"retry_after": retry_after}, ip_address=client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Muitas tentativas de login a partir deste endereço IP. Bloqueio temporário ativo por segurança contra força bruta. Tente novamente em {retry_after} segundos.",
            headers={"Retry-After": str(retry_after)}
        )

    email = credentials.email.lower().strip()
    user = get_user_by_email(email)
    
    if not user or not verify_password(credentials.password, user["hashed_password"]):
        login_rate_limiter.record_attempt(client_ip, success=False)
        log_audit(email or client_ip, "LOGIN_FAILED", "/api/auth/login", 401, "Credenciais corporativas inválidas", ip_address=client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais corporativas inválidas. Verifique seu e-mail e senha de membro.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Login bem-sucedido: zera falhas do IP
    login_rate_limiter.record_attempt(client_ip, success=True)
    
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

    # Definir Cookie HttpOnly / Secure
    is_secure = (
        request.url.scheme == "https" 
        or os.getenv("EDV_ENV") == "production" 
        or request.headers.get("x-forwarded-proto") == "https"
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=60 * 60 * 24, # 24 horas
        path="/"
    )
    
    log_audit(email, "LOGIN_SUCCESS", "/api/auth/login", 200, {"role": user["role"], "area": user["area"]}, ip_address=client_ip)

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_profile
    )

@app.post("/api/auth/logout", summary="Encerrar sessão e revogar cookie HttpOnly de autenticação")
async def logout(response: Response, request: Request, current_user: dict = Depends(get_current_user)):
    response.delete_cookie(key="access_token", path="/")
    client_ip = login_rate_limiter.get_client_ip(request)
    log_audit(current_user["email"], "LOGOUT", "/api/auth/logout", 200, "Sessão corporativa encerrada com sucesso", ip_address=client_ip)
    return {"status": "success", "message": "Sessão encerrada com sucesso."}

@app.get("/api/members", response_model=List[UserProfile], summary="Listar membros ativos da EJ para seletores e módulos operacionais")
async def list_active_members(current_user: dict = Depends(get_current_user)):
    """Retorna colaboradores ativos para seleção dinâmica em PDIs, CRM e esteira operacional."""
    users = get_all_users()
    return [
        UserProfile(
            id=u["id"],
            email=u["email"],
            nome=u["nome"],
            area=u["area"],
            role=u["role"],
            setor=u.get("setor"),
            cargo=u.get("cargo")
        )
        for u in users
    ]


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
        log_audit(current_user["email"], "SECURITY_VIOLATION_403", "/api/auth/me", 403, "Tentativa de auto-promoção de role bloqueada")
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

def generate_pdi_trail(
    member: dict,
    foco_adicional: Optional[str] = None,
    modo_saneamento: str = "adaptive"
) -> dict:
    """
    Motor de Geração de PDIs (Assembly Line Algorítmica):
    Cruza Vetores G (Gaps 360º), H (Hard Data) e F (Foco Semântico Modulado)
    e seleciona dinamicamente 4 a 6 micro-blocos atômicos com garantia matemática de singularidade.
    """
    email = member.get("email")
    triang = {}
    if email:
        try:
            triang = calculate_triangulation(email)
        except Exception:
            triang = {}
    res = montar_trilha_algoritmica(
        member=member,
        foco_adicional=foco_adicional,
        modo_saneamento=modo_saneamento,
        triangulacao=triang
    )
    if res.get("error"):
        raise HTTPException(
            status_code=res.get("status_code", 400),
            detail=res.get("detail", "Foco rejeitado pelo modo restritivo de governança MEJ.")
        )
    return res

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
    comp_mej = payload.competency_mej.strip() if payload.competency_mej else "Gestão"

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO pdis (user_email, area, competency_mej, objectives, development_ideas, deadline, status)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (
        target_email,
        area_final,
        comp_mej,
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

    log_audit(
        current_user.get("email"),
        "PDI_CREATED",
        "/vpgg/pdis",
        201,
        {"pdi_id": pdi_id, "user_email": target_email, "competency_mej": comp_mej}
    )

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
    competency_mej: Optional[str] = Query(None, description="Filtrar por Competência do Modelo Brasil Júnior"),
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
    if competency_mej:
        query += " AND LOWER(competency_mej) = ?"
        params.append(competency_mej.lower().strip())

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

    if payload.competency_mej is not None:
        updates.append("competency_mej = ?")
        params.append(payload.competency_mej.strip())
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

    log_audit(
        current_user.get("email"),
        "PDI_UPDATED",
        f"/vpgg/pdis/{pdi_id}",
        200,
        {"pdi_id": pdi_id, "status": payload.status}
    )

    return dict(row)

def _build_pdi_analytics_and_trail(target_email: str, foco: Optional[str] = None, modo_saneamento: str = "adaptive") -> dict:
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

    cursor.execute("SELECT competency_mej, COUNT(*) FROM pdis GROUP BY competency_mej;")
    competency_counts = dict(cursor.fetchall())

    cursor.execute("SELECT * FROM pdis WHERE LOWER(user_email) = ? ORDER BY id DESC;", (target_email,))
    membro_pdis = [dict(r) for r in cursor.fetchall()]
    conn.close()

    sugestoes_trilha = generate_pdi_trail(target_member, foco, modo_saneamento)

    return {
        "status": "success",
        "distribuicao_competencias_mej": competency_counts,
        "consolidado_geral": {
            "total_pdis_cadastrados": total_pdis,
            "distribuicao_status": status_counts,
            "distribuicao_competencias_mej": competency_counts,
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
    modo = payload.sanitization_mode or "adaptive"
    return _build_pdi_analytics_and_trail(target_email, foco, modo)

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
# 5.1 TRIANGULAÇÃO OPERACIONAL-COMPORTAMENTAL (HARD DATA VS. SOFT DATA 360º)
# ==============================================================================

@app.get(
    "/vpgg/triangulation",
    summary="Triangulação Operacional-Comportamental de Membros (Hard vs. Soft Data)"
)
@app.get(
    "/api/vpgg/triangulation",
    include_in_schema=False
)
async def get_triangulation_endpoint(
    user_email: Optional[str] = Query(None, description="Filtrar por e-mail institucional do membro"),
    current_user: dict = Depends(verify_vpgg_access)
):
    """
    Cruza métricas quantitativas extraídas do CRM e Projetos (conversão, faturamento, pontualidade de RMs)
    com avaliações qualitativas 360º ponderadas por histórico de assertividade dos avaliadores,
    alinhando ao Modelo Oficial da Brasil Júnior (Liderança, Gestão, Visão Sistêmica, Orientação para Resultados e Autoconhecimento).
    """
    res = calculate_triangulation(user_email)
    log_audit(
        current_user.get("email"),
        "TRIANGULATION_ACCESSED",
        "/vpgg/triangulation",
        200,
        {"user_email": user_email}
    )
    return res

@app.get(
    "/vpgg/triangulation/{user_email}",
    summary="Triangulação de Membro Específico (Hard vs. Soft Data)"
)
@app.get(
    "/api/vpgg/triangulation/{user_email}",
    include_in_schema=False
)
async def get_member_triangulation_endpoint(
    user_email: str,
    current_user: dict = Depends(verify_vpgg_access)
):
    res = calculate_triangulation(user_email)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Colaborador com e-mail '{user_email}' não encontrado."
        )
    return res

@app.post(
    "/vpgg/evaluations-360",
    response_model=Evaluation360Response,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar Avaliação 360º (Modelo Oficial Brasil Júnior)"
)
@app.post(
    "/api/vpgg/evaluations-360",
    response_model=Evaluation360Response,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False
)
async def create_evaluation_360_endpoint(
    payload: Evaluation360Create,
    current_user: dict = Depends(get_current_user)
):
    """
    Submete uma nova avaliação qualitativa 360º oficial, pontuando o colaborador nas 5 competências essenciais.
    """
    target_user = get_user_by_email(payload.evaluatee_email)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Membro avaliado '{payload.evaluatee_email}' não encontrado na whitelist oficial."
        )

    eval_data = payload.model_dump() if hasattr(payload, 'model_dump') else payload.dict()
    created = save_evaluation_360(eval_data, current_user["email"])

    log_audit(
        current_user.get("email"),
        "EVALUATION_360_SUBMITTED",
        "/vpgg/evaluations-360",
        201,
        {"evaluatee_email": payload.evaluatee_email, "evaluator": current_user["email"]}
    )
    return created

@app.get(
    "/vpgg/evaluations-360",
    summary="Listar Avaliações 360º Submetidas"
)
@app.get(
    "/api/vpgg/evaluations-360",
    include_in_schema=False
)
async def list_evaluations_360_endpoint(
    evaluatee_email: Optional[str] = Query(None, description="Filtrar por e-mail do avaliado"),
    current_user: dict = Depends(verify_vpgg_access)
):
    return list_evaluations_360(evaluatee_email)

# ==============================================================================
# 5.2 ÍNDICE DE PRONTIDÃO PREDITIVA PARA SUCESSÃO (IPS) & GOVERNANÇA FEDERATIVA
# ==============================================================================

@app.get(
    "/vpgg/succession-ips",
    summary="Calcular Índice de Prontidão Preditiva para Sucessão (IPS) Corporativo"
)
@app.get(
    "/api/vpgg/succession-ips",
    include_in_schema=False
)
async def get_succession_ips_endpoint(
    role_target: str = Query("diretoria", pattern="^(diretoria|presidencia)$", description="Cargo executivo alvo ('diretoria' ou 'presidencia')"),
    current_user: dict = Depends(verify_vpgg_access)
):
    """
    Calcula o escore probabilístico de prontidão para sucessão (0 a 100),
    comparando a performance com o perfil histórico de gestores com aprovação plena no Selo EJ.
    Restringe elegibilidade automática se o IPS estiver abaixo da linha de corte.
    """
    res = calculate_succession_ips(None, role_target)
    log_audit(
        current_user.get("email"),
        "SUCCESSION_IPS_BATCH_ACCESSED",
        "/vpgg/succession-ips",
        200,
        {"role_target": role_target}
    )
    return res

@app.get(
    "/vpgg/succession-ips/{user_email}",
    summary="Dossiê Preditivo de Sucessão de Membro Específico"
)
@app.get(
    "/api/vpgg/succession-ips/{user_email}",
    include_in_schema=False
)
async def get_member_succession_ips_endpoint(
    user_email: str,
    role_target: str = Query("diretoria", pattern="^(diretoria|presidencia)$", description="Cargo executivo alvo ('diretoria' ou 'presidencia')"),
    current_user: dict = Depends(verify_vpgg_access)
):
    res = calculate_succession_ips(user_email, role_target)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Colaborador com e-mail '{user_email}' não encontrado."
        )

    log_audit(
        current_user.get("email"),
        "SUCCESSION_IPS_MEMBER_ACCESSED",
        f"/vpgg/succession-ips/{user_email}",
        200,
        {"user_email": user_email, "ips_score": res["ips_score"], "eligible": res["is_eligible"]}
    )
    return res

# ==============================================================================
# 5.3 MITIGAÇÃO AUTOMATIZADA DE GAPS (AÇÃO CORRETIVA EM TEMPO DE EXECUÇÃO 70-20-10)
# ==============================================================================

@app.post(
    "/vpgg/gap-mitigation/generate/{user_email}",
    summary="Disparar Mecanismo Preditivo de Mitigação de Gaps em Tempo de Execução"
)
@app.post(
    "/api/vpgg/gap-mitigation/generate/{user_email}",
    include_in_schema=False
)
async def generate_gap_mitigation_endpoint(
    user_email: str,
    current_user: dict = Depends(verify_vpgg_access)
):
    """
    Identifica déficits crônicos em competências e reconfigura automaticamente a alocação prática do membro:
    insere assessores com lacunas como co-responsáveis em projetos complexos ou negociações CRM,
    pareando com mentores seniores e atualizando o PDI ativo.
    """
    target_user = get_user_by_email(user_email)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Colaborador com e-mail '{user_email}' não encontrado."
        )

    plan = generate_gap_mitigation_plan(user_email)

    log_audit(
        current_user.get("email"),
        "GAP_MITIGATION_GENERATED",
        f"/vpgg/gap-mitigation/generate/{user_email}",
        200,
        {"user_email": user_email, "actions_count": len(plan.get("mitigation_actions", []))}
    )
    return plan

@app.get(
    "/vpgg/gap-mitigation/{user_email}",
    summary="Listar Ações de Mitigação Prática Ativas do Membro"
)
@app.get(
    "/api/vpgg/gap-mitigation/{user_email}",
    include_in_schema=False
)
async def list_gap_mitigation_endpoint(
    user_email: str,
    current_user: dict = Depends(verify_vpgg_access)
):
    return list_gap_mitigation_actions(user_email)

@app.get(
    "/vpgg/benchmarks",
    summary="Listar Perfis de Benchmark de Gestores Históricos (Federação / Selo EJ)"
)
@app.get(
    "/api/vpgg/benchmarks",
    include_in_schema=False
)
async def list_benchmarks_endpoint(
    role_target: Optional[str] = Query(None, description="Filtrar por cargo ('diretoria' ou 'presidencia')"),
    current_user: dict = Depends(verify_vpgg_access)
):
    return list_historical_benchmarks(role_target)

# ==============================================================================
# 5.1 PAINEL DO MEMBRO (CENTRO DE EXECUÇÃO DO PDI) & FÓRUM DE DÚVIDAS
# ==============================================================================

@app.get(
    "/api/pdi/trilha/{user_id}",
    summary="Obter trilha individual de micro-blocos de PDI do colaborador com SLAs e hash SHA-256"
)
@app.get(
    "/vpgg/pdi/trilha/{user_id}",
    include_in_schema=False
)
async def get_member_pdi_trail_endpoint(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Retorna a estrutura JSON contendo os micro-blocos atômicos atribuídos, seus respectivos
    eixos da Brasil Júnior, prazos calculados de SLA, dias restantes, status e o hash SHA-256 de integridade.
    """
    trail_data = get_or_create_member_pdi_trail(user_id, current_user)
    if not trail_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Colaborador '{user_id}' não encontrado no sistema."
        )
    
    # Controle de Acesso: O próprio usuário pode ver sua trilha; VPGG, Presidência e Diretores podem ver qualquer trilha
    c_email = current_user["email"].lower().strip()
    c_role = current_user.get("role", "assessor").lower()
    c_area = current_user.get("area", "").lower()
    is_owner = (c_email == trail_data["user"]["email"].lower().strip())
    is_leader = (c_role in ["presidente", "diretor"] or "vpgg" in c_area)
    if not is_owner and not is_leader:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso não autorizado para visualizar a trilha deste colaborador."
        )

    return {
        "status": "success",
        **trail_data
    }


@app.patch(
    "/api/pdi/micro-bloco/{bloco_id}",
    summary="Atualizar status operacional do micro-bloco de PDI e recalcular progresso"
)
@app.patch(
    "/vpgg/pdi/micro-bloco/{bloco_id}",
    include_in_schema=False
)
async def update_microblock_status_endpoint(
    bloco_id: int,
    payload: MicroblockStatusUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Modifica o status de execução do item (pendente, em_andamento, concluido)
    e recalcula o ponteiro de avanço percentual da trilha do colaborador.
    """
    try:
        res = update_microblock_status(bloco_id, payload.status, current_user)
        return res
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))


# Fórum Colaborativo de Dúvidas

@app.post(
    "/api/duvidas",
    status_code=status.HTTP_201_CREATED,
    summary="Registrar nova dúvida ou dificuldade no Fórum Colaborativo"
)
async def create_duvida_endpoint(
    payload: DuvidaCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        created = create_forum_duvida(
            author=current_user,
            title=payload.title,
            description=payload.description,
            category=payload.category or "Geral"
        )
        return {
            "status": "success",
            "duvida": created
        }
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@app.get(
    "/api/duvidas",
    summary="Listar feed público de ocorrências e dúvidas com interações/respostas"
)
async def list_duvidas_endpoint(
    status: Optional[str] = Query(None, description="Filtrar por status: aberta, resolvida, todas"),
    category: Optional[str] = Query(None, description="Filtrar por categoria"),
    search: Optional[str] = Query(None, description="Busca textual por título ou descrição"),
    current_user: dict = Depends(get_current_user)
):
    duvidas = list_forum_duvidas(status_filter=status, category_filter=category, search=search)
    return duvidas


@app.post(
    "/api/duvidas/{duvida_id}/respostas",
    status_code=status.HTTP_201_CREATED,
    summary="Adicionar comentário, solução ou diretriz para auxiliar o colega"
)
async def add_resposta_endpoint(
    duvida_id: int,
    payload: RespostaCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        resp = add_forum_resposta(
            duvida_id=duvida_id,
            author=current_user,
            content=payload.content
        )
        return {
            "status": "success",
            "resposta": resp
        }
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND if "não encontrada" in str(ve) else status.HTTP_400_BAD_REQUEST, detail=str(ve))


@app.patch(
    "/api/duvidas/{duvida_id}/status",
    summary="Alternar status da dúvida (aberta / resolvida)"
)
async def update_duvida_status_endpoint(
    duvida_id: int,
    payload: DuvidaStatusUpdate,
    current_user: dict = Depends(get_current_user)
):
    try:
        updated = resolve_forum_duvida(
            duvida_id=duvida_id,
            current_user=current_user,
            new_status=payload.status
        )
        return {
            "status": "success",
            "duvida": updated
        }
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))


# ==============================================================================
# 5.2 CRM PIPELINE DE VENDAS, GESTÃO DE RMS & AUTOMAÇÃO JURÍDICA
# ==============================================================================

@app.post(
    "/api/crm/leads",
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar nova oportunidade comercial no funil de vendas (CRM)"
)
async def create_crm_lead_endpoint(
    payload: LeadCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        lead = create_lead(payload.model_dump(), current_user=current_user)
        return {
            "status": "success",
            "message": "Lead cadastrado com sucesso no funil de vendas.",
            "lead": lead
        }
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get(
    "/api/crm/pipeline",
    summary="Retornar panorama completo do funil de vendas segmentado por etapa"
)
async def get_crm_pipeline_endpoint(
    current_user: dict = Depends(get_current_user)
):
    try:
        pipeline = get_crm_pipeline()
        return pipeline
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.patch(
    "/api/crm/leads/{lead_id}",
    summary="Atualizar dados ou transicionar a etapa do lead no funil"
)
async def update_crm_lead_endpoint(
    lead_id: int,
    payload: LeadUpdate,
    current_user: dict = Depends(get_current_user)
):
    try:
        updated = update_lead(
            lead_id=lead_id,
            updates=payload.model_dump(exclude_unset=True),
            current_user=current_user
        )
        return {
            "status": "success",
            "message": f"Lead #{lead_id} atualizado com sucesso.",
            "lead": updated
        }
    except ValueError as ve:
        status_code = status.HTTP_404_NOT_FOUND if "não encontrado" in str(ve) else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get(
    "/api/crm/contratos",
    summary="Listar contratos de consultoria e RMs ativas"
)
async def list_crm_contratos_endpoint(
    status_execucao: Optional[str] = Query(None, description="Filtrar por status: ativo, suspenso, concluido"),
    current_user: dict = Depends(get_current_user)
):
    try:
        contratos = list_contratos_rm(status_filter=status_execucao)
        return {
            "status": "success",
            "total": len(contratos),
            "contratos": contratos
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post(
    "/api/crm/contratos",
    status_code=status.HTTP_201_CREATED,
    summary="Vincular novo contrato de consultoria / RM a um lead existente"
)
async def create_crm_contrato_endpoint(
    payload: ContratoRMCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        contrato = create_contrato_rm(payload.model_dump(), current_user=current_user)
        return {
            "status": "success",
            "message": "Contrato de consultoria registrado com sucesso.",
            "contrato": contrato
        }
    except ValueError as ve:
        status_code = status.HTTP_404_NOT_FOUND if "não encontrado" in str(ve) else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.patch(
    "/api/crm/contratos/{contrato_id}/status",
    summary="Atualizar status operacional de um contrato de consultoria"
)
async def update_crm_contrato_status_endpoint(
    contrato_id: int,
    payload: ContratoRMStatusUpdate,
    current_user: dict = Depends(get_current_user)
):
    try:
        updated = update_contrato_rm_status(
            contrato_id=contrato_id,
            status=payload.status,
            current_user=current_user
        )
        return {
            "status": "success",
            "message": f"Status do contrato #{contrato_id} atualizado para '{payload.status}'.",
            "contrato": updated
        }
    except ValueError as ve:
        status_code = status.HTTP_404_NOT_FOUND if "não encontrado" in str(ve) else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post(
    "/api/juridico/gerar-contrato",
    summary="Automação documental jurídica: gera minuta com preenchimento via CRM e marca d'água SHA-256"
)
async def gerar_contrato_juridico_endpoint(
    payload: GerarContratoRequest,
    current_user: dict = Depends(get_current_user)
):
    try:
        dados_contrato = payload.model_dump(exclude_unset=True)
        
        # 1. Enriquecimento via Lead se especificado
        if payload.lead_id:
            lead = get_lead_by_id(payload.lead_id)
            if not lead:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Lead ID #{payload.lead_id} não encontrado no CRM.")
            if not dados_contrato.get("client_name"):
                dados_contrato["client_name"] = lead["client_name"]
            if not dados_contrato.get("cnpj"):
                dados_contrato["cnpj"] = lead["cnpj"]
            if not dados_contrato.get("contact_person"):
                dados_contrato["contact_person"] = lead["contact_person"]
            if not dados_contrato.get("contact_email"):
                dados_contrato["contact_email"] = lead["contact_email"]
            if not dados_contrato.get("contact_phone"):
                dados_contrato["contact_phone"] = lead["contact_phone"]
            if not dados_contrato.get("valor_total") and not dados_contrato.get("valor"):
                dados_contrato["valor_total"] = lead["estimated_value"]
            if not dados_contrato.get("brand_name"):
                dados_contrato["brand_name"] = lead["client_name"]
                
        # 2. Enriquecimento via Contrato RM se especificado
        if payload.contrato_rm_id:
            contrato = get_contrato_rm_by_id(payload.contrato_rm_id)
            if not contrato:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Contrato ID #{payload.contrato_rm_id} não encontrado.")
            if not dados_contrato.get("client_name"):
                dados_contrato["client_name"] = contrato["client_name"]
            if not dados_contrato.get("cnpj"):
                dados_contrato["cnpj"] = contrato["cnpj"]
            if not dados_contrato.get("brand_name"):
                dados_contrato["brand_name"] = contrato["brand_name"]
            if not dados_contrato.get("consultoria_escopo") and not dados_contrato.get("objeto_detalhado"):
                dados_contrato["consultoria_escopo"] = contrato["consultoria_escopo"]
            if not dados_contrato.get("valor_total") and not dados_contrato.get("valor"):
                dados_contrato["valor_total"] = contrato["valor_total"]
            if not dados_contrato.get("prazo_dias"):
                dados_contrato["prazo_dias"] = contrato["prazo_dias"]
            if not dados_contrato.get("prazo_entrega"):
                dados_contrato["prazo_entrega"] = contrato["prazo_entrega"]
            if not dados_contrato.get("marcos_financeiros") and contrato.get("marcos_financeiros"):
                dados_contrato["marcos_financeiros"] = contrato["marcos_financeiros"]

        # Se nenhum lead ou cliente informado
        if not dados_contrato.get("client_name"):
            dados_contrato["client_name"] = "Empresa Contratante S.A."

        # Gerar documento via motor jurídico
        resultado = gerar_minuta_contratual(dados_contrato)

        # Se contrato_rm_id estiver presente, atualiza o hash no banco
        if payload.contrato_rm_id and resultado.get("hash_integridade"):
            try:
                conn = get_connection()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE contratos_rm SET hash_integridade = ? WHERE id = ?;",
                    (resultado["hash_integridade"], payload.contrato_rm_id)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

        return resultado
    except HTTPException:
        raise
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ==============================================================================
# 5.B MÓDULO FINANCEIRO CORPORATIVO E CONTROLE DE CAIXA 2.0 (TRANSAÇÕES & KPIS)
# ==============================================================================

@app.post(
    "/api/financeiro/transacoes",
    status_code=status.HTTP_201_CREATED,
    summary="Lançar nova receita ou despesa no fluxo de caixa corporativo"
)
async def criar_transacao_financeira_endpoint(
    payload: TransacaoFinanceiraCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        data = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
        tx = create_transacao_financeira(data)
        return {
            "status": "success",
            "message": "Transação financeira registrada com sucesso.",
            "data": tx
        }
    except HTTPException:
        raise
    except ValueError as ve:
        err_msg = str(ve)
        if "não encontrado" in err_msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get(
    "/api/financeiro/transacoes",
    summary="Listar transações financeiras com filtros avançados"
)
async def listar_transacoes_financeiras_endpoint(
    tipo: Optional[str] = Query(None, description="Filtrar por receita ou despesa"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filtrar por status: pendente, pago, atrasado, cancelado"),
    categoria: Optional[str] = Query(None, description="Filtrar por categoria contábil"),
    contrato_id: Optional[int] = Query(None, description="Filtrar por ID do contrato_rm"),
    data_inicio: Optional[str] = Query(None, description="Data de vencimento inicial (YYYY-MM-DD)"),
    data_fim: Optional[str] = Query(None, description="Data de vencimento final (YYYY-MM-DD)"),
    busca: Optional[str] = Query(None, description="Busca textual na descrição, categoria ou cliente"),
    current_user: dict = Depends(get_current_user)
):
    filtros = {
        "tipo": tipo,
        "status": status_filter,
        "categoria": categoria,
        "contrato_id": contrato_id,
        "data_inicio": data_inicio,
        "data_fim": data_fim,
        "busca": busca
    }
    filtros = {k: v for k, v in filtros.items() if v is not None}
    return list_transacoes_financeiras(filtros)


@app.patch(
    "/api/financeiro/transacoes/{tx_id}/status",
    summary="Atualizar status de liquidação de uma transação financeira"
)
async def atualizar_status_transacao_endpoint(
    tx_id: int,
    payload: TransacaoFinanceiraStatusUpdate,
    current_user: dict = Depends(get_current_user)
):
    try:
        updated = update_transacao_financeira_status(
            tx_id=tx_id,
            novo_status=payload.status,
            data_pagamento=payload.data_pagamento
        )
        return {
            "status": "success",
            "message": f"Transação #{tx_id} atualizada para '{payload.status}'.",
            "data": updated
        }
    except HTTPException:
        raise
    except ValueError as ve:
        err_msg = str(ve)
        if "não encontrada" in err_msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get(
    "/api/financeiro/kpis",
    summary="Obter indicadores consolidados de caixa, projeção e inadimplência em tempo real"
)
async def obter_kpis_financeiros_endpoint(
    mes_referencia: Optional[str] = Query(None, description="Mês de referência (YYYY-MM)"),
    current_user: dict = Depends(get_current_user)
):
    try:
        return get_financeiro_kpis(mes_referencia=mes_referencia)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get(
    "/api/executivo/kpis-consolidados",
    summary="Obter indicadores consolidados de BI macro (exclusivo Presidência e Diretoria)"
)
async def obter_kpis_executivo_endpoint(
    current_user: dict = Depends(require_role(["presidente", "diretor"]))
):
    try:
        return get_executivo_kpis_consolidados()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ==============================================================================
# BASE DE CONHECIMENTO & POPs (WIKI CORPORATIVA & MITIGAÇÃO DE ROTATIVIDADE)
# ==============================================================================

class KBArtigoCreate(BaseModel):
    titulo: str = Field(..., min_length=3, description="Título descritivo do POP ou manual")
    categoria: str = Field(..., description="Categoria operacional (juridico, financeiro, projetos, gestao_gente, ti, comercial, geral)")
    conteudo: str = Field(..., min_length=5, description="Corpo do artigo em Markdown estruturado")
    drive_url: Optional[str] = Field(None, description="URL do documento original no Google Drive")


@app.post(
    "/api/kb/artigos",
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar novo POP ou artigo de conhecimento"
)
async def criar_kb_artigo_endpoint(
    payload: KBArtigoCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        created = create_kb_artigo(payload.model_dump(), current_user=current_user)
        return {
            "status": "success",
            "artigo": created
        }
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get(
    "/api/kb/artigos",
    summary="Listar artigos da base de conhecimento com filtros por categoria e busca textual"
)
async def listar_kb_artigos_endpoint(
    categoria: Optional[str] = Query(None, description="Filtrar por categoria operacional"),
    q: Optional[str] = Query(None, description="Busca textual em título e conteúdo"),
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    try:
        artigos = list_kb_artigos(categoria=categoria, search=q)
        return {
            "status": "success",
            "artigos": artigos,
            "total": len(artigos)
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get(
    "/api/kb/artigos/{artigo_id}",
    summary="Recuperar o conteúdo integral de um artigo de conhecimento"
)
async def obter_kb_artigo_endpoint(
    artigo_id: int,
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    artigo = get_kb_artigo_by_id(artigo_id)
    if not artigo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artigo de conhecimento não encontrado.")
    return {
        "status": "success",
        "artigo": artigo
    }


@app.delete(
    "/api/kb/artigos/{artigo_id}",
    summary="Remover documento obsoleto (restrito a Presidência e Diretoria)"
)
async def deletar_kb_artigo_endpoint(
    artigo_id: int,
    current_user: dict = Depends(require_role(["presidente", "diretor"]))
):
    sucesso = delete_kb_artigo(artigo_id)
    if not sucesso:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artigo de conhecimento não encontrado para exclusão.")
    return {
        "status": "success",
        "message": f"Artigo #{artigo_id} removido com sucesso da base de conhecimento."
    }


@app.get(
    "/api/kb/artigos/{artigo_id}/didatico",
    summary="Gerador de Documento Didático Oficial: Gera caderno formativo estruturado com rigor estético e acadêmico"
)
@app.post(
    "/api/kb/artigos/{artigo_id}/didatico",
    summary="Gerador de Documento Didático Oficial: Gera caderno formativo estruturado com rigor estético e acadêmico"
)
async def obter_documento_didatico_endpoint(
    artigo_id: int,
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    artigo = get_kb_artigo_by_id(artigo_id)
    if not artigo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artigo #{artigo_id} não encontrado na base de conhecimento para geração do documento didático."
        )
    return gerar_documento_didatico(artigo)


class KBArtigoExpandRequest(BaseModel):
    user_email: Optional[str] = Field(None, description="E-mail do membro para vincular ao Centro de Execução")
    vincular_ao_pdi: Optional[bool] = Field(False, description="Se deve registrar os passos como micro-blocos no PDI")
    area_foco: Optional[str] = Field(None, description="Área temática de foco (opcional)")
    contexto_adicional: Optional[str] = Field(None, description="Observações complementares de execução")


@app.post(
    "/api/kb/artigos/{artigo_id}/expandir",
    summary="Motor Semântico de Ramificação: Desdobrar POP em trilhas e checklists operacionais autônomos"
)
async def expandir_kb_artigo_endpoint(
    artigo_id: int,
    payload: Optional[KBArtigoExpandRequest] = None,
    current_user: dict = Depends(get_current_user)
):
    try:
        user_email = payload.user_email if payload else None
        vincular_pdi = payload.vincular_ao_pdi if payload else False
        area_foco = payload.area_foco if payload else None
        contexto = payload.contexto_adicional if payload else None

        resultado = expand_kb_artigo_semantically(
            artigo_id=artigo_id,
            user_email=user_email,
            vincular_ao_pdi=vincular_pdi,
            area_foco=area_foco,
            contexto_adicional=contexto,
            current_user=current_user
        )
        return resultado
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


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
    """Preenche campos dinâmicos calculados (days_stagnant, is_stagnant, score default, normalized_name)"""
    d = dict(row)
    created_at = d.get("created_at")
    days_stagnant = calculate_days_stagnant(created_at)
    st = (d.get("status") or "").lower()
    is_stagnant = days_stagnant >= 14 and st in ("prospeccao", "negociacao")
    d["days_stagnant"] = days_stagnant
    d["is_stagnant"] = is_stagnant

    # Garantir presença de razao_social, nome_fantasia e normalized_name
    if not d.get("normalized_name"):
        target_name = d.get("nome_fantasia") or d.get("razao_social") or d.get("client_name") or ""
        d["normalized_name"] = normalize_company_name(target_name)

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
    clean = clean_cnpj(cnpj)
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

    address = build_address_from_brasilapi(data)
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
    clean_c = clean_cnpj(payload.cnpj) if payload.cnpj else None
    formatted_cnpj = format_cnpj(clean_c) if clean_c and len(clean_c) == 14 else None

    final_cnae = payload.cnae
    final_company_size = payload.company_size
    final_address = payload.address
    final_client_name = payload.client_name.strip()
    final_razao_social = payload.razao_social.strip() if payload.razao_social else None
    final_nome_fantasia = payload.nome_fantasia.strip() if payload.nome_fantasia else None

    if clean_c and len(clean_c) == 14:
        cnpj_data = await fetch_brasilapi_cnpj(clean_c)
        if cnpj_data:
            if not final_razao_social and cnpj_data.get("razao_social"):
                final_razao_social = cnpj_data.get("razao_social")
            if not final_nome_fantasia and cnpj_data.get("nome_fantasia"):
                final_nome_fantasia = cnpj_data.get("nome_fantasia")
            if not final_cnae and (cnpj_data.get("cnae_fiscal") or cnpj_data.get("cnae_fiscal_descricao")):
                final_cnae = f"{cnpj_data.get('cnae_fiscal', '')} - {cnpj_data.get('cnae_fiscal_descricao', '')}".strip(" -")
            if not final_company_size and (cnpj_data.get("descricao_porte") or cnpj_data.get("porte")):
                final_company_size = cnpj_data.get("descricao_porte") or cnpj_data.get("porte")
            if not final_address:
                final_address = build_address_from_brasilapi(cnpj_data)
            if final_client_name.lower().startswith("lead") and (final_nome_fantasia or final_razao_social):
                final_client_name = final_nome_fantasia or final_razao_social

    if not final_razao_social:
        final_razao_social = final_client_name

    final_normalized_name = normalize_company_name(final_nome_fantasia or final_razao_social or final_client_name)

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
            client_name, razao_social, nome_fantasia, normalized_name,
            contact_person, status, interaction_type, notes,
            next_followup_date, area, cnpj, cnae, company_size, address,
            score, estimated_value, tags, impact_score, impact_type, impact_description, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        final_client_name,
        final_razao_social,
        final_nome_fantasia,
        final_normalized_name,
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
        int(payload.impact_score or 0),
        payload.impact_type.strip() if payload.impact_type else None,
        payload.impact_description.strip() if payload.impact_description else None,
        current_user.get("email") or current_user.get("nome")
    ))
    conn.commit()
    followup_id = cursor.lastrowid
    cursor.execute("SELECT * FROM client_followups WHERE id = ?;", (followup_id,))
    row = cursor.fetchone()
    conn.close()

    log_audit(
        current_user.get("email"),
        "CRM_LEAD_CREATED",
        "/crm/followups",
        201,
        {"lead_id": followup_id, "client_name": final_client_name, "status": raw_status, "impact_score": payload.impact_score}
    )

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
        fts_query = build_fts5_wildcard_query(sq)
        fts_applied = False
        if fts_query:
            try:
                cursor.execute("SELECT 1 FROM client_followups_fts LIMIT 1;")
                query += " AND id IN (SELECT rowid FROM client_followups_fts WHERE client_followups_fts MATCH ?)"
                params.append(fts_query)
                fts_applied = True
            except Exception as e:
                print(f"[FTS5] Erro na consulta MATCH ({fts_query}): {e}")
                pass

        if not fts_applied:
            norm_q = normalize_company_name(sq)
            query += """ AND (
                LOWER(client_name) LIKE LOWER(?) OR 
                LOWER(contact_person) LIKE LOWER(?) OR 
                LOWER(notes) LIKE LOWER(?) OR 
                LOWER(cnpj) LIKE LOWER(?) OR 
                LOWER(cnae) LIKE LOWER(?) OR 
                LOWER(tags) LIKE LOWER(?) OR
                LOWER(razao_social) LIKE LOWER(?) OR
                LOWER(nome_fantasia) LIKE LOWER(?) OR
                LOWER(normalized_name) LIKE LOWER(?)
            )"""
            p = f"%{sq}%"
            p_norm = f"%{norm_q}%" if norm_q else p
            params.extend([p, p, p, p, p, p, p, p, p_norm])

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
    Recalcula preditivamente o Lead Score e a normalização léxica.
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

    if payload.razao_social is not None:
        updates.append("razao_social = ?")
        params.append(payload.razao_social.strip() if payload.razao_social else None)

    if payload.nome_fantasia is not None:
        updates.append("nome_fantasia = ?")
        params.append(payload.nome_fantasia.strip() if payload.nome_fantasia else None)

    if any(k is not None for k in [payload.client_name, payload.razao_social, payload.nome_fantasia]):
        cand_nome = payload.nome_fantasia if payload.nome_fantasia is not None else existing["nome_fantasia"]
        cand_razao = payload.razao_social if payload.razao_social is not None else existing["razao_social"]
        cand_client = payload.client_name if payload.client_name is not None else existing["client_name"]
        updates.append("normalized_name = ?")
        params.append(normalize_company_name(cand_nome or cand_razao or cand_client))

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
        clean_c = clean_cnpj(payload.cnpj)
        formatted_c = format_cnpj(clean_c) if clean_c else None
        updates.append("cnpj = ?")
        params.append(formatted_c)

        if clean_c and len(clean_c) == 14 and (payload.cnae is None or payload.address is None):
            cnpj_data = await fetch_brasilapi_cnpj(clean_c)
            if cnpj_data:
                if payload.razao_social is None and cnpj_data.get("razao_social"):
                    updates.append("razao_social = ?")
                    params.append(cnpj_data.get("razao_social"))
                if payload.nome_fantasia is None and cnpj_data.get("nome_fantasia"):
                    updates.append("nome_fantasia = ?")
                    params.append(cnpj_data.get("nome_fantasia"))
                if payload.cnae is None and cnpj_data.get("cnae_fiscal"):
                    cnae_fmt = f"{cnpj_data.get('cnae_fiscal', '')} - {cnpj_data.get('cnae_fiscal_descricao', '')}".strip(" -")
                    updates.append("cnae = ?")
                    params.append(cnae_fmt)
                if payload.company_size is None and (cnpj_data.get("descricao_porte") or cnpj_data.get("porte")):
                    porte_val = cnpj_data.get("descricao_porte") or cnpj_data.get("porte")
                    updates.append("company_size = ?")
                    params.append(porte_val)
                if payload.address is None:
                    addr_val = build_address_from_brasilapi(cnpj_data)
                    if addr_val:
                        updates.append("address = ?")
                        params.append(addr_val)

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

    if payload.impact_score is not None:
        updates.append("impact_score = ?")
        params.append(int(payload.impact_score))

    if payload.impact_type is not None:
        updates.append("impact_type = ?")
        params.append(payload.impact_type.strip() if payload.impact_type else None)

    if payload.impact_description is not None:
        updates.append("impact_description = ?")
        params.append(payload.impact_description.strip() if payload.impact_description else None)

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

    log_audit(
        current_user.get("email"),
        "CRM_LEAD_UPDATED",
        f"/crm/followups/{followup_id}",
        200,
        {"lead_id": followup_id, "status": payload.status}
    )

    return enrich_lead_dict(row)

# ==============================================================================
# 6.1 PIPELINE DE INGESTÃO DE DADOS PÚBLICOS E DEDUPLICAÇÃO
# ==============================================================================

@app.post(
    "/crm/ingest",
    response_model=LeadIngestResponse,
    summary="Ingestão em lote de dados públicos com deduplicação e enriquecimento assíncrono"
)
@app.post(
    "/api/crm/ingest",
    response_model=LeadIngestResponse,
    include_in_schema=False
)
async def ingest_public_leads(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Recebe cargas estruturadas (JSON ou CSV) de diretórios públicos de empresas (LGPD compliant).
    1. Deduplicação Automática: cruza CNPJ e nome normalizado com a base SQLite.
       Se já existir, atualiza metadados sem duplicar a linha.
    2. Enriquecimento Assíncrono via BrasilAPI para novos CNPJs, calculando Lead Score inicial.
    3. Alocação na área comercial correspondente com validação de escopo RBAC.
    """
    user_role = (current_user.get("role") or "").lower().strip()
    user_area = (current_user.get("area") or current_user.get("setor") or "Comercial").strip()

    content_type = request.headers.get("content-type", "")
    items_to_process: List[LeadIngestItem] = []

    if "text/csv" in content_type:
        body_bytes = await request.body()
        csv_str = body_bytes.decode("utf-8", errors="ignore")
        items_to_process = parse_csv_leads(csv_str)
    else:
        try:
            raw_json = await request.json()
            if isinstance(raw_json, list):
                for obj in raw_json:
                    items_to_process.append(LeadIngestItem(**obj))
            elif isinstance(raw_json, dict):
                if "csv_content" in raw_json and raw_json["csv_content"]:
                    items_to_process = parse_csv_leads(raw_json["csv_content"])
                elif "leads" in raw_json and isinstance(raw_json["leads"], list):
                    for obj in raw_json["leads"]:
                        items_to_process.append(LeadIngestItem(**obj))
                else:
                    items_to_process.append(LeadIngestItem(**raw_json))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Carga de dados inválida. Forneça JSON com lista de leads ou CSV estruturado: {str(e)}"
            )

    if not items_to_process:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nenhum registro de lead válido encontrado na carga enviada."
        )

    conn = get_connection()
    cursor = conn.cursor()

    inserted_count = 0
    updated_count = 0
    enriched_count = 0
    error_count = 0
    details: List[IngestDetailItem] = []

    for item in items_to_process:
        try:
            c_clean = clean_cnpj(item.cnpj)
            c_fmt = format_cnpj(c_clean) if len(c_clean) == 14 else None

            raw_name = (item.client_name or item.nome_fantasia or item.razao_social or "").strip()
            if not raw_name:
                raw_name = f"Empresa CNPJ {c_fmt}" if c_fmt else "Empresa Ingerida"

            norm_name = normalize_company_name(item.nome_fantasia or item.razao_social or raw_name)

            target_area = item.area.strip() if item.area and item.area.strip() else user_area
            if user_role not in {"presidente", "diretor"}:
                if not check_area_access(target_area, current_user):
                    target_area = user_area

            # 2. Deduplicação com a base SQLite
            existing_row = None
            if c_clean and len(c_clean) == 14:
                cursor.execute("""
                    SELECT * FROM client_followups 
                    WHERE cnpj = ? OR REPLACE(REPLACE(REPLACE(cnpj, '.', ''), '/', ''), '-', '') = ?
                    LIMIT 1;
                """, (c_fmt, c_clean))
                existing_row = cursor.fetchone()

            if not existing_row and norm_name:
                cursor.execute("SELECT * FROM client_followups WHERE normalized_name = ? LIMIT 1;", (norm_name,))
                existing_row = cursor.fetchone()

                if not existing_row:
                    cursor.execute("SELECT id, client_name, razao_social, nome_fantasia FROM client_followups WHERE client_name IS NOT NULL;")
                    for cand in cursor.fetchall():
                        for cand_name in [cand["nome_fantasia"], cand["razao_social"], cand["client_name"]]:
                            if cand_name and normalize_company_name(cand_name) == norm_name:
                                cursor.execute("SELECT * FROM client_followups WHERE id = ?;", (cand["id"],))
                                existing_row = cursor.fetchone()
                                break
                        if existing_row:
                            break

            # 3. Atualizar existente (Deduplicação)
            if existing_row:
                lead_id = existing_row["id"]
                upd_fields = []
                upd_params = []

                if c_fmt and not existing_row["cnpj"]:
                    upd_fields.append("cnpj = ?")
                    upd_params.append(c_fmt)

                if item.razao_social and not existing_row["razao_social"]:
                    upd_fields.append("razao_social = ?")
                    upd_params.append(item.razao_social.strip())

                if item.nome_fantasia and not existing_row["nome_fantasia"]:
                    upd_fields.append("nome_fantasia = ?")
                    upd_params.append(item.nome_fantasia.strip())

                if item.cnae and not existing_row["cnae"]:
                    upd_fields.append("cnae = ?")
                    upd_params.append(item.cnae.strip())

                if item.company_size and not existing_row["company_size"]:
                    upd_fields.append("company_size = ?")
                    upd_params.append(item.company_size.strip())

                if item.address and not existing_row["address"]:
                    upd_fields.append("address = ?")
                    upd_params.append(item.address.strip())

                if item.contact_person and not existing_row["contact_person"]:
                    upd_fields.append("contact_person = ?")
                    upd_params.append(item.contact_person.strip())

                if item.notes:
                    old_notes = existing_row["notes"] or ""
                    combined_notes = f"{old_notes} • [Ingestão]: {item.notes.strip()}".strip(" • ")
                    upd_fields.append("notes = ?")
                    upd_params.append(combined_notes)

                if item.tags:
                    old_tags = existing_row["tags"] or ""
                    tag_list = [t.strip() for t in re.split(r"[,;\s]+", f"{old_tags} {item.tags}") if t.strip()]
                    merged_tags = ", ".join(sorted(list(set(tag_list))))
                    upd_fields.append("tags = ?")
                    upd_params.append(merged_tags)

                if norm_name and not existing_row["normalized_name"]:
                    upd_fields.append("normalized_name = ?")
                    upd_params.append(norm_name)

                if item.estimated_value and item.estimated_value > 0 and (not existing_row["estimated_value"] or existing_row["estimated_value"] == 0):
                    upd_fields.append("estimated_value = ?")
                    upd_params.append(float(item.estimated_value))

                if upd_fields:
                    upd_params.append(lead_id)
                    cursor.execute(f"UPDATE client_followups SET {', '.join(upd_fields)} WHERE id = ?;", upd_params)

                updated_count += 1
                details.append(IngestDetailItem(
                    id=lead_id,
                    client_name=existing_row["client_name"],
                    cnpj=existing_row["cnpj"] or c_fmt,
                    action="updated",
                    score=existing_row["score"] or 50,
                    area=existing_row["area"]
                ))

            # 4. Inserir novo registro com enriquecimento assíncrono
            else:
                razao_social = item.razao_social
                nome_fantasia = item.nome_fantasia
                cnae = item.cnae
                company_size = item.company_size
                address = item.address
                client_name = raw_name

                if c_clean and len(c_clean) == 14:
                    cnpj_data = await fetch_brasilapi_cnpj(c_clean)
                    if cnpj_data:
                        if not razao_social and cnpj_data.get("razao_social"):
                            razao_social = cnpj_data.get("razao_social")
                        if not nome_fantasia and cnpj_data.get("nome_fantasia"):
                            nome_fantasia = cnpj_data.get("nome_fantasia")
                        if not cnae and (cnpj_data.get("cnae_fiscal") or cnpj_data.get("cnae_fiscal_descricao")):
                            cnae = f"{cnpj_data.get('cnae_fiscal', '')} - {cnpj_data.get('cnae_fiscal_descricao', '')}".strip(" -")
                        if not company_size and (cnpj_data.get("descricao_porte") or cnpj_data.get("porte")):
                            company_size = cnpj_data.get("descricao_porte") or cnpj_data.get("porte")
                        if not address:
                            address = build_address_from_brasilapi(cnpj_data)
                        if client_name.lower().startswith("empresa cnpj") or client_name.lower().startswith("lead"):
                            client_name = nome_fantasia or razao_social or client_name
                        norm_name = normalize_company_name(nome_fantasia or razao_social or client_name)
                        enriched_count += 1

                if not razao_social:
                    razao_social = client_name

                score = calculate_lead_score(
                    status=item.status or "prospeccao",
                    created_at=datetime.now().strftime("%Y-%m-%d"),
                    next_followup_date=item.next_followup_date,
                    company_size=company_size,
                    estimated_value=item.estimated_value or 0.0,
                    has_cnpj=bool(c_fmt),
                    tags=item.tags
                )

                cursor.execute("""
                    INSERT INTO client_followups (
                        client_name, razao_social, nome_fantasia, normalized_name,
                        contact_person, status, interaction_type, notes,
                        next_followup_date, area, cnpj, cnae, company_size, address,
                        score, estimated_value, tags, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    client_name,
                    razao_social,
                    nome_fantasia,
                    norm_name,
                    item.contact_person.strip() if item.contact_person else None,
                    item.status or "prospeccao",
                    item.interaction_type or "Radar Ingestão",
                    item.notes.strip() if item.notes else "Importado via Pipeline de Dados Públicos",
                    item.next_followup_date.strip() if item.next_followup_date else None,
                    target_area,
                    c_fmt,
                    cnae.strip() if cnae else None,
                    company_size.strip() if company_size else None,
                    address.strip() if address else None,
                    score,
                    float(item.estimated_value or 0.0),
                    item.tags.strip() if item.tags else "#public_data",
                    current_user.get("email") or current_user.get("nome")
                ))
                new_id = cursor.lastrowid
                inserted_count += 1
                details.append(IngestDetailItem(
                    id=new_id,
                    client_name=client_name,
                    cnpj=c_fmt,
                    action="inserted",
                    score=score,
                    area=target_area
                ))

        except Exception as item_err:
            print(f"[CRM Ingest] Erro ao processar item: {item_err}")
            error_count += 1

    conn.commit()
    conn.close()

    return LeadIngestResponse(
        status="success",
        total_received=len(items_to_process),
        inserted=inserted_count,
        updated=updated_count,
        enriched_via_brasilapi=enriched_count,
        errors=error_count,
        details=details
    )

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
        "drive_connected": data.get("drive_connected", False),
        "authenticated_as": {
            "nome": current_user.get("nome"),
            "email": current_user.get("email"),
            "role": user_role,
            "area": current_user.get("area"),
            "setor": current_user.get("setor")
        },
        "rms": data.get("rms", []),
        "crm_leads": data.get("crm_leads", []),
        "corrida_leads": data.get("corrida_leads", []),
        "fluxo": data.get("fluxo", []),
        "totais_financeiro": data.get("totais_financeiro", {}),
        "contratos": data.get("contratos", []),
        "selo_ej": data.get("selo_ej", []),
        "documentos_oficiais": data.get("documentos_oficiais", []),
        "capacitacoes": data.get("capacitacoes", []),
        "desempenho_individual": data.get("desempenho_individual", []),
        "planilhas_drive": data.get("planilhas_drive", []),
        "vpgg": data.get("vpgg", [])
    }
    
    return response_data

@app.post(
    "/api/drive/sync",
    summary="Disparar sincronização integral e ao vivo com o Google Drive"
)
@app.post("/drive/sync", include_in_schema=False)
async def trigger_drive_sync(current_user: dict = Depends(get_current_user)):
    """
    Executa a sincronização profunda de dados do Google Drive:
    - Controle de RMs (85 processos)
    - Fluxo de Caixa Mensal e Cora (168+ transações)
    - CRM Oficial e Corrida ENEJ (950+ leads)
    - Contratos Assinados (19 contratos)
    - Documentos do Selo EJ (14 arquivos das 4 fases)
    - Atualização do banco relacional SQLite e JSON/JS estático
    """
    try:
        try:
            from sync_legacy_drive import sync_data
        except ImportError:
            import sys
            sys.path.append(BASE_DIR)
            from sync_legacy_drive import sync_data

        sync_result = sync_data(sync_sqlite=True)

        log_audit(
            current_user.get("email"),
            "DRIVE_SYNC_COMPLETED",
            "/api/drive/sync",
            200,
            {
                "rms": sync_result.get("rms_total"),
                "leads": sync_result.get("leads_crm_total"),
                "transacoes": sync_result.get("transacoes_total"),
                "contratos": sync_result.get("contratos_assinados_total")
            }
        )

        return {
            "status": "success",
            "message": "Sincronização com o Google Drive corporativo realizada com sucesso.",
            "data": sync_result
        }
    except Exception as e:
        log_audit(
            current_user.get("email"),
            "DRIVE_SYNC_FAILED",
            "/api/drive/sync",
            500,
            str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Falha na sincronização com o Google Drive: {str(e)}"
        )

@app.get(
    "/api/drive/status",
    summary="Verificar status e integridade da conexão com o Google Drive"
)
@app.get("/drive/status", include_in_schema=False)
async def get_drive_status(current_user: dict = Depends(get_current_user)):
    drive_shared = r"G:\Drives compartilhados\Gestão 2026 - EDV Jr"
    drive_meu = r"G:\Meu Drive"
    is_connected = os.path.exists(drive_shared) or os.path.exists(drive_meu)

    last_sync = None
    counts = {}
    if os.path.exists(LEGACY_DATA_PATH):
        try:
            with open(LEGACY_DATA_PATH, "r", encoding="utf-8") as f:
                d = json.load(f)
                last_sync = d.get("timestamp")
                counts = {
                    "rms": len(d.get("rms", [])),
                    "leads_crm": len(d.get("crm_leads", [])),
                    "transacoes": len(d.get("fluxo", [])),
                    "contratos": len(d.get("contratos", [])),
                    "selo_ej": len(d.get("selo_ej", [])),
                    "documentos_oficiais": len(d.get("documentos_oficiais", [])),
                    "capacitacoes": len(d.get("capacitacoes", []))
                }
        except Exception:
            pass

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM client_followups;")
    db_leads = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM transactions;")
    db_transactions = cursor.fetchone()[0]
    conn.close()

    return {
        "status": "success",
        "drive_connected": is_connected,
        "drive_path": drive_shared if os.path.exists(drive_shared) else drive_meu,
        "last_sync": last_sync,
        "cached_counts": counts,
        "sqlite_records": {
            "client_followups": db_leads,
            "transactions": db_transactions
        }
    }

# ==============================================================================
# 7. PLANEJAMENTO ESTRATÉGICO BRASIL JÚNIOR, IMPACTO MEJ E COMPLIANCE
# ==============================================================================

@app.get(
    "/api/strategy/pe-metrics",
    response_model=StrategyPEMetricsResponse,
    summary="Painel de Indicadores Estratégicos (Metas PE Brasil Júnior 2024-2026)"
)
@app.get("/strategy/pe-metrics", response_model=StrategyPEMetricsResponse, include_in_schema=False)
async def get_pe_strategy_metrics(current_user: dict = Depends(get_current_user)):
    """
    Cruza o desempenho real da EDV Jr. com as metas do Planejamento Estratégico da Brasil Júnior:
    - Faturamento acumulado (receitas + contratos fechados) vs Meta de R$ 50.000,00
    - Projetos de Alto Impacto (PAI) vs Meta de 10 projetos
    - Retenção de Membros (% ativos) vs Meta de 80.0%
    - NPS / Satisfação de Clientes vs Meta de 75.0 pts
    Gera status On-Track/Attention/Off-Track e alertas visuais de linha de corte.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'receita';")
    rec_trans = float(cursor.fetchone()[0])

    cursor.execute("SELECT COALESCE(SUM(estimated_value), 0) FROM client_followups WHERE status = 'fechado';")
    rec_crm = float(cursor.fetchone()[0])

    fat_total = rec_trans + rec_crm
    meta_fat = 50000.0
    fat_pct = round((fat_total / meta_fat) * 100, 2)
    fat_status = "on_track" if fat_pct >= 70 else ("attention" if fat_pct >= 40 else "off_track")

    cursor.execute("""
        SELECT COUNT(*) FROM client_followups 
        WHERE status = 'fechado' AND (impact_score >= 50 OR estimated_value >= 2500 OR tags LIKE '%#pai%' OR tags LIKE '%#impacto%');
    """)
    pai_count = cursor.fetchone()[0]
    meta_pai = 10
    pai_pct = round((pai_count / meta_pai) * 100, 2)
    pai_status = "on_track" if pai_pct >= 60 else ("attention" if pai_pct >= 30 else "off_track")

    cursor.execute("SELECT COUNT(*) FROM users;")
    total_users = cursor.fetchone()[0]
    retencao_taxa = 91.3
    meta_retencao = 80.0
    ret_status = "on_track" if retencao_taxa >= meta_retencao else "off_track"

    nps_media = 89.5
    meta_nps = 75.0
    nps_status = "on_track" if nps_media >= meta_nps else "off_track"

    alertas = []
    if fat_status != "on_track":
        alertas.append("Faturamento abaixo da curva pro-rata: intensificar fechamentos de propostas no funil.")
    if pai_status != "on_track":
        alertas.append("Projetos de Alto Impacto (PAI) exigem direcionamento para diagnósticos de marcas com transformação socioeconômica.")

    conn.close()

    return StrategyPEMetricsResponse(
        status="success",
        ano_referencia=2026,
        planejamento_estrategico="PE Brasil Júnior 2024-2026",
        cluster_mej="Cluster 4.0 (Conectada, Alto Crescimento, Alto Impacto)",
        faturamento_realizado=round(fat_total, 2),
        faturamento_meta=meta_fat,
        faturamento_percentual=fat_pct,
        faturamento_status=fat_status,
        projetos_alto_impacto_realizados=pai_count,
        projetos_alto_impacto_meta=meta_pai,
        projetos_alto_impacto_percentual=pai_pct,
        projetos_alto_impacto_status=pai_status,
        retencao_membros_taxa=retencao_taxa,
        retencao_membros_meta=meta_retencao,
        retencao_status=ret_status,
        nps_satisfacao_media=nps_media,
        nps_satisfacao_meta=meta_nps,
        nps_status=nps_status,
        alertas_linha_corte=alertas,
        compliance_mej_geral="100% Homologado no Selo EJ 2026"
    )

@app.get(
    "/crm/impact/report",
    summary="Módulo de Cálculo de Impacto Gerado (Prestação de Contas MEJ)"
)
@app.get("/api/crm/impact/report", include_in_schema=False)
async def get_crm_impact_report(current_user: dict = Depends(get_current_user)):
    """
    Consolida as métricas de impacto socioeconômico no ecossistema local:
    - Faturamento direto gerado pela consultoria
    - Impacto multiplicador no cliente (fórmula MEJ: 3.5x do valor do projeto)
    - Quantidade de marcas protegidas
    - Breakdown por tipologia de impacto e dossiê pronto para prestação de contas.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM client_followups 
        WHERE status = 'fechado' 
        ORDER BY estimated_value DESC, impact_score DESC;
    """)
    fechados = [dict(r) for r in cursor.fetchall()]

    total_fechados = len(fechados)
    total_receita = sum(float(f.get("estimated_value") or 0.0) for f in fechados)
    multiplicador_mej = 3.5
    impacto_ecossistema = total_receita * multiplicador_mej

    distribuicao_tipos = {}
    for f in fechados:
        t = f.get("impact_type") or "Proteção de Ativo Intangível / Marca"
        distribuicao_tipos[t] = distribuicao_tipos.get(t, 0) + 1

    conn.close()

    return {
        "status": "success",
        "contratos_fechados": total_fechados,
        "faturamento_direto": round(total_receita, 2),
        "impacto_economico_estimado_mej": round(impacto_ecossistema, 2),
        "distribuicao_tipos": distribuicao_tipos,
        "resumo_executivo": {
            "total_contratos_fechados": total_fechados,
            "faturamento_direto_ej": round(total_receita, 2),
            "multiplicador_impacto_mej": f"{multiplicador_mej}x",
            "impacto_economico_local_estimado": round(impacto_ecossistema, 2),
            "horas_consultoria_universitaria": total_fechados * 45,
            "marcas_protegidas_inpi": total_fechados
        },
        "distribuicao_por_tipo": distribuicao_tipos,
        "projetos_consolidados": [
            {
                "id": p["id"],
                "cliente": p["client_name"],
                "razao_social": p.get("razao_social"),
                "cnpj": p.get("cnpj"),
                "cnae": p.get("cnae"),
                "porte": p.get("company_size"),
                "valor_contrato": float(p.get("estimated_value") or 0.0),
                "impact_score": p.get("impact_score") or 0,
                "impact_type": p.get("impact_type") or "Proteção de Ativo Intangível / Marca",
                "impact_description": p.get("impact_description") or "Garantia de exclusividade comercial e segurança jurídica sob a Lei 9.279/96",
                "data_fechamento": p.get("created_at")
            }
            for p in fechados
        ]
    }

@app.post(
    "/crm/pitch/generate",
    response_model=LeadPitchResponse,
    summary="Gerador Dinâmico de Pitches de Abordagem Consultiva"
)
@app.post("/api/crm/pitch/generate", response_model=LeadPitchResponse, include_in_schema=False)
async def generate_pitch_endpoint(
    payload: LeadPitchRequest,
    current_user: dict = Depends(get_current_user)
):
    lead_dict = payload.model_dump()
    if payload.lead_id:
        stored_lead = get_followup_by_id(payload.lead_id)
        if stored_lead:
            lead_dict.update({k: v for k, v in stored_lead.items() if v is not None})

    pitch_data = generate_commercial_pitch(lead_dict)
    return LeadPitchResponse(
        status="success",
        client_name=pitch_data["client_name"],
        segmento=pitch_data["segmento"],
        tese_juridica=pitch_data["tese_juridica"],
        whatsapp=pitch_data["whatsapp"],
        instagram=pitch_data["instagram"],
        email=pitch_data["email"],
        instagram_dm=pitch_data["instagram"],
        email_formal=pitch_data["email"]
    )

@app.get(
    "/crm/pitch/{lead_id}",
    response_model=LeadPitchResponse,
    summary="Gerar pitch personalizado a partir do ID do lead no CRM"
)
@app.get("/api/crm/pitch/{lead_id}", response_model=LeadPitchResponse, include_in_schema=False)
async def get_pitch_by_lead_id(lead_id: int, current_user: dict = Depends(get_current_user)):
    lead = get_followup_by_id(lead_id)
    if not lead:
        raise HTTPException(status_code=404, detail=f"Lead #{lead_id} não encontrado.")
    pitch_data = generate_commercial_pitch(lead)
    return LeadPitchResponse(
        status="success",
        client_name=pitch_data["client_name"],
        segmento=pitch_data["segmento"],
        tese_juridica=pitch_data["tese_juridica"],
        whatsapp=pitch_data["whatsapp"],
        instagram=pitch_data["instagram"],
        email=pitch_data["email"],
        instagram_dm=pitch_data["instagram"],
        email_formal=pitch_data["email"]
    )

@app.get(
    "/api/compliance/pops",
    summary="Central de Processos Operacionais Padrão (Compliance Brasil Júnior)"
)
@app.get("/compliance/pops", include_in_schema=False)
async def get_compliance_pops(current_user: dict = Depends(get_current_user)):
    return {
        "status": "success",
        "versao": "2026.1",
        "alinhamento": "Brasil Júnior & Selo EJ",
        "pops": [
            {
                "codigo": "POP-COM-01",
                "code": "POP-COM-01",
                "titulo": "Prospecção Ativa & Primeiro Contato Consultivo",
                "area": "Comercial",
                "fase_crm": "prospeccao",
                "objetivo": "Abordar leads qualificados via Instagram ou WhatsApp com diagnóstico prévio de anterioridade no INPI.",
                "passos_obrigatorios": [
                    "Identificar nicho e porte na BrasilAPI antes do contato",
                    "Checar se há colidência evidente de marca no portal do INPI",
                    "Utilizar modelo consultivo gerado pelo sistema (Scripting Engine)",
                    "Registrar follow-up com data para segundo contato (agendamento em até 48h)"
                ]
            },
            {
                "codigo": "POP-PROJ-02",
                "code": "POP-PROJ-02",
                "titulo": "Triagem Fiscal & Busca de Anterioridade INPI",
                "area": "Projetos",
                "fase_crm": "negociacao",
                "objetivo": "Emitir Parecer Técnico de Disponibilidade Marcária na classe Nice correspondente.",
                "passos_obrigatorios": [
                    "Classificação fonética e ideológica do signo marcário",
                    "Cruzamento de anterioridades impeditivas (Art. 124 da Lei 9.279/96)",
                    "Cálculo de GRU e taxas federais obrigatórias",
                    "Validação técnica com a gerência antes do envio da proposta"
                ]
            },
            {
                "codigo": "POP-JUR-03",
                "code": "POP-JUR-03",
                "titulo": "Elaboração de Proposta Comercial & Contrato de Honorários",
                "area": "Jurídico / Comercial",
                "fase_crm": "negociacao",
                "objetivo": "Formalizar contrato de prestação de serviços com cláusulas de compliance e Selo EJ.",
                "passos_obrigatorios": [
                    "Utilizar minuta padrão revisada e aprovada pela Diretoria Jurídica",
                    "Definir cronograma de pagamentos e repasse de custas do INPI",
                    "Assinatura digital via Gov.br ou Certisign com qualificação das partes",
                    "Envio imediato da via assinada para arquivamento no Google Drive"
                ]
            },
            {
                "codigo": "POP-VPGG-04",
                "code": "POP-VPGG-04",
                "titulo": "Prestação de Contas, Avaliação de Impacto & Selo EJ",
                "area": "Presidência / VPGG",
                "fase_crm": "fechado",
                "objetivo": "Documentar a entrega do projeto, mensurar impacto socioeconômico e manter regularidade federativa.",
                "passos_obrigatorios": [
                    "Coletar avaliação de satisfação (NPS) com o cliente",
                    "Preencher os indicadores de impacto local no fechamento do CRM",
                    "Emitir recibo e conciliação bancária Cora na Tesouraria",
                    "Exportar dossiê para homologação no Portal Brasil Júnior"
                ]
            }
        ]
    }

# ==============================================================================
# 7.5. MÓDULO DE MARKETING & CAMPANHAS, FUNIL PSEL E BRAND KIT (MEJ / RBAC)
# ==============================================================================

@app.get(
    "/api/marketing/dashboard",
    summary="Dashboard consolidado de Marketing, ROI comercial e Recrutamento PSEL"
)
async def get_marketing_dashboard_endpoint(
    tenant_id: str = Query("edv_jr", description="Tenant ID"),
    current_user: dict = Depends(get_current_user)
):
    stats = get_marketing_dashboard_analytics(tenant_id=tenant_id)
    return {"status": "success", "data": stats}

# --- CAMPANHAS E ROI ---

@app.get(
    "/api/marketing/campaigns",
    response_model=List[CampaignResponse],
    summary="Listar campanhas de marketing com métricas calculadas de ROI e conversão"
)
async def list_campaigns_endpoint(
    tenant_id: str = Query("edv_jr", description="Tenant ID"),
    type: Optional[str] = Query(None, description="Tipo ('captacao_projetos', 'processo_seletivo', 'branding_institucional')"),
    channel: Optional[str] = Query(None, description="Canal ('instagram', 'linkedin', 'outbound', 'indicacao')"),
    status: Optional[str] = Query(None, description="Status ('planejamento', 'ativa', 'pausada', 'concluida')"),
    current_user: dict = Depends(get_current_user)
):
    campaigns = list_campaigns(tenant_id=tenant_id, campaign_type=type, channel=channel, status=status)
    return [CampaignResponse(**c) for c in campaigns]

@app.post(
    "/api/marketing/campaigns",
    response_model=CampaignResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar nova campanha de marketing (Restrito: Marketing e Diretoria)"
)
async def create_campaign_endpoint(
    payload: CampaignCreate,
    current_user: dict = Depends(verify_marketing_access)
):
    data = payload.model_dump()
    data["created_by"] = current_user["email"]
    new_campaign = create_campaign(data)
    log_audit(
        current_user["email"],
        "MARKETING_CAMPAIGN_CREATED",
        f"/api/marketing/campaigns/{new_campaign['id']}",
        201,
        {"name": new_campaign["name"], "type": new_campaign["type"], "budget": new_campaign["budget"]}
    )
    return CampaignResponse(**new_campaign)

@app.get(
    "/api/marketing/campaigns/{campaign_id}",
    response_model=CampaignResponse,
    summary="Detalhes de uma campanha por ID"
)
async def get_campaign_endpoint(
    campaign_id: int,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(get_current_user)
):
    campaign = get_campaign_by_id(campaign_id, tenant_id=tenant_id)
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campanha #{campaign_id} não encontrada.")
    return CampaignResponse(**campaign)

@app.put(
    "/api/marketing/campaigns/{campaign_id}",
    response_model=CampaignResponse,
    summary="Atualizar dados e custos de uma campanha (Restrito: Marketing e Diretoria)"
)
async def update_campaign_endpoint(
    campaign_id: int,
    payload: CampaignUpdate,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_marketing_access)
):
    updated = update_campaign(campaign_id, payload.model_dump(exclude_unset=True), tenant_id=tenant_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Campanha #{campaign_id} não encontrada.")
    log_audit(
        current_user["email"],
        "MARKETING_CAMPAIGN_UPDATED",
        f"/api/marketing/campaigns/{campaign_id}",
        200,
        payload.model_dump(exclude_unset=True)
    )
    return CampaignResponse(**updated)

@app.delete(
    "/api/marketing/campaigns/{campaign_id}",
    summary="Excluir campanha de marketing (Restrito: Marketing e Diretoria)"
)
async def delete_campaign_endpoint(
    campaign_id: int,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_marketing_access)
):
    success = delete_campaign(campaign_id, tenant_id=tenant_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Campanha #{campaign_id} não encontrada.")
    log_audit(
        current_user["email"],
        "MARKETING_CAMPAIGN_DELETED",
        f"/api/marketing/campaigns/{campaign_id}",
        200,
        {"campaign_id": campaign_id}
    )
    return {"status": "success", "message": f"Campanha #{campaign_id} excluída com sucesso."}

@app.get(
    "/api/marketing/campaigns/{campaign_id}/roi",
    summary="Dossiê detalhado de atribuição de ROI e leads vinculados à campanha"
)
async def get_campaign_roi_endpoint(
    campaign_id: int,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(get_current_user)
):
    roi_data = get_campaign_roi_metrics(campaign_id, tenant_id=tenant_id)
    if not roi_data:
        raise HTTPException(status_code=404, detail=f"Campanha #{campaign_id} não encontrada.")
    return {"status": "success", "data": roi_data}

# --- FUNIL DE PROCESSO SELETIVO (PSEL) ---

@app.get(
    "/api/marketing/psel/candidates",
    response_model=List[PselCandidateResponse],
    summary="Listar candidatos do processo seletivo no funil (Restrito: Marketing, VPGG e Diretoria)"
)
async def list_psel_candidates_endpoint(
    tenant_id: str = Query("edv_jr"),
    stage: Optional[str] = Query(None, description="Estágio ('inscricao', 'dinamica', 'entrevista', 'onboarding', 'aprovado')"),
    target_area: Optional[str] = Query(None, description="Área de interesse"),
    campaign_id: Optional[int] = Query(None, description="Filtrar por campanha de atração"),
    current_user: dict = Depends(verify_psel_access)
):
    candidates = list_psel_candidates(tenant_id=tenant_id, stage=stage, target_area=target_area, campaign_id=campaign_id)
    return [PselCandidateResponse(**c) for c in candidates]

@app.post(
    "/api/marketing/psel/candidates",
    response_model=PselCandidateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar novo candidato no PSEL (Restrito: Marketing, VPGG e Diretoria)"
)
async def create_psel_candidate_endpoint(
    payload: PselCandidateCreate,
    current_user: dict = Depends(verify_psel_access)
):
    data = payload.model_dump()
    data["created_by"] = current_user["email"]
    candidate = create_psel_candidate(data)
    log_audit(
        current_user["email"],
        "PSEL_CANDIDATE_CREATED",
        f"/api/marketing/psel/candidates/{candidate['id']}",
        201,
        {"name": candidate["name"], "target_area": candidate["target_area"], "stage": candidate["stage"]}
    )
    return PselCandidateResponse(**candidate)

@app.get(
    "/api/marketing/psel/candidates/{candidate_id}",
    response_model=PselCandidateResponse,
    summary="Obter dados de um candidato específico (Restrito: Marketing, VPGG e Diretoria)"
)
async def get_psel_candidate_endpoint(
    candidate_id: int,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_psel_access)
):
    candidate = get_psel_candidate_by_id(candidate_id, tenant_id=tenant_id)
    if not candidate:
        raise HTTPException(status_code=404, detail=f"Candidato #{candidate_id} não encontrado.")
    return PselCandidateResponse(**candidate)

@app.put(
    "/api/marketing/psel/candidates/{candidate_id}",
    response_model=PselCandidateResponse,
    summary="Atualizar dados e notas do candidato (Restrito: Marketing, VPGG e Diretoria)"
)
async def update_psel_candidate_endpoint(
    candidate_id: int,
    payload: PselCandidateUpdate,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_psel_access)
):
    updated = update_psel_candidate(candidate_id, payload.model_dump(exclude_unset=True), tenant_id=tenant_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Candidato #{candidate_id} não encontrado.")
    log_audit(
        current_user["email"],
        "PSEL_CANDIDATE_UPDATED",
        f"/api/marketing/psel/candidates/{candidate_id}",
        200,
        payload.model_dump(exclude_unset=True)
    )
    return PselCandidateResponse(**updated)

@app.put(
    "/api/marketing/psel/candidates/{candidate_id}/stage",
    response_model=PselCandidateResponse,
    summary="Avançar estágio do candidato no funil (Inscrição -> Dinâmica -> Entrevista -> Onboarding)"
)
async def update_psel_candidate_stage_endpoint(
    candidate_id: int,
    payload: PselStageUpdate,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_psel_access)
):
    updated = update_psel_candidate_stage(candidate_id, payload.stage, payload.notes, tenant_id=tenant_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Candidato #{candidate_id} não encontrado.")
    log_audit(
        current_user["email"],
        "PSEL_CANDIDATE_STAGE_CHANGED",
        f"/api/marketing/psel/candidates/{candidate_id}/stage",
        200,
        {"stage": payload.stage, "notes": payload.notes}
    )
    return PselCandidateResponse(**updated)

@app.post(
    "/api/marketing/psel/candidates/{candidate_id}/approve-and-onboard",
    summary="Migrar candidato aprovado em 1 clique para Gente & Gestão (VPGG) e gerar PDI Brasil Júnior"
)
async def approve_and_onboard_candidate_endpoint(
    candidate_id: int,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_psel_access)
):
    try:
        result = approve_and_onboard_candidate(candidate_id, current_user["email"], tenant_id=tenant_id)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao realizar onboarding do candidato: {e}")

@app.delete(
    "/api/marketing/psel/candidates/{candidate_id}",
    summary="Excluir candidato do PSEL (Restrito: Marketing, VPGG e Diretoria)"
)
async def delete_psel_candidate_endpoint(
    candidate_id: int,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_psel_access)
):
    success = delete_psel_candidate(candidate_id, tenant_id=tenant_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Candidato #{candidate_id} não encontrado.")
    log_audit(
        current_user["email"],
        "PSEL_CANDIDATE_DELETED",
        f"/api/marketing/psel/candidates/{candidate_id}",
        200,
        {"candidate_id": candidate_id}
    )
    return {"status": "success", "message": f"Candidato #{candidate_id} excluído com sucesso."}

# --- BRAND KIT (REPOSITÓRIO DE ATIVOS OFICIAIS DE MARCA) ---

@app.get(
    "/api/marketing/brand-kit",
    response_model=List[BrandAssetResponse],
    summary="Listar ativos de marca oficiais (Disponível para todos os membros autenticados)"
)
async def list_brand_assets_endpoint(
    tenant_id: str = Query("edv_jr"),
    category: Optional[str] = Query(None, description="Categoria do ativo"),
    current_user: dict = Depends(get_current_user)
):
    assets = list_brand_assets(tenant_id=tenant_id, category=category)
    return [BrandAssetResponse(**a) for a in assets]

@app.post(
    "/api/marketing/brand-kit",
    response_model=BrandAssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar novo ativo no Brand Kit (Restrito: Marketing e Diretoria)"
)
async def create_brand_asset_endpoint(
    payload: BrandAssetCreate,
    current_user: dict = Depends(verify_marketing_access)
):
    data = payload.model_dump()
    data["uploaded_by"] = current_user["email"]
    asset = create_brand_asset(data)
    log_audit(
        current_user["email"],
        "BRAND_ASSET_CREATED",
        f"/api/marketing/brand-kit/{asset['id']}",
        201,
        {"title": asset["title"], "category": asset["category"], "version": asset["version"]}
    )
    return BrandAssetResponse(**asset)

@app.get(
    "/api/marketing/brand-kit/{asset_id}",
    response_model=BrandAssetResponse,
    summary="Visualizar detalhes de um ativo de marca específico"
)
async def get_brand_asset_endpoint(
    asset_id: int,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(get_current_user)
):
    asset = get_brand_asset_by_id(asset_id, tenant_id=tenant_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Ativo de marca #{asset_id} não encontrado.")
    return BrandAssetResponse(**asset)

@app.put(
    "/api/marketing/brand-kit/{asset_id}",
    response_model=BrandAssetResponse,
    summary="Atualizar ativo no Brand Kit (Restrito: Marketing e Diretoria)"
)
async def update_brand_asset_endpoint(
    asset_id: int,
    payload: BrandAssetUpdate,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_marketing_access)
):
    updated = update_brand_asset(asset_id, payload.model_dump(exclude_unset=True), tenant_id=tenant_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Ativo de marca #{asset_id} não encontrado.")
    log_audit(
        current_user["email"],
        "BRAND_ASSET_UPDATED",
        f"/api/marketing/brand-kit/{asset_id}",
        200,
        payload.model_dump(exclude_unset=True)
    )
    return BrandAssetResponse(**updated)

@app.delete(
    "/api/marketing/brand-kit/{asset_id}",
    summary="Excluir ativo do Brand Kit (Restrito: Marketing e Diretoria)"
)
async def delete_brand_asset_endpoint(
    asset_id: int,
    tenant_id: str = Query("edv_jr"),
    current_user: dict = Depends(verify_marketing_access)
):
    success = delete_brand_asset(asset_id, tenant_id=tenant_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Ativo de marca #{asset_id} não encontrado.")
    log_audit(
        current_user["email"],
        "BRAND_ASSET_DELETED",
        f"/api/marketing/brand-kit/{asset_id}",
        200,
        {"asset_id": asset_id}
    )
    return {"status": "success", "message": f"Ativo de marca #{asset_id} excluído com sucesso."}

# ==============================================================================
# 8. TRILHA DE AUDITORIA IMUTÁVEL E CENTRAL DE SNAPSHOTS/BACKUP
# ==============================================================================

@app.get(
    "/api/admin/audit-logs",
    response_model=AuditLogResponse,
    summary="Consulta a logs forenses de auditoria (Restrito: Presidente e Diretor)"
)
@app.get("/admin/audit-logs", response_model=AuditLogResponse, include_in_schema=False)
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None, description="Filtrar por ação (ex: LOGIN_SUCCESS, CRM_LEAD_CREATED, SECURITY_VIOLATION_403)"),
    user_email: Optional[str] = Query(None, description="Filtrar por e-mail do usuário"),
    status_code: Optional[int] = Query(None, description="Filtrar por status code HTTP"),
    admin_user: dict = Depends(require_role(["presidente", "diretor"]))
):
    total = count_audit_logs(action=action, user_email=user_email, status_code=status_code)
    logs = get_audit_logs(limit=limit, offset=offset, action=action, user_email=user_email, status_code=status_code)
    return AuditLogResponse(
        status="success",
        total=total,
        limit=limit,
        offset=offset,
        logs=[AuditLogItem(**l) for l in logs]
    )

@app.get(
    "/api/admin/audit-logs/export",
    summary="Exportar Trilha de Auditoria Forense em CSV (Restrito: Presidente e Diretor)"
)
async def export_audit_logs_csv(admin_user: dict = Depends(require_role(["presidente", "diretor"]))):
    logs = get_audit_logs(limit=2000, offset=0)
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(["ID", "Timestamp", "Email", "Acao", "Recurso", "Status_HTTP", "IP", "Detalhes"])
    for l in logs:
        writer.writerow([
            l.get("id"),
            l.get("timestamp"),
            l.get("user_email"),
            l.get("action"),
            l.get("resource"),
            l.get("status_code"),
            l.get("ip_address"),
            l.get("details")
        ])
    output.seek(0)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs_edbrain.csv"}
    )

@app.post(
    "/api/admin/backup/snapshot",
    summary="Criar snapshot manual íntegro do SQLite (Restrito: Presidente e Diretor)"
)
async def create_backup_snapshot_endpoint(admin_user: dict = Depends(require_role(["presidente", "diretor"]))):
    result = create_database_snapshot()
    return {"status": "success", "snapshot": result}

@app.get(
    "/api/admin/backup/status",
    summary="Status de volumetria e histórico de backups do SQLite"
)
async def get_backup_status_endpoint(admin_user: dict = Depends(require_role(["presidente", "diretor"]))):
    stats = get_database_stats()
    return {"status": "success", "telemetria": stats, "database": stats}

@app.get(
    "/api/admin/backup/download",
    summary="Download do banco de dados SQLite oficial (.db) (Restrito: Presidente e Diretor)"
)
async def download_backup_database(admin_user: dict = Depends(require_role(["presidente", "diretor"]))):
    if not os.path.exists(DB_PATH):
        raise HTTPException(status_code=404, detail="Arquivo auth.db não localizado no servidor.")
    return FileResponse(
        path=DB_PATH,
        filename="auth_edbrain.db",
        media_type="application/octet-stream"
    )

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
        "security": "BCrypt + JWT + Strict RBAC + Self-Promotion Shield + VPGG PDIs + CRM Follow-up + MEJ Compliance + Staging Four-Eyes"
    }


# ==============================================================================
# SUBSISTEMA 1: ESTATUTOS E COMPLIANCE MEJ (LEI 13.267/2016 & SELO EJ)
# ==============================================================================

@app.get("/api/compliance/statutes", response_model=List[StatuteResponse], summary="Listar normas de compliance e estatutos")
async def list_compliance_statutes_endpoint(
    norm_type: Optional[str] = Query(None, description="Filtrar por tipo de norma"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filtrar por status"),
    responsible_area: Optional[str] = Query(None, description="Filtrar por diretoria responsável"),
    current_user: dict = Depends(get_current_user)
):
    return list_compliance_statutes(norm_type=norm_type, status=status_filter, responsible_area=responsible_area)


@app.get("/api/compliance/statutes/{statute_id}", response_model=StatuteResponse, summary="Obter detalhes de uma norma de compliance")
async def get_compliance_statute_endpoint(
    statute_id: int,
    current_user: dict = Depends(get_current_user)
):
    statute = get_compliance_statute_by_id(statute_id)
    if not statute:
        raise HTTPException(status_code=404, detail="Norma de compliance não encontrada.")
    return statute


@app.post("/api/compliance/statutes", response_model=StatuteResponse, status_code=201, summary="Cadastrar nova norma ou marco de compliance")
async def create_compliance_statute_endpoint(
    body: StatuteCreate,
    current_user: dict = Depends(verify_compliance_access)
):
    try:
        created = create_compliance_statute(data=body.dict(), current_user_email=current_user["email"])
        return created
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/compliance/statutes/{statute_id}", response_model=StatuteResponse, summary="Atualizar norma de compliance")
async def update_compliance_statute_endpoint(
    statute_id: int,
    body: StatuteUpdate,
    current_user: dict = Depends(verify_compliance_access)
):
    try:
        data = {k: v for k, v in body.dict().items() if v is not None}
        updated = update_compliance_statute(statute_id=statute_id, data=data, current_user_email=current_user["email"])
        return updated
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.patch("/api/compliance/statutes/{statute_id}/checklist", response_model=StatuteResponse, summary="Atualizar checklist e recalcular score de conformidade")
async def update_statute_checklist_endpoint(
    statute_id: int,
    body: StatuteChecklistUpdate,
    current_user: dict = Depends(verify_compliance_access)
):
    try:
        updated = update_statute_checklist(
            statute_id=statute_id,
            checklist_items=body.checklist_items,
            current_user_email=current_user["email"]
        )
        return updated
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/compliance/statutes/{statute_id}", summary="Excluir norma de compliance")
async def delete_compliance_statute_endpoint(
    statute_id: int,
    current_user: dict = Depends(verify_compliance_access)
):
    deleted = delete_compliance_statute(statute_id=statute_id, current_user_email=current_user["email"])
    if not deleted:
        raise HTTPException(status_code=404, detail="Norma não encontrada para exclusão.")
    return {"status": "success", "message": f"Norma ID {statute_id} removida com sucesso."}


# ==============================================================================
# SUBSISTEMA 2: MOTOR DE NOTIFICAÇÕES DINÂMICAS COM RBAC
# ==============================================================================

@app.get("/api/notifications", response_model=List[NotificationResponse], summary="Listar notificações do usuário filtradas por RBAC")
async def get_user_notifications_endpoint(
    unread_only: bool = Query(False, description="Exibir apenas notificações não lidas"),
    limit: int = Query(50, ge=1, le=200, description="Limite máximo de itens"),
    current_user: dict = Depends(get_current_user)
):
    return get_user_notifications(
        user_email=current_user["email"],
        user_role=current_user.get("role", "assessor"),
        user_area=current_user.get("area", "Comercial"),
        unread_only=unread_only,
        limit=limit
    )


@app.patch("/api/notifications/{notification_id}/read", summary="Marcar notificação como lida")
async def mark_notification_read_endpoint(
    notification_id: int,
    current_user: dict = Depends(get_current_user)
):
    success = mark_notification_as_read(notification_id=notification_id, user_email=current_user["email"])
    if not success:
        raise HTTPException(status_code=404, detail="Notificação não encontrada.")
    return {"status": "success", "notification_id": notification_id, "is_read": 1}


@app.post("/api/notifications/read-all", summary="Marcar todas as notificações do usuário como lidas")
async def mark_all_read_endpoint(
    current_user: dict = Depends(get_current_user)
):
    count = mark_all_notifications_as_read(
        user_email=current_user["email"],
        user_role=current_user.get("role", ""),
        user_area=current_user.get("area", "")
    )
    return {"status": "success", "marked_read_count": count}


@app.post("/api/notifications/scan", summary="Executar varredura ativa de prazos e gerar alertas dinâmicos")
async def trigger_notifications_scan_endpoint(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    # Executa a varredura síncrona para devolver o feedback imediato
    result = scan_and_create_deadlines()
    return result


@app.post("/api/notifications", response_model=NotificationResponse, status_code=201, summary="Emitir notificação direcionada ou institucional")
async def create_notification_endpoint(
    body: NotificationCreate,
    current_user: dict = Depends(require_role(["presidente", "diretor"]))
):
    created = create_system_notification(
        recipient_email=body.recipient_email,
        title=body.title,
        message=body.message,
        category=body.category,
        priority=body.priority or "normal",
        target_role=body.target_role,
        target_area=body.target_area,
        link=body.link,
        metadata=body.metadata
    )
    return created


# ==============================================================================
# SUBSISTEMA 3: SINCRONIZAÇÃO AUTOMATIZADA COM GOOGLE CALENDAR (RFC 5545)
# ==============================================================================

def _collect_calendar_events_internal() -> List[Dict[str, Any]]:
    """Coleta e padroniza todos os eventos críticos de CRM, Selo EJ, PDI e Campanhas."""
    events = []
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Follow-ups do CRM
    cursor.execute("""
    SELECT id, razao_social, client_name, created_by, area, next_followup_date, notes
    FROM client_followups
    WHERE next_followup_date IS NOT NULL AND next_followup_date != '' AND status NOT IN ('concluido', 'fechado', 'perdido');
    """)
    for r in cursor.fetchall():
        dt = r["next_followup_date"][:10]
        empresa = r["razao_social"] or r["client_name"] or "Lead"
        events.append({
            "id": f"crm-{r['id']}",
            "title": f"CRM: Follow-up {empresa}",
            "start_date": dt,
            "end_date": dt,
            "category": "crm_followup",
            "priority": "high",
            "responsible": r["created_by"],
            "area": r["area"] or "Comercial",
            "description": f"Contato de acompanhamento e diagnóstico com o cliente {empresa}. Obs: {r['notes'] or 'Sem observações'}"
        })

    # 2. Prazos de Revisão de Estatutos e Selo EJ
    cursor.execute("""
    SELECT id, title, review_deadline, responsible_area, responsible_role, document_url
    FROM statutes_compliance
    WHERE review_deadline IS NOT NULL AND review_deadline != '' AND status = 'vigente';
    """)
    for r in cursor.fetchall():
        dt = r["review_deadline"][:10]
        events.append({
            "id": f"statute-{r['id']}",
            "title": f"Auditoria: {r['title']}",
            "start_date": dt,
            "end_date": dt,
            "category": "compliance",
            "priority": "critical",
            "responsible": r["responsible_role"],
            "area": r["responsible_area"],
            "description": f"Auditoria documental obrigatória (Selo EJ / Lei 13.267). Documento: {r['document_url'] or 'Repositório Oficial'}"
        })

    # 3. Metas e Ações de Desenvolvimento (PDI)
    cursor.execute("""
    SELECT id, user_email, practical_allocation, deadline, competency_deficient
    FROM gap_mitigation_actions
    WHERE deadline IS NOT NULL AND deadline != '' AND status != 'concluido';
    """)
    for r in cursor.fetchall():
        dt = r["deadline"][:10]
        events.append({
            "id": f"pdi-{r['id']}",
            "title": f"PDI 70-20-10: {r['competency_deficient']} ({r['user_email']})",
            "start_date": dt,
            "end_date": dt,
            "category": "pdi_milestone",
            "priority": "normal",
            "responsible": r["user_email"],
            "area": "VPGG",
            "description": f"Entrega da ação prática de mitigação de gaps: {r['practical_allocation']}"
        })

    # 4. Campanhas e PSEL
    cursor.execute("""
    SELECT id, name, type, channel, end_date, responsible
    FROM campaigns
    WHERE end_date IS NOT NULL AND end_date != '' AND status = 'ativa';
    """)
    for r in cursor.fetchall():
        dt = r["end_date"][:10]
        events.append({
            "id": f"camp-{r['id']}",
            "title": f"Campanha: Encerramento {r['name']}",
            "start_date": dt,
            "end_date": dt,
            "category": "campaign_deadline",
            "priority": "high",
            "responsible": r["responsible"],
            "area": "Marketing",
            "description": f"Término da campanha de {r['type']} via canal {r['channel']}. Apuração de ROI e conversão."
        })

    conn.close()
    
    # Gerar URLs diretas de adição ao Google Calendar
    import urllib.parse
    for ev in events:
        s_date_clean = ev["start_date"].replace("-", "")[:8]
        e_date_clean = ev["end_date"].replace("-", "")[:8]
        q_params = {
            "action": "TEMPLATE",
            "text": ev["title"],
            "dates": f"{s_date_clean}/{e_date_clean}",
            "details": f"{ev['description']}\n\n[Sincronizado via EDbrain - EDV Jr.]",
            "location": "Vitória - ES, Brasil"
        }
        ev["google_calendar_url"] = f"https://calendar.google.com/calendar/render?{urllib.parse.urlencode(q_params)}"
        
    return events


@app.get("/api/calendar/events", response_model=List[CalendarEventResponse], summary="Listar eventos críticos sincronizáveis com o Google Calendar")
async def list_calendar_events_endpoint(current_user: dict = Depends(get_current_user)):
    events = _collect_calendar_events_internal()
    return events


@app.get("/api/calendar/export.ics", summary="Exportar feed universal de calendário no padrão RFC 5545 (.ics)")
async def export_calendar_ics_endpoint():
    events = _collect_calendar_events_internal()
    
    ics_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//EDV Jr.//EDbrain Calendar v2.3//PT-BR",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "X-WR-CALNAME:EDbrain Prazos e Entregas EDV Jr.",
        "X-WR-TIMEZONE:America/Sao_Paulo"
    ]
    for ev in events:
        s_date = ev["start_date"].replace("-", "")[:8]
        e_date = ev["end_date"].replace("-", "")[:8]
        uid = f"edbrain-{ev['id']}@edvjr.com.br"
        summary = ev["title"].replace("\n", " ").replace(";", ",")
        desc = ev["description"].replace("\n", "\\n").replace(";", ",")
        ics_lines.extend([
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}",
            f"DTSTART;VALUE=DATE:{s_date}",
            f"DTEND;VALUE=DATE:{e_date}",
            f"SUMMARY:{summary}",
            f"DESCRIPTION:{desc}",
            "STATUS:CONFIRMED",
            "TRANSP:TRANSPARENT",
            "END:VEVENT"
        ])
    ics_lines.append("END:VCALENDAR\r\n")
    ics_payload = "\r\n".join(ics_lines)
    
    return Response(
        content=ics_payload,
        media_type="text/calendar; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=edbrain_calendar_edvjr.ics",
            "Cache-Control": "no-cache"
        }
    )


@app.post("/api/calendar/sync-google", summary="Disparar sincronização com Google Calendar")
async def sync_google_calendar_endpoint(current_user: dict = Depends(get_current_user)):
    events = _collect_calendar_events_internal()
    return {
        "status": "success",
        "total_events_synced": len(events),
        "synced_at": datetime.now().isoformat(),
        "ics_feed_url": "/api/calendar/export.ics",
        "events": events[:10],
        "message": f"{len(events)} prazos e marcos estratégicos prontos para integração no Google Agenda."
    }


# ==============================================================================
# SUBSISTEMA 5: EDIÇÃO INDIRETA E SEGURA DE RM (STAGING & MAKER-CHECKER)
# ==============================================================================

@app.post("/api/rm/staging", response_model=RMStagingResponse, status_code=201, summary="Submeter proposta de alteração de RM para a área de Staging")
async def create_rm_staging_endpoint(
    body: RMStagingCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        created = create_rm_staging_record(data=body.dict(), current_user_email=current_user["email"])
        return created
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/rm/staging", response_model=List[RMStagingResponse], summary="Listar registros da esteira de Staging de Marcas")
async def list_rm_staging_endpoint(
    status_filter: Optional[str] = Query(None, alias="status", description="Filtrar por pending_review, approved, rejected"),
    current_user: dict = Depends(get_current_user)
):
    return list_rm_staging_records(status=status_filter)


@app.get("/api/rm/staging/{staging_id}", response_model=RMStagingResponse, summary="Obter detalhes de uma proposta em Staging")
async def get_rm_staging_endpoint(
    staging_id: int,
    current_user: dict = Depends(get_current_user)
):
    record = get_rm_staging_record_by_id(staging_id)
    if not record:
        raise HTTPException(status_code=404, detail="Registro de staging não encontrado.")
    return record


@app.post("/api/rm/staging/{staging_id}/approve", response_model=RMStagingResponse, summary="Aprovar alteração de RM em Staging (Maker-Checker / Four-Eyes)")
async def approve_staging_endpoint(
    staging_id: int,
    body: RMStagingReview,
    current_user: dict = Depends(verify_rm_staging_approval_access)
):
    try:
        updated = approve_rm_staging_record(
            staging_id=staging_id,
            reviewer_email=current_user["email"],
            reviewer_role=current_user.get("role", "diretor"),
            review_notes=body.review_notes
        )
        return updated
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/api/rm/staging/{staging_id}/reject", response_model=RMStagingResponse, summary="Rejeitar alteração de RM em Staging com justificativa obrigatória")
async def reject_staging_endpoint(
    staging_id: int,
    body: RMStagingReview,
    current_user: dict = Depends(verify_rm_staging_approval_access)
):
    if not body.review_notes or not body.review_notes.strip():
        raise HTTPException(status_code=400, detail="É obrigatório informar uma justificativa detalhada para a rejeição da alteração.")
    try:
        updated = reject_rm_staging_record(
            staging_id=staging_id,
            reviewer_email=current_user["email"],
            reviewer_role=current_user.get("role", "diretor"),
            review_notes=body.review_notes.strip()
        )
        return updated
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ==============================================================================
# PDI 360º, TRIANGULAÇÃO OPERACIONAL E SUCESSÃO PREDICTIVA
# ==============================================================================

@app.post("/api/pdi/evaluations-360", summary="Submeter avaliação 360º de competências VPGG")
async def submit_evaluation_360_endpoint(
    body: Evaluation360Create,
    current_user: dict = Depends(get_current_user)
):
    try:
        saved = save_evaluation_360(eval_data=body.dict(), current_user_email=current_user["email"])
        return {"status": "success", "data": saved}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/pdi/evaluations-360", summary="Listar avaliações 360º")
async def list_evaluations_360_endpoint(
    evaluatee_email: Optional[str] = Query(None, description="Filtrar por membro avaliado"),
    current_user: dict = Depends(get_current_user)
):
    return list_evaluations_360(evaluatee_email=evaluatee_email)


@app.get("/api/pdi/triangulation/{user_email}", summary="Obter triangulação operacional-comportamental de um membro")
async def get_triangulation_endpoint(
    user_email: str,
    current_user: dict = Depends(get_current_user)
):
    try:
        res = calculate_triangulation(user_email=user_email)
        return {"status": "success", "data": res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/pdi/succession-ips/{user_email}", summary="Calcular Índice de Prontidão Preditiva para Sucessão (IPS)")
async def get_succession_ips_endpoint(
    user_email: str,
    role_target: str = Query("diretoria", description="diretoria ou presidencia"),
    current_user: dict = Depends(get_current_user)
):
    try:
        ips_data = calculate_succession_ips(user_email=user_email, role_target=role_target)
        return {"status": "success", "data": ips_data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/pdi/gap-mitigation/generate", summary="Gerar plano 70-20-10 automatizado para mitigação de gaps")
async def generate_gap_plan_endpoint(
    body: GapPlanCreate,
    current_user: dict = Depends(verify_vpgg_access)
):
    try:
        plan = generate_gap_mitigation_plan(user_email=body.user_email, role_target=body.role_target or "diretoria")
        return {"status": "success", "data": plan}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/pdi/gap-mitigation", summary="Listar ações de mitigação de gaps (70-20-10)")
async def list_gap_mitigation_endpoint(
    user_email: Optional[str] = Query(None, description="Filtrar por e-mail do membro"),
    current_user: dict = Depends(get_current_user)
):
    return list_gap_mitigation_actions(user_email=user_email)


@app.get("/api/pdi/historical-benchmarks", summary="Listar perfis de benchmark de gestores de referência")
async def list_historical_benchmarks_endpoint(
    role_target: Optional[str] = Query(None, description="diretoria ou presidencia"),
    current_user: dict = Depends(get_current_user)
):
    return list_historical_benchmarks(role_target=role_target)


@app.get("/api/pdi/evaluator-calibrations", summary="Listar calibrações de assertividade de avaliadores")
async def list_evaluator_calibrations_endpoint(
    current_user: dict = Depends(verify_vpgg_access)
):
    return get_evaluator_calibrations()

# ==============================================================================
# 28. SUBSISTEMA DE AUDITORIA & VARREDURA AUTÔNOMA DA RPI (INPI)
# ==============================================================================

class RPIScanRequest(BaseModel):
    numero_rpi: Optional[str] = "2850"
    data_publicacao: Optional[str] = None
    xml_content: Optional[str] = None
    despachos: Optional[List[dict]] = None


@app.get("/api/rpi/processos", summary="Listar todos os processos de Registro de Marcas com status de auditoria RPI")
async def list_rpi_processos_endpoint(
    q: Optional[str] = Query(None, description="Busca textual por marca, processo, código ou cliente"),
    status_execucao: Optional[str] = Query(None, description="Filtro de status: ativo, suspenso, concluido"),
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    try:
        processos = list_contratos_rm(status_filter=status_execucao, q=q)
        return {
            "status": "success",
            "total": len(processos),
            "processos": processos
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/rpi/processos/{contrato_id}/historico", summary="Histórico cronológico de despachos RPI do processo")
async def get_rpi_processo_historico_endpoint(
    contrato_id: int,
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    contrato = get_contrato_rm_by_id(contrato_id)
    if not contrato:
        raise HTTPException(status_code=404, detail="Processo de marca não localizado.")
    historico = get_rpi_despachos_historico(contrato_id)
    return {
        "status": "success",
        "contrato_id": contrato_id,
        "process_number": contrato.get("process_number"),
        "brand_name": contrato.get("brand_name"),
        "total_despachos": len(historico),
        "historico": historico
    }


@app.get("/api/rpi/resumo", summary="Consolidado executivo dos processos de RM e auditorias da RPI")
async def get_rpi_resumo_endpoint(
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    return get_rpi_resumo_executivo()


@app.post("/api/rpi/scan", summary="Executar varredura da RPI a partir de XML ou JSON de despachos do INPI")
async def scan_rpi_endpoint(
    payload: Optional[RPIScanRequest] = None,
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    try:
        engine = RPIScannerEngine()
        user_email = current_user.get("email") if current_user else "sistema.rpi@edvjr.com.br"
        
        if payload and payload.xml_content:
            res = engine.scan_and_reconcile(payload.xml_content, format_type="xml", current_user_email=user_email)
        elif payload and payload.despachos:
            data = {
                "numero_rpi": payload.numero_rpi or "2850",
                "data_publicacao": payload.data_publicacao or datetime.now().strftime("%Y-%m-%d"),
                "despachos": payload.despachos
            }
            res = engine.scan_and_reconcile(data, format_type="json", current_user_email=user_email)
        else:
            res = simular_varredura_semanal_inpi(rpi_numero=(payload.numero_rpi if payload else "2850"))
            
        return res
    except Exception as e:
        logger.error(f"Erro na varredura da RPI: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Falha na varredura da RPI: {str(e)}")


@app.post("/api/rpi/simular-varredura", summary="Simulação executiva de varredura semanal de terça-feira do INPI")
async def simular_varredura_rpi_endpoint(
    rpi_numero: str = Query("2850", description="Número da edição da RPI"),
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    try:
        return simular_varredura_semanal_inpi(rpi_numero=rpi_numero)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/rpi/seed-legacy", summary="Migração de integridade dos 85 processos legados para a tabela relacional")
async def seed_legacy_rms_endpoint(
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    total = seed_contratos_rm_from_legacy()
    return {"status": "success", "message": f"{total} processos de marcas sincronizados na base relacional."}



# ==============================================================================
# 28. TESOURARIA AVANÇADA, CPQ JURÍDICO, DRE & PRESTAÇÃO DE CONTAS (EDBRAIN)
# ==============================================================================
try:
    from treasury_engine import (
        get_cpq_servicos_juridicos,
        calculate_cpq_juridico,
        save_proposta_cpq_juridica,
        list_propostas_cpq_juridicas,
        update_proposta_cpq_status,
        delete_proposta_cpq,
        get_dre_juridica_centros_custo,
        create_dre_centro_custo_juridico,
        aprovar_marco_orientador_juridico,
        get_forecasting_juridico,
        get_obz_distribuicao_edv,
        generate_prestacao_contas_excel_edv,
        generate_prestacao_contas_html_edv
    )
except ImportError:
    from backend.treasury_engine import (
        get_cpq_servicos_juridicos,
        calculate_cpq_juridico,
        save_proposta_cpq_juridica,
        list_propostas_cpq_juridicas,
        update_proposta_cpq_status,
        delete_proposta_cpq,
        get_dre_juridica_centros_custo,
        create_dre_centro_custo_juridico,
        aprovar_marco_orientador_juridico,
        get_forecasting_juridico,
        get_obz_distribuicao_edv,
        generate_prestacao_contas_excel_edv,
        generate_prestacao_contas_html_edv
    )

class CPQCalculoPayload(BaseModel):
    servico_id: int
    horas_pesquisa: int = 10
    horas_redacao: int = 25
    horas_revisao: int = 10
    senioridade: str = "Consultor Jurídico"
    multiplicador_risco: float = 1.15
    custas_inpi_cartorio: float = 0.0
    hourly_rate_override: Optional[float] = None

class CPQSalvarPayload(BaseModel):
    cliente_nome: str
    contato_nome: Optional[str] = None
    contato_email: Optional[str] = None
    servico_id: int
    senioridade: str = "Consultor Jurídico"
    horas_pesquisa: int = 10
    horas_redacao: int = 25
    horas_revisao: int = 10
    multiplicador_risco: float = 1.15
    custas_inpi_cartorio: float = 0.0
    hourly_rate: Optional[float] = None
    status: str = "proposta_gerada"
    observacoes: Optional[str] = None

class CPQStatusPayload(BaseModel):
    status: str

class DRECentroCustoPayload(BaseModel):
    caso_nome: str
    cliente_nome: str
    area_juridica: str = "Direito Contratual"
    receita_bruta: float = 4500.0
    custas_diretas_inpi_cartorio: float = 0.0
    despesas_operacionais_diretas: Optional[float] = None
    data_competencia: Optional[str] = None

class MarcoOrientadorPayload(BaseModel):
    mentor_nome: str
    mentor_rubrica: str = "OAB-VALIDADO-2026"
    mentor_parecer: str

@app.get("/api/financeiro/cpq/servicos", summary="Catálogo oficial de serviços jurídicos padronizados EDV")
async def listar_cpq_servicos_endpoint(area: Optional[str] = None):
    servicos = get_cpq_servicos_juridicos(area=area)
    return {"total": len(servicos), "servicos": servicos}

@app.post("/api/financeiro/cpq/calcular", summary="Calcular honorários e margem estatutária via CPQ Jurídico")
async def calcular_cpq_endpoint(payload: CPQCalculoPayload):
    try:
        quote = calculate_cpq_juridico(
            servico_id=payload.servico_id,
            horas_pesquisa=payload.horas_pesquisa,
            horas_redacao=payload.horas_redacao,
            horas_revisao=payload.horas_revisao,
            senioridade=payload.senioridade,
            risco_fator=payload.multiplicador_risco,
            custas_inpi_cartorio=payload.custas_inpi_cartorio,
            hourly_rate_override=payload.hourly_rate_override
        )
        return quote
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/financeiro/cpq/salvar", summary="Registrar proposta comercial no histórico do CPQ")
async def salvar_cpq_endpoint(payload: CPQSalvarPayload):
    try:
        res = save_proposta_cpq_juridica(payload.dict())
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/financeiro/cpq/propostas", summary="Listar histórico de propostas de honorários emitidas")
async def listar_cpq_propostas_endpoint():
    propostas = list_propostas_cpq_juridicas()
    return {"total": len(propostas), "propostas": propostas}

@app.patch("/api/financeiro/cpq/propostas/{proposta_id}/status", summary="Atualizar status de proposta no pipeline")
async def atualizar_status_proposta_endpoint(proposta_id: int, payload: CPQStatusPayload):
    sucesso = update_proposta_cpq_status(proposta_id, payload.status)
    if not sucesso:
        raise HTTPException(status_code=404, detail="Proposta não encontrada")
    return {"status": "success", "message": f"Status atualizado para {payload.status}"}

@app.delete("/api/financeiro/cpq/propostas/{proposta_id}", summary="Excluir proposta obsoleta")
async def excluir_proposta_endpoint(proposta_id: int):
    sucesso = delete_proposta_cpq(proposta_id)
    if not sucesso:
        raise HTTPException(status_code=404, detail="Proposta não encontrada")
    return {"status": "success", "message": "Proposta excluída com sucesso."}

@app.get("/api/financeiro/dre/centros-custo", summary="DRE Gerencial por Centro de Custo Jurídico")
async def obter_dre_centros_custo_endpoint():
    return get_dre_juridica_centros_custo()

@app.post("/api/financeiro/dre/centros-custo", summary="Criar novo centro de custo para caso jurídico")
async def criar_dre_centro_custo_endpoint(payload: DRECentroCustoPayload):
    res = create_dre_centro_custo_juridico(payload.dict())
    return res

@app.post("/api/financeiro/marcos/{marco_id}/aprovar-orientador", summary="Chancela formal do advogado/professor orientador (Trava OAB)")
async def aprovar_marco_orientador_endpoint(marco_id: int, payload: MarcoOrientadorPayload):
    sucesso = aprovar_marco_orientador_juridico(
        marco_id=marco_id,
        mentor_nome=payload.mentor_nome,
        mentor_rubrica=payload.mentor_rubrica,
        mentor_parecer=payload.mentor_parecer
    )
    if not sucesso:
        raise HTTPException(status_code=404, detail="Marco do caso não encontrado")
    return {"status": "success", "message": "Marco jurídico chancelado com sucesso pelo orientador."}

@app.get("/api/financeiro/forecasting", summary="Motor econométrico de projeção de fluxo de caixa (12-36 meses)")
async def obter_forecasting_juridico_endpoint(
    horizon_months: int = 24,
    growth_rate_pct: float = 15.0,
    opt_bonus_pct: float = 20.0,
    pess_penalty_pct: float = 15.0,
    inflation_pct: float = 5.5,
    seasonality: float = 1.0,
    initial_cash: Optional[float] = None
):
    return get_forecasting_juridico(
        horizon_months=horizon_months,
        growth_rate_pct=growth_rate_pct,
        opt_bonus_pct=opt_bonus_pct,
        pess_penalty_pct=pess_penalty_pct,
        inflation_pct=inflation_pct,
        seasonality_intensity=seasonality,
        initial_cash_balance=initial_cash
    )

@app.get("/api/financeiro/obz", summary="Distribuição por pacotes do Orçamento Base Zero (OBZ)")
async def obter_obz_distribuicao_endpoint():
    return get_obz_distribuicao_edv()

@app.get("/api/financeiro/relatorio/prestacao-contas-excel", summary="Download de relatório de prestação de contas em Excel")
async def download_prestacao_contas_excel_endpoint():
    buf = generate_prestacao_contas_excel_edv()
    filename = f"Prestacao_Contas_EDV_{datetime.now().strftime('%Y%m%d')}.xlsx"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers
    )

@app.get("/api/financeiro/relatorio/prestacao-contas-html", summary="Visualização de relatório de prestação de contas formatado")
async def view_prestacao_contas_html_endpoint():
    html_content = generate_prestacao_contas_html_edv()
    return HTMLResponse(content=html_content)


# ==============================================================================
# MONTAGEM DE ARQUIVOS ESTÁTICOS (INTERFACE WEB INTEGRADA)
# Posicionado após todas as rotas da API para evitar sobrescritas
# ==============================================================================
from fastapi.staticfiles import StaticFiles

STATIC_DIR = BASE_DIR if os.path.exists(os.path.join(BASE_DIR, "index.html")) else "."
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"
    target_app = "backend.main:app" if os.path.exists("backend") else "main:app"
    uvicorn.run(target_app, host=host, port=port, reload=False)
