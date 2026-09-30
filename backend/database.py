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
from typing import Any, Optional, List, Dict

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
    if "competency_mej" not in existing_pdi_cols:
        cursor.execute("ALTER TABLE pdis ADD COLUMN competency_mej TEXT DEFAULT 'Gestão';")

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
            
    conn.commit()
    cursor.execute("SELECT COUNT(*) FROM users;")
    total_users = cursor.fetchone()[0]
    print(f"[SQLite] Base inicializada e sincronizada com {total_users} membros no padrão RBAC estrito.")
    conn.close()

def get_user_by_email(email: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?;", (email.lower().strip(),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def get_user_by_id(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def get_all_users():
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
    
    tables = ["users", "transactions", "notices", "pdis", "client_followups", "audit_logs", "campaigns", "psel_candidates", "brand_assets"]
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


if __name__ == "__main__":
    init_db()
