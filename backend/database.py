"""
EDV Jr. - Camada de Banco de Dados Local (SQLite - Custo Zero)
Armazena credenciais criptografadas, perfis de controle de acesso (RBAC),
transações financeiras e mural de avisos institucionais.
"""

import sqlite3
import os
import bcrypt

DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")

VALID_ROLES = {"presidente", "diretor", "gerente", "assessor"}

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

    # 4. Tabela de Planos de Desenvolvimento Individual (PDI - VPGG)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pdis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        area TEXT NOT NULL DEFAULT 'VPGG',
        objectives TEXT NOT NULL,
        development_ideas TEXT NOT NULL,
        deadline TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'em_andamento',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. Tabela de Follow-up de Clientes e CRM Comercial (Com Atributos Corporativos, Razão Social e Nome Fantasia)
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
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Migração segura de colunas corporativas para bases existentes
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
        "normalized_name": "TEXT"
    }
    for col_name, col_def in new_followup_cols.items():
        if col_name not in existing_followup_cols:
            cursor.execute(f"ALTER TABLE client_followups ADD COLUMN {col_name} {col_def};")

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

if __name__ == "__main__":
    init_db()
