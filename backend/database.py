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

    # 5. Tabela de Follow-up de Clientes e CRM Comercial
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS client_followups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_name TEXT NOT NULL,
        contact_person TEXT,
        status TEXT NOT NULL DEFAULT 'prospeccao' CHECK(status IN ('prospeccao', 'negociacao', 'fechado', 'perdido')),
        interaction_type TEXT,
        notes TEXT,
        next_followup_date TEXT,
        area TEXT NOT NULL DEFAULT 'Comercial',
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
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
