"""
EDV Jr. - Camada de Banco de Dados Local (SQLite - Custo Zero)
Armazena credenciais criptografadas e perfis de controle de acesso (RBAC).
"""

import sqlite3
import os
import bcrypt

DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")

MEMBROS_WHITELIST = [
    {"email": "charles.junior@edvjr.com.br", "nome": "Charles", "setor": "Presidência", "cargo": "Presidente Institucional", "role": "ADMIN"},
    {"email": "alice.mizuki@edvjr.com.br", "nome": "Alice Mizuki", "setor": "Projetos / RMs", "cargo": "Assessora de Projetos", "role": "ANALYST"},
    {"email": "alice.ney@edvjr.com.br", "nome": "Alice Ney", "setor": "VPGG", "cargo": "Vice-Presidente de Gestão", "role": "ADMIN"},
    {"email": "alicia.athayde@edvjr.com.br", "nome": "Alicia", "setor": "Marketing", "cargo": "Assessora de Conteúdo", "role": "ANALYST"},
    {"email": "aline.tartaglia@edvjr.com.br", "nome": "Aline", "setor": "Jurídico", "cargo": "Assessora de Contratos", "role": "ANALYST"},
    {"email": "amanda.bede@edvjr.com.br", "nome": "Amanda", "setor": "Projetos / RMs", "cargo": "Assessora de Projetos", "role": "ANALYST"},
    {"email": "karolina.krause@edvjr.com.br", "nome": "Ana Karolina", "setor": "Jurídico", "cargo": "Assessora de Compliance", "role": "ANALYST"},
    {"email": "estevao.coutinho@edvjr.com.br", "nome": "Estevão", "setor": "Comercial", "cargo": "Assessor de Vendas", "role": "ANALYST"},
    {"email": "evelyn.roldi@edvjr.com.br", "nome": "Evelyn", "setor": "Marketing", "cargo": "Diretora de Marketing", "role": "MANAGER"},
    {"email": "gabriel.orienrac@edvjr.com.br", "nome": "Cachorrão (Gabriel)", "setor": "Projetos / RMs", "cargo": "Assessor de Projetos", "role": "ANALYST"},
    {"email": "giulia.moulin@edvjr.com.br", "nome": "Giulia", "setor": "VPGG", "cargo": "Assessora de Gente & Gestão", "role": "ANALYST"},
    {"email": "guilherme.borges@edvjr.com.br", "nome": "Guilherme Borges", "setor": "Comercial", "cargo": "Assessor de Vendas", "role": "ANALYST"},
    {"email": "isadora.epichin@edvjr.com.br", "nome": "Isadora", "setor": "Comercial / Vendas", "cargo": "Diretora Comercial", "role": "MANAGER"},
    {"email": "joaop.lecco@edvjr.com.br", "nome": "Chillibão (João P.)", "setor": "Marketing", "cargo": "Assessor de Criação", "role": "ANALYST"},
    {"email": "marialice.bacelar@edvjr.com.br", "nome": "Maria Alice", "setor": "Comercial", "cargo": "Assessora de Negociação", "role": "ANALYST"},
    {"email": "mariaeduarda.dias@edvjr.com.br", "nome": "Maria Eduarda", "setor": "VPGG", "cargo": "Assessora de Gente & Gestão", "role": "ANALYST"},
    {"email": "maria.teixeira@edvjr.com.br", "nome": "Maria Luyza", "setor": "Jurídico", "cargo": "Assessora de Governança", "role": "ANALYST"},
    {"email": "marina.moretto@edvjr.com.br", "nome": "Marina", "setor": "Tesouraria / CJA", "cargo": "Diretora Financeira", "role": "MANAGER"},
    {"email": "marllon.oliveira@edvjr.com.br", "nome": "Marllon", "setor": "Projetos / RMs", "cargo": "Assessor de Projetos", "role": "ANALYST"},
    {"email": "pedro.barros@edvjr.com.br", "nome": "Pedro Barros", "setor": "Comercial", "cargo": "Assessor de Inbound", "role": "ANALYST"},
    {"email": "renato.moura@edvjr.com.br", "nome": "Renato", "setor": "Projetos / RMs", "cargo": "Assessor de Projetos", "role": "ANALYST"},
    {"email": "samuel.garcia@edvjr.com.br", "nome": "Samuel", "setor": "Comercial / Radar", "cargo": "Assessor de Prospecção", "role": "ANALYST"},
    {"email": "thais.junger@edvjr.com.br", "nome": "Thais", "setor": "Projetos / RMs", "cargo": "Gerente de Registro de Marca", "role": "MANAGER"}
]

DEFAULT_PASSWORD = "edv2026!"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL,
        hashed_password TEXT NOT NULL,
        setor TEXT NOT NULL,
        cargo TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()

    # Preencher automaticamente a base com os 23 membros se estiver vazia
    cursor.execute("SELECT COUNT(*) FROM users;")
    count = cursor.fetchone()[0]

    if count == 0:
        default_hash = bcrypt.hashpw(DEFAULT_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        for m in MEMBROS_WHITELIST:
            cursor.execute("""
            INSERT INTO users (email, nome, hashed_password, setor, cargo, role)
            VALUES (?, ?, ?, ?, ?, ?);
            """, (m["email"], m["nome"], default_hash, m["setor"], m["cargo"], m["role"]))
        conn.commit()
        print(f"[SQLite] Base inicializada com {len(MEMBROS_WHITELIST)} usuários da Whitelist oficial.")
    else:
        print(f"[SQLite] Base de autenticação pronta com {count} usuários.")

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

if __name__ == "__main__":
    init_db()
