"""
EDV Jr. - Script de Inicialização e Seeding Seguro do Banco de Dados
Garante a injeção da conta de Administrador/Presidência e liderança em PostgreSQL e SQLite,
garantindo acesso corporativo imediato e validação estrita via hash BCrypt.
"""

import sys
import os

# Adicionar diretório pai ao sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, ensure_initial_admin, get_all_users, get_user_by_email, DATABASE_URL

def run_seed():
    print(f"[*] Iniciando Seeding do Banco de Dados...")
    print(f"[*] DATABASE_URL: {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL}")
    
    # 1. Inicializar tabelas e índices
    init_db()
    
    # 2. Assegurar conta Administrador/Presidência
    ensure_initial_admin()
    
    admin_user = get_user_by_email("charles.junior@edvjr.com.br")
    if admin_user:
        print(f"[OK] Conta de Administrador/Presidência verificada com sucesso:")
        print(f"     Email: {admin_user['email']}")
        print(f"     Nome:  {admin_user['nome']}")
        print(f"     Papel: {admin_user['role']}")
        print(f"     Área:  {admin_user['area']}")
    else:
        print("[ERRO] Falha ao verificar conta de Administrador!")
        sys.exit(1)
        
    users = get_all_users()
    print(f"[OK] Total de colaboradores ativos no banco: {len(users)}")
    print("[OK] Seeding concluído com sucesso!")

if __name__ == "__main__":
    run_seed()
