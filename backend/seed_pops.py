"""
Script de Inicialização e Injeção do Catálogo Oficial de Tutoriais e POPs Técnicos (EDbrain)
Executa a persistência e atualização dos 8 POPs Oficiais na tabela kb_artigos.
"""
import sys
import os

# Garantir imports corretos independentemente do diretório de chamada
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import seed_official_kb_pops, OFFICIAL_KB_POPS


def main():
    print(f"[*] Iniciando injeção do Catálogo Oficial de POPs Técnicos ({len(OFFICIAL_KB_POPS)} artigos)...")
    res = seed_official_kb_pops()
    print(f"[OK] Injeção concluída com sucesso: {res}")
    print("\nCatálogo Oficial de POPs do EDbrain:")
    for pop in OFFICIAL_KB_POPS:
        print(f"  • [{pop['codigo']}] {pop['titulo']} ({pop['categoria']})")


if __name__ == "__main__":
    main()
