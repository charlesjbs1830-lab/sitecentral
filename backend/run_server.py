"""
EDV Jr. - Script de Inicialização do Backend FastAPI (Custo Zero)
Inicia o servidor na porta 8000 com recarregamento dinâmico.
"""

import os
import sys
import uvicorn

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("=" * 65)
    print("  EDV Jr. - Servidor de Autenticação JWT e RBAC (Custo Zero)")
    print("  Executando em: http://127.0.0.1:8000")
    print("  Documentação Swagger: http://127.0.0.1:8000/docs")
    print("=" * 65)
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
