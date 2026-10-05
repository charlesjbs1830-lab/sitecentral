"""
EDV Jr. - Testes de Integração Automatizados (RBAC, Módulo Financeiro e Avisos)
Executa cenários completos de validação conforme a especificação técnica do EDbrain.
"""

import sys
import os
import unittest
from fastapi.testclient import TestClient

# Adicionar diretório backend ao sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, login_rate_limiter
from database import init_db, get_connection, VALID_ROLES, seed_official_kb_pops, OFFICIAL_KB_POPS, seed_contratos_rm_from_legacy

class TestEDbrainRBACAndFinancial(unittest.TestCase):

    def setUp(self):
        login_rate_limiter.reset()
        if hasattr(self, 'client'):
            self.client.cookies.clear()

    def tearDown(self):
        login_rate_limiter.reset()
        if hasattr(self, 'client'):
            self.client.cookies.clear()

    @classmethod
    def setUpClass(cls):
        # Reiniciar banco e carregar whitelist
        init_db()
        conn = get_connection()
        conn.execute("DELETE FROM client_followups;")
        conn.execute("DELETE FROM client_followups_fts;")
        conn.execute("DELETE FROM transactions;")
        conn.execute("DELETE FROM notices;")
        conn.execute("DELETE FROM pdis;")
        conn.execute("DELETE FROM member_pdi_blocks;")
        conn.execute("DELETE FROM forum_respostas;")
        conn.execute("DELETE FROM forum_duvidas;")
        conn.execute("DELETE FROM transacoes_financeiras;")
        conn.execute("DELETE FROM contratos_rm;")
        conn.execute("DELETE FROM leads;")
        conn.execute("DELETE FROM kb_artigos;")
        conn.commit()
        conn.close()
        cls.client = TestClient(app)
        
        # Obter tokens para cada perfil
        cls.tokens = {}
        
        # 1. Presidente: Charles (Presidência)
        res = cls.client.post("/api/auth/login", json={"email": "charles.junior@edvjr.com.br", "password": "edv2026!"})
        assert res.status_code == 200, res.text
        cls.tokens["presidente"] = res.json()["access_token"]
        
        # 2. Diretor: Alice Ney (VPGG)
        res = cls.client.post("/api/auth/login", json={"email": "alice.ney@edvjr.com.br", "password": "edv2026!"})
        assert res.status_code == 200, res.text
        cls.tokens["diretor"] = res.json()["access_token"]
        
        # 3. Gerente: Thais (Projetos)
        res = cls.client.post("/api/auth/login", json={"email": "thais.junger@edvjr.com.br", "password": "edv2026!"})
        assert res.status_code == 200, res.text
        cls.tokens["gerente"] = res.json()["access_token"]
        
        # 4. Assessor Projetos: Alice Mizuki (Projetos)
        res = cls.client.post("/api/auth/login", json={"email": "alice.mizuki@edvjr.com.br", "password": "edv2026!"})
        assert res.status_code == 200, res.text
        cls.tokens["assessor_projetos"] = res.json()["access_token"]
        
        # 5. Assessor Comercial: Estevão (Comercial)
        res = cls.client.post("/api/auth/login", json={"email": "estevao.coutinho@edvjr.com.br", "password": "edv2026!"})
        assert res.status_code == 200, res.text
        cls.tokens["assessor_comercial"] = res.json()["access_token"]
        
        # 6. Assessor VPGG: Giulia (VPGG)
        res = cls.client.post("/api/auth/login", json={"email": "giulia.moulin@edvjr.com.br", "password": "edv2026!"})
        assert res.status_code == 200, res.text
        cls.tokens["assessor_vpgg"] = res.json()["access_token"]

        # 7. Assessor Marketing: Alicia (Marketing)
        res = cls.client.post("/api/auth/login", json={"email": "alicia.athayde@edvjr.com.br", "password": "edv2026!"})
        assert res.status_code == 200, res.text
        cls.tokens["assessor_marketing"] = res.json()["access_token"]

    def test_01_user_schema_and_roles(self):
        """Verifica se o esquema de usuários possui colunas area e role estritas"""
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT area, role FROM users;")
        rows = cursor.fetchall()
        conn.close()
        
        self.assertGreater(len(rows), 0)
        for r in rows:
            self.assertIn(r["role"], VALID_ROLES)
            self.assertTrue(bool(r["area"]))

    def test_02_rbac_area_scope_assessor(self):
        """Assessor só pode lançar na sua própria área. Cross-area deve retornar 403"""
        token = self.tokens["assessor_projetos"]
        
        # Tentativa de lançar em Comercial (deve ser bloqueado)
        payload_invalid = {
            "area": "Comercial",
            "type": "despesa",
            "category": "Material de Escritório",
            "amount": 250.0,
            "description": "Tentativa indevida cross-area"
        }
        res = self.client.post("/finance/transactions", json=payload_invalid, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("Acesso negado", res.json()["detail"])
        
        # Lançar na própria área (Projetos) dentro do teto -> Permitido
        payload_valid = {
            "area": "Projetos",
            "type": "despesa",
            "category": "Taxa INPI",
            "amount": 355.0,
            "description": "Taxa GRU INPI Pedido RM"
        }
        res = self.client.post("/finance/transactions", json=payload_valid, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["area"], "Projetos")
        self.assertEqual(data["amount"], 355.0)

    def test_03_financial_teto_de_alcada_assessor(self):
        """Assessor lançando acima de R$ 1.000,00 deve ser bloqueado por Teto de Alçada (403)"""
        token = self.tokens["assessor_projetos"]
        
        payload_over_limit = {
            "area": "Projetos",
            "type": "despesa",
            "category": "Software",
            "amount": 1250.00,
            "description": "Licença anual de software"
        }
        res = self.client.post("/finance/transactions", json=payload_over_limit, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("Teto de alçada excedido", res.json()["detail"])

    def test_04_leadership_cross_area_and_limits(self):
        """Presidente e Diretor possuem privilégios cross-area e não possuem teto de assessor"""
        # Presidente lançando em Marketing acima de R$ 1.000,00
        token_pres = self.tokens["presidente"]
        res = self.client.post("/finance/transactions", json={
            "area": "Marketing",
            "type": "despesa",
            "category": "Campanha Institucional",
            "amount": 4500.00,
            "description": "Anúncios Meta Ads Q2"
        }, headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["area"], "Marketing")
        self.assertEqual(res.json()["amount"], 4500.00)

        # Diretor (VPGG) lançando receita em Tesouraria
        token_dir = self.tokens["diretor"]
        res = self.client.post("/finance/transactions", json={
            "area": "Tesouraria",
            "type": "receita",
            "category": "Aporte de Projeto",
            "amount": 3200.00,
            "description": "Entrada Contrato Consultoria"
        }, headers={"Authorization": f"Bearer {token_dir}"})
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["area"], "Tesouraria")

        # Gerente de Projetos lançando R$ 2.500,00 em Projetos (permitido na área, sem teto de assessor)
        token_ger = self.tokens["gerente"]
        res = self.client.post("/finance/transactions", json={
            "area": "Projetos",
            "type": "despesa",
            "category": "Honorários Técnicos",
            "amount": 2500.00,
            "description": "Contratação de parecerista externo"
        }, headers={"Authorization": f"Bearer {token_ger}"})
        self.assertEqual(res.status_code, 201)

        # Gerente tentando lançar em outra área (Comercial) -> Bloqueado
        res = self.client.post("/finance/transactions", json={
            "area": "Comercial",
            "type": "despesa",
            "category": "Gasto Comercial",
            "amount": 100.00,
            "description": "Tentativa de gasto fora de escopo"
        }, headers={"Authorization": f"Bearer {token_ger}"})
        self.assertEqual(res.status_code, 403)

    def test_05_notices_posting_permissions(self):
        """Apenas presidente, diretor e gerente podem publicar comunicados no mural"""
        # Assessor tentando publicar -> 403
        token_assessor = self.tokens["assessor_projetos"]
        res = self.client.post("/notices", json={
            "title": "Aviso do Assessor",
            "content": "Tentativa de publicação"
        }, headers={"Authorization": f"Bearer {token_assessor}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("Acesso negado", res.json()["detail"])

        # Gerente publicando comunicado setorial para Projetos -> 201
        token_ger = self.tokens["gerente"]
        res = self.client.post("/notices", json={
            "title": "Reunião Geral de Projetos",
            "content": "Alinhamento das RMs da semana na sexta-feira às 14h.",
            "target_area": "Projetos"
        }, headers={"Authorization": f"Bearer {token_ger}"})
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["target_area"], "Projetos")

        # Diretor publicando comunicado setorial para Comercial -> 201
        token_dir = self.tokens["diretor"]
        res = self.client.post("/notices", json={
            "title": "Meta Comercial Batida",
            "content": "Parabéns ao time comercial pelo fechamento recorde.",
            "target_area": "Comercial"
        }, headers={"Authorization": f"Bearer {token_dir}"})
        self.assertEqual(res.status_code, 201)

        # Presidente publicando comunicado geral (target_area=None) -> 201
        token_pres = self.tokens["presidente"]
        res = self.client.post("/notices", json={
            "title": "Assembleia Geral EDV Jr. 2026",
            "content": "Todos os membros convocados para a AGE na segunda-feira.",
            "target_area": None
        }, headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res.status_code, 201)
        self.assertIsNone(res.json()["target_area"])

    def test_06_notices_filtered_consumption(self):
        """GET /notices deve retornar apenas comunicados globais + comunicados da área do colaborador"""
        token_proj = self.tokens["assessor_projetos"]
        token_com = self.tokens["assessor_comercial"]

        # Assessor de Projetos consulta avisos
        res_proj = self.client.get("/notices", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_proj.status_code, 200)
        notices_proj = res_proj.json()
        titles_proj = [n["title"] for n in notices_proj]
        
        # Deve conter o global e o de Projetos
        self.assertIn("Assembleia Geral EDV Jr. 2026", titles_proj)
        self.assertIn("Reunião Geral de Projetos", titles_proj)
        # NÃO deve conter o exclusivo de Comercial
        self.assertNotIn("Meta Comercial Batida", titles_proj)

        # Assessor de Comercial consulta avisos
        res_com = self.client.get("/notices", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_com.status_code, 200)
        notices_com = res_com.json()
        titles_com = [n["title"] for n in notices_com]
        
        # Deve conter o global e o de Comercial
        self.assertIn("Assembleia Geral EDV Jr. 2026", titles_com)
        self.assertIn("Meta Comercial Batida", titles_com)
        # NÃO deve conter o exclusivo de Projetos
        self.assertNotIn("Reunião Geral de Projetos", titles_com)

    def test_07_self_promotion_shield(self):
        """Verifica se PUT /api/auth/me bloqueia auto-promoção e alteração de área/setor/cargo (403), permitindo apenas nome (200)"""
        token = self.tokens["assessor_projetos"]

        # 1. Tentativa de auto-promover para diretor -> 403 Forbidden
        res = self.client.put("/api/auth/me", json={"role": "diretor"}, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("auto-promoção", res.json()["detail"].lower())

        # 2. Tentativa de alterar própria área para VPGG -> 403 Forbidden
        res = self.client.put("/api/auth/me", json={"area": "VPGG"}, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("alteração de área", res.json()["detail"].lower())

        # 3. Tentativa de alterar cargo próprio -> 403 Forbidden
        res = self.client.put("/api/auth/me", json={"cargo": "Diretor de Projetos"}, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("alteração de cargo", res.json()["detail"].lower())

        # 4. Atualização cadastral legítima (apenas nome) -> 200 OK
        res = self.client.put("/api/auth/me", json={"nome": "Alice Mizuki Updated"}, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["nome"], "Alice Mizuki Updated")
        self.assertEqual(res.json()["role"], "assessor")
        self.assertEqual(res.json()["area"], "Projetos")

    def test_08_admin_hierarchy_control(self):
        """Endpoints /api/admin/users são exclusivos para presidente e diretor (403 para assessores e gerentes)"""
        token_assessor = self.tokens["assessor_projetos"]
        token_gerente = self.tokens["gerente"]
        token_presidente = self.tokens["presidente"]
        token_diretor = self.tokens["diretor"]

        # 1. Assessor tentando listar ou editar membros via admin -> 403
        res = self.client.get("/api/admin/users", headers={"Authorization": f"Bearer {token_assessor}"})
        self.assertEqual(res.status_code, 403)

        res = self.client.put("/api/admin/users/alice.mizuki@edvjr.com.br", json={"cargo": "Consultora"}, headers={"Authorization": f"Bearer {token_assessor}"})
        self.assertEqual(res.status_code, 403)

        # 2. Gerente tentando editar membro via admin -> 403
        res = self.client.put("/api/admin/users/alice.mizuki@edvjr.com.br", json={"cargo": "Consultora"}, headers={"Authorization": f"Bearer {token_gerente}"})
        self.assertEqual(res.status_code, 403)

        # 3. Diretor listando todos os membros -> 200
        res = self.client.get("/api/admin/users", headers={"Authorization": f"Bearer {token_diretor}"})
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)
        self.assertGreater(len(res.json()), 10)

        # 4. Presidente promovendo ou ajustando cargo/setor de membro -> 200
        res = self.client.put("/api/admin/users/alice.mizuki@edvjr.com.br", json={
            "cargo": "Assessora Sênior de Projetos",
            "setor": "Projetos / Patentes"
        }, headers={"Authorization": f"Bearer {token_presidente}"})
        self.assertEqual(res.status_code, 200)
        updated = res.json()
        self.assertEqual(updated["cargo"], "Assessora Sênior de Projetos")
        self.assertEqual(updated["setor"], "Projetos / Patentes")

    def test_09_vpgg_pdi_access_control(self):
        """Módulo VPGG (/vpgg/pdis) restringe leitura e escrita estritamente a VPGG, Presidente e Diretores"""
        token_proj = self.tokens["assessor_projetos"]
        token_vpgg = self.tokens["assessor_vpgg"]
        token_pres = self.tokens["presidente"]
        token_dir = self.tokens["diretor"]

        # 1. Membro fora da VPGG tentando cadastrar PDI -> 403 Forbidden
        pdi_payload = {
            "user_email": "estevao.coutinho@edvjr.com.br",
            "area": "Comercial",
            "objectives": "Desenvolver técnica de negociação consultiva e qualificação",
            "development_ideas": "Estudo de metodologia SPIN Selling e simulações com clientes",
            "deadline": "2026-06-30",
            "status": "em_andamento"
        }
        res = self.client.post("/vpgg/pdis", json=pdi_payload, headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("Acesso negado", res.json()["detail"])

        # 2. Membro fora da VPGG tentando listar PDIs -> 403 Forbidden
        res = self.client.get("/vpgg/pdis", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res.status_code, 403)

        # 3. Assessor de VPGG cadastrando PDI -> 201 Created
        res = self.client.post("/vpgg/pdis", json=pdi_payload, headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res.status_code, 201)
        created_pdi = res.json()
        self.assertEqual(created_pdi["user_email"], "estevao.coutinho@edvjr.com.br")
        self.assertEqual(created_pdi["status"], "em_andamento")
        pdi_id = created_pdi["id"]

        # 4. Assessor de VPGG listando PDIs -> 200 OK
        res = self.client.get("/vpgg/pdis", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res.status_code, 200)
        pdis_list = res.json()
        self.assertTrue(any(p["id"] == pdi_id for p in pdis_list))

        # 5. Diretor (ou Presidente) atualizando status do PDI -> 200 OK
        res = self.client.put(f"/vpgg/pdis/{pdi_id}", json={"status": "concluido"}, headers={"Authorization": f"Bearer {token_dir}"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "concluido")

        # 6. Presidente consultando listagem com filtro -> 200 OK
        res = self.client.get(f"/vpgg/pdis?user_email=estevao.coutinho@edvjr.com.br", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res.status_code, 200)
        self.assertGreater(len(res.json()), 0)

    def test_10_vpgg_pdi_generation_engine_and_analytics(self):
        """Motor de geração de trilhas (/vpgg/pdis/generate) gera planos customizados e estatísticas analíticas"""
        token_proj = self.tokens["assessor_projetos"]
        token_vpgg = self.tokens["assessor_vpgg"]
        token_pres = self.tokens["presidente"]

        # 1. Não-VPGG tentando gerar plano -> 403 Forbidden
        res = self.client.post("/vpgg/pdis/generate", json={
            "member_email": "estevao.coutinho@edvjr.com.br"
        }, headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res.status_code, 403)

        # 2. VPGG gerando plano estruturado para membro comercial -> 200 OK
        res = self.client.post("/vpgg/pdis/generate", json={
            "member_email": "estevao.coutinho@edvjr.com.br",
            "foco_adicional": "Prospecção de Grandes Contas"
        }, headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        
        # Validar métricas consolidadas
        self.assertIn("consolidado_geral", data)
        self.assertIn("total_pdis_cadastrados", data["consolidado_geral"])
        
        # Validar plano sugerido
        plano = data["plano_estruturado_sugerido"]
        self.assertIn("hard_skills_prioritarias", plano)
        self.assertIn("soft_skills_essenciais", plano)
        self.assertIn("acoes_praticas_edv", plano)
        self.assertIn("metas_com_prazos", plano)
        self.assertTrue(any("Prospecção de Grandes Contas" in a for a in plano["acoes_praticas_edv"]))

        # 3. Presidente consultando endpoint analítico -> 200 OK
        res_analytics = self.client.get("/vpgg/pdis/analytics", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_analytics.status_code, 200)
        analytics_data = res_analytics.json()
        self.assertIn("consolidado_geral", analytics_data)
        self.assertIn("distribuicao_status", analytics_data["consolidado_geral"])

    def test_11_crm_followup_creation_and_area_isolation(self):
        """Validação de inserção e isolamento de área (RBAC) no CRM Comercial"""
        token_com = self.tokens["assessor_comercial"]
        token_proj = self.tokens["assessor_projetos"]
        token_pres = self.tokens["presidente"]

        # 1. Assessor Comercial cadastra follow-up legítimo na sua área -> 201 Created
        payload_com = {
            "client_name": "Padaria Alfa Ltda",
            "contact_person": "Carlos Silva",
            "status": "prospeccao",
            "interaction_type": "WhatsApp",
            "notes": "Primeiro contato comercial via Radar e triagem fiscal",
            "next_followup_date": "2026-10-15",
            "area": "Comercial"
        }
        res = self.client.post("/crm/followups", json=payload_com, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["client_name"], "Padaria Alfa Ltda")
        self.assertEqual(data["status"], "prospeccao")
        self.assertEqual(data["area"], "Comercial")
        self.assertTrue(data["id"] > 0)

        # 2. Assessor de Projetos tenta cadastrar lead na área Comercial -> 403 Forbidden
        payload_cross = {
            "client_name": "Empresa Invasora",
            "status": "prospeccao",
            "area": "Comercial"
        }
        res_cross = self.client.post("/crm/followups", json=payload_cross, headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_cross.status_code, 403)
        self.assertIn("Acesso negado", res_cross.json()["detail"])

        # 3. Tentativa de cadastro com status inválido -> 400 Bad Request
        payload_invalid_status = {
            "client_name": "Cliente Teste",
            "status": "desconhecido",
            "area": "Comercial"
        }
        res_inv = self.client.post("/crm/followups", json=payload_invalid_status, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_inv.status_code, 400)

        # 4. Tentativa de cadastro sem nome de cliente -> 400 ou 422
        res_no_name = self.client.post("/crm/followups", json={"client_name": ""}, headers={"Authorization": f"Bearer {token_com}"})
        self.assertIn(res_no_name.status_code, [400, 422])

        # 5. Presidente com privilégio cross-area cadastrando em qualquer setor -> 201 Created
        payload_pres = {
            "client_name": "Holding Delta S.A.",
            "contact_person": "Dra. Renata",
            "status": "negociacao",
            "interaction_type": "Reunião Presencial",
            "notes": "Negociação institucional de parceria",
            "next_followup_date": "2026-10-20",
            "area": "Comercial"
        }
        res_pres = self.client.post("/crm/followups", json=payload_pres, headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_pres.status_code, 201)
        self.assertEqual(res_pres.json()["client_name"], "Holding Delta S.A.")

    def test_12_crm_followup_listing_and_rbac_filtering(self):
        """Validação de listagem filtrada por área no CRM e visão global para liderança"""
        token_com = self.tokens["assessor_comercial"]
        token_proj = self.tokens["assessor_projetos"]
        token_pres = self.tokens["presidente"]

        # 1. Assessor de Projetos cadastra follow-up na sua própria área
        payload_proj = {
            "client_name": "Startup Tech Beta",
            "contact_person": "Lucas",
            "status": "prospeccao",
            "interaction_type": "Email",
            "notes": "Análise de viabilidade técnica de registro de software",
            "next_followup_date": "2026-10-18",
            "area": "Projetos"
        }
        res_p = self.client.post("/crm/followups", json=payload_proj, headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_p.status_code, 201)
        proj_id = res_p.json()["id"]

        # 2. Assessor Comercial lista follow-ups -> deve ver apenas Comercial
        res_com_list = self.client.get("/crm/followups", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_com_list.status_code, 200)
        items_com = res_com_list.json()
        names_com = [item["client_name"] for item in items_com]
        self.assertIn("Padaria Alfa Ltda", names_com)
        self.assertNotIn("Startup Tech Beta", names_com)

        # 3. Assessor de Projetos lista follow-ups -> deve ver apenas Projetos
        res_proj_list = self.client.get("/crm/followups", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_proj_list.status_code, 200)
        items_proj = res_proj_list.json()
        names_proj = [item["client_name"] for item in items_proj]
        self.assertIn("Startup Tech Beta", names_proj)
        self.assertNotIn("Padaria Alfa Ltda", names_proj)

        # 4. Assessor tentando forçar consulta em outra área via query param -> 403 Forbidden
        res_forbidden = self.client.get("/crm/followups?area=Projetos", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_forbidden.status_code, 403)

        # 5. Presidente com visão global -> vê todas as áreas consolidadas
        res_pres_list = self.client.get("/crm/followups", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_pres_list.status_code, 200)
        names_all = [item["client_name"] for item in res_pres_list.json()]
        self.assertIn("Padaria Alfa Ltda", names_all)
        self.assertIn("Startup Tech Beta", names_all)
        self.assertIn("Holding Delta S.A.", names_all)

        # 6. Atualização de status e notas via PUT /crm/followups/{id} -> 200 OK
        res_update = self.client.put(f"/crm/followups/{proj_id}", json={
            "status": "negociacao",
            "notes": "Parecer de anterioridade favorável enviado ao cliente."
        }, headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_update.status_code, 200)
        self.assertEqual(res_update.json()["status"], "negociacao")

        # 7. Assessor de outra área tentando atualizar -> 403 Forbidden
        res_update_forb = self.client.put(f"/crm/followups/{proj_id}", json={
            "status": "perdido"
        }, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_update_forb.status_code, 403)

    def test_13_cnpj_enrichment_and_scoring(self):
        """Valida enriquecimento de CNPJ, Lead Score preditivo e novos atributos corporativos"""
        token_com = self.tokens["assessor_comercial"]

        payload = {
            "client_name": "Indústria Metalúrgica Vitória",
            "contact_person": "Engenheiro Marcos",
            "status": "negociacao",
            "interaction_type": "Reunião",
            "notes": "Interesse em proteção de marca mista e patente industrial",
            "next_followup_date": "2026-10-25",
            "area": "Comercial",
            "cnpj": "33.592.510/0001-54",
            "cnae": "2411-0 - Metalurgia dos metais preciosos",
            "company_size": "DEMAIS",
            "address": "Av. Beira Mar, 1000 - Vitória - ES",
            "estimated_value": 8500.0,
            "tags": "#quente, #indústria, #alta_prioridade"
        }
        res = self.client.post("/crm/followups", json=payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res.status_code, 201)
        lead = res.json()
        self.assertEqual(lead["client_name"], "Indústria Metalúrgica Vitória")
        self.assertEqual(lead["cnpj"], "33.592.510/0001-54")
        self.assertEqual(lead["company_size"], "DEMAIS")
        self.assertEqual(lead["estimated_value"], 8500.0)
        self.assertIn("#quente", lead["tags"])
        # Score ponderado: negociação (70) + porte DEMAIS (15) + agendado (10) + value > 5000 (10) + tags (5) >= 80
        self.assertGreaterEqual(lead["score"], 80)
        self.assertIn("days_stagnant", lead)
        self.assertIn("is_stagnant", lead)

    def test_14_radar_advanced_search_and_filters(self):
        """Valida o endpoint /crm/radar/search com múltiplos filtros compostos e escopo RBAC"""
        token_com = self.tokens["assessor_comercial"]
        token_proj = self.tokens["assessor_projetos"]
        token_pres = self.tokens["presidente"]

        # 1. Filtro por min_score >= 80 no escopo Comercial
        res_high_score = self.client.get("/crm/radar/search?min_score=80&sort_by=score", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_high_score.status_code, 200)
        leads = res_high_score.json()
        self.assertTrue(len(leads) > 0)
        for l in leads:
            self.assertGreaterEqual(l["score"], 80)
            self.assertEqual(l["area"], "Comercial")

        # 2. Filtro por CNAE
        res_cnae = self.client.get("/crm/radar/search?cnae=Metalurgia", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_cnae.status_code, 200)
        cnae_leads = res_cnae.json()
        self.assertTrue(len(cnae_leads) > 0)
        self.assertIn("Indústria Metalúrgica Vitória", [l["client_name"] for l in cnae_leads])

        # 3. Filtro por Tags
        res_tags = self.client.get("/crm/radar/search?tags=quente", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_tags.status_code, 200)
        tag_leads = res_tags.json()
        self.assertTrue(len(tag_leads) > 0)

        # 4. Assessor tentando filtrar área alheia no radar -> 403 Forbidden
        res_forb = self.client.get("/crm/radar/search?area=Projetos", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_forb.status_code, 403)

        # 5. Presidente com visão global -> vê todas as áreas
        res_global = self.client.get("/crm/radar/search?sort_by=score", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_global.status_code, 200)
        all_leads = res_global.json()
        areas = {l["area"] for l in all_leads}
        self.assertIn("Comercial", areas)
        self.assertIn("Projetos", areas)

    def test_15_cnpj_preview_route(self):
        """Valida endpoint de pré-visualização de CNPJ (/crm/radar/cnpj/{cnpj})"""
        token_com = self.tokens["assessor_comercial"]

        # CNPJ com tamanho inválido -> 400
        res_inv = self.client.get("/crm/radar/cnpj/123", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_inv.status_code, 400)
        self.assertIn("14 dígitos", res_inv.json()["detail"])

    def test_16_company_name_normalization(self):
        """Valida a normalização léxica e tratamento de sufixos societários (normalize_company_name)"""
        from utils import normalize_company_name, build_fts5_wildcard_query

        # 1. Remoção de acentos, minúsculas e sufixos societários (LTDA, ME, S/A, etc.)
        self.assertEqual(normalize_company_name("Padaria do Zé LTDA - ME"), "padaria ze")
        self.assertEqual(normalize_company_name("J. S. Alimentos LTDA ME"), "j s alimentos")
        self.assertEqual(normalize_company_name("Comércio e Indústria Silva S/A"), "silva")
        self.assertEqual(normalize_company_name("SUPERMERCADO CENTRAL EIRELI"), "supermercado central")
        self.assertEqual(normalize_company_name("Alpha Tecnologia SLU"), "alpha tecnologia")

        # 2. Injeção de wildcards FTS5
        self.assertEqual(build_fts5_wildcard_query("tec"), "tec*")
        self.assertEqual(build_fts5_wildcard_query("Padaria do Ze"), "padaria* ze*")
        self.assertEqual(build_fts5_wildcard_query("J. S. Alimentos"), "j* s* alimentos*")

    def test_17_fts5_wildcard_search_and_double_index(self):
        """Valida indexação dupla (razao_social e nome_fantasia) e operadores wildcard no Radar FTS5"""
        token_pres = self.tokens["presidente"]

        # Cadastrar lead com Razão Social e Nome Fantasia distintos
        payload = {
            "client_name": "Padaria do Zé",
            "razao_social": "J. S. Alimentos LTDA ME",
            "nome_fantasia": "Padaria do Zé",
            "contact_person": "José Ferreira",
            "status": "prospeccao",
            "area": "Comercial",
            "cnae": "1091-1/01 - Fabricação de produtos de panificação",
            "tags": "#padaria, #panificadora"
        }
        res = self.client.post("/crm/followups", json=payload, headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res.status_code, 201)
        lead = res.json()
        self.assertEqual(lead["razao_social"], "J. S. Alimentos LTDA ME")
        self.assertEqual(lead["nome_fantasia"], "Padaria do Zé")
        self.assertEqual(lead["normalized_name"], "padaria ze")

        # 1. Busca por Nome Fantasia "Padaria do Ze" encontra a empresa
        res_fantasia = self.client.get("/crm/radar/search?search_query=Padaria do Ze", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_fantasia.status_code, 200)
        found_f = res_fantasia.json()
        self.assertTrue(any(l["id"] == lead["id"] for l in found_f))

        # 2. Busca por Razão Social "Alimentos" encontra a mesma empresa
        res_razao = self.client.get("/crm/radar/search?search_query=Alimentos", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_razao.status_code, 200)
        found_r = res_razao.json()
        self.assertTrue(any(l["id"] == lead["id"] for l in found_r))

        # 3. Busca por prefixo wildcard (ex: 'padari' -> 'padari*')
        res_prefix = self.client.get("/crm/radar/search?search_query=padari", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_prefix.status_code, 200)
        found_p = res_prefix.json()
        self.assertTrue(any(l["id"] == lead["id"] for l in found_p))

    def test_18_batch_ingest_public_data_and_deduplication(self):
        """Valida endpoint de importação em lote (/crm/ingest) com deduplicação e enriquecimento"""
        token_pres = self.tokens["presidente"]
        token_com = self.tokens["assessor_comercial"]

        # 1. Ingestão em lote via JSON de dados abertos
        batch_payload = {
            "leads": [
                {
                    "cnpj": "12.345.678/0001-95",
                    "razao_social": "Padaria & Confeitaria Bela Vista Ltda",
                    "nome_fantasia": "Bela Vista Pães",
                    "cnae": "1091 - Panificação",
                    "company_size": "ME",
                    "area": "Comercial",
                    "estimated_value": 3000.0,
                    "tags": "#public_data, #panificacao"
                },
                {
                    "cnpj": "98.765.432/0001-10",
                    "razao_social": "Oficina Mecânica São Cristóvão EIRELI",
                    "nome_fantasia": "Auto Center São Cristóvão",
                    "cnae": "4520 - Reparação de veículos",
                    "company_size": "EPP",
                    "area": "Comercial",
                    "estimated_value": 4500.0,
                    "tags": "#automotivo"
                }
            ]
        }
        res_batch = self.client.post("/crm/ingest", json=batch_payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_batch.status_code, 200)
        data_batch = res_batch.json()
        self.assertEqual(data_batch["status"], "success")
        self.assertEqual(data_batch["total_received"], 2)
        self.assertGreaterEqual(data_batch["inserted"], 2)

        # 2. Deduplicação Automática: Reenvio do mesmo CNPJ com novas notas e valor atualizado
        reingest_payload = {
            "leads": [
                {
                    "cnpj": "12.345.678/0001-95",
                    "contact_person": "Dona Maria",
                    "notes": "Cliente consultado via lista pública da Junta Comercial",
                    "estimated_value": 5000.0,
                    "tags": "#prioridade"
                }
            ]
        }
        res_re = self.client.post("/crm/ingest", json=reingest_payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_re.status_code, 200)
        data_re = res_re.json()
        self.assertEqual(data_re["total_received"], 1)
        self.assertEqual(data_re["updated"], 1)
        self.assertEqual(data_re["inserted"], 0)

        # 3. Deduplicação por Nome Normalizado (mesmo sem CNPJ)
        norm_payload = {
            "leads": [
                {
                    "client_name": "Bela Vista Paes LTDA ME",
                    "notes": "Tentativa de duplicata por variação societária"
                }
            ]
        }
        res_norm = self.client.post("/crm/ingest", json=norm_payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_norm.status_code, 200)
        data_norm = res_norm.json()
        # Deve ter sido atualizado e NÃO duplicado
        self.assertEqual(data_norm["updated"], 1)
        self.assertEqual(data_norm["inserted"], 0)

        # 4. Ingestão via CSV estruturado
        csv_data = "cnpj;razao_social;nome_fantasia;cnae;porte;valor\n55.444.333/0001-22;Distribuidora Capixaba de Bebidas S/A;Capixaba Bebidas;4635;DEMAIS;12000"
        res_csv = self.client.post("/crm/ingest", json={"csv_content": csv_data}, headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_csv.status_code, 200)
        data_csv = res_csv.json()
        self.assertEqual(data_csv["total_received"], 1)
        self.assertGreaterEqual(data_csv["inserted"], 1)

    def test_19_strategy_pe_metrics(self):
        """Valida painel de indicadores estratégicos alinhados ao PE Brasil Júnior 2024-2026"""
        token = self.tokens["assessor_comercial"]
        res = self.client.get("/api/strategy/pe-metrics", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("faturamento_realizado", data)
        self.assertIn("faturamento_meta", data)
        self.assertIn("faturamento_status", data)
        self.assertIn("projetos_alto_impacto_realizados", data)
        self.assertIn("retencao_membros_taxa", data)
        self.assertIn("nps_satisfacao_media", data)
        self.assertIn("alertas_linha_corte", data)
        self.assertIn(data["faturamento_status"], ["on_track", "attention", "off_track"])

    def test_20_pdi_competency_mej(self):
        """Valida persistência e agregação de competências MEJ no módulo de PDI da VPGG"""
        token_vpgg = self.tokens["assessor_vpgg"]
        payload = {
            "user_email": "giulia.moulin@edvjr.com.br",
            "competency_mej": "Liderança",
            "objectives": "Desenvolver postura de liderança servidora em squads",
            "development_ideas": "Conduzir reuniões gerais e leitura do livro Pipeline de Liderança",
            "deadline": "2026-11-30",
            "status": "em_andamento"
        }
        res = self.client.post("/vpgg/pdis", json=payload, headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["competency_mej"], "Liderança")

        # Verifica distribuição na trilha
        res_trail = self.client.get("/vpgg/pdis/analytics", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res_trail.status_code, 200)
        analytics = res_trail.json()
        self.assertIn("distribuicao_competencias_mej", analytics)
        self.assertIn("Liderança", analytics["distribuicao_competencias_mej"])

    def test_21_commercial_pitch_generator(self):
        """Valida geração inteligente de pitches comerciais (WhatsApp, Instagram DM, E-mail e Tese Jurídica)"""
        token_com = self.tokens["assessor_comercial"]
        payload = {
            "client_name": "Padaria e Confeitaria Bella Massa LTDA",
            "cnae": "1091-1/02",
            "company_size": "ME",
            "contact_person": "Silvia",
            "notes": "Marca consolidada no bairro há 10 anos sem registro no INPI"
        }
        res = self.client.post("/crm/pitch/generate", json=payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("whatsapp", data)
        self.assertIn("instagram_dm", data)
        self.assertIn("email_formal", data)
        self.assertIn("tese_juridica", data)
        self.assertIn("9.279/96", data["tese_juridica"])

    def test_22_compliance_pops(self):
        """Valida central de compliance e playbooks operacionais MEJ (POPs)"""
        token = self.tokens["assessor_projetos"]
        res = self.client.get("/api/compliance/pops", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("pops", data)
        pop_codes = [p["code"] for p in data["pops"]]
        self.assertIn("POP-COM-01", pop_codes)
        self.assertIn("POP-PROJ-02", pop_codes)
        self.assertIn("POP-JUR-03", pop_codes)
        self.assertIn("POP-VPGG-04", pop_codes)

    def test_23_impact_report_mej(self):
        """Valida módulo de cálculo e dossiê de impacto gerado com multiplicador 3.5x"""
        token_com = self.tokens["assessor_comercial"]
        
        # Registrar lead fechado com impacto
        lead_payload = {
            "client_name": "Supermercado Popular Capixaba",
            "status": "fechado",
            "area": "Comercial",
            "estimated_value": 4000.0,
            "impact_score": 85,
            "impact_type": "Desenvolvimento Local / Geração de Renda",
            "impact_description": "Blindagem de marca de 30 colaboradores e expansão regional"
        }
        res_lead = self.client.post("/crm/followups", json=lead_payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_lead.status_code, 201)

        # Consulta relatório de impacto
        res_rep = self.client.get("/crm/impact/report", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_rep.status_code, 200)
        rep = res_rep.json()
        self.assertGreaterEqual(rep["contratos_fechados"], 1)
        self.assertGreaterEqual(rep["faturamento_direto"], 4000.0)
        self.assertGreaterEqual(rep["impacto_economico_estimado_mej"], 14000.0) # 4000 * 3.5
        self.assertIn("distribuicao_tipos", rep)

    def test_24_audit_logs_security(self):
        """Valida isolamento forense da trilha de auditoria: Assessor bloqueado (403), Diretoria autorizada"""
        token_assessor = self.tokens["assessor_projetos"]
        token_pres = self.tokens["presidente"]

        # 1. Assessor tenta acessar audit logs -> 403 Forbidden
        res_blocked = self.client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {token_assessor}"})
        self.assertEqual(res_blocked.status_code, 403)

        # 2. Presidente acessa audit logs -> 200 OK
        res_ok = self.client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_ok.status_code, 200)
        data = res_ok.json()
        self.assertIn("logs", data)
        self.assertGreater(data["total"], 0)

        # 3. Exportação de auditoria em CSV
        res_csv = self.client.get("/api/admin/audit-logs/export", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_csv.status_code, 200)
        self.assertIn("text/csv", res_csv.headers["content-type"])
        self.assertIn("ID;Timestamp;Email;Acao", res_csv.text)

    def test_25_sqlite_backup_and_snapshot(self):
        """Valida rotina zero-cost de snapshot atômico e governança de backup no SQLite"""
        token_assessor = self.tokens["assessor_comercial"]
        token_pres = self.tokens["presidente"]

        # 1. Assessor tenta acionar snapshot -> 403 Forbidden
        res_blocked = self.client.post("/api/admin/backup/snapshot", headers={"Authorization": f"Bearer {token_assessor}"})
        self.assertEqual(res_blocked.status_code, 403)

        # 2. Presidente aciona snapshot -> 200 OK
        res_snap = self.client.post("/api/admin/backup/snapshot", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_snap.status_code, 200)
        snap_data = res_snap.json()
        self.assertEqual(snap_data["status"], "success")
        self.assertIn("backup_auth_", snap_data["snapshot"]["filename"])
        self.assertGreater(snap_data["snapshot"]["size_bytes"], 0)

        # 3. Presidente consulta status dos backups
        res_stat = self.client.get("/api/admin/backup/status", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_stat.status_code, 200)
        stat_data = res_stat.json()
        self.assertGreater(stat_data["database"]["total_backups"], 0)

    def test_26_drive_sync_and_status(self):
        """Valida sincronização profunda com Google Drive e endpoint de telemetria /api/drive/status"""
        token_pres = self.tokens["presidente"]

        # 1. Consulta status da conexão com Google Drive
        res_status = self.client.get("/api/drive/status", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_status.status_code, 200)
        status_data = res_status.json()
        self.assertEqual(status_data["status"], "success")
        self.assertIn("drive_connected", status_data)
        self.assertIn("sqlite_records", status_data)

        # 2. Dispara sincronização integral do Google Drive
        res_sync = self.client.post("/api/drive/sync", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_sync.status_code, 200)
        sync_payload = res_sync.json()
        self.assertEqual(sync_payload["status"], "success")
        self.assertIn("data", sync_payload)
        sync_info = sync_payload["data"]
        self.assertGreaterEqual(sync_info.get("rms_total", 0), 80)
        self.assertGreaterEqual(sync_info.get("transacoes_total", 0), 100)
        self.assertGreaterEqual(sync_info.get("leads_crm_total", 0), 600)

        # 3. Consulta dados operacionais protegidos e valida novas coleções
        res_op = self.client.get("/api/data/operational", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_op.status_code, 200)
        op_data = res_op.json()
        self.assertIn("contratos", op_data)
        self.assertIn("selo_ej", op_data)
        self.assertIn("documentos_oficiais", op_data)
        self.assertIn("capacitacoes", op_data)
        self.assertIn("planilhas_drive", op_data)

    def test_27_marketing_campaigns_and_roi_attribution(self):
        """Valida criação de campanhas, métricas automáticas de ROI, CPL, CAC e blindagem RBAC"""
        token_pres = self.tokens["presidente"]
        token_mkt = self.tokens["assessor_marketing"]
        token_proj = self.tokens["assessor_projetos"]

        # 1. Assessor de Projetos tenta criar campanha de Marketing -> 403 Forbidden
        payload_camp = {
            "name": "Campanha Teste Não Autorizada",
            "type": "captacao_projetos",
            "channel": "instagram",
            "budget": 500.0,
            "actual_cost": 250.0,
            "responsible": "Alice Mizuki"
        }
        res_blocked = self.client.post("/api/marketing/campaigns", json=payload_camp, headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_blocked.status_code, 403)

        # 2. Assessora de Marketing cria campanha autorizada -> 201 Created
        payload_valid = {
            "name": "Captação Startups Hub ES 2026",
            "type": "captacao_projetos",
            "channel": "linkedin",
            "status": "ativa",
            "budget": 800.0,
            "actual_cost": 300.0,
            "target_leads": 50,
            "responsible": "Alicia Athayde",
            "description": "Prospecção direcionada a fundadores de startups e empresas de tecnologia."
        }
        res_create = self.client.post("/api/marketing/campaigns", json=payload_valid, headers={"Authorization": f"Bearer {token_mkt}"})
        self.assertEqual(res_create.status_code, 201)
        camp_data = res_create.json()
        camp_id = camp_data["id"]
        self.assertEqual(camp_data["name"], "Captação Startups Hub ES 2026")
        self.assertEqual(camp_data["channel"], "linkedin")
        self.assertEqual(camp_data["actual_cost"], 300.0)
        self.assertIn("roi", camp_data)
        self.assertIn("cpl", camp_data)

        # 3. Qualquer membro autenticado pode consultar campanhas (GET)
        res_list = self.client.get("/api/marketing/campaigns", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_list.status_code, 200)
        campaigns = res_list.json()
        self.assertGreaterEqual(len(campaigns), 1)

        # 4. Consulta dossiê detalhado de ROI
        res_roi = self.client.get(f"/api/marketing/campaigns/{camp_id}/roi", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_roi.status_code, 200)
        roi_resp = res_roi.json()
        self.assertEqual(roi_resp["status"], "success")
        self.assertIn("metricas", roi_resp["data"])
        self.assertIn("detalhe_leads", roi_resp["data"])

        # 5. Atualização de campanha pela Assessora de Marketing -> 200 OK
        res_up = self.client.put(
            f"/api/marketing/campaigns/{camp_id}",
            json={"actual_cost": 450.0, "status": "concluida"},
            headers={"Authorization": f"Bearer {token_mkt}"}
        )
        self.assertEqual(res_up.status_code, 200)
        self.assertEqual(res_up.json()["actual_cost"], 450.0)
        self.assertEqual(res_up.json()["status"], "concluida")

    def test_28_psel_recruitment_funnel_and_rbac(self):
        """Valida funil do Processo Seletivo (Inscrição -> Dinâmica -> Entrevista -> Onboarding) e RBAC"""
        token_com = self.tokens["assessor_comercial"]
        token_vpgg = self.tokens["assessor_vpgg"]
        token_mkt = self.tokens["assessor_marketing"]
        token_pres = self.tokens["presidente"]

        # 1. Assessor Comercial sem permissão tenta listar candidatos -> 403 Forbidden
        res_blocked = self.client.get("/api/marketing/psel/candidates", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_blocked.status_code, 403)

        # 2. VPGG lista candidatos -> 200 OK
        res_vpgg = self.client.get("/api/marketing/psel/candidates", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res_vpgg.status_code, 200)
        self.assertIsInstance(res_vpgg.json(), list)

        # 3. Marketing cadastra novo candidato no funil -> 201 Created
        cand_payload = {
            "name": "Leonardo Da Vinci Junior",
            "email": "leonardo.vinci@email.com",
            "phone": "(27) 99123-4567",
            "course": "Direito",
            "period": "2º Período",
            "stage": "inscricao",
            "target_area": "Projetos",
            "score_dinamica": 9.1,
            "score_entrevista": 9.3,
            "interviewer": "Laura",
            "competency_focus": "Visão Sistêmica",
            "notes": "Candidato proativo com interesse em direito marcário."
        }
        res_cand = self.client.post("/api/marketing/psel/candidates", json=cand_payload, headers={"Authorization": f"Bearer {token_mkt}"})
        self.assertEqual(res_cand.status_code, 201)
        new_cand = res_cand.json()
        cand_id = new_cand["id"]
        self.assertEqual(new_cand["stage"], "inscricao")

        # 4. Transição de estágio: avança para 'dinamica' e depois 'entrevista'
        res_stage = self.client.put(
            f"/api/marketing/psel/candidates/{cand_id}/stage",
            json={"stage": "entrevista", "notes": "Aprovado na dinâmica em grupo com louvor"},
            headers={"Authorization": f"Bearer {token_vpgg}"}
        )
        self.assertEqual(res_stage.status_code, 200)
        self.assertEqual(res_stage.json()["stage"], "entrevista")
        self.assertIn("louvor", res_stage.json()["notes"])

    def test_29_psel_candidate_one_click_onboarding_to_vpgg_and_pdi(self):
        """Valida a migração em 1 clique do candidato aprovado para users e geração de PDI com competência Brasil Júnior"""
        token_vpgg = self.tokens["assessor_vpgg"]

        # 1. Cria candidato específico para o teste de onboarding
        cand_payload = {
            "name": "Mariana Barcellos MEJ",
            "email": "mariana.barcellos@gmail.com",
            "phone": "(27) 99222-3344",
            "course": "Direito",
            "period": "3º Período",
            "stage": "entrevista",
            "target_area": "Comercial",
            "score_dinamica": 9.4,
            "score_entrevista": 9.6,
            "competency_focus": "Orientação para Resultados",
            "notes": "Destaque absoluto em negociação e fit cultural."
        }
        res_cand = self.client.post("/api/marketing/psel/candidates", json=cand_payload, headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res_cand.status_code, 201)
        cand_id = res_cand.json()["id"]

        # 2. Executa a migração em 1 clique para Onboarding
        res_onboard = self.client.post(
            f"/api/marketing/psel/candidates/{cand_id}/approve-and-onboard",
            headers={"Authorization": f"Bearer {token_vpgg}"}
        )
        self.assertEqual(res_onboard.status_code, 200)
        onboard_data = res_onboard.json()
        self.assertEqual(onboard_data["status"], "success")
        self.assertEqual(onboard_data["area"], "Comercial")
        self.assertEqual(onboard_data["competencia_brasil_junior"], "Orientação para Resultados")
        inst_email = onboard_data["email_institucional"]
        self.assertTrue(inst_email.endswith("@edvjr.com.br"))

        # 3. Verifica no SQLite se o usuário foi criado com papel assessor na área Comercial
        conn = get_connection()
        user_row = conn.execute("SELECT email, area, role, cargo FROM users WHERE email = ?;", (inst_email,)).fetchone()
        self.assertIsNotNone(user_row)
        self.assertEqual(user_row["area"], "Comercial")
        self.assertEqual(user_row["role"], "assessor")

        # 4. Verifica no SQLite se o PDI foi criado com competência oficial Brasil Júnior
        pdi_row = conn.execute("SELECT * FROM pdis WHERE id = ?;", (onboard_data["pdi_id"],)).fetchone()
        self.assertIsNotNone(pdi_row)
        self.assertEqual(pdi_row["competency_mej"], "Orientação para Resultados")
        self.assertEqual(pdi_row["user_email"], inst_email)
        self.assertEqual(pdi_row["status"], "em_andamento")
        conn.close()

    def test_30_brand_kit_repository_and_rbac(self):
        """Valida repositório de Brand Kit, visualização por qualquer membro e blindagem de criação/edição"""
        token_proj = self.tokens["assessor_projetos"]
        token_mkt = self.tokens["assessor_marketing"]
        token_pres = self.tokens["presidente"]

        # 1. Qualquer membro pode visualizar os ativos de marca oficiais
        res_assets = self.client.get("/api/marketing/brand-kit", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_assets.status_code, 200)
        assets = res_assets.json()
        self.assertGreaterEqual(len(assets), 1)

        # 2. Assessor de Projetos tenta adicionar novo ativo de marca -> 403 Forbidden
        asset_payload = {
            "title": "Apresentação Não Autorizada",
            "category": "pitch_deck",
            "file_format": "PPTX",
            "file_url": "https://drive.google.com/exemplo"
        }
        res_blocked = self.client.post("/api/marketing/brand-kit", json=asset_payload, headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_blocked.status_code, 403)

        # 3. Assessora de Marketing adiciona novo ativo oficial -> 201 Created
        asset_valid = {
            "title": "Pitch Comercial Registro de Software MEJ 2026",
            "category": "pitch_deck",
            "file_format": "PPTX",
            "version": "v1.0",
            "file_url": "https://drive.google.com/pitch_software_2026",
            "description": "Pitch oficial para venda de registros de programa de computador e contratos de software.",
            "tags": "software, inpi, comercial, pitch",
            "is_official": True
        }
        res_create = self.client.post("/api/marketing/brand-kit", json=asset_valid, headers={"Authorization": f"Bearer {token_mkt}"})
        self.assertEqual(res_create.status_code, 201)
        created_asset = res_create.json()
        asset_id = created_asset["id"]
        self.assertEqual(created_asset["title"], "Pitch Comercial Registro de Software MEJ 2026")

        # 4. Presidente edita o ativo -> 200 OK
        res_edit = self.client.put(
            f"/api/marketing/brand-kit/{asset_id}",
            json={"version": "v1.1", "description": "Atualizado com novas regras INPI 2026"},
            headers={"Authorization": f"Bearer {token_pres}"}
        )
        self.assertEqual(res_edit.status_code, 200)
        self.assertEqual(res_edit.json()["version"], "v1.1")

    def test_31_marketing_dashboard_analytics(self):
        """Valida endpoint analítico consolidado do dashboard de marketing"""
        token_com = self.tokens["assessor_comercial"]
        res = self.client.get("/api/marketing/dashboard", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res.status_code, 200)
        dash_data = res.json()
        self.assertEqual(dash_data["status"], "success")
        data = dash_data["data"]
        self.assertIn("total_campanhas", data)
        self.assertIn("investimento_total", data)
        self.assertIn("roi_global_percentual", data)
        self.assertIn("psel_metricas", data)
        self.assertIn("desempenho_canais", data)
    def test_32_hard_data_vs_soft_data_triangulation_and_evaluator_weights(self):
        """Valida a triangulação de métricas operacionais quantitativas (Hard Data) com avaliações 360º (Soft Data) e calibração de avaliadores"""
        token_vpgg = self.tokens["diretor"]
        token_com = self.tokens["assessor_comercial"]

        # 1. Assessor comercial não tem acesso direto a métricas globais de VPGG -> 403
        res_denied = self.client.get("/api/vpgg/triangulation", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_denied.status_code, 403)

        # 2. Diretora de VPGG acessa triangulação corporativa -> 200 OK
        res = self.client.get("/api/vpgg/triangulation", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res.status_code, 200)
        members = res.json()
        self.assertGreaterEqual(len(members), 20)

        # 3. Valida triangulação de membro específico (Samuel Garcia)
        res_samuel = self.client.get("/api/vpgg/triangulation/samuel.garcia@edvjr.com.br", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res_samuel.status_code, 200)
        data = res_samuel.json()

        # Hard Data extraído do CRM, RMs e Assiduidade
        self.assertIn("hard_data", data)
        hard_scores = data["hard_data"]["scores"]
        self.assertIn("conversion_score", hard_scores)
        self.assertIn("project_punctuality_score", hard_scores)
        self.assertIn("assiduidade_score", hard_scores)
        self.assertIn("overall_hard_score", hard_scores)

        # Soft Data calibrado nas 5 competências oficiais da Brasil Júnior
        soft_scores = data["soft_scores_calibrated"]
        for comp in ["lideranca", "gestao", "visao_sistemica", "orientacao_resultados", "autoconhecimento"]:
            self.assertIn(comp, soft_scores)
            self.assertGreater(soft_scores[comp], 0.0)

        # Triangulação ponderada
        triang = data["triangulated_competencies"]
        for comp in ["lideranca", "gestao", "visao_sistemica", "orientacao_resultados", "autoconhecimento"]:
            self.assertIn(comp, triang)
        self.assertGreater(data["overall_triangulated_score"], 0.0)

    def test_33_evaluations_360_creation_and_brasil_junior_competencies(self):
        """Valida submissão de avaliação 360º oficial, validação de limites de notas e feedback"""
        token_com = self.tokens["assessor_comercial"]

        # 1. Submissão válida por par
        eval_payload = {
            "evaluatee_email": "samuel.garcia@edvjr.com.br",
            "cycle_id": "2026.1",
            "relationship_type": "peer",
            "score_lideranca": 4.2,
            "score_gestao": 3.8,
            "score_visao_sistemica": 4.0,
            "score_orientacao_resultados": 3.9,
            "score_autoconhecimento": 4.1,
            "feedback_qualitativo": "Excelente postura proativa e comunicação clara com a equipe comercial."
        }
        res = self.client.post("/api/vpgg/evaluations-360", json=eval_payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res.status_code, 201)
        created = res.json()
        self.assertEqual(created["evaluatee_email"], "samuel.garcia@edvjr.com.br")
        self.assertEqual(created["relationship_type"], "peer")

        # 2. Rejeição de nota fora da escala 1.0 a 5.0 -> 422 Unprocessable Entity
        invalid_payload = dict(eval_payload)
        invalid_payload["score_lideranca"] = 5.5
        res_invalid = self.client.post("/api/vpgg/evaluations-360", json=invalid_payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_invalid.status_code, 422)

        # 3. Rejeição de membro inexistente -> 404 Not Found
        ghost_payload = dict(eval_payload)
        ghost_payload["evaluatee_email"] = "fantasma@edvjr.com.br"
        res_ghost = self.client.post("/api/vpgg/evaluations-360", json=ghost_payload, headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_ghost.status_code, 404)

    def test_34_succession_predictive_index_ips_and_governance_cutoff(self):
        """Valida o cálculo preditivo do IPS, similaridade com perfil federativo e bloqueio por corte de governança"""
        token_vpgg = self.tokens["diretor"]

        # 1. Cálculo do IPS para Diretoria (linha de corte = 70.0)
        res_dir = self.client.get("/api/vpgg/succession-ips/samuel.garcia@edvjr.com.br?role_target=diretoria", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res_dir.status_code, 200)
        data_dir = res_dir.json()

        self.assertIn("ips_score", data_dir)
        self.assertIn("similarity_to_benchmark", data_dir)
        self.assertEqual(data_dir["cutoff_threshold"], 70.0)
        self.assertGreater(data_dir["similarity_to_benchmark"], 0.8)

        # Como Samuel possui gaps operacionais, IPS < 70 restringe elegibilidade automática
        if data_dir["ips_score"] < 70.0:
            self.assertFalse(data_dir["is_eligible"])
            self.assertEqual(data_dir["status_sucessao"], "Restrição de Governança Ativa")
            self.assertIsNotNone(data_dir["restriction_reason"])
            self.assertIn("abaixo da linha de corte", data_dir["restriction_reason"])

        # 2. Cálculo do IPS para Presidência (linha de corte = 80.0)
        res_pres = self.client.get("/api/vpgg/succession-ips/samuel.garcia@edvjr.com.br?role_target=presidencia", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res_pres.status_code, 200)
        data_pres = res_pres.json()
        self.assertEqual(data_pres["cutoff_threshold"], 80.0)
        self.assertFalse(data_pres["is_eligible"])

    def test_35_gap_mitigation_runtime_action_and_pdi_70_20_10_update(self):
        """Valida detecção preditiva de déficits crônicos e geração de plano 70-20-10 com alocação prática e atualização de PDI"""
        token_vpgg = self.tokens["diretor"]

        # 1. Dispara o mecanismo de mitigação preditiva
        res = self.client.post("/api/vpgg/gap-mitigation/generate/samuel.garcia@edvjr.com.br", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res.status_code, 200)
        plan = res.json()

        self.assertIn("action_plan_70_20_10", plan)
        self.assertIn("mitigation_actions", plan)
        self.assertGreaterEqual(len(plan["mitigation_actions"]), 1)

        plan_text = plan["action_plan_70_20_10"]
        self.assertIn("70% Experiencial (On-the-Job)", plan_text)
        self.assertIn("20% Social (Mentoria)", plan_text)
        self.assertIn("10% Formal (Estudo)", plan_text)

        # 2. Verifica se a alocação prática especifica inserção em projetos complexos ou negociações CRM
        first_action = plan["mitigation_actions"][0]
        self.assertEqual(first_action["action_type"], "70_on_the_job")
        self.assertIsNotNone(first_action["practical_allocation"])

        # 3. Verifica no SQLite se a tabela pdis foi atualizada com o plano 70-20-10
        conn = get_connection()
        pdi_row = conn.execute("SELECT action_plan_70_20_10, status FROM pdis WHERE LOWER(user_email) = 'samuel.garcia@edvjr.com.br' ORDER BY id DESC LIMIT 1;").fetchone()
        self.assertIsNotNone(pdi_row)
        self.assertIsNotNone(pdi_row["action_plan_70_20_10"])
        self.assertEqual(pdi_row["status"], "em_andamento")
        conn.close()

    def test_36_historical_manager_benchmarks_and_rbac_protection(self):
        """Valida consulta de perfis de benchmark federativos (Selo EJ 100%) e proteção RBAC"""
        token_vpgg = self.tokens["diretor"]
        token_proj = self.tokens["assessor_projetos"]

        # 1. Assessor de Projetos tenta acessar benchmarks de gestão -> 403 Forbidden
        res_denied = self.client.get("/api/vpgg/benchmarks", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_denied.status_code, 403)

        # 2. Diretora de VPGG consulta os benchmarks -> 200 OK
        res = self.client.get("/api/vpgg/benchmarks", headers={"Authorization": f"Bearer {token_vpgg}"})
        self.assertEqual(res.status_code, 200)
        benchmarks = res.json()
        self.assertGreaterEqual(len(benchmarks), 2)
        for b in benchmarks:
            self.assertEqual(b["federation_audit_score"], 100.0)
            self.assertIn(b["role_target"], ["diretoria", "presidencia"])

    def test_37_statutes_compliance_crud_and_checklist(self):
        """Valida CRUD de estatutos, Selo EJ (Brasil Júnior) e atualização dinâmica de checklist com recálculo de conformidade"""
        token_pres = self.tokens["presidente"]
        token_proj = self.tokens["assessor_projetos"]

        # 1. Consulta inicial de normas semeadas
        res = self.client.get("/api/compliance/statutes", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res.status_code, 200)
        statutes = res.json()
        self.assertGreaterEqual(len(statutes), 5)
        titles = [s["title"] for s in statutes]
        self.assertTrue(any("Lei Federal nº 13.267" in t for t in titles))
        self.assertTrue(any("Selo EJ 2026" in t for t in titles))

        # 2. Assessor sem permissão tenta criar norma -> 403 Forbidden
        new_statute = {
            "title": "Regulamento Interno de Estágio e Horas Complementares",
            "norm_type": "regimento_interno",
            "version": "v1.0",
            "status": "vigente",
            "effective_date": "2026-03-01",
            "review_deadline": "2026-12-31",
            "responsible_area": "VPGG",
            "responsible_role": "diretor",
            "description": "Regras de computo de horas para a FDV",
            "checklist_items": [
                {"id": "c1", "item": "Validação pela Coordenação de Estágio da FDV", "compliant": True, "notes": "Aprovado em colegiado"},
                {"id": "c2", "item": "Termo de compromisso arquivado", "compliant": False, "notes": "Pendente de assinatura"}
            ]
        }
        res_denied = self.client.post("/api/compliance/statutes", json=new_statute, headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_denied.status_code, 403)

        # 3. Presidência cadastra a norma com sucesso -> 201 Created
        res_created = self.client.post("/api/compliance/statutes", json=new_statute, headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_created.status_code, 201)
        created_statute = res_created.json()
        statute_id = created_statute["id"]
        # Score inicial: 1 de 2 compliant = 50.0%
        self.assertEqual(created_statute["conformity_score"], 50.0)

        # 4. Atualizar checklist marcando segundo item como compliant -> recálculo para 100%
        updated_checklist = [
            {"id": "c1", "item": "Validação pela Coordenação de Estágio da FDV", "compliant": True, "notes": "Aprovado em colegiado"},
            {"id": "c2", "item": "Termo de compromisso arquivado", "compliant": True, "notes": "Assinado digitalmente"}
        ]
        res_patch = self.client.patch(
            f"/api/compliance/statutes/{statute_id}/checklist",
            json={"checklist_items": updated_checklist},
            headers={"Authorization": f"Bearer {token_pres}"}
        )
        self.assertEqual(res_patch.status_code, 200)
        self.assertEqual(res_patch.json()["conformity_score"], 100.0)

        # 5. Excluir norma criada -> 200 OK
        res_del = self.client.delete(f"/api/compliance/statutes/{statute_id}", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_del.status_code, 200)

    def test_38_dynamic_notifications_and_rbac_filtering(self):
        """Valida o motor de notificações dinâmicas com RBAC, varredura ativa de prazos e marcação de leitura"""
        token_com = self.tokens["assessor_comercial"]
        token_pres = self.tokens["presidente"]

        # 1. Dispara varredura ativa de prazos (Deadlines Scanner)
        res_scan = self.client.post("/api/notifications/scan", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_scan.status_code, 200)
        scan_data = res_scan.json()
        self.assertEqual(scan_data["status"], "success")

        # 2. Assessor busca suas notificações -> vê apenas notificações pertinentes
        res_notifs = self.client.get("/api/notifications", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_notifs.status_code, 200)
        notifs = res_notifs.json()
        self.assertIsInstance(notifs, list)
        self.assertTrue(len(notifs) > 0)
        # Notificação global 'ALL' deve ser visível para todos
        self.assertTrue(any(n["recipient_email"] == "ALL" for n in notifs))

        # 3. Marcação individual como lida
        first_notif_id = notifs[0]["id"]
        res_read = self.client.patch(f"/api/notifications/{first_notif_id}/read", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_read.status_code, 200)
        self.assertEqual(res_read.json()["is_read"], 1)

        # 4. Marcar todas como lidas
        res_all_read = self.client.post("/api/notifications/read-all", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_all_read.status_code, 200)
        self.assertIn("marked_read_count", res_all_read.json())

    def test_39_google_calendar_events_and_rfc5545_ics_export(self):
        """Valida agregação de prazos críticos para o Google Calendar e exportação no padrão RFC 5545 (.ics)"""
        token_pres = self.tokens["presidente"]

        # 1. Consulta eventos do calendário
        res_events = self.client.get("/api/calendar/events", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_events.status_code, 200)
        events = res_events.json()
        self.assertGreaterEqual(len(events), 1)

        # Cada evento deve conter URL direta de inclusão no Google Calendar
        first_event = events[0]
        self.assertIn("google_calendar_url", first_event)
        self.assertIn("calendar.google.com/calendar/render?action=TEMPLATE", first_event["google_calendar_url"])

        # 2. Exportação do feed universal RFC 5545 (.ics)
        res_ics = self.client.get("/api/calendar/export.ics")
        self.assertEqual(res_ics.status_code, 200)
        self.assertIn("text/calendar", res_ics.headers.get("content-type", ""))
        ics_text = res_ics.text
        self.assertIn("BEGIN:VCALENDAR", ics_text)
        self.assertIn("BEGIN:VEVENT", ics_text)
        self.assertIn("SUMMARY:", ics_text)
        self.assertIn("END:VCALENDAR", ics_text)

        # 3. Disparo de sincronização
        res_sync = self.client.post("/api/calendar/sync-google", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_sync.status_code, 200)
        self.assertEqual(res_sync.json()["status"], "success")

    def test_40_rm_staging_maker_checker_four_eyes_enforcement(self):
        """Valida esteira de Staging de Marcas, edição indireta e Princípio Maker-Checker (o autor não pode aprovar)"""
        token_maker = self.tokens["assessor_projetos"]
        token_pres_checker = self.tokens["presidente"]

        # 1. Maker submete proposta de alteração de RM para Staging (sem alterar banco oficial diretamente)
        staging_payload = {
            "brand_name": "Cervejaria Artesanal Capixaba",
            "process_number": "938210492",
            "client_name": "Lucas Alvarenga",
            "client_phone": "27999887766",
            "responsible_name": "Alice Mizuki",
            "phase": "Exame Substantivo",
            "operation_type": "UPDATE",
            "original_data": {"phase": "Publicação de Pedido", "brand_name": "Cervejaria Artesanal Capixaba"},
            "proposed_data": {"phase": "Exame Substantivo", "brand_name": "Cervejaria Artesanal Capixaba", "gru_paga": True}
        }
        res_sub = self.client.post("/api/rm/staging", json=staging_payload, headers={"Authorization": f"Bearer {token_maker}"})
        self.assertEqual(res_sub.status_code, 201)
        staged = res_sub.json()
        staging_id = staged["id"]
        self.assertEqual(staged["status"], "pending_review")
        self.assertEqual(staged["applied_to_main_db"], 0)
        self.assertEqual(staged["submitted_by"], "alice.mizuki@edvjr.com.br")

        # 2. O próprio Maker tenta aprovar a própria proposta -> Violação Four-Eyes -> 403 Forbidden
        res_self_approve = self.client.post(
            f"/api/rm/staging/{staging_id}/approve",
            json={"review_notes": "Tentativa indevida de auto-aprovação"},
            headers={"Authorization": f"Bearer {token_maker}"}
        )
        self.assertEqual(res_self_approve.status_code, 403)

        # 3. Assessor comercial tentando aprovar -> 403 Forbidden (não é diretor nem presidente)
        token_com = self.tokens["assessor_comercial"]
        res_assessor_approve = self.client.post(
            f"/api/rm/staging/{staging_id}/approve",
            json={"review_notes": "Aprovação por outro assessor"},
            headers={"Authorization": f"Bearer {token_com}"}
        )
        self.assertEqual(res_assessor_approve.status_code, 403)

        # 4. Checker legítimo (Presidente != Maker) aprova a alteração -> 200 OK
        res_approved = self.client.post(
            f"/api/rm/staging/{staging_id}/approve",
            json={"review_notes": "Aprovado após conferência do protocolo RPI no INPI"},
            headers={"Authorization": f"Bearer {token_pres_checker}"}
        )
        self.assertEqual(res_approved.status_code, 200)
        data_approved = res_approved.json()
        self.assertEqual(data_approved["status"], "approved")
        self.assertEqual(data_approved["applied_to_main_db"], 1)
        self.assertEqual(data_approved["reviewed_by"], "charles.junior@edvjr.com.br")

        # 5. Validação de Audit Log 2.0 com rastreabilidade Maker-Checker
        conn = get_connection()
        audit_row = conn.execute(
            "SELECT * FROM audit_logs WHERE action = 'RM_STAGING_APPROVED' AND details LIKE ? ORDER BY id DESC LIMIT 1;",
            (f"%ID: {staging_id}%",)
        ).fetchone()
        self.assertIsNotNone(audit_row)
        self.assertIn("Maker: alice.mizuki@edvjr.com.br", audit_row["details"])
        self.assertIn("Checker: charles.junior@edvjr.com.br", audit_row["details"])
        conn.close()

    def test_41_rm_staging_rejection_with_justification(self):
        """Valida rejeição de alteração em Staging com obrigatoriedade de justificativa formal"""
        token_maker = self.tokens["assessor_comercial"]
        token_dir = self.tokens["diretor"]

        # 1. Maker submete proposta de RM
        payload = {
            "brand_name": "Café Conilon Prime",
            "process_number": "912345678",
            "client_name": "Fazenda Boa Vista ME",
            "responsible_name": "Estevão Coutinho",
            "phase": "Arquivamento",
            "operation_type": "UPDATE",
            "proposed_data": {"phase": "Arquivamento"}
        }
        res_sub = self.client.post("/api/rm/staging", json=payload, headers={"Authorization": f"Bearer {token_maker}"})
        self.assertEqual(res_sub.status_code, 201)
        staging_id = res_sub.json()["id"]

        # 2. Rejeitar sem justificativa -> 400 Bad Request
        res_no_just = self.client.post(
            f"/api/rm/staging/{staging_id}/reject",
            json={"review_notes": ""},
            headers={"Authorization": f"Bearer {token_dir}"}
        )
        self.assertEqual(res_no_just.status_code, 400)

        # 3. Rejeitar com justificativa fundamentada -> 200 OK
        res_rejected = self.client.post(
            f"/api/rm/staging/{staging_id}/reject",
            json={"review_notes": "Recurso contra arquivamento ainda está dentro do prazo legal de 60 dias (Art. 212 LPI). Manter ativo."},
            headers={"Authorization": f"Bearer {token_dir}"}
        )
        self.assertEqual(res_rejected.status_code, 200)
        self.assertEqual(res_rejected.json()["status"], "rejected")
        self.assertEqual(res_rejected.json()["reviewed_by"], "alice.ney@edvjr.com.br")

    def test_42_login_database_only_bcrypt_validation(self):
        """Valida login estritamente via banco de dados e hash BCrypt sem whitelist de contingência offline"""
        # 1. Login com credenciais válidas do administrador inicial persistido no banco
        res_ok = self.client.post("/api/auth/login", json={"email": "charles.junior@edvjr.com.br", "password": "edv2026!"})
        self.assertEqual(res_ok.status_code, 200)
        data = res_ok.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], "charles.junior@edvjr.com.br")
        self.assertEqual(data["user"]["role"], "presidente")

        # 2. Senha incorreta -> 401 Unauthorized
        res_wrong = self.client.post("/api/auth/login", json={"email": "charles.junior@edvjr.com.br", "password": "wrong_password!"})
        self.assertEqual(res_wrong.status_code, 401)
        self.assertIn("Credenciais corporativas inválidas", res_wrong.json()["detail"])

        # 3. Usuário inexistente -> 401 Unauthorized
        res_none = self.client.post("/api/auth/login", json={"email": "fake.user@edvjr.com.br", "password": "edv2026!"})
        self.assertEqual(res_none.status_code, 401)

    def test_43_httponly_secure_cookie_and_cookie_auth(self):
        """Valida emissão de cookie HttpOnly no login e autenticação transparente via cookie de sessão"""
        # 1. Login emite cookie access_token HttpOnly
        res_login = self.client.post("/api/auth/login", json={"email": "alice.ney@edvjr.com.br", "password": "edv2026!"})
        self.assertEqual(res_login.status_code, 200)
        self.assertIn("access_token", res_login.cookies)
        
        # Inspecionar cabeçalho Set-Cookie para confirmar flag HttpOnly
        set_cookie_header = res_login.headers.get("set-cookie", "")
        self.assertIn("HttpOnly", set_cookie_header)

        # 2. Acesso a rota protegida enviando EXCLUSIVAMENTE o cookie no cliente (sem header Authorization)
        token_val = res_login.cookies.get("access_token")
        cookie_client = TestClient(app, cookies={"access_token": token_val})
        res_cookie_auth = cookie_client.get("/api/auth/me")
        self.assertEqual(res_cookie_auth.status_code, 200)
        me_data = res_cookie_auth.json()
        self.assertEqual(me_data["email"], "alice.ney@edvjr.com.br")

        # 3. Logout invalida o cookie
        res_logout = cookie_client.post("/api/auth/logout")
        self.assertEqual(res_logout.status_code, 200)
        logout_cookie_header = res_logout.headers.get("set-cookie", "")
        self.assertTrue("max-age=0" in logout_cookie_header.lower() or "expires=" in logout_cookie_header.lower())

    def test_44_ip_rate_limiting_brute_force_defense(self):
        """Valida rate limiting por IP na rota de login contra ataques de força bruta (HTTP 429)"""
        login_rate_limiter.reset()

        # 5 tentativas falhas consecutivas com senha errada
        for i in range(5):
            res_fail = self.client.post("/api/auth/login", json={"email": "charles.junior@edvjr.com.br", "password": f"bad_pwd_{i}"})
            self.assertEqual(res_fail.status_code, 401)

        # Na 6ª tentativa, IP deve estar bloqueado (retornando HTTP 429)
        res_blocked = self.client.post("/api/auth/login", json={"email": "charles.junior@edvjr.com.br", "password": "edv2026!"})
        self.assertEqual(res_blocked.status_code, 429)
        self.assertIn("Bloqueio temporário ativo por segurança", res_blocked.json()["detail"])
        self.assertIn("Retry-After", res_blocked.headers)

        # Após reset administrativo ou expiração da janela, o acesso é liberado
        login_rate_limiter.reset()
        res_restored = self.client.post("/api/auth/login", json={"email": "charles.junior@edvjr.com.br", "password": "edv2026!"})
        self.assertEqual(res_restored.status_code, 200)

    def test_45_api_members_dynamic_listing(self):
        """Valida endpoint /api/members para povoamento dinâmico sem expor credenciais nem senhas"""
        token = self.tokens["presidente"]
        res = self.client.get("/api/members", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        members = res.json()
        self.assertIsInstance(members, list)
        self.assertGreaterEqual(len(members), 23)

        # Verificar se nenhum dado sensível (ex: hashed_password) é exposto
        for m in members:
            self.assertIn("email", m)
            self.assertIn("nome", m)
            self.assertNotIn("hashed_password", m)
            self.assertNotIn("password", m)

        # Acesso anônimo deve ser rejeitado com 401
        anon_client = TestClient(app)
        res_anon = anon_client.get("/api/members")
        self.assertEqual(res_anon.status_code, 401)

    def test_46_semantic_nlp_classification_and_intent_filtering(self):
        """Valida camada NLP heurística de classificação semântica (Hard vs Soft Skills) e fator de modulação alpha"""
        from semantic_nlp import SemanticIntentProcessor

        proc = SemanticIntentProcessor(modo_saneamento="adaptive")

        # 1. Foco em Hard Skills (Comercial/Vendas)
        res_hard = proc.processar_foco("fechamento de contratos comerciais, margem de lucro e funil de vendas crm")
        self.assertFalse(res_hard["is_anomalia"])
        self.assertEqual(res_hard["eixo_predominante"], "hard_skills")
        self.assertIn("orientacao_resultados", res_hard["competencias_alvo"])
        self.assertGreaterEqual(res_hard["fator_modulacao_alpha"], 1.20)
        self.assertLessEqual(res_hard["fator_modulacao_alpha"], 1.80)
        self.assertTrue(any(t in res_hard["tokens_detectados"] for t in ["vendas", "contrato", "crm", "margem"]))

        # 2. Foco em Soft Skills (Liderança/Comunicação)
        res_soft = proc.processar_foco("comunicacao assertiva, resolucao de conflitos com a equipe e escuta ativa da lideranca")
        self.assertFalse(res_soft["is_anomalia"])
        self.assertEqual(res_soft["eixo_predominante"], "soft_skills")
        self.assertIn("lideranca", res_soft["competencias_alvo"])
        self.assertGreaterEqual(res_soft["fator_modulacao_alpha"], 1.20)
        self.assertLessEqual(res_soft["fator_modulacao_alpha"], 1.80)
        self.assertTrue(any(t in res_soft["tokens_detectados"] for t in ["comunicacao", "conflito", "lideranca", "equipe"]))

    def test_47_scope_anomaly_filtering_adaptive_vs_restrictive(self):
        """Valida filtro de desvios de escopo/anomalias com exemplo real ('ser o melhor namorado para a dudinha')"""
        token = self.tokens["diretor"]
        target_email = "alice.ney@edvjr.com.br"
        anomalia_texto = "ser o melhor namorado para a dudinha"

        # 1. Modo Adaptativo (Inteligente): deve retornar 200, saneando a intenção para competências corporativas MEJ
        res_adapt = self.client.post(
            "/vpgg/pdis/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "member_email": target_email,
                "foco_adicional": anomalia_texto,
                "sanitization_mode": "adaptive"
            }
        )
        self.assertEqual(res_adapt.status_code, 200)
        data_adapt = res_adapt.json()
        plano_adapt = data_adapt["plano_estruturado_sugerido"]
        analise_adapt = plano_adapt["analise_foco_semantico"]
        
        self.assertTrue(analise_adapt["is_anomalia"])
        self.assertEqual(analise_adapt["status"], "adaptado_inteligente")
        self.assertIn("autoconhecimento", analise_adapt["competencias_alvo"])
        self.assertIsNotNone(analise_adapt["alerta_governanca"])
        self.assertTrue(len(analise_adapt["interpretacao_corporativa"]) > 0)
        # Deve ter gerado micro-blocos válidos
        self.assertGreaterEqual(len(plano_adapt["micro_blocos_selecionados"]), 4)

        # 2. Modo Restritivo: deve rejeitar a anomalia com HTTP 400 Bad Request
        res_restrit = self.client.post(
            "/vpgg/pdis/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "member_email": target_email,
                "foco_adicional": anomalia_texto,
                "sanitization_mode": "restrictive"
            }
        )
        self.assertEqual(res_restrit.status_code, 400)
        detail_msg = res_restrit.json().get("detail", "")
        self.assertIn("Modo Restritivo", detail_msg)
        self.assertIn("desvio de escopo", detail_msg.lower())

        # 3. Modo Restritivo com input corporativo legítimo: deve passar com HTTP 200
        res_legit = self.client.post(
            "/vpgg/pdis/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "member_email": target_email,
                "foco_adicional": "otimizar processos de compliance e auditoria estatutaria da brasil junior",
                "sanitization_mode": "restrictive"
            }
        )
        self.assertEqual(res_legit.status_code, 200)

    def test_48_combinatorial_matrix_urgency_calculation(self):
        """Valida o cálculo dos Vetores G, H, F e da Matriz Combinatória Ponderada (Uc = (0.55*dG + 0.45*dH) * F)"""
        from semantic_nlp import calcular_matriz_combinatoria

        # Cenário: Membro com grande gap em Gestão e baixo gap em Autoconhecimento
        gaps_360 = {
            "lideranca": 1.2,
            "gestao": 2.8,
            "visao_sistemica": 1.0,
            "orientacao_resultados": 1.5,
            "autoconhecimento": 0.4
        }
        hard_data = {
            "pontualidade_sla": 0.50, # Defasagem de SLA afeta Gestão e Orientação a Resultados
            "taxa_conversao_crm": 0.80,
            "assiduidade_rg": 0.95
        }
        analise_foco = {
            "fator_modulacao_alpha": 1.50,
            "competencias_alvo": ["gestao"]
        }

        matriz = calcular_matriz_combinatoria(gaps_360, hard_data, analise_foco)
        scores = matriz["scores_urgencia"]

        # Todas as 5 competências MEJ devem estar presentes
        for comp in ["lideranca", "gestao", "visao_sistemica", "orientacao_resultados", "autoconhecimento"]:
            self.assertIn(comp, scores)
            self.assertGreater(scores[comp], 0)

        # Gestão deve ter o score de urgência mais crítico devido ao gap alto + modulação alpha de 1.5
        self.assertEqual(matriz["competencia_mais_critica"], "gestao")
        self.assertGreater(scores["gestao"], scores["autoconhecimento"])
        self.assertGreater(scores["gestao"], scores["visao_sistemica"])

        # Verificar se as ordenações estão decrescentes
        ordenadas = matriz["competencias_ordenadas"]
        self.assertEqual(ordenadas[0], "gestao")
        self.assertGreaterEqual(scores[ordenadas[0]], scores[ordenadas[1]])

    def test_49_modular_microblocks_assembly_and_uniqueness(self):
        """Valida montagem algorítmica de 4 a 6 micro-blocos cirúrgicos e a garantia de singularidade SHA-256"""
        token = self.tokens["presidente"]

        # Gerar trilha para Presidente (Charles)
        res_charles = self.client.post(
            "/vpgg/pdis/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "member_email": "charles.junior@edvjr.com.br",
                "foco_adicional": "governanca corporativa, articulacao institucional mej e pe 2025"
            }
        )
        self.assertEqual(res_charles.status_code, 200)
        data_charles = res_charles.json()["plano_estruturado_sugerido"]
        blocos_charles = data_charles["micro_blocos_selecionados"]

        # Validação da Assembly Line: entre 4 e 6 micro-blocos
        self.assertGreaterEqual(len(blocos_charles), 4)
        self.assertLessEqual(len(blocos_charles), 6)

        # Validação da estrutura atômica de cada micro-bloco
        for b in blocos_charles:
            self.assertTrue(b["code"].startswith("MB-"))
            self.assertTrue(bool(b["title"]))
            self.assertIn(b["eixo"], ["hard_skills", "soft_skills"])
            self.assertIn("deliverable_format", b)
            self.assertIn("evaluation_metric", b)
            self.assertIn("suggested_deadline_days", b)
            self.assertIn("justificativa_algoritmica", b)

        hash_charles = data_charles["singularidade_hash"]
        self.assertEqual(len(hash_charles), 64) # SHA-256 em hexadecimal tem 64 caracteres

        # Gerar trilha para Assessor Comercial (Estevão) com foco diferente
        res_estevao = self.client.post(
            "/vpgg/pdis/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "member_email": "estevao.coutinho@edvjr.com.br",
                "foco_adicional": "negociacao consultiva b2b e propostas comerciais"
            }
        )
        self.assertEqual(res_estevao.status_code, 200)
        data_estevao = res_estevao.json()["plano_estruturado_sugerido"]
        hash_estevao = data_estevao["singularidade_hash"]

        # Garantia de Singularidade Matemática: hashes devem ser distintos
        self.assertNotEqual(hash_charles, hash_estevao)

    def test_50_pdi_member_execution_trail_generation_and_listing(self):
        """Valida endpoint /api/pdi/trilha/{user_id} para consulta individual, SLAs, dias restantes e hash SHA-256"""
        token_com = self.tokens["assessor_comercial"]
        token_pres = self.tokens["presidente"]

        # 1. Assessor Comercial acessa sua própria trilha via 'me'
        res_me = self.client.get("/api/pdi/trilha/me", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_me.status_code, 200)
        data_me = res_me.json()
        self.assertEqual(data_me["status"], "success")
        self.assertEqual(data_me["user"]["email"], "estevao.coutinho@edvjr.com.br")

        trilha = data_me["trilha"]
        self.assertGreaterEqual(trilha["total_blocos"], 4)
        self.assertLessEqual(trilha["total_blocos"], 6)
        self.assertEqual(trilha["progresso_percentual"], 0.0)
        self.assertEqual(len(trilha["singularidade_hash"]), 64)

        # Validar atributos de cada micro-bloco
        for b in trilha["blocos"]:
            self.assertTrue(b["microblock_code"].startswith("MB-"))
            self.assertTrue(bool(b["title"]))
            self.assertIn(b["eixo"], ["hard_skills", "soft_skills"])
            self.assertIn("sla_days", b)
            self.assertIn("dias_restantes", b)
            self.assertEqual(b["status"], "pendente")
            self.assertTrue(bool(b["justificativa_algoritmica"]))

        # 2. Consulta via ID numérico
        user_id = data_me["user"]["id"]
        res_id = self.client.get(f"/api/pdi/trilha/{user_id}", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_id.status_code, 200)

        # 3. Tentativa de Assessor acessar a trilha de outro membro -> 403 Forbidden
        token_proj = self.tokens["assessor_projetos"]
        res_forbidden = self.client.get(f"/api/pdi/trilha/{user_id}", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_forbidden.status_code, 403)

        # 4. Presidente tem autoridade de visualizar qualquer trilha -> 200 OK
        res_leader = self.client.get(f"/api/pdi/trilha/{user_id}", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_leader.status_code, 200)

    def test_51_pdi_microblock_status_update_and_progress_recalculation(self):
        """Valida transição de status de micro-blocos (PATCH /api/pdi/micro-bloco/{id}) e recálculo dinâmico do avanço percentual"""
        token_com = self.tokens["assessor_comercial"]

        # Obter primeiro bloco da trilha
        res_trilha = self.client.get("/api/pdi/trilha/me", headers={"Authorization": f"Bearer {token_com}"})
        blocos = res_trilha.json()["trilha"]["blocos"]
        bloco_id = blocos[0]["id"]
        total_blocos = len(blocos)

        # 1. Mudar status para 'em_andamento'
        res_andamento = self.client.patch(
            f"/api/pdi/micro-bloco/{bloco_id}",
            headers={"Authorization": f"Bearer {token_com}"},
            json={"status": "em_andamento"}
        )
        self.assertEqual(res_andamento.status_code, 200)
        data_andamento = res_andamento.json()
        self.assertEqual(data_andamento["micro_bloco"]["status"], "em_andamento")
        self.assertEqual(data_andamento["trilha_progresso"]["em_andamento"], 1)

        # 2. Concluir o micro-bloco
        res_concluido = self.client.patch(
            f"/api/pdi/micro-bloco/{bloco_id}",
            headers={"Authorization": f"Bearer {token_com}"},
            json={"status": "concluido"}
        )
        self.assertEqual(res_concluido.status_code, 200)
        data_concluido = res_concluido.json()
        self.assertEqual(data_concluido["micro_bloco"]["status"], "concluido")
        self.assertIsNotNone(data_concluido["micro_bloco"]["completed_at"])
        
        # Validar recálculo percentual matemático
        prog_esperado = round((1 / total_blocos * 100), 1)
        self.assertEqual(data_concluido["trilha_progresso"]["progresso_percentual"], prog_esperado)
        self.assertEqual(data_concluido["trilha_progresso"]["concluidos"], 1)

        # 3. Tentativa de status inválido -> 400 Bad Request
        res_invalido = self.client.patch(
            f"/api/pdi/micro-bloco/{bloco_id}",
            headers={"Authorization": f"Bearer {token_com}"},
            json={"status": "status_inexistente"}
        )
        self.assertEqual(res_invalido.status_code, 400)

    def test_52_forum_duvidas_creation_and_public_feed(self):
        """Valida criação de dúvidas (POST /api/duvidas) e consulta do feed coletivo (GET /api/duvidas)"""
        token_proj = self.tokens["assessor_projetos"]

        # 1. Registrar dúvida
        payload = {
            "title": "Dúvida sobre especificação da classe 35 no INPI",
            "description": "Ao cadastrar processo de registro de marca de contabilidade, devemos usar classe 35 ou 36?",
            "category": "Execução de Serviços/RMs"
        }
        res_post = self.client.post("/api/duvidas", headers={"Authorization": f"Bearer {token_proj}"}, json=payload)
        self.assertEqual(res_post.status_code, 201)
        duvida_criada = res_post.json()["duvida"]
        self.assertEqual(duvida_criada["title"], payload["title"])
        self.assertEqual(duvida_criada["status"], "aberta")
        self.assertIn("Alice Mizuki", duvida_criada["author_name"])
        duvida_id = duvida_criada["id"]

        # 2. Consultar feed público
        res_feed = self.client.get("/api/duvidas", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_feed.status_code, 200)
        feed = res_feed.json()
        self.assertIsInstance(feed, list)
        self.assertTrue(any(d["id"] == duvida_id for d in feed))

        # 3. Filtragem por categoria e busca
        res_cat = self.client.get("/api/duvidas?category=Execução de Serviços/RMs", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_cat.status_code, 200)
        self.assertTrue(all("Serviços" in d["category"] for d in res_cat.json()))

        res_search = self.client.get("/api/duvidas?search=INPI", headers={"Authorization": f"Bearer {token_proj}"})
        self.assertEqual(res_search.status_code, 200)
        self.assertTrue(any("INPI" in d["title"] for d in res_search.json()))

    def test_53_forum_threaded_responses_and_resolution(self):
        """Valida respostas em thread colaborativa (POST /api/duvidas/{id}/respostas) e encerramento/resolução da ocorrência"""
        token_proj = self.tokens["assessor_projetos"]
        token_ger = self.tokens["gerente"]

        # 1. Criar dúvida
        res_post = self.client.post(
            "/api/duvidas",
            headers={"Authorization": f"Bearer {token_proj}"},
            json={
                "title": "Dúvida sobre emissão de nota fiscal de honorários",
                "description": "Qual o código de tributação municipal correto para serviços de consultoria jurídica?",
                "category": "Financeiro"
            }
        )
        self.assertEqual(res_post.status_code, 201)
        duvida_id = res_post.json()["duvida"]["id"]

        # 2. Gerente (Thais) responde a dúvida de Alice
        res_resp = self.client.post(
            f"/api/duvidas/{duvida_id}/respostas",
            headers={"Authorization": f"Bearer {token_ger}"},
            json={"content": "Utilize o código 17.01 da LC 116/03 com retenção simples na fonte conforme o manual da prefeitura."}
        )
        self.assertEqual(res_resp.status_code, 201)
        resposta_data = res_resp.json()["resposta"]
        self.assertEqual(resposta_data["author_name"], "Thais")

        # 3. Verificar que o feed reflete a resposta na thread
        res_feed = self.client.get("/api/duvidas", headers={"Authorization": f"Bearer {token_proj}"})
        duvida_no_feed = next(d for d in res_feed.json() if d["id"] == duvida_id)
        self.assertGreaterEqual(duvida_no_feed["total_respostas"], 1)
        self.assertEqual(duvida_no_feed["respostas"][0]["content"], resposta_data["content"])

        # 4. Autor marca a dúvida como resolvida
        res_resolvida = self.client.patch(
            f"/api/duvidas/{duvida_id}/status",
            headers={"Authorization": f"Bearer {token_proj}"},
            json={"status": "resolvida"}
        )
        self.assertEqual(res_resolvida.status_code, 200)
        self.assertEqual(res_resolvida.json()["duvida"]["status"], "resolvida")

    def test_54_crm_leads_creation_and_validation(self):
        """Valida POST /api/crm/leads para cadastro de oportunidades comerciais com atributos corporativos e CNPJ"""
        token_com = self.tokens["assessor_comercial"]

        # 1. Cadastro com dados válidos
        payload = {
            "client_name": "Cervejaria Artesanal Mestre Álvaro Ltda",
            "cnpj": "14.285.714/0001-99",
            "contact_person": "Bernardo Furtado",
            "contact_email": "bernardo@mestrealvaro.com.br",
            "contact_phone": "(27) 99888-1234",
            "estimated_value": 2800.0,
            "etapa": "prospeccao",
            "responsible": "estevao.coutinho@edvjr.com.br",
            "notes": "Cliente busca proteção de marca de cerveja artesanal na classe 32."
        }
        res = self.client.post("/api/crm/leads", headers={"Authorization": f"Bearer {token_com}"}, json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["status"], "success")
        lead = data["lead"]
        self.assertEqual(lead["client_name"], payload["client_name"])
        self.assertEqual(lead["cnpj"], payload["cnpj"])
        self.assertEqual(lead["estimated_value"], 2800.0)
        self.assertEqual(lead["etapa"], "prospeccao")
        self.assertIsNotNone(lead["id"])

        # 2. Validação: rejeição de etapa inválida (400)
        payload_invalid_etapa = payload.copy()
        payload_invalid_etapa["client_name"] = "Outra Empresa"
        payload_invalid_etapa["etapa"] = "etapa_inexistente"
        res_inv = self.client.post("/api/crm/leads", headers={"Authorization": f"Bearer {token_com}"}, json=payload_invalid_etapa)
        self.assertEqual(res_inv.status_code, 400)

        # 3. Validação: client_name em branco ou ausente (422 ou 400)
        payload_no_name = payload.copy()
        payload_no_name["client_name"] = ""
        res_no_name = self.client.post("/api/crm/leads", headers={"Authorization": f"Bearer {token_com}"}, json=payload_no_name)
        self.assertIn(res_no_name.status_code, [400, 422])

    def test_55_crm_pipeline_panoramic_view_and_metrics(self):
        """Valida GET /api/crm/pipeline retornando o panorama completo do funil nas 6 etapas padronizadas"""
        token_com = self.tokens["assessor_comercial"]

        # Cadastrar leads em diferentes etapas para conferência matemática
        etapas_amostra = [
            ("Alpha Diagnóstico ME", "diagnostico", 2000.0),
            ("Beta Proposta S.A.", "proposta", 3500.0),
            ("Gama Negociação Eireli", "negociacao", 4000.0),
            ("Delta Fechado Ltda", "fechado", 2440.0),
            ("Epsilon Perdido ME", "perdido", 1500.0)
        ]
        for c_name, st, val in etapas_amostra:
            self.client.post(
                "/api/crm/leads",
                headers={"Authorization": f"Bearer {token_com}"},
                json={"client_name": c_name, "etapa": st, "estimated_value": val}
            )

        res = self.client.get("/api/crm/pipeline", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")

        # Assegurar que as 6 etapas exigidas estão presentes no retorno estruturado
        etapas = data["etapas"]
        for etapa_esperada in ["prospeccao", "diagnostico", "proposta", "negociacao", "fechado", "perdido"]:
            self.assertIn(etapa_esperada, etapas)
            self.assertIsInstance(etapas[etapa_esperada], list)

        # Conferir métricas agregadas
        self.assertGreaterEqual(data["total_leads_count"], 5)
        self.assertGreater(data["total_pipeline_value"], 0.0)
        self.assertGreater(data["total_fechado_value"], 0.0)
        self.assertIn("conversion_rate", data)
        self.assertGreater(data["conversion_rate"], 0.0)

    def test_56_crm_lead_stage_transition_and_patch(self):
        """Valida PATCH /api/crm/leads/{lead_id} para transição ágil de estágios no funil e regras de integridade"""
        token_com = self.tokens["assessor_comercial"]

        # Criar lead inicial em 'prospeccao'
        res_post = self.client.post(
            "/api/crm/leads",
            headers={"Authorization": f"Bearer {token_com}"},
            json={"client_name": "Startup Logix Tech", "estimated_value": 3000.0, "etapa": "prospeccao"}
        )
        lead_id = res_post.json()["lead"]["id"]

        # 1. Transicionar de prospeccao para diagnostico
        res_patch1 = self.client.patch(
            f"/api/crm/leads/{lead_id}",
            headers={"Authorization": f"Bearer {token_com}"},
            json={"etapa": "diagnostico"}
        )
        self.assertEqual(res_patch1.status_code, 200)
        self.assertEqual(res_patch1.json()["lead"]["etapa"], "diagnostico")

        # 2. Transicionar para proposta com ajuste de valor
        res_patch2 = self.client.patch(
            f"/api/crm/leads/{lead_id}",
            headers={"Authorization": f"Bearer {token_com}"},
            json={"etapa": "proposta", "estimated_value": 3200.0}
        )
        self.assertEqual(res_patch2.status_code, 200)
        self.assertEqual(res_patch2.json()["lead"]["etapa"], "proposta")
        self.assertEqual(res_patch2.json()["lead"]["estimated_value"], 3200.0)

        # 3. Transicionar para negociacao e depois fechado
        self.client.patch(f"/api/crm/leads/{lead_id}", headers={"Authorization": f"Bearer {token_com}"}, json={"etapa": "negociacao"})
        res_fechado = self.client.patch(f"/api/crm/leads/{lead_id}", headers={"Authorization": f"Bearer {token_com}"}, json={"etapa": "fechado"})
        self.assertEqual(res_fechado.status_code, 200)
        self.assertEqual(res_fechado.json()["lead"]["etapa"], "fechado")

        # 4. Transição inválida -> 400
        res_inv = self.client.patch(f"/api/crm/leads/{lead_id}", headers={"Authorization": f"Bearer {token_com}"}, json={"etapa": "etapa_falsa"})
        self.assertEqual(res_inv.status_code, 400)

        # 5. Lead inexistente -> 404
        res_404 = self.client.patch("/api/crm/leads/999999", headers={"Authorization": f"Bearer {token_com}"}, json={"etapa": "diagnostico"})
        self.assertEqual(res_404.status_code, 404)

    def test_57_crm_contratos_rm_foreign_key_and_tracking(self):
        """Valida integridade de chave estrangeira entre leads e contratos_rm, marcos financeiros e status de execução"""
        token_com = self.tokens["assessor_comercial"]
        token_pres = self.tokens["presidente"]

        # Criar lead fechado
        res_lead = self.client.post(
            "/api/crm/leads",
            headers={"Authorization": f"Bearer {token_com}"},
            json={
                "client_name": "BioNatur Cosméticos Sustentáveis Ltda",
                "cnpj": "23.456.789/0001-01",
                "contact_person": "Gisela Duarte",
                "estimated_value": 3660.0,
                "etapa": "fechado"
            }
        )
        lead_id = res_lead.json()["lead"]["id"]

        # 1. Tentar criar contrato com lead_id inexistente -> 404/400
        res_fk_invalida = self.client.post(
            "/api/crm/contratos",
            headers={"Authorization": f"Bearer {token_pres}"},
            json={
                "lead_id": 888888,
                "brand_name": "BIONATUR",
                "consultoria_escopo": "Registro de Marca INPI"
            }
        )
        self.assertEqual(res_fk_invalida.status_code, 404)

        # 2. Criar contrato válido vinculado ao lead fechado
        contrato_payload = {
            "lead_id": lead_id,
            "brand_name": "BIONATUR ORGÂNICOS",
            "client_name": "BioNatur Cosméticos Sustentáveis Ltda",
            "cnpj": "23.456.789/0001-01",
            "consultoria_escopo": "Assessoria e depósito de pedido de registro de marca mista perante o INPI na classe 03 (cosméticos e perfumaria).",
            "prazo_dias": 60,
            "valor_total": 3660.0,
            "marcos_financeiros": [
                {"parcela": 1, "valor": 1830.0, "vencimento": "2026-10-20", "status": "pago"},
                {"parcela": 2, "valor": 1830.0, "vencimento": "2026-11-20", "status": "pendente"}
            ],
            "status_execucao": "ativo",
            "responsavel_tecnico": "thais.junger@edvjr.com.br"
        }
        res_contrato = self.client.post(
            "/api/crm/contratos",
            headers={"Authorization": f"Bearer {token_pres}"},
            json=contrato_payload
        )
        self.assertEqual(res_contrato.status_code, 201)
        contrato_data = res_contrato.json()["contrato"]
        contrato_id = contrato_data["id"]
        self.assertEqual(contrato_data["lead_id"], lead_id)
        self.assertEqual(contrato_data["brand_name"], "BIONATUR ORGÂNICOS")
        self.assertEqual(contrato_data["status_execucao"], "ativo")

        # 3. Listagem do Painel de Contratos
        res_list = self.client.get("/api/crm/contratos", headers={"Authorization": f"Bearer {token_com}"})
        self.assertEqual(res_list.status_code, 200)
        contratos_lista = res_list.json()["contratos"]
        self.assertTrue(any(c["id"] == contrato_id for c in contratos_lista))

        # 4. Atualizar status de execução do contrato (ativo -> concluido)
        res_st = self.client.patch(
            f"/api/crm/contratos/{contrato_id}/status",
            headers={"Authorization": f"Bearer {token_pres}"},
            json={"status": "concluido"}
        )
        self.assertEqual(res_st.status_code, 200)
        self.assertEqual(res_st.json()["contrato"]["status_execucao"], "concluido")

    def test_58_juridico_gerar_contrato_data_injection_and_hash_watermark(self):
        """Valida POST /api/juridico/gerar-contrato com injeção automática de dados cadastrais, Lei 13.267/2016 e marca d'água SHA-256"""
        token_com = self.tokens["assessor_comercial"]

        # Criar lead corporativo
        res_lead = self.client.post(
            "/api/crm/leads",
            headers={"Authorization": f"Bearer {token_com}"},
            json={
                "client_name": "Mundial Logística & Transportes S.A.",
                "cnpj": "11.222.333/0001-44",
                "contact_person": "Dra. Renata Vasconcelos",
                "contact_email": "renata@mundiallog.com.br",
                "contact_phone": "(27) 99876-5432",
                "estimated_value": 4880.0,
                "etapa": "negociacao"
            }
        )
        lead_id = res_lead.json()["lead"]["id"]

        # 1. Gerar contrato a partir do lead
        req_body = {
            "lead_id": lead_id,
            "modelo": "prestacao_servicos_rm",
            "condicoes_pagamento": "Entrada de 50% no ato e 50% após o protocolo inicial perante o INPI."
        }
        res_doc = self.client.post("/api/juridico/gerar-contrato", headers={"Authorization": f"Bearer {token_com}"}, json=req_body)
        self.assertEqual(res_doc.status_code, 200)
        doc = res_doc.json()

        # Validações estruturais e cadastrais
        self.assertEqual(doc["status"], "success")
        self.assertEqual(doc["client_name"], "Mundial Logística & Transportes S.A.")
        self.assertEqual(doc["cnpj"], "11.222.333/0001-44")
        self.assertEqual(doc["valor_total"], 4880.0)

        # Exatidão da injeção de dados no corpo do documento
        md_text = doc["documento_markdown"]
        html_text = doc["documento_html"]
        self.assertIn("MUNDIAL LOGÍSTICA & TRANSPORTES S.A.", md_text)
        self.assertIn("11.222.333/0001-44", md_text)
        self.assertIn("Dra. Renata Vasconcelos", md_text)
        self.assertIn("Lei Federal nº 13.267/2016", md_text)
        self.assertIn("Vitória, Estado do Espírito Santo", md_text)

        # Marca d'água formal e hash SHA-256 de integridade
        marca_dagua = doc["marca_dagua"]
        hash_integ = doc["hash_integridade"]
        self.assertIn("DOCUMENTO OFICIAL EDV JR.", marca_dagua)
        self.assertIn("REGISTRADO SOB LEI 13.267/2016", marca_dagua)
        self.assertEqual(len(hash_integ), 64)
        self.assertIn(hash_integ, marca_dagua)
        self.assertIn(hash_integ, md_text)
        self.assertIn(hash_integ, html_text)

    def test_59_financeiro_transacoes_creation_and_contract_link(self):
        """Valida lançamento de receitas e despesas com validações e vínculo relacional com contratos_rm"""
        token = self.tokens["presidente"]

        # 1. Obter um contrato de RM existente ou criar um
        res_contratos = self.client.get("/api/crm/contratos", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_contratos.status_code, 200)
        contratos = res_contratos.json().get("contratos", [])
        if not contratos:
            res_lead = self.client.post("/api/crm/leads", headers={"Authorization": f"Bearer {token}"}, json={
                "client_name": "Empresa Teste RM",
                "estimated_value": 2440.0,
                "etapa": "fechado"
            })
            lead_id = res_lead.json()["lead"]["id"]
            res_c = self.client.post("/api/crm/contratos", headers={"Authorization": f"Bearer {token}"}, json={
                "lead_id": lead_id,
                "brand_name": "MARCA TESTE",
                "consultoria_escopo": "Registro de Marca INPI",
                "valor_total": 2440.0
            })
            contrato_id = res_c.json()["contrato"]["id"]
        else:
            contrato_id = contratos[0]["id"]

        # 2. Lançar Receita vinculada ao contrato
        payload_rec = {
            "tipo": "receita",
            "categoria": "consultoria_rm",
            "descricao": "Parcela 1/2 Consultoria Registro de Marca INPI",
            "valor": 1220.0,
            "data_vencimento": "2026-10-15",
            "status": "pago",
            "contrato_id": contrato_id
        }
        res_rec = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json=payload_rec)
        self.assertEqual(res_rec.status_code, 201)
        data_rec = res_rec.json()
        self.assertEqual(data_rec["status"], "success")
        self.assertEqual(data_rec["data"]["tipo"], "receita")
        self.assertEqual(data_rec["data"]["valor"], 1220.0)
        self.assertEqual(data_rec["data"]["contrato_id"], contrato_id)
        self.assertEqual(data_rec["data"]["status"], "pago")
        self.assertIsNotNone(data_rec["data"]["data_pagamento"])

        # 3. Lançar Despesa avulsa sem contrato
        payload_desp = {
            "tipo": "despesa",
            "categoria": "infraestrutura",
            "descricao": "Renovação Servidor Cloud EDbrain",
            "valor": 250.0,
            "data_vencimento": "2026-10-25",
            "status": "pendente"
        }
        res_desp = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json=payload_desp)
        self.assertEqual(res_desp.status_code, 201)
        data_desp = res_desp.json()["data"]
        self.assertEqual(data_desp["tipo"], "despesa")
        self.assertEqual(data_desp["valor"], 250.0)
        self.assertIsNone(data_desp["contrato_id"])
        self.assertEqual(data_desp["status"], "pendente")

        # 4. Validações Impeditivas:
        # 4.1 Valor negativo ou zero
        res_invalid_val = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json={
            "tipo": "receita",
            "categoria": "consultoria_rm",
            "descricao": "Valor zero inválido",
            "valor": 0.0,
            "data_vencimento": "2026-10-15"
        })
        self.assertIn(res_invalid_val.status_code, [400, 422])

        # 4.2 Tipo inválido
        res_invalid_type = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json={
            "tipo": "emprestimo",
            "categoria": "consultoria_rm",
            "descricao": "Tipo inválido",
            "valor": 100.0,
            "data_vencimento": "2026-10-15"
        })
        self.assertEqual(res_invalid_type.status_code, 400)

        # 4.3 Contrato ID inexistente
        res_invalid_contrato = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json={
            "tipo": "receita",
            "categoria": "consultoria_rm",
            "descricao": "Contrato inexistente",
            "valor": 500.0,
            "data_vencimento": "2026-10-15",
            "contrato_id": 99999
        })
        self.assertEqual(res_invalid_contrato.status_code, 404)

    def test_60_financeiro_transacoes_listing_and_filters(self):
        """Valida listagem de transações financeiras e filtros por tipo, status, categoria e período"""
        token = self.tokens["presidente"]

        # Listagem completa
        res = self.client.get("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        todas = res.json()
        self.assertIsInstance(todas, list)
        if len(todas) < 2:
            self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json={
                "tipo": "receita", "categoria": "consultoria_rm", "descricao": "Rec Test 60 EDbrain", "valor": 500.0, "data_vencimento": "2026-10-10", "status": "pago"
            })
            self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json={
                "tipo": "despesa", "categoria": "infraestrutura", "descricao": "Desp Test 60 EDbrain", "valor": 150.0, "data_vencimento": "2026-10-15", "status": "pendente"
            })
            res = self.client.get("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"})
            todas = res.json()
        self.assertGreaterEqual(len(todas), 2)

        # Filtro por tipo=receita
        res_rec = self.client.get("/api/financeiro/transacoes?tipo=receita", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_rec.status_code, 200)
        for r in res_rec.json():
            self.assertEqual(r["tipo"], "receita")

        # Filtro por tipo=despesa
        res_desp = self.client.get("/api/financeiro/transacoes?tipo=despesa", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_desp.status_code, 200)
        for d in res_desp.json():
            self.assertEqual(d["tipo"], "despesa")

        # Filtro por status=pago
        res_pagos = self.client.get("/api/financeiro/transacoes?status=pago", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_pagos.status_code, 200)
        for p in res_pagos.json():
            self.assertEqual(p["status"], "pago")

        # Filtro por busca textual
        res_busca = self.client.get("/api/financeiro/transacoes?busca=EDbrain", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_busca.status_code, 200)
        self.assertGreaterEqual(len(res_busca.json()), 1)

    def test_61_financeiro_transacoes_status_update_quittance(self):
        """Valida quitação de transações via PATCH, gravação de data de pagamento e erros para IDs inexistentes"""
        token = self.tokens["presidente"]

        # 1. Criar transação pendente
        payload = {
            "tipo": "receita",
            "categoria": "consultoria_rm",
            "descricao": "Honorários para teste de quitação",
            "valor": 1500.0,
            "data_vencimento": "2026-10-20",
            "status": "pendente"
        }
        res_create = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json=payload)
        tx_id = res_create.json()["data"]["id"]

        # 2. Dar baixa / quitar
        res_patch = self.client.patch(f"/api/financeiro/transacoes/{tx_id}/status", headers={"Authorization": f"Bearer {token}"}, json={
            "status": "pago",
            "data_pagamento": "2026-10-18"
        })
        self.assertEqual(res_patch.status_code, 200)
        updated = res_patch.json()["data"]
        self.assertEqual(updated["status"], "pago")
        self.assertEqual(updated["data_pagamento"], "2026-10-18")

        # 3. Cancelar transação
        res_cancel = self.client.patch(f"/api/financeiro/transacoes/{tx_id}/status", headers={"Authorization": f"Bearer {token}"}, json={
            "status": "cancelado"
        })
        self.assertEqual(res_cancel.status_code, 200)
        self.assertEqual(res_cancel.json()["data"]["status"], "cancelado")

        # 4. Transação inexistente retorna 404
        res_404 = self.client.patch("/api/financeiro/transacoes/99999/status", headers={"Authorization": f"Bearer {token}"}, json={
            "status": "pago"
        })
        self.assertEqual(res_404.status_code, 404)

        # 5. Status inválido retorna 400
        res_inv = self.client.patch(f"/api/financeiro/transacoes/{tx_id}/status", headers={"Authorization": f"Bearer {token}"}, json={
            "status": "liquidado_indevido"
        })
        self.assertEqual(res_inv.status_code, 400)

    def test_62_financeiro_kpis_realtime_calculation(self):
        """Valida recálculo dinâmico de KPIs de caixa, valores do mês e índice percentual de inadimplência"""
        token = self.tokens["presidente"]

        # Obter KPIs atuais
        res_kpis = self.client.get("/api/financeiro/kpis", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_kpis.status_code, 200)
        kpis = res_kpis.json()

        # Validar estrutura de chaves exigidas
        self.assertIn("saldo_caixa", kpis)
        self.assertIn("total_receber_mes", kpis)
        self.assertIn("total_pagar_mes", kpis)
        self.assertIn("taxa_inadimplencia", kpis)
        self.assertIn("total_receitas_atrasadas", kpis)

        # Criar transação vencida não paga (atrasada) para aferir taxa de inadimplência > 0
        res_atraso = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token}"}, json={
            "tipo": "receita",
            "categoria": "consultoria_rm",
            "descricao": "Parcela com atraso proposital para teste de inadimplência",
            "valor": 1000.0,
            "data_vencimento": "2026-07-01",
            "status": "atrasado"
        })
        self.assertEqual(res_atraso.status_code, 201)

        # Recalcular KPIs
        res_kpis2 = self.client.get("/api/financeiro/kpis", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_kpis2.status_code, 200)
        kpis2 = res_kpis2.json()

        # Inadimplência deve ser positiva e refletir os recebíveis atrasados
        self.assertGreater(kpis2["taxa_inadimplencia"], 0.0)
        self.assertGreaterEqual(kpis2["total_receitas_atrasadas"], 1000.0)
        self.assertEqual(kpis2["saldo_caixa"], round(kpis2["total_receitas_pagas"] - kpis2["total_despesas_pagas"], 2))

    def test_63_executivo_bi_rbac_protection(self):
        """Valida que o endpoint de BI executivo é estritamente protegido por RBAC (401 sem token, 403 para assessor e gerente, 200 para diretor e presidente)"""
        # 1. Sem autenticação (deve retornar 401)
        res_no_auth = self.client.get("/api/executivo/kpis-consolidados")
        self.assertEqual(res_no_auth.status_code, 401)

        # 2. Perfil Assessor Comercial (deve retornar 403)
        token_assessor_com = self.tokens["assessor_comercial"]
        res_assessor_com = self.client.get("/api/executivo/kpis-consolidados", headers={"Authorization": f"Bearer {token_assessor_com}"})
        self.assertEqual(res_assessor_com.status_code, 403)
        self.assertIn("Acesso negado", res_assessor_com.json()["detail"])

        # 3. Perfil Assessor Projetos (deve retornar 403)
        token_assessor_proj = self.tokens["assessor_projetos"]
        res_assessor_proj = self.client.get("/api/executivo/kpis-consolidados", headers={"Authorization": f"Bearer {token_assessor_proj}"})
        self.assertEqual(res_assessor_proj.status_code, 403)
        self.assertIn("Acesso negado", res_assessor_proj.json()["detail"])

        # 4. Perfil Gerente (deve retornar 403)
        token_gerente = self.tokens["gerente"]
        res_gerente = self.client.get("/api/executivo/kpis-consolidados", headers={"Authorization": f"Bearer {token_gerente}"})
        self.assertEqual(res_gerente.status_code, 403)
        self.assertIn("Acesso negado", res_gerente.json()["detail"])

        # 5. Perfil Diretor (deve retornar 200)
        token_diretor = self.tokens["diretor"]
        res_diretor = self.client.get("/api/executivo/kpis-consolidados", headers={"Authorization": f"Bearer {token_diretor}"})
        self.assertEqual(res_diretor.status_code, 200)
        data_diretor = res_diretor.json()
        self.assertEqual(data_diretor["status"], "success")

        # 6. Perfil Presidente (deve retornar 200)
        token_pres = self.tokens["presidente"]
        res_pres = self.client.get("/api/executivo/kpis-consolidados", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_pres.status_code, 200)
        data_pres = res_pres.json()
        self.assertEqual(data_pres["status"], "success")

    def test_64_executivo_bi_data_aggregation_integrity(self):
        """Valida a consolidação de dados dos 4 quadrantes (Financeiro, Comercial, PDI e Governança) e geração dinâmica de alertas"""
        token_pres = self.tokens["presidente"]

        # 1. Semear dados específicos para garantir presença em todos os quadrantes
        # A. Financeiro: Receita paga e despesa paga
        res_rec = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token_pres}"}, json={
            "tipo": "receita",
            "categoria": "consultoria_rm",
            "descricao": "Parcela RM BI Executivo",
            "valor": 5000.0,
            "data_vencimento": "2026-08-15",
            "status": "pago"
        })
        self.assertEqual(res_rec.status_code, 201)

        res_desp = self.client.post("/api/financeiro/transacoes", headers={"Authorization": f"Bearer {token_pres}"}, json={
            "tipo": "despesa",
            "categoria": "capacitacao",
            "descricao": "Treinamento de Liderança Executiva",
            "valor": 1200.0,
            "data_vencimento": "2026-08-20",
            "status": "pago"
        })
        self.assertEqual(res_desp.status_code, 201)

        # B. Comercial: Lead em negociação
        res_lead = self.client.post("/api/crm/leads", headers={"Authorization": f"Bearer {token_pres}"}, json={
            "client_name": "Holding Inovação BI",
            "cnpj": "12.345.678/0001-90",
            "contact_person": "Dr. Fernando BI",
            "contact_email": "fernando@holdingbi.com.br",
            "estimated_value": 7500.0,
            "etapa": "negociacao"
        })
        self.assertEqual(res_lead.status_code, 201)
        lead_id = res_lead.json()["lead"]["id"]

        # C. Contrato RM ativo
        res_ct = self.client.post("/api/crm/contratos", headers={"Authorization": f"Bearer {token_pres}"}, json={
            "lead_id": lead_id,
            "brand_name": "Holding Inovação BI",
            "consultoria_escopo": "Registro de Marca e Proteção Intelectual",
            "valor_total": 7500.0,
            "prazo_dias": 45,
            "marcos_financeiros": [{"marco": "Entrada", "valor": 3750.0}],
            "status_execucao": "ativo"
        })
        self.assertEqual(res_ct.status_code, 201)

        # D. Fórum de dúvidas: dúvida aberta
        res_forum = self.client.post("/api/duvidas", headers={"Authorization": f"Bearer {token_pres}"}, json={
            "title": "Dúvida sobre registro de marca e procuração no INPI",
            "description": "Precisamos de alinhamento com a presidência sobre procuração em cartório.",
            "category": "tecnica"
        })
        self.assertEqual(res_forum.status_code, 201)

        # 2. Consultar BI Executivo Consolidado
        res_bi = self.client.get("/api/executivo/kpis-consolidados", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_bi.status_code, 200)
        data = res_bi.json()

        # 3. Validar seções de topo
        self.assertEqual(data["status"], "success")
        self.assertIn("financeiro", data)
        self.assertIn("comercial", data)
        self.assertIn("pessoas_pdi", data)
        self.assertIn("governanca_operacional", data)
        self.assertIn("alertas_atencao", data)
        self.assertIn("resumo_executivo", data)

        # 4. Validar Quadrante Financeiro
        fin = data["financeiro"]
        self.assertIn("saldo_caixa", fin)
        self.assertIn("total_receber_mes", fin)
        self.assertIn("total_pagar_mes", fin)
        self.assertIn("taxa_inadimplencia", fin)

        # 5. Validar Quadrante Comercial
        com = data["comercial"]
        self.assertGreaterEqual(com["volume_pipeline_aberto"], 7500.0)
        self.assertGreaterEqual(com["leads_em_negociacao"], 1)
        self.assertGreaterEqual(com["contratos_rm_ativos"], 1)

        # 6. Validar Quadrante PDI
        pdi = data["pessoas_pdi"]
        self.assertIn("media_avanco_global_pct", pdi)
        self.assertIn("micro_blocos_concluidos", pdi)
        self.assertIn("micro_blocos_pendentes", pdi)

        # 7. Validar Quadrante Governança
        gov = data["governanca_operacional"]
        self.assertGreaterEqual(gov["duvidas_forum_abertas"], 1)

        # 8. Validar Alertas de Atenção
        alertas = data["alertas_atencao"]
        self.assertIsInstance(alertas, list)
        tipos_alertas = [a["tipo"] for a in alertas]
        self.assertIn("comercial", tipos_alertas)
        self.assertIn("governanca", tipos_alertas)

        # 9. Validar Resumo Executivo
        resumo = data["resumo_executivo"]
        self.assertIn("score_saude_organizacional", resumo)
        self.assertIn("status_geral", resumo)
        self.assertIn(resumo["status_geral"], ["saudavel", "atencao", "critico"])

    def test_65_kb_artigos_creation_listing_and_filtering(self):
        """Valida cadastro de POPs/artigos na base de conhecimento, validação de categorias, listagem filtrada e busca textual"""
        token = self.tokens["presidente"]

        # 1. Validação: rejeição de categoria inexistente
        res_bad_cat = self.client.post("/api/kb/artigos", headers={"Authorization": f"Bearer {token}"}, json={
            "titulo": "Procedimento Inválido",
            "categoria": "categoria_fantasma",
            "conteudo": "Texto descritivo de teste"
        })
        self.assertEqual(res_bad_cat.status_code, 400)
        self.assertIn("inválida", res_bad_cat.json()["detail"].lower())

        # 2. Cadastro de artigo de Projetos com Drive URL
        res_artigo1 = self.client.post("/api/kb/artigos", headers={"Authorization": f"Bearer {token}"}, json={
            "titulo": "Manual de Oposição Marcária no INPI",
            "categoria": "projetos",
            "conteudo": "## Diretriz de Oposição\nPasso a passo para manifestação contra pedidos colidentes de marcas no INPI com base no art. 158 da LPI.\n\nLink: https://drive.google.com/drive/folders/oposicao-inpi",
            "drive_url": "https://drive.google.com/drive/folders/oposicao-inpi"
        })
        self.assertEqual(res_artigo1.status_code, 201)
        data1 = res_artigo1.json()["artigo"]
        artigo1_id = data1["id"]
        self.assertEqual(data1["categoria"], "projetos")
        self.assertIn("oposicao-inpi", data1["drive_url"])

        # 3. Cadastro de artigo de Financeiro
        res_artigo2 = self.client.post("/api/kb/artigos", headers={"Authorization": f"Bearer {token}"}, json={
            "titulo": "Fluxo de Conciliação Bancária no Banco Cora",
            "categoria": "financeiro",
            "conteudo": "## Fechamento Mensal de Caixa\nInstruções detalhadas para emissão de extrato OFX e conferência das faturas liquidadas.",
            "drive_url": "https://drive.google.com/drive/folders/cora-extratos"
        })
        self.assertEqual(res_artigo2.status_code, 201)
        data2 = res_artigo2.json()["artigo"]
        artigo2_id = data2["id"]

        # 4. Listagem geral
        res_list = self.client.get("/api/kb/artigos", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_list.status_code, 200)
        artigos = res_list.json()["artigos"]
        self.assertGreaterEqual(len(artigos), 2)

        # 5. Filtragem por categoria (projetos)
        res_cat = self.client.get("/api/kb/artigos?categoria=projetos", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_cat.status_code, 200)
        artigos_proj = res_cat.json()["artigos"]
        self.assertTrue(all(a["categoria"] == "projetos" for a in artigos_proj))
        ids_proj = [a["id"] for a in artigos_proj]
        self.assertIn(artigo1_id, ids_proj)
        self.assertNotIn(artigo2_id, ids_proj)

        # 6. Busca textual por palavra-chave (q="Conciliação")
        res_busca = self.client.get("/api/kb/artigos?q=Conciliação", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_busca.status_code, 200)
        artigos_busca = res_busca.json()["artigos"]
        self.assertTrue(any("Conciliação" in a["titulo"] for a in artigos_busca))

        # 7. Recuperação por ID
        res_detalhe = self.client.get(f"/api/kb/artigos/{artigo1_id}", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_detalhe.status_code, 200)
        detalhe = res_detalhe.json()["artigo"]
        self.assertEqual(detalhe["id"], artigo1_id)
        self.assertIn("Manual de Oposição", detalhe["titulo"])
        self.assertIn("LPI", detalhe["conteudo"])

    def test_66_kb_artigos_rbac_delete_and_lifecycle(self):
        """Valida que a remoção de documentos obsoletos na base de conhecimento é restrita a Diretores e Presidente (403 para assessores e gerentes)"""
        token_pres = self.tokens["presidente"]
        token_assessor = self.tokens["assessor_comercial"]
        token_gerente = self.tokens["gerente"]
        token_diretor = self.tokens["diretor"]

        # 1. Cadastrar artigo para teste de ciclo de vida
        res_novo = self.client.post("/api/kb/artigos", headers={"Authorization": f"Bearer {token_pres}"}, json={
            "titulo": "Procedimento Temporário para Teste de Exclusão",
            "categoria": "geral",
            "conteudo": "Este procedimento será removido durante o teste de RBAC."
        })
        self.assertEqual(res_novo.status_code, 201)
        artigo_id = res_novo.json()["artigo"]["id"]

        # 2. Tentativa de exclusão por Assessor (deve retornar 403 Forbidden)
        res_del_assessor = self.client.delete(f"/api/kb/artigos/{artigo_id}", headers={"Authorization": f"Bearer {token_assessor}"})
        self.assertEqual(res_del_assessor.status_code, 403)
        self.assertIn("Acesso negado", res_del_assessor.json()["detail"])

        # 3. Tentativa de exclusão por Gerente (deve retornar 403 Forbidden)
        res_del_gerente = self.client.delete(f"/api/kb/artigos/{artigo_id}", headers={"Authorization": f"Bearer {token_gerente}"})
        self.assertEqual(res_del_gerente.status_code, 403)
        self.assertIn("Acesso negado", res_del_gerente.json()["detail"])

        # 4. Exclusão autorizada por Diretor ou Presidente (deve retornar 200 OK)
        res_del_dir = self.client.delete(f"/api/kb/artigos/{artigo_id}", headers={"Authorization": f"Bearer {token_diretor}"})
        self.assertEqual(res_del_dir.status_code, 200)
        self.assertEqual(res_del_dir.json()["status"], "success")

        # 5. Consulta subsequente ao artigo excluído deve retornar 404 Not Found
        res_get_deleted = self.client.get(f"/api/kb/artigos/{artigo_id}", headers={"Authorization": f"Bearer {token_pres}"})
        self.assertEqual(res_get_deleted.status_code, 404)

    def test_67_seed_oficial_8_pops_persistence_and_retrieval(self):
        """Valida a injeção do Catálogo Oficial com os 8 POPs Técnicos e a recuperação estruturada via API"""
        token = self.tokens["presidente"]

        # 1. Executar injeção oficial
        res_seed = seed_official_kb_pops()
        self.assertEqual(res_seed["total"], 8)
        self.assertGreaterEqual(res_seed["inserted"] + res_seed["updated"], 8)

        # 2. Recuperar listagem completa via API
        res_list = self.client.get("/api/kb/artigos", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_list.status_code, 200)
        artigos = res_list.json()["artigos"]
        self.assertGreaterEqual(len(artigos), 8)

        # 3. Validar a presença de cada um dos 8 POPs oficiais
        codigos_esperados = [f"POP-0{i}" for i in range(1, 9)]
        titulos = [a["titulo"] for a in artigos]

        for cod in codigos_esperados:
            self.assertTrue(any(cod in t for t in titulos), f"Código {cod} não encontrado nos artigos cadastrados.")

        # 4. Validar estrutura detalhada e hierarquia Markdown de cada POP
        for pop_ref in OFFICIAL_KB_POPS:
            cod = pop_ref["codigo"]
            artigo_match = next((a for a in artigos if cod in a["titulo"]), None)
            self.assertIsNotNone(artigo_match, f"Artigo {cod} não encontrado na listagem.")

            artigo_id = artigo_match["id"]
            res_detalhe = self.client.get(f"/api/kb/artigos/{artigo_id}", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(res_detalhe.status_code, 200)
            detalhe = res_detalhe.json()["artigo"]

            # Validar campos de metadados
            self.assertEqual(detalhe["categoria"], pop_ref["categoria"])
            if pop_ref.get("drive_url"):
                self.assertIn("drive.google.com", detalhe["drive_url"])

            # Validar estrutura Markdown obrigatória
            conteudo = detalhe["conteudo"]
            self.assertIn(f"# {cod} -", conteudo)
            self.assertIn("**Área Responsável**:", conteudo)
            self.assertIn("**Nível de Acesso**:", conteudo)
            self.assertIn("## 1. Objetivo Operacional", conteudo)
            self.assertIn("## 2. Pré-requisitos Sistêmicos", conteudo)
            self.assertIn("## 3. Passo a Passo na Interface do EDbrain", conteudo)
            self.assertIn("## 4. Tratamento de Exceções & Suporte Coletivo", conteudo)

        # 5. Validar filtragem por categoria específica
        # Ex: ti deve conter POP-02
        res_ti = self.client.get("/api/kb/artigos?categoria=ti", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_ti.status_code, 200)
        artigos_ti = res_ti.json()["artigos"]
        self.assertTrue(any("POP-02" in a["titulo"] for a in artigos_ti))

        # Ex: comercial deve conter POP-03
        res_com = self.client.get("/api/kb/artigos?categoria=comercial", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_com.status_code, 200)
        artigos_com = res_com.json()["artigos"]
        self.assertTrue(any("POP-03" in a["titulo"] for a in artigos_com))

        # 6. Validar busca textual
        res_busca_sha = self.client.get("/api/kb/artigos?q=SHA-256", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_busca_sha.status_code, 200)
        artigos_sha = res_busca_sha.json()["artigos"]
        self.assertTrue(any("POP-04" in a["titulo"] for a in artigos_sha))

    def test_68_kb_artigos_semantic_branching_and_pdi_linking(self):
        """Valida a Ramificação Semântica Autônoma de POPs e Vinculação ao PDI"""
        token = self.tokens["presidente"]
        token_assessor = self.tokens["assessor_comercial"]

        # 1. Garantir que exista um artigo base (ex: POP-03 Funil Comercial)
        seed_official_kb_pops()
        res_list = self.client.get("/api/kb/artigos?categoria=comercial", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_list.status_code, 200)
        artigos = res_list.json()["artigos"]
        self.assertTrue(len(artigos) > 0)
        base_artigo = artigos[0]
        base_id = base_artigo["id"]

        # 2. Rejeição de chamada anônima (401)
        anon_client = TestClient(app)
        res_anon = anon_client.post(f"/api/kb/artigos/{base_id}/expandir", json={})
        self.assertEqual(res_anon.status_code, 401)

        # 3. Erro 404 para artigo inexistente
        res_404 = self.client.post("/api/kb/artigos/999999/expandir", headers={"Authorization": f"Bearer {token}"}, json={})
        self.assertEqual(res_404.status_code, 404)

        # 4. Executar Ramificação Semântica sem vincular ao PDI (apenas geração nativa e dedução)
        res_exp = self.client.post(
            f"/api/kb/artigos/{base_id}/expandir",
            headers={"Authorization": f"Bearer {token_assessor}"},
            json={
                "vincular_ao_pdi": False,
                "area_foco": "comercial",
                "contexto_adicional": "Sprint de fechamento de metas comerciais do PE 2026"
            }
        )
        self.assertEqual(res_exp.status_code, 200)
        data_exp = res_exp.json()
        self.assertTrue(data_exp["success"])
        self.assertEqual(data_exp["area_foco"], "comercial")
        self.assertFalse(data_exp["vinculado_ao_pdi"])
        self.assertGreaterEqual(data_exp["total_etapas"], 3)
        self.assertEqual(len(data_exp["blocos_pdi_vinculados"]), 0)

        # Validar conteúdo das etapas autônomas geradas
        etapas = data_exp["etapas_autonomas"]
        self.assertTrue(all("passo" in s and "titulo" in s and "criterio_aceite" in s for s in etapas))
        self.assertTrue(all("sla_dias" in s and "formato_entregavel" in s for s in etapas))

        # Validar checklist consolidado
        checklist = data_exp["checklist_consolidado"]
        self.assertGreaterEqual(len(checklist), 3)

        # Validar artigo derivado nativo persistido no banco
        derivado = data_exp["artigo_derivado"]
        deriv_id = derivado["id"]
        self.assertTrue(derivado["gerado_por_ia"])

        res_deriv_detalhe = self.client.get(f"/api/kb/artigos/{deriv_id}", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_deriv_detalhe.status_code, 200)
        artigo_detalhe = res_deriv_detalhe.json()["artigo"]
        self.assertTrue(artigo_detalhe["gerado_por_ia"])
        self.assertEqual(artigo_detalhe["trilha_derivada_id"], base_id)
        self.assertIn("# [Trilha Autônoma]", artigo_detalhe["conteudo"])
        self.assertIn("## 1. Etapas Operacionais Deduzidas", artigo_detalhe["conteudo"])
        self.assertIn("## 2. Checklist Executivo de Validação", artigo_detalhe["conteudo"])

        # 5. Executar Ramificação com vinculação ao PDI do membro logado
        res_pdi = self.client.post(
            f"/api/kb/artigos/{base_id}/expandir",
            headers={"Authorization": f"Bearer {token_assessor}"},
            json={
                "vincular_ao_pdi": True,
                "area_foco": "comercial"
            }
        )
        self.assertEqual(res_pdi.status_code, 200)
        data_pdi = res_pdi.json()
        self.assertTrue(data_pdi["success"])
        self.assertTrue(data_pdi["vinculado_ao_pdi"])
        self.assertGreater(len(data_pdi["blocos_pdi_vinculados"]), 0)

        blocos = data_pdi["blocos_pdi_vinculados"]
        for b in blocos:
            self.assertIn("id", b)
            self.assertTrue(b["microblock_code"].startswith("POP"))
            self.assertEqual(b["status"], "pendente")
            self.assertGreater(b["sla_days"], 0)

        # Verificar se os blocos estão de fato persistidos no banco
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM member_pdi_blocks WHERE user_email = ? AND microblock_code LIKE 'POP%'",
            ("estevao.coutinho@edvjr.com.br",)
        ).fetchall()
        conn.close()
        self.assertGreaterEqual(len(rows), 1)

    def test_69_kb_content_unification_and_didactic_document_generation(self):
        """
        Teste 69: Valida a unificação de chaves de conteúdo (conteudo, content, body, texto)
        e a geração de Cadernos Didáticos Oficiais pelo motor em backend/legal_engine.py.
        Garante hierarquia visual estrita, tom acadêmico, densidade conceitual,
        paleta oficial EDbrain (#0f172a, #1e293b, #3b82f6, #6366f1) e integridade SHA-256.
        """
        from datetime import datetime
        from backend.legal_engine import gerar_documento_didatico

        # 1. Testar unificação com chave alternativa 'content'
        artigo_alt_1 = {
            "id": 991,
            "titulo": "POP-09: Guia Descomplicado de Registro de Marca no INPI",
            "categoria": "projetos",
            "content": "Orientações para protocolo no e-Marcas e acompanhamento na RPI.",
            "autor_nome": "Thais Junger"
        }
        res_did_1 = gerar_documento_didatico(artigo_alt_1)
        self.assertEqual(res_did_1["status"], "success")
        self.assertEqual(res_did_1["protocolo"], f"ED-DID-0991/{datetime.now().year}")
        self.assertIn("Lei Federal nº 9.279/1996", res_did_1["marco_normativo"])
        self.assertIn("INPI", res_did_1["orgao_competente"])
        self.assertEqual(len(res_did_1["secoes"]), 4)
        self.assertTrue(all(len(s["paragrafos"]) >= 2 for s in res_did_1["secoes"]))

        # Verificar presença das cores da identidade visual EDbrain no HTML gerado
        html_1 = res_did_1["documento_html"]
        self.assertIn("#0f172a", html_1)
        self.assertIn("#1e293b", html_1)
        self.assertIn("#3b82f6", html_1)
        self.assertIn("#6366f1", html_1)
        self.assertIn(res_did_1["hash_sha256"], html_1)

        # 2. Testar unificação com chave alternativa 'body'
        artigo_alt_2 = {
            "id": 992,
            "titulo": "POP-10: Elaboração e Revisão de Contratos de Prestação de Serviços",
            "categoria": "projetos",
            "body": "Procedimento de revisão com Legal Design e cláusula resolutiva.",
            "autor_nome": "Charles Junior"
        }
        res_did_2 = gerar_documento_didatico(artigo_alt_2)
        self.assertEqual(res_did_2["status"], "success")
        self.assertIn("13.267/2016", res_did_2["marco_normativo"])
        self.assertIn("Código Civil", res_did_2["marco_normativo"])
        self.assertIn("## 1. FUNDAMENTAÇÃO NORMATIVA E ENQUADRAMENTO DOGMÁTICO", res_did_2["documento_markdown"])
        self.assertIn("## 2. PRESSUPOSTOS MATERIAIS E METODOLOGIA OPERATÓRIA", res_did_2["documento_markdown"])
        self.assertIn("## 3. GESTÃO DE RISCOS REGULATÓRIOS E COMPLIANCE INSTITUCIONAL", res_did_2["documento_markdown"])
        self.assertIn("## 4. PARÂMETROS DE EFICÁCIA PRÁTICA E CONTROLE DE QUALIDADE", res_did_2["documento_markdown"])

        # 3. Testar unificação com chave alternativa 'texto'
        artigo_alt_3 = {
            "id": 993,
            "titulo": "POP-16: Rotina Prática de Emissão de Nota Fiscal de Serviços (NFS-e)",
            "categoria": "financeiro",
            "texto": "Acesso ao portal da PMV Vitória e conciliação bancária Cora.",
            "autor_nome": "Diretoria Financeira"
        }
        res_did_3 = gerar_documento_didatico(artigo_alt_3)
        self.assertEqual(res_did_3["status"], "success")
        self.assertIn("ISSQN", res_did_3["marco_normativo"])
        self.assertIn("Secretaria Municipal de Fazenda", res_did_3["orgao_competente"])

    def test_70_didactic_document_api_endpoint(self):
        """
        Teste 70: Valida os endpoints GET e POST /api/kb/artigos/{id}/didatico.
        Verifica o acesso público/intranet (sem barreira 401), integridade do JSON retornado
        e tratamento de erro 404 para identificadores inexistentes.
        """
        # Obter um artigo válido da base
        res_list = self.client.get("/api/kb/artigos")
        self.assertEqual(res_list.status_code, 200)
        artigos = res_list.json()["artigos"]
        self.assertGreater(len(artigos), 0)
        target_artigo = artigos[0]
        target_id = target_artigo["id"]

        # Chamada GET anônima/intranet
        res_get = self.client.get(f"/api/kb/artigos/{target_id}/didatico")
        self.assertEqual(res_get.status_code, 200)
        data_get = res_get.json()
        self.assertEqual(data_get["status"], "success")
        self.assertEqual(data_get["artigo_id"], target_id)
        self.assertEqual(data_get["titulo"], target_artigo["titulo"])
        self.assertIn("hash_sha256", data_get)
        self.assertIn("documento_html", data_get)
        self.assertIn("documento_markdown", data_get)
        self.assertEqual(len(data_get["secoes"]), 4)

        # Chamada POST com autenticação
        token = self.tokens["presidente"]
        res_post = self.client.post(
            f"/api/kb/artigos/{target_id}/didatico",
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res_post.status_code, 200)
        data_post = res_post.json()
        self.assertEqual(data_post["status"], "success")
        self.assertEqual(data_post["hash_sha256"], data_get["hash_sha256"])

        # Chamada para artigo inexistente
        res_404 = self.client.get("/api/kb/artigos/999999/didatico")
        self.assertEqual(res_404.status_code, 404)

    def test_71_avaliacao_360_error_extraction_and_resilience(self):
        """
        Teste 71: Valida o tratamento e extração de erros na Avaliação 360º (VPGG),
        assegurando que falhas de validação (HTTP 422/400) retornem mensagens descritivas
        e que a lógica de formatação impeça a injeção da string literal '[object Object]'.
        """
        token = self.tokens["diretor"]
        
        # 1. Envio de payload com nota inválida (> 10)
        payload_invalido = {
            "evaluatee_email": "thais.junger@edvjr.com.br",
            "evaluation_cycle": "2026.1",
            "relationship": "gestor_direto",
            "score_lideranca": 15.0,  # Máximo permitido é 10.0
            "score_gestao": 9.0,
            "score_visao_sistemica": 8.5,
            "score_orientacao_resultados": 9.2,
            "score_autoconhecimento": 8.0,
            "qualitative_feedback": "Líder inspiradora."
        }
        res_422 = self.client.post(
            "/vpgg/evaluations-360",
            headers={"Authorization": f"Bearer {token}"},
            json=payload_invalido
        )
        self.assertIn(res_422.status_code, [400, 422])
        err_json = res_422.json()
        self.assertIn("detail", err_json)
        
        # Validação do algoritmo de extração (extrairMensagemErro)
        detail = err_json["detail"]
        if isinstance(detail, list):
            msgs = []
            for item in detail:
                if isinstance(item, dict):
                    loc = ".".join([str(l) for l in item.get("loc", []) if l != "body"])
                    msg = item.get("msg") or item.get("message") or str(item)
                    msgs.append(f"{loc}: {msg}" if loc else msg)
                else:
                    msgs.append(str(item))
            formatted_error = " | ".join(msgs)
        elif isinstance(detail, dict):
            formatted_error = detail.get("msg") or detail.get("message") or str(detail)
        else:
            formatted_error = str(detail)
            
        self.assertNotIn("[object Object]", formatted_error)
        self.assertTrue(len(formatted_error) > 0)
        
        # 2. Envio de avaliação válida
        payload_valido = {
            "evaluatee_email": "thais.junger@edvjr.com.br",
            "cycle_id": "2026.1",
            "relationship_type": "peer",
            "score_lideranca": 4.8,
            "score_gestao": 4.5,
            "score_visao_sistemica": 4.2,
            "score_orientacao_resultados": 4.9,
            "score_autoconhecimento": 4.0,
            "feedback_qualitativo": "Excelente liderança técnica na gestão de marcas."
        }
        res_valido = self.client.post(
            "/vpgg/evaluations-360",
            headers={"Authorization": f"Bearer {token}"},
            json=payload_valido
        )
        self.assertIn(res_valido.status_code, [200, 201])
        data_valido = res_valido.json()
        self.assertEqual(data_valido["evaluatee_email"], "thais.junger@edvjr.com.br")

    def test_72_rpi_scanner_and_contracts_rm_integration(self):
        """
        Teste 72: Valida o motor autônomo de varredura da RPI (INPI), ingestão de despachos
        em XML/JSON, cruzamento automático com contratos_rm, atualização de status,
        cálculo de prazo fatal de 60 dias e emissão de alertas críticos para a Presidência.
        """
        token_pres = self.tokens["presidente"]
        
        # 1. Cadastrar lead e contrato de RM para monitoramento
        res_lead = self.client.post(
            "/api/crm/leads",
            headers={"Authorization": f"Bearer {token_pres}"},
            json={
                "client_name": "AeroTech Soluções em Drones S.A.",
                "cnpj": "55.666.777/0001-88",
                "contact_person": "Felipe Albuquerque",
                "estimated_value": 3660.0,
                "etapa": "fechado"
            }
        )
        self.assertEqual(res_lead.status_code, 201)
        lead_id = res_lead.json()["lead"]["id"]
        
        proc_num = "935889901"
        res_contrato = self.client.post(
            "/api/crm/contratos",
            headers={"Authorization": f"Bearer {token_pres}"},
            json={
                "lead_id": lead_id,
                "rm_code": "RM-999",
                "process_number": proc_num,
                "brand_name": "AEROTECH DRONES",
                "client_name": "AeroTech Soluções em Drones S.A.",
                "consultoria_escopo": "Monitoramento de registro de marca e despachos RPI.",
                "valor_total": 3660.0,
                "status_execucao": "ativo"
            }
        )
        self.assertEqual(res_contrato.status_code, 201)
        contrato_id = res_contrato.json()["contrato"]["id"]
        
        # 2. Simular ingestão de XML oficial da RPI com despacho de Exigência (IPAS005)
        rpi_xml = f"""<?xml version="1.0" encoding="utf-8"?>
        <revista numero="2851" data="2026-10-06">
          <processo numero="{proc_num}" nome="AEROTECH DRONES">
            <despacho codigo="IPAS005" nome="Exigência formal" texto="Apresentar certidão simplificada da Junta Comercial no prazo de 60 dias."/>
          </processo>
        </revista>
        """
        
        res_scan = self.client.post(
            "/api/rpi/scan",
            headers={"Authorization": f"Bearer {token_pres}"},
            json={
                "numero_rpi": "2851",
                "xml_content": rpi_xml
            }
        )
        self.assertEqual(res_scan.status_code, 200)
        data_scan = res_scan.json()
        self.assertEqual(data_scan["status"], "success")
        self.assertEqual(data_scan["rpi_numero"], "2851")
        self.assertGreaterEqual(data_scan["processos_correspondidos"], 1)
        self.assertGreaterEqual(data_scan["alertas_presidencia_gerados"], 1)
        
        # 3. Validar consulta de processos e integridade dos dados atualizados
        res_proc = self.client.get(f"/api/rpi/processos?q={proc_num}")
        self.assertEqual(res_proc.status_code, 200)
        processos = res_proc.json()["processos"]
        self.assertGreaterEqual(len(processos), 1)
        proc_item = [p for p in processos if p["process_number"] == proc_num][0]
        self.assertEqual(proc_item["rpi_ultimo_despacho_codigo"], "IPAS005")
        self.assertEqual(proc_item["rpi_exigencia_pendente"], 1)
        self.assertEqual(proc_item["rpi_numero"], "2851")
        self.assertIsNotNone(proc_item["rpi_prazo_fatal"])
        
        # 4. Validar histórico cronológico de despachos
        res_hist = self.client.get(f"/api/rpi/processos/{contrato_id}/historico")
        self.assertEqual(res_hist.status_code, 200)
        historico_data = res_hist.json()
        self.assertEqual(historico_data["total_despachos"], 1)
        despacho_auditado = historico_data["historico"][0]
        self.assertEqual(despacho_auditado["codigo_despacho"], "IPAS005")
        self.assertEqual(despacho_auditado["afeta_prazo"], 1)
        self.assertEqual(despacho_auditado["prazo_dias"], 60)
        
        # 5. Validar geração de notificação para a Presidência
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM system_notifications WHERE target_role = 'presidente' AND category = 'audit_alert' AND metadata_json LIKE ?;",
            (f"%{proc_num}%",)
        )
        notif_count = cur.fetchone()[0]
        conn.close()
        self.assertGreaterEqual(notif_count, 1)
        
        # 6. Validar resumo executivo
        res_resumo = self.client.get("/api/rpi/resumo")
        self.assertEqual(res_resumo.status_code, 200)
        resumo = res_resumo.json()
        self.assertGreaterEqual(resumo["total_processos_monitorados"], 1)
        self.assertGreaterEqual(resumo["processos_com_exigencia"], 1)
        self.assertEqual(resumo["ultima_rpi_auditada"], "2851")

    def test_73_preservacao_integral_rms_legados_e_atualizacao_incremental(self):
        """
        Teste 73: Valida a retenção integral de 100% dos RMs legados (zero data loss),
        persistência e integridade de todos os campos descritivos (participantes, telefone,
        última conferência, último contato, responsável técnico) e a atualização
        estritamente incremental via motor autônomo da RPI (sem sobrescrever dados cadastrais).
        """
        # 1. Executar o seed de migração da base legada para contratos_rm
        total_seeded = seed_contratos_rm_from_legacy()
        self.assertGreaterEqual(total_seeded, 85, "A rotina de seed deve garantir pelo menos 85 processos legados importados.")

        # 2. Consultar todos os processos via endpoint oficial
        res_list = self.client.get("/api/rpi/processos")
        self.assertEqual(res_list.status_code, 200)
        data_proc = res_list.json()
        self.assertEqual(data_proc["status"], "success")
        self.assertGreaterEqual(data_proc["total"], 85)
        processos = data_proc["processos"]

        # Validar integridade cadastral de 100% dos RMs legados
        rms_legados = [p for p in processos if p.get("origem_legado") == 1]
        self.assertGreaterEqual(len(rms_legados), 85)

        for p in rms_legados:
            self.assertIsNotNone(p.get("rm_code"))
            self.assertIsNotNone(p.get("brand_name"))
            self.assertIsNotNone(p.get("process_number"))
            self.assertEqual(p["origem_legado"], 1)
            self.assertEqual(p.get("dados_legados_preservados"), 1)

        # 3. Idempotência do seed: Executar novamente e garantir que nenhum dado é duplicado ou apagado
        total_seeded_2 = seed_contratos_rm_from_legacy()
        self.assertEqual(total_seeded, total_seeded_2, "Chamadas consecutivas do seed não devem duplicar registros.")

        # 4. Capturar snapshot de RM-001 (Vivacidade) antes da varredura RPI
        target_rm = next((p for p in rms_legados if p["rm_code"] == "RM-001"), None)
        self.assertIsNotNone(target_rm, "RM-001 deve estar presente na base de dados.")
        
        proc_num_target = target_rm["process_number"]
        original_participantes = target_rm["participantes"]
        original_telefone = target_rm["telefone"]
        original_responsavel = target_rm["responsavel_tecnico"]
        original_conferencia = target_rm["ultima_conferencia"]
        original_escopo = target_rm["consultoria_escopo"]
        original_valor = target_rm["valor_total"]

        self.assertEqual(target_rm["brand_name"], "Vivacidade")
        self.assertEqual(original_participantes, "Flaviane e Anna Paula")
        self.assertIn("99935-4662", original_telefone)

        # 5. Executar varredura da RPI com despacho oficial para RM-001 (Deferimento do registro)
        payload_rpi = {
            "numero_rpi": "2855",
            "data_publicacao": "2026-10-13",
            "despachos": [
                {
                    "numero_processo": proc_num_target,
                    "marca": "Vivacidade",
                    "codigo_despacho": "IPAS157",
                    "nome_despacho": "Deferimento do pedido de registro (Art. 159/160 da LPI)",
                    "texto_complementar": "Pedido deferido com base no exame de mérito favorável."
                }
            ]
        }
        res_scan = self.client.post(
            "/api/rpi/scan",
            headers={"Authorization": f"Bearer {self.tokens['presidente']}"},
            json=payload_rpi
        )
        self.assertEqual(res_scan.status_code, 200)
        scan_data = res_scan.json()
        self.assertEqual(scan_data["status"], "success")
        self.assertEqual(scan_data["processos_correspondidos"], 1)

        # 6. Re-consultar RM-001 e atestar que:
        # A. Campos RPI foram cirurgicamente atualizados
        # B. Campos cadastrais e dados legados originais foram 100% PRESERVADOS (Zero Data Loss)
        res_target = self.client.get(f"/api/rpi/processos?q={proc_num_target}")
        self.assertEqual(res_target.status_code, 200)
        target_atualizado = res_target.json()["processos"][0]

        # Auditoria RPI atualizada
        self.assertEqual(target_atualizado["rpi_ultimo_despacho_codigo"], "IPAS157")
        self.assertIn("Deferimento", target_atualizado["rpi_ultimo_status"])
        self.assertEqual(target_atualizado["rpi_numero"], "2855")
        self.assertEqual(target_atualizado["fase_inpi"], "DEFERIDO - AGUARDANDO DECÊNIO")
        self.assertIsNotNone(target_atualizado["rpi_prazo_fatal"])

        # Preservação absoluta dos dados cadastrais originais (Zero Alteração)
        self.assertEqual(target_atualizado["brand_name"], "Vivacidade")
        self.assertEqual(target_atualizado["participantes"], original_participantes)
        self.assertEqual(target_atualizado["telefone"], original_telefone)
        self.assertEqual(target_atualizado["responsavel_tecnico"], original_responsavel)
        self.assertEqual(target_atualizado["ultima_conferencia"], original_conferencia)
        self.assertEqual(target_atualizado["consultoria_escopo"], original_escopo)
        self.assertEqual(target_atualizado["valor_total"], original_valor)
        self.assertEqual(target_atualizado["origem_legado"], 1)
        self.assertEqual(target_atualizado["dados_legados_preservados"], 1)

        # 7. Garantir que os demais processos não correspondidos permaneceram intactos
        res_all_after = self.client.get("/api/rpi/processos")
        self.assertEqual(res_all_after.json()["total"], data_proc["total"])

        # RM-002 (Sementes Vitória) não deve ter sido afetado
        rm_002 = next((p for p in res_all_after.json()["processos"] if p["rm_code"] == "RM-002"), None)
        self.assertIsNotNone(rm_002)
        self.assertEqual(rm_002["brand_name"], "Sementes Vitória")
        self.assertEqual(rm_002["participantes"], "Alice e Gabrielle")
        self.assertIn("99619-3002", rm_002["telefone"])


if __name__ == "__main__":
    unittest.main()



