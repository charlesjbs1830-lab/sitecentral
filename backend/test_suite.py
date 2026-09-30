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

from main import app
from database import init_db, get_connection, VALID_ROLES

class TestEDbrainRBACAndFinancial(unittest.TestCase):

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

if __name__ == "__main__":
    unittest.main()

