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

if __name__ == "__main__":
    unittest.main()
