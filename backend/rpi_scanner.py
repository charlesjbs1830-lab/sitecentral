"""
Módulo do Motor Autônomo de Varredura da RPI (Revista da Propriedade Industrial)
Google Antigravity / EDbrain - Empresa Júnior EDV Jr.

Automatiza a ingestão e rastreio de despachos publicados semanalmente às terças-feiras
pelo Instituto Nacional da Propriedade Industrial (INPI), cruzando os dados da RPI
com os processos cadastrados na tabela 'contratos_rm', atualizando status e gerando
alertas executivos imediatos para a Presidência em caso de prazos críticos.
"""

import os
import re
import json
import logging
import unicodedata
from datetime import datetime, date, timedelta
from typing import Dict, List, Optional, Union, Tuple
import xml.etree.ElementTree as ET

try:
    from backend.database import get_connection, create_system_notification
except ImportError:
    from database import get_connection, create_system_notification

logger = logging.getLogger("EDbrain.RPIScanner")


def normalize_marca(texto: Optional[str]) -> str:
    """Normaliza nomes de marcas e titulares para comparação fonética e textual."""
    if not texto:
        return ""
    # Remover acentuação
    nfkd = unicodedata.normalize('NFKD', str(texto))
    sem_acento = "".join([c for c in nfkd if not unicodedata.combining(c)])
    # Converter para maiúsculas e remover pontuações
    limpo = re.sub(r'[^a-zA-Z0-9\s]', ' ', sem_acento).upper()
    return " ".join(limpo.split())


def normalize_processo(num: Optional[str]) -> str:
    """Normaliza número do processo INPI mantendo apenas dígitos."""
    if not num:
        return ""
    return re.sub(r'\D', '', str(num))


# ==============================================================================
# TIPOLOGIA DE DESPACHOS DO INPI (LEI DE PROPRIEDADE INDUSTRIAL - LEI 9.279/1996)
# ==============================================================================

DESPACHO_RULES = {
    # 1. EXIGÊNCIAS FORMAIS OU DE MÉRITO (Art. 157 da LPI)
    "EXIGENCIA": {
        "tipo": "exigencia",
        "prazo_dias": 60,
        "afeta_prazo": True,
        "status_alerta": "urgente",
        "is_critico": True,
        "fase_inpi": "EM EXIGÊNCIA",
        "exigencia_flag": 1,
        "oposicao_flag": 0,
        "descricao_padrao": "Exigência formal ou técnica formulada pelo examinador do INPI. Prazo improrrogável de 60 dias para cumprimento sob pena de arquivamento definitivo (Art. 157 da LPI)."
    },
    # 2. OPOSIÇÃO DE TERCEIROS (Art. 158 da LPI)
    "OPOSICAO": {
        "tipo": "oposicao",
        "prazo_dias": 60,
        "afeta_prazo": True,
        "status_alerta": "urgente",
        "is_critico": True,
        "fase_inpi": "OPOSIÇÃO ABERTA",
        "exigencia_flag": 0,
        "oposicao_flag": 1,
        "descricao_padrao": "Notificação de oposição protocolada por terceiro titular de marca anterior ou colidente. Abertura do prazo de 60 dias para apresentação de manifestação defensiva."
    },
    # 3. DEFERIMENTO DO PEDIDO DE REGISTRO (Art. 159/160 da LPI)
    "DEFERIMENTO": {
        "tipo": "deferimento",
        "prazo_dias": 60,
        "afeta_prazo": True,
        "status_alerta": "urgente",
        "is_critico": True,
        "fase_inpi": "DEFERIDO - AGUARDANDO DECÊNIO",
        "exigencia_flag": 0,
        "oposicao_flag": 0,
        "descricao_padrao": "Pedido de registro deferido pela Diretoria de Marcas do INPI! Prazo ordinário de 60 dias para recolhimento da taxa de concessão e 1º decênio da marca."
    },
    # 4. CONCESSÃO DO REGISTRO DE MARCA (Art. 161 da LPI)
    "CONCESSAO": {
        "tipo": "concessao",
        "prazo_dias": 0,
        "afeta_prazo": False,
        "status_alerta": "normal",
        "is_critico": False,
        "fase_inpi": "CONCEDIDO",
        "exigencia_flag": 0,
        "oposicao_flag": 0,
        "descricao_padrao": "Concessão oficial do registro de marca e expedição do certificado de registro com vigência decenal assegurada pelo INPI."
    },
    # 5. INDEFERIMENTO DO PEDIDO (Art. 166 da LPI)
    "INDEFERIMENTO": {
        "tipo": "indeferimento",
        "prazo_dias": 60,
        "afeta_prazo": True,
        "status_alerta": "urgente",
        "is_critico": True,
        "fase_inpi": "INDEFERIDO",
        "exigencia_flag": 0,
        "oposicao_flag": 0,
        "descricao_padrao": "Pedido indeferido com base em anterioridade ou irregistrabilidade marcária. Prazo de 60 dias para interposição de Recurso Administrativo (Art. 212 da LPI)."
    },
    # 6. PUBLICAÇÃO DE PEDIDO PARA OPOSIÇÃO (Art. 158 da LPI)
    "PUBLICACAO": {
        "tipo": "publicacao",
        "prazo_dias": 60,
        "afeta_prazo": True,
        "status_alerta": "normal",
        "is_critico": False,
        "fase_inpi": "PUBLICADO",
        "exigencia_flag": 0,
        "oposicao_flag": 0,
        "descricao_padrao": "Publicação do pedido de registro na RPI para abertura do prazo legal de 60 dias para eventuais oposições de terceiros."
    },
    # 7. ARQUIVAMENTO DEFINITIVO
    "ARQUIVAMENTO": {
        "tipo": "arquivamento",
        "prazo_dias": 0,
        "afeta_prazo": False,
        "status_alerta": "alerta",
        "is_critico": True,
        "fase_inpi": "ARQUIVADO",
        "exigencia_flag": 0,
        "oposicao_flag": 0,
        "descricao_padrao": "Arquivamento definitivo do pedido por ausência de cumprimento de exigência ou renúncia do requerente."
    }
}


def classify_despacho(codigo: str, nome: str) -> dict:
    """Classifica um despacho da RPI com base no código e texto oficial."""
    cod = str(codigo or "").strip().upper()
    txt = str(nome or "").strip().upper()
    
    # Códigos canônicos IPAS / INPI
    if any(k in cod for k in ["IPAS005", "IPAS006", "IPAS007", "IPAS010", "IPAS011", "001"]) or "EXIGÊNCIA" in txt or "EXIGENCIA" in txt:
        rule = DESPACHO_RULES["EXIGENCIA"].copy()
    elif any(k in cod for k in ["IPAS029", "IPAS030", "IPAS031", "002"]) or "OPOSIÇÃO" in txt or "OPOSICAO" in txt:
        rule = DESPACHO_RULES["OPOSICAO"].copy()
    elif any(k in cod for k in ["IPAS157", "IPAS024", "003"]) or "DEFERIMENTO" in txt:
        rule = DESPACHO_RULES["DEFERIMENTO"].copy()
    elif any(k in cod for k in ["IPAS273", "IPAS270", "005"]) or "CONCESSÃO" in txt or "CONCESSAO" in txt:
        rule = DESPACHO_RULES["CONCESSAO"].copy()
    elif any(k in cod for k in ["IPAS161", "004"]) or "INDEFERIMENTO" in txt:
        rule = DESPACHO_RULES["INDEFERIMENTO"].copy()
    elif any(k in cod for k in ["IPAS002", "IPAS003"]) or "PUBLICAÇÃO DE PEDIDO" in txt or "PUBLICACAO" in txt:
        rule = DESPACHO_RULES["PUBLICACAO"].copy()
    elif any(k in cod for k in ["IPAS100", "IPAS101", "IPAS102"]) or "ARQUIVAMENTO" in txt:
        rule = DESPACHO_RULES["ARQUIVAMENTO"].copy()
    else:
        # Fallback genérico
        rule = {
            "tipo": "outros",
            "prazo_dias": 0,
            "afeta_prazo": False,
            "status_alerta": "normal",
            "is_critico": False,
            "fase_inpi": "EM ANDAMENTO",
            "exigencia_flag": 0,
            "oposicao_flag": 0,
            "descricao_padrao": f"Despacho ordinário publicado no INPI: {nome or codigo}"
        }
    
    rule["codigo"] = cod or "IPAS-GEN"
    rule["nome"] = nome or cod or "Despacho Geral INPI"
    return rule


# ==============================================================================
# PARSERS DA RPI (XML E JSON)
# ==============================================================================

def parse_rpi_xml(xml_content: str) -> dict:
    """
    Realiza o parsing de arquivo XML oficial da Revista da Propriedade Industrial (RPI).
    Suporta variações de esquemas de marcas do INPI.
    """
    root = ET.fromstring(xml_content)
    
    # Extrair metadados da revista
    rpi_numero = root.attrib.get("numero") or root.attrib.get("num") or "2850"
    rpi_data = root.attrib.get("data") or root.attrib.get("dataPublicacao") or datetime.now().strftime("%Y-%m-%d")
    
    # Normalizar formato de data YYYY-MM-DD
    if "/" in rpi_data:
        partes = rpi_data.split("/")
        if len(partes) == 3:
            # DD/MM/YYYY -> YYYY-MM-DD
            rpi_data = f"{partes[2]}-{partes[1]}-{partes[0]}"

    despachos_list = []
    
    # Processos podem estar sob <processo>, <processo-marca>, ou diretamente no root
    processos = root.findall(".//processo") or root.findall(".//processo-marca") or root.findall("./processo")
    
    for proc in processos:
        num_proc = proc.attrib.get("numero") or proc.attrib.get("numeroProcesso") or ""
        
        # Obter nome da marca
        marca_elem = proc.find(".//marca") or proc.find("./marca")
        marca_nome = proc.attrib.get("nome") or proc.attrib.get("marca") or ""
        if marca_elem is not None:
            marca_nome = marca_elem.attrib.get("nome") or marca_elem.text or marca_nome
            
        titular_elem = proc.find(".//titular") or proc.find("./titular")
        titular_nome = titular_elem.attrib.get("nome") if titular_elem is not None else ""
        
        # Despachos do processo
        desps = proc.findall(".//despacho") or proc.findall("./despacho")
        if not desps:
            # Caso o próprio processo represente um despacho
            codigo = proc.attrib.get("codigo") or proc.attrib.get("codigoDespacho") or ""
            nome = proc.attrib.get("nomeDespacho") or proc.attrib.get("despacho") or ""
            texto = proc.text or ""
            if codigo or nome:
                despachos_list.append({
                    "numero_processo": normalize_processo(num_proc),
                    "marca": marca_nome.strip(),
                    "titular": titular_nome.strip(),
                    "codigo_despacho": codigo.strip(),
                    "nome_despacho": nome.strip(),
                    "texto_complementar": texto.strip()
                })
        else:
            for d in desps:
                codigo = d.attrib.get("codigo") or d.attrib.get("codigoDespacho") or ""
                nome = d.attrib.get("nome") or d.attrib.get("nomeDespacho") or d.attrib.get("titulo") or ""
                texto = d.attrib.get("texto") or d.text or ""
                despachos_list.append({
                    "numero_processo": normalize_processo(num_proc),
                    "marca": marca_nome.strip(),
                    "titular": titular_nome.strip(),
                    "codigo_despacho": codigo.strip(),
                    "nome_despacho": nome.strip(),
                    "texto_complementar": texto.strip()
                })

    return {
        "numero_rpi": str(rpi_numero).strip(),
        "data_publicacao": str(rpi_data).strip(),
        "total_despachos": len(despachos_list),
        "despachos": despachos_list
    }


def parse_rpi_json(json_content: Union[str, dict]) -> dict:
    """Realiza o parsing de payload JSON de RPI."""
    if isinstance(json_content, str):
        data = json.loads(json_content)
    else:
        data = json_content
        
    rpi_numero = str(data.get("numero_rpi") or data.get("revista") or data.get("rpi_numero") or "2850").strip()
    rpi_data = str(data.get("data_publicacao") or data.get("data") or datetime.now().strftime("%Y-%m-%d")).strip()
    
    if "/" in rpi_data:
        partes = rpi_data.split("/")
        if len(partes) == 3:
            rpi_data = f"{partes[2]}-{partes[1]}-{partes[0]}"
            
    raw_despachos = data.get("despachos") or data.get("processos") or []
    despachos_list = []
    
    for item in raw_despachos:
        num_proc = item.get("numero_processo") or item.get("processo") or item.get("numero") or ""
        marca = item.get("marca") or item.get("brand_name") or item.get("nome") or ""
        titular = item.get("titular") or item.get("client_name") or ""
        codigo = item.get("codigo_despacho") or item.get("codigo") or ""
        nome = item.get("nome_despacho") or item.get("nome") or item.get("despacho") or ""
        texto = item.get("texto_complementar") or item.get("texto") or item.get("complemento") or ""
        
        despachos_list.append({
            "numero_processo": normalize_processo(num_proc),
            "marca": str(marca).strip(),
            "titular": str(titular).strip(),
            "codigo_despacho": str(codigo).strip(),
            "nome_despacho": str(nome).strip(),
            "texto_complementar": str(texto).strip()
        })
        
    return {
        "numero_rpi": rpi_numero,
        "data_publicacao": rpi_data,
        "total_despachos": len(despachos_list),
        "despachos": despachos_list
    }


# ==============================================================================
# MOTOR AUTÔNOMO DE VARREDURA E CRUZAMENTO (RPI SCANNER ENGINE)
# ==============================================================================

class RPIScannerEngine:
    """
    Motor executivo de ingestão da RPI e conciliação com a carteira de processos
    de Registro de Marcas (contratos_rm) da EDV Jr.
    """

    def __init__(self):
        pass

    def scan_and_reconcile(
        self,
        rpi_payload: Union[str, dict],
        format_type: str = "auto",
        current_user_email: str = "sistema.rpi@edvjr.com.br"
    ) -> dict:
        """
        Executa a ingestão da RPI, cruza despachos com contratos_rm,
        atualiza o banco de dados e emite alertas para a Presidência.
        """
        # 1. Parsing da RPI
        if format_type == "xml" or (isinstance(rpi_payload, str) and rpi_payload.strip().startswith("<")):
            parsed = parse_rpi_xml(rpi_payload)
        else:
            parsed = parse_rpi_json(rpi_payload)
            
        rpi_numero = parsed["numero_rpi"]
        rpi_data = parsed["data_publicacao"]
        despachos = parsed["despachos"]
        
        # 2. Obter base de processos cadastrados
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM contratos_rm;")
        rows = cursor.fetchall()
        contratos = [dict(r) for r in rows]
        
        # Construir índices de busca rápida
        mapa_por_processo: Dict[str, dict] = {}
        mapa_por_codigo_rm: Dict[str, dict] = {}
        mapa_por_marca: Dict[str, dict] = {}
        
        for c in contratos:
            if c.get("process_number"):
                mapa_por_processo[normalize_processo(c["process_number"])] = c
            if c.get("rm_code"):
                mapa_por_codigo_rm[str(c["rm_code"]).strip().upper()] = c
            if c.get("brand_name"):
                mapa_por_marca[normalize_marca(c["brand_name"])] = c

        matches_processados = []
        alertas_emitidos = 0
        now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 3. Cruzamento de cada despacho com a base de clientes
        for d in despachos:
            num_proc = d["numero_processo"]
            marca_nome = d["marca"]
            marca_norm = normalize_marca(marca_nome)
            
            contrato_alvo = None
            criterio_match = None
            
            # Tentativa 1: Cruzamento exato por número do processo INPI (9 dígitos)
            if num_proc and num_proc in mapa_por_processo:
                contrato_alvo = mapa_por_processo[num_proc]
                criterio_match = "process_number"
            # Tentativa 2: Cruzamento por nome normalizado da marca
            elif marca_norm and marca_norm in mapa_por_marca:
                contrato_alvo = mapa_por_marca[marca_norm]
                criterio_match = "brand_name"
            # Tentativa 3: Cruzamento por código RM se constar no payload
            elif d.get("rm_code") and str(d["rm_code"]).strip().upper() in mapa_por_codigo_rm:
                contrato_alvo = mapa_por_codigo_rm[str(d["rm_code"]).strip().upper()]
                criterio_match = "rm_code"

            if contrato_alvo:
                contrato_id = contrato_alvo["id"]
                processo_final = contrato_alvo.get("process_number") or num_proc or f"92500{contrato_id:04d}"
                marca_final = contrato_alvo.get("brand_name") or marca_nome
                
                # Classificar despacho
                cls_info = classify_despacho(d["codigo_despacho"], d["nome_despacho"])
                
                # Calcular prazo fatal (se aplicável)
                prazo_dias = cls_info["prazo_dias"]
                data_limite_str = None
                if cls_info["afeta_prazo"] and prazo_dias > 0:
                    try:
                        base_dt = datetime.strptime(rpi_data, "%Y-%m-%d")
                    except Exception:
                        base_dt = datetime.now()
                    prazo_fatal = base_dt + timedelta(days=prazo_dias)
                    data_limite_str = prazo_fatal.strftime("%Y-%m-%d")

                descricao_detalhada = d.get("texto_complementar") or cls_info["descricao_padrao"]

                # A. Inserir no histórico de despachos RPI
                cursor.execute("""
                INSERT INTO rpi_despachos_historico (
                    contrato_id, process_number, brand_name, rpi_numero,
                    rpi_data_publicacao, codigo_despacho, nome_despacho,
                    descricao_detalhada, afeta_prazo, prazo_dias,
                    data_limite_resposta, status_alerta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    contrato_id,
                    processo_final,
                    marca_final,
                    rpi_numero,
                    rpi_data,
                    cls_info["codigo"],
                    cls_info["nome"],
                    descricao_detalhada,
                    1 if cls_info["afeta_prazo"] else 0,
                    prazo_dias,
                    data_limite_str,
                    cls_info["status_alerta"]
                ))

                # B. Atualizar estado do contrato em contratos_rm (estritamente incremental, sem sobrescrever dados cadastrais)
                cursor.execute("""
                UPDATE contratos_rm
                SET rpi_ultimo_status = ?,
                    rpi_ultimo_despacho_codigo = ?,
                    rpi_ultimo_despacho_nome = ?,
                    rpi_numero = ?,
                    rpi_data_auditoria = ?,
                    rpi_prazo_fatal = ?,
                    fase_inpi = ?,
                    rpi_exigencia_pendente = ?,
                    rpi_oposicao_pendente = ?,
                    process_number = COALESCE(process_number, ?),
                    dados_legados_preservados = 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
                """, (
                    cls_info["nome"],
                    cls_info["codigo"],
                    cls_info["nome"],
                    rpi_numero,
                    now_iso,
                    data_limite_str,
                    cls_info["fase_inpi"],
                    cls_info["exigencia_flag"],
                    cls_info["oposicao_flag"],
                    processo_final,
                    contrato_id
                ))

                # C. Gerar Alerta Executivo para a Presidência em caso crítico
                if cls_info["is_critico"]:
                    titulo_alerta = f"🚨 RPI nº {rpi_numero}: Despacho Crítico - Processo {processo_final} ({marca_final})"
                    msg_alerta = (
                        f"A varredura autônoma da RPI nº {rpi_numero} ({rpi_data}) identificou o despacho "
                        f"'{cls_info['nome']}' para a marca {marca_final}. "
                        f"Prazo legal improrrogável de {prazo_dias} dias até {data_limite_str or 'imediato'}. "
                        f"Ação requerida da diretoria e da equipe técnica de Projetos."
                    )
                    
                    try:
                        cursor.execute("""
                        INSERT INTO system_notifications (
                            tenant_id, recipient_email, target_role, target_area,
                            title, message, category, priority, link,
                            is_read, email_sent, metadata_json
                        ) VALUES (
                            'edv_jr', 'charles.junior@edvjr.com.br', 'presidente', 'presidencia',
                            ?, ?, 'audit_alert', 'critical', '#view-projetos',
                            0, 0, ?
                        );
                        """, (
                            titulo_alerta,
                            msg_alerta,
                            json.dumps({
                                "rpi_numero": rpi_numero,
                                "contrato_id": contrato_id,
                                "process_number": processo_final,
                                "brand_name": marca_final,
                                "codigo_despacho": cls_info["codigo"],
                                "prazo_fatal": data_limite_str
                            }, ensure_ascii=False)
                        ))
                        alertas_emitidos += 1
                    except Exception as err_notif:
                        logger.warning(f"Falha ao gerar notificação da RPI para Presidência: {err_notif}")

                matches_processados.append({
                    "contrato_id": contrato_id,
                    "process_number": processo_final,
                    "brand_name": marca_final,
                    "criterio_match": criterio_match,
                    "codigo_despacho": cls_info["codigo"],
                    "nome_despacho": cls_info["nome"],
                    "status_alerta": cls_info["status_alerta"],
                    "prazo_fatal": data_limite_str,
                    "fase_inpi": cls_info["fase_inpi"]
                })

        conn.commit()
        conn.close()

        return {
            "status": "success",
            "rpi_numero": rpi_numero,
            "data_publicacao": rpi_data,
            "total_despachos_lidos": len(despachos),
            "processos_correspondidos": len(matches_processados),
            "alertas_presidencia_gerados": alertas_emitidos,
            "auditoria_executada_em": now_iso,
            "itens_processados": matches_processados
        }


# ==============================================================================
# SIMULAÇÃO DE VARREDURA SEMANAL (TERÇA-FEIRA / INPI)
# ==============================================================================

def simular_varredura_semanal_inpi(rpi_numero: str = "2850") -> dict:
    """
    Gera um pacote demonstrativo de despachos reais da RPI correspondendo aos processos
    cadastrados e executa a conciliação completa.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, rm_code, process_number, brand_name FROM contratos_rm LIMIT 5;")
    amostra = [dict(r) for r in cursor.fetchall()]
    conn.close()

    data_hoje = datetime.now().strftime("%Y-%m-%d")
    
    if not amostra:
        # Criar processos fictícios se a base estiver vazia
        despachos_mock = [
            {
                "numero_processo": "925000001",
                "marca": "Vivacidade",
                "codigo_despacho": "IPAS005",
                "nome_despacho": "Exigência formal (Art. 157 da LPI)",
                "texto_complementar": "Apresentar comprovação de legitimidade das atividades econômicas requeridas na especificação."
            },
            {
                "numero_processo": "925000002",
                "marca": "Sementes Vitória",
                "codigo_despacho": "IPAS273",
                "nome_despacho": "Concessão de registro de marca e expedição de certificado",
                "texto_complementar": "Certificado de registro expedido com vigência decenal assegurada."
            }
        ]
    else:
        despachos_mock = []
        tipos_exemplo = [
            ("IPAS005", "Exigência formal (Art. 157 da LPI)", "Cumprir exigência formal de procuração com poderes específicos."),
            ("IPAS029", "Notificação de oposição (Art. 158 da LPI)", "Oposição tempestiva protocolada por empresa do mesmo segmento mercadológico."),
            ("IPAS157", "Deferimento do pedido de registro", "Abertura do prazo de 60 dias para recolhimento da taxa de primeiro decênio."),
            ("IPAS273", "Concessão de registro de marca", "Expedido certificado definitivo de registro da marca."),
            ("IPAS002", "Publicação de pedido de registro para oposição", "Publicação para abertura de prazo de oposição de terceiros.")
        ]
        for idx, c in enumerate(amostra):
            cod, nome, txt = tipos_exemplo[idx % len(tipos_exemplo)]
            despachos_mock.append({
                "numero_processo": c.get("process_number") or f"92500{c['id']:04d}",
                "marca": c["brand_name"],
                "codigo_despacho": cod,
                "nome_despacho": nome,
                "texto_complementar": txt
            })

    engine = RPIScannerEngine()
    payload = {
        "numero_rpi": rpi_numero,
        "data_publicacao": data_hoje,
        "despachos": despachos_mock
    }
    return engine.scan_and_reconcile(payload, format_type="json")
