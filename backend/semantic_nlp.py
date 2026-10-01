"""
EDV Jr. - Camada de Processamento Semântico, Filtragem de Intenção e Matriz Combinatória
Módulo NLP Heurístico e Motor Algorítmico de Montagem de Trilhas de Desenvolvimento (EDbrain).
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple, Any

# ==============================================================================
# 1. TAXONOMIAS E DICIONÁRIOS LÉXICOS (BRASIL JÚNIOR & HARD/SOFT SKILLS)
# ==============================================================================

TOKENS_HARD_SKILLS = {
    # Comercial e Vendas
    "vendas", "venda", "comercial", "crm", "lead", "leads", "prospecção", "prospeccao",
    "spin", "negociação", "negociacao", "contrato", "contratos", "proposta", "propostas",
    "margem", "conversão", "conversao", "radar", "b2b", "fechamento", "funil", "pipeline",
    # Projetos e Registro de Marcas
    "inpi", "marca", "marcas", "registro", "ncl", "nice", "anterioridade", "rpi",
    "oposição", "oposicao", "recurso", "patente", "patentes", "protocolo", "despacho",
    # Jurídico e Compliance
    "estatuto", "regimento", "lei", "compliance", "lgpd", "selo ej", "certidão", "certidao",
    "parecer", "minuta", "cláusula", "clausula", "societário", "societario",
    # Financeiro e Tesouraria
    "obz", "dre", "fluxo de caixa", "conciliação", "conciliacao", "tesouraria",
    "faturamento", "nota fiscal", "precificação", "precificacao", "inadimplência", "inadimplencia",
    # Marketing e Criação
    "inbound", "outbound", "reels", "copywriting", "tráfego", "trafego", "social media",
    "campanha", "campanhas", "engajamento", "conteúdo", "conteudo", "design"
}

TOKENS_COMPETENCIAS_MEJ = {
    "lideranca": {
        "liderança", "lideranca", "liderar", "equipe", "time", "motivar", "motivação", "motivacao",
        "engajar", "engajamento", "delegar", "delegação", "delegacao", "inspiração", "inspiracao",
        "conselho", "assembleia", "condução", "conducao", "feedback", "gestão de pessoas",
        "gestao de pessoas", "sucessão", "sucessao", "formação", "formacao", "cultura", "exemplo"
    },
    "gestao": {
        "gestão", "gestao", "processo", "processos", "prazo", "prazos", "cronograma", "rotina",
        "rotinas", "organização", "organizacao", "sprint", "sla", "pop", "priorização", "priorizacao",
        "backlog", "planejamento", "tempo", "disciplina", "produtividade", "método", "metodo",
        "metodologia", "eficiência", "eficiencia", "execução", "execucao"
    },
    "visao_sistemica": {
        "visão sistêmica", "visao sistemica", "sistêmica", "sistemica", "ecossistema", "federação",
        "federacao", "fejemg", "fejep", "brasil júnior", "brasil junior", "bj", "mej",
        "intersetorial", "estratégia", "estrategia", "planejamento estratégico", "alinhamento",
        "sustentabilidade", "governança", "governanca", "propósito", "proposito", "cadeia de valor",
        "macro", "visão macro", "visao macro"
    },
    "orientacao_resultados": {
        "orientação para resultados", "orientacao para resultados", "resultados", "resultado",
        "meta", "metas", "conversão", "conversao", "atingimento", "fechamento", "receita",
        "faturamento", "impacto", "alta performance", "indicador", "indicadores", "kpi", "okr",
        "superação", "superacao", "entrega", "entregas", "foco em resultados", "lucro"
    },
    "autoconhecimento": {
        "autoconhecimento", "inteligência emocional", "inteligencia emocional", "escuta ativa",
        "postura", "vulnerabilidade", "resiliência", "resiliencia", "1-on-1", "one-on-one",
        "reflexão", "reflexao", "relacionamento", "relacionamentos", "empatia", "diálogo",
        "dialogo", "autoavaliação", "autoavaliacao", "maturidade", "intrapessoal", "comportamento",
        "comportamental", "autocrítica", "autocritica"
    }
}

# ==============================================================================
# 2. DETECTOR DE DESVIO DE ESCOPO / ANOMALIAS COLOQUIAIS
# ==============================================================================

PATTERNS_ANOMALIAS = [
    # Afetivo / Relacionamentos amorosos
    (
        r"\b(namorad[oa]|crush|dudinha|moz[aã]o|amor|beij[oa]r?|casar|casamento|paix[aã]o|romance)\b",
        "afetivo_interpessoal",
        "Inteligência Interpessoal, Gestão de Equilíbrio Emocional e Gestão de Tempo / Priorização em Relações de Confiança",
        ["autoconhecimento", "gestao"],
        "soft_skills",
        "A intenção afetiva/interpessoal foi canalizada pelo motor adaptativo para o desenvolvimento de competências socioemocionais, inteligência interpessoal e gestão equilibrada de tempo entre vida pessoal e rotina corporativa da EJ."
    ),
    # Lazer / Sono / Preguiça / Entretenimento pessoal
    (
        r"\b(dormir|pregui[çc]a|sono|ressaca|videogame|jogar|playstation|xbox|netflix|s[ée]rie|balada|cerveja|festa|farra)\b",
        "lazer_rotina_pessoal",
        "Autogestão de Rotinas, Disciplina Operacional e Produtividade Pessoal sob Pressão",
        ["gestao", "autoconhecimento"],
        "soft_skills",
        "A expressão de cansaço ou necessidade de lazer foi traduzida adaptativamente em técnicas de autogestão de rotinas, controle de cronograma e disciplina produtiva nas sprints."
    ),
    # Enriquecimento ilusório / Jogos de azar
    (
        r"\b(ficar rico|ficar milion[áa]rio|loteria|mega-sena|ficar bilion[áa]rio|dinheiro f[áa]cil)\b",
        "enriquecimento_ilusorio",
        "Gestão Financeira Estratégica, Precificação e Orientação para Resultados Sustentáveis",
        ["orientacao_resultados", "gestao"],
        "hard_skills",
        "O anseio financeiro pessoal foi canalizado para competências corporativas de viabilidade econômica, inteligência orçamentária e geração de valor no MEJ."
    )
]

# ==============================================================================
# 3. CLASSE DE PROCESSAMENTO SEMÂNTICO (SEMANTIC INTENT PROCESSOR)
# ==============================================================================

class SemanticIntentProcessor:
    """
    Submete o foco de desenvolvimento inserido pelo usuário a uma validação,
    classificação semântica em eixos de habilidades e saneamento de desvio de escopo.
    """

    def __init__(self, modo_saneamento: str = "adaptive"):
        self.modo_saneamento = (modo_saneamento or "adaptive").lower().strip()

    def processar_foco(self, texto_foco: Optional[str]) -> Dict[str, Any]:
        """
        Analisa e classifica o foco textual inserido.
        Retorna dicionário estruturado com tokens, eixos, pesos e interpretação corporativa.
        """
        if not texto_foco or not texto_foco.strip():
            return {
                "foco_original": None,
                "status": "sem_foco",
                "is_anomalia": False,
                "eixo_predominante": "geral",
                "tokens_detectados": [],
                "competencias_alvo": [],
                "interpretacao_corporativa": "Desenvolvimento equilibrado conforme gaps mapeados da área.",
                "fator_modulacao_alpha": 1.0,
                "alerta_governanca": None
            }

        texto_limpo = texto_foco.strip()
        texto_lower = texto_limpo.lower()

        # 1. Verificar se há desvio de escopo / anomalia
        for regex_pat, tipo_anomalia, trad_corp, comps, eixo, justificativa in PATTERNS_ANOMALIAS:
            if re.search(regex_pat, texto_lower, re.IGNORECASE):
                if self.modo_saneamento == "restrictive":
                    return {
                        "foco_original": texto_limpo,
                        "status": "rejeitado_restritivo",
                        "is_anomalia": True,
                        "error_detail": (
                            f"[Modo Restritivo MEJ] Desvio de escopo detectado: o foco inserido ('{texto_limpo}') não possui aderência "
                            f"às competências corporativas do MEJ ou da Brasil Júnior. Redefina seu objetivo "
                            f"com foco em Liderança, Gestão, Vendas, Projetos ou Autoconhecimento."
                        )
                    }

                # Modo Adaptativo (Inteligente)
                return {
                    "foco_original": texto_limpo,
                    "status": "adaptado_inteligente",
                    "is_anomalia": True,
                    "tipo_anomalia": tipo_anomalia,
                    "eixo_predominante": eixo,
                    "tokens_detectados": [m.group(0) for m in re.finditer(regex_pat, texto_lower, re.IGNORECASE)],
                    "competencias_alvo": comps,
                    "interpretacao_corporativa": trad_corp,
                    "fator_modulacao_alpha": 1.45,
                    "alerta_governanca": justificativa
                }

        # 2. Extração de Tokens de Hard Skills e Soft Skills
        tokens_encontrados_hard = []
        for th in TOKENS_HARD_SKILLS:
            if re.search(r"\b" + re.escape(th) + r"\b", texto_lower):
                tokens_encontrados_hard.append(th)

        competencias_detectadas = {}
        for comp_key, token_set in TOKENS_COMPETENCIAS_MEJ.items():
            matches = [t for t in token_set if re.search(r"\b" + re.escape(t) + r"\b", texto_lower)]
            if matches:
                competencias_detectadas[comp_key] = matches

        total_hard = len(tokens_encontrados_hard)
        total_soft = sum(len(m) for m in competencias_detectadas.values())

        if total_hard == 0 and total_soft == 0:
            # Texto não reconhecido nas taxonomias corporativas
            if self.modo_saneamento == "restrictive" and len(texto_limpo) > 3:
                return {
                    "foco_original": texto_limpo,
                    "status": "rejeitado_restritivo",
                    "is_anomalia": True,
                    "error_detail": (
                        f"Termo corporativo não reconhecido: '{texto_limpo}'. "
                        f"Utilize termos vinculados às competências da Brasil Júnior ou entregáveis da EDV Jr."
                    )
                }

            # Modo adaptativo para texto genérico
            return {
                "foco_original": texto_limpo,
                "status": "adaptado_inteligente",
                "is_anomalia": False,
                "eixo_predominante": "hibrido",
                "tokens_detectados": [texto_limpo[:30]],
                "competencias_alvo": ["orientacao_resultados", "lideranca"],
                "interpretacao_corporativa": f"Aprofundamento temático focado em: {texto_limpo}",
                "fator_modulacao_alpha": 1.25,
                "alerta_governanca": "Foco personalizado incorporado com modulação moderada de prioridade."
            }

        # Classificação do Eixo Predominante
        if total_hard > total_soft:
            eixo_pred = "hard_skills"
        elif total_soft > total_hard:
            eixo_pred = "soft_skills"
        else:
            eixo_pred = "hibrido"

        # Definir competências-alvo primárias
        comps_alvo = list(competencias_detectadas.keys())
        if not comps_alvo:
            if "vendas" in tokens_encontrados_hard or "crm" in tokens_encontrados_hard:
                comps_alvo = ["orientacao_resultados"]
            elif "inpi" in tokens_encontrados_hard or "contrato" in tokens_encontrados_hard:
                comps_alvo = ["gestao"]
            elif "obz" in tokens_encontrados_hard or "dre" in tokens_encontrados_hard:
                comps_alvo = ["gestao", "orientacao_resultados"]
            else:
                comps_alvo = ["orientacao_resultados"]

        # Modulação Alpha: 1.30 a 1.60 dependendo da densidade de tokens
        densidade = total_hard + total_soft
        alpha = min(1.65, round(1.20 + (densidade * 0.08), 2))

        all_tokens = tokens_encontrados_hard + [t for sub in competencias_detectadas.values() for t in sub]

        return {
            "foco_original": texto_limpo,
            "status": "validado_direto",
            "is_anomalia": False,
            "eixo_predominante": eixo_pred,
            "tokens_detectados": list(set(all_tokens)),
            "competencias_alvo": comps_alvo,
            "interpretacao_corporativa": f"Ênfase técnica e comportamental direcionada em: {texto_limpo}",
            "fator_modulacao_alpha": alpha,
            "alerta_governanca": None
        }


# ==============================================================================
# 4. MATRIZ COMBINATÓRIA PONDERADA (SCORE DE URGÊNCIA POR MICRO-COMPETÊNCIA)
# ==============================================================================

def calcular_matriz_combinatoria(
    gaps_360: Dict[str, float],
    hard_data: Dict[str, float],
    analise_foco: Dict[str, Any]
) -> Dict[str, Any]:
    r"""
    Cruza três vetores independentes:
    - Vetor G: Gaps 360º calibrados (Brasil Júnior).
    - Vetor H: Hard Data operacional (CRM, Projetos, Financeiro, Assiduidade).
    - Vetor F: Fator de modulação semântica do foco customizado (\alpha).

    Fórmula:
    U_c = (0.55 * \Delta G_c + 0.45 * \Delta H_c) * F_c
    """
    BENCHMARK_ESPERADO = 80.0  # Nota 4.0 na escala de 100

    competencias = ["lideranca", "gestao", "visao_sistemica", "orientacao_resultados", "autoconhecimento"]

    # 1. Vetor G (Delta Gaps 360º)
    vetor_g = {}
    for c in competencias:
        score_360 = gaps_360.get(c, 70.0)
        delta_g = max(0.0, round(BENCHMARK_ESPERADO - score_360, 2))
        vetor_g[c] = delta_g

    # 2. Vetor H (Hard Data Deficits)
    # hard_data contém: conversion_score, project_punctuality_score, revenue_score, assiduidade_score
    conv = hard_data.get("conversion_score", 70.0)
    punct = hard_data.get("project_punctuality_score", 75.0)
    rev = hard_data.get("revenue_score", 70.0)
    assid = hard_data.get("assiduidade_score", 85.0)

    hard_competency_scores = {
        "orientacao_resultados": 0.60 * ((conv + rev) / 2.0) + 0.40 * assid,
        "gestao": 0.70 * punct + 0.30 * assid,
        "lideranca": 0.60 * assid + 0.40 * punct,
        "visao_sistemica": 0.50 * conv + 0.50 * punct,
        "autoconhecimento": 0.70 * assid + 0.30 * punct
    }

    vetor_h = {}
    for c in competencias:
        score_h = hard_competency_scores.get(c, 70.0)
        delta_h = max(0.0, round(100.0 - score_h, 2))
        vetor_h[c] = delta_h

    # 3. Vetor F (Foco Especial Parametrizado)
    alpha = analise_foco.get("fator_modulacao_alpha", 1.0)
    comps_alvo = analise_foco.get("competencias_alvo", [])

    vetor_f = {}
    for c in competencias:
        vetor_f[c] = alpha if c in comps_alvo else 1.0

    # 4. Cálculo do Score de Urgência Combinado U_c
    urgency_scores = {}
    for c in competencias:
        u_val = (0.55 * vetor_g[c] + 0.45 * vetor_h[c]) * vetor_f[c]
        urgency_scores[c] = round(u_val, 2)

    # Ordenar por criticidade decrescente
    sorted_urgency = sorted(urgency_scores.items(), key=lambda x: x[1], reverse=True)

    return {
        "vetor_g_gaps_360": vetor_g,
        "vetor_h_hard_data": vetor_h,
        "vetor_f_foco": vetor_f,
        "scores_urgencia": dict(sorted_urgency),
        "competencias_ordenadas": [k for k, v in sorted_urgency],
        "competencia_mais_critica": sorted_urgency[0][0] if sorted_urgency else "gestao"
    }


# ==============================================================================
# 5. GERADOR DE HASH CRIPTOGRÁFICO DE SINGULARIDADE
# ==============================================================================

def gerar_hash_singularidade(
    user_email: str,
    urgency_scores: Dict[str, float],
    microblock_codes: List[str]
) -> str:
    """
    Gera assinatura SHA-256 única da trilha baseada na identidade, nos scores de urgência
    e na combinação exata dos micro-blocos gerados.
    """
    payload_str = f"{user_email.lower().strip()}|{sorted(urgency_scores.items())}|{sorted(microblock_codes)}"
    return hashlib.sha256(payload_str.encode("utf-8")).hexdigest()


# ==============================================================================
# 6. MOTOR DE MONTAGEM ALGORÍTMICA (ASSEMBLY LINE DE MICRO-BLOCOS ATÔMICOS)
# ==============================================================================

def montar_trilha_algoritmica(
    member: dict,
    foco_adicional: Optional[str] = None,
    modo_saneamento: str = "adaptive",
    triangulacao: Optional[dict] = None,
    all_microblocks: Optional[List[dict]] = None
) -> Dict[str, Any]:
    """
    Substitui os templates monolíticos fixos pela montagem dinâmica de 4 a 6
    micro-blocos atômicos baseados na matriz combinatória ponderada de gaps e foco semântico.
    """
    # 1. Processamento Semântico do Foco
    processor = SemanticIntentProcessor(modo_saneamento=modo_saneamento)
    analise_foco = processor.processar_foco(foco_adicional)

    # Se modo restritivo e desvio detectado -> interrompe com erro de governança
    if analise_foco.get("status") == "rejeitado_restritivo":
        return {
            "error": True,
            "status_code": 400,
            "detail": analise_foco.get("error_detail", "Foco rejeitado pelo modo restritivo de governança.")
        }

    # 2. Dados de Gaps 360º e Hard Data da Triangulação
    triang = triangulacao or {}
    gaps_360 = triang.get("soft_scores_calibrated") or {
        "lideranca": 70.0, "gestao": 70.0, "visao_sistemica": 70.0,
        "orientacao_resultados": 70.0, "autoconhecimento": 70.0
    }
    hard_data = triang.get("hard_data") or {
        "conversion_score": 70.0,
        "project_punctuality_score": 75.0,
        "revenue_score": 70.0,
        "assiduidade_score": 85.0
    }

    # 3. Matriz Combinatória Ponderada (Vetor G, H, F -> U_c)
    matriz = calcular_matriz_combinatoria(gaps_360, hard_data, analise_foco)
    scores_urgencia = matriz["scores_urgencia"]
    competencias_ordenadas = matriz["competencias_ordenadas"]

    # 4. Obter Catálogo de Micro-Blocos Atômicos
    if all_microblocks is None:
        try:
            from database import list_learning_microblocks
        except ImportError:
            from backend.database import list_learning_microblocks
        blocks_pool = list_learning_microblocks()
    else:
        blocks_pool = list(all_microblocks)

    user_role = (member.get("role") or "assessor").lower().strip()
    user_area = (member.get("area") or "Projetos").strip()
    user_nome = member.get("nome") or "Colaborador"
    user_email = (member.get("email") or "").lower().strip()

    # Filtro de elegibilidade de blocos para o membro (área compatível e nível hierárquico)
    def is_eligible_block(b: dict) -> bool:
        area_match = b.get("area") in {user_area, "Cross-Setorial"}
        level = (b.get("hierarchical_level") or "todos").lower().strip()
        level_match = level in {user_role, "todos"}
        if user_role in {"presidente", "diretor"} and level in {"gerente", "assessor"}:
            level_match = True
        return area_match and level_match

    eligible_blocks = [b for b in blocks_pool if is_eligible_block(b)]
    if len(eligible_blocks) < 6:
        # Fallback de segurança: expandir para todos os blocos cross-setoriais
        eligible_blocks = [b for b in blocks_pool if b.get("area") in {user_area, "Cross-Setorial"}]

    # 5. Montagem Algorítmica da Trilha (Assembly Line - Seleção de 4 a 6 blocos)
    selected_blocks: List[dict] = []
    selected_codes = set()

    # A. Priorizar as 2 competências com maior Score de Urgência
    top_competencies = competencias_ordenadas[:2]
    foco_comps = analise_foco.get("competencias_alvo", [])
    for fc in foco_comps:
        if fc not in top_competencies:
            top_competencies.append(fc)

    # Coleta de blocos para as competências prioritárias
    for comp in top_competencies:
        c_blocks = [b for b in eligible_blocks if b.get("competency_mej") == comp and b["code"] not in selected_codes]
        
        # Preferir Hard Skill
        hards = [b for b in c_blocks if b.get("eixo") == "hard_skills"]
        if hards:
            b_chosen = hards[0]
            b_copy = dict(b_chosen)
            b_copy["justificativa_algoritmica"] = (
                f"Priorizado pelo Score de Urgência ({scores_urgencia.get(comp, 0.0)}) na competência '{comp}', "
                f"abordando déficit técnico em {b_copy.get('area')}."
            )
            selected_blocks.append(b_copy)
            selected_codes.add(b_copy["code"])

        # Preferir Soft Skill
        softs = [b for b in c_blocks if b.get("eixo") == "soft_skills" and b["code"] not in selected_codes]
        if softs:
            b_chosen = softs[0]
            b_copy = dict(b_chosen)
            b_copy["justificativa_algoritmica"] = (
                f"Priorizado pelo Score de Urgência ({scores_urgencia.get(comp, 0.0)}) na competência '{comp}', "
                f"alavancando postura comportamental e liderança."
            )
            selected_blocks.append(b_copy)
            selected_codes.add(b_copy["code"])

        if len(selected_blocks) >= 5:
            break

    # B. Se ainda tiver menos de 4 blocos, preencher com blocos da área específica
    if len(selected_blocks) < 4:
        area_blocks = [b for b in eligible_blocks if b.get("area") == user_area and b["code"] not in selected_codes]
        for b in area_blocks:
            b_copy = dict(b)
            b_copy["justificativa_algoritmica"] = f"Selecionado para reforço operacional do core business da área de {user_area}."
            selected_blocks.append(b_copy)
            selected_codes.add(b_copy["code"])
            if len(selected_blocks) >= 4:
                break

    # C. Se ainda tiver menos de 5 blocos, preencher com qualquer bloco elegível
    for b in eligible_blocks:
        if len(selected_blocks) >= 5:
            break
        if b["code"] not in selected_codes:
            b_copy = dict(b)
            b_copy["justificativa_algoritmica"] = "Selecionado para nivelamento multidimensional de competências."
            selected_blocks.append(b_copy)
            selected_codes.add(b_copy["code"])

    # Limitar entre 4 e 6 blocos no máximo
    selected_blocks = selected_blocks[:6]

    # Garantir evaluation_metric em todos os blocos selecionados
    for b in selected_blocks:
        if not b.get("evaluation_metric"):
            b["evaluation_metric"] = f"Aprovação formal do {b.get('deliverable_format', 'Entregável')} pela liderança e conformidade com SLA."

    # 6. Síntese dos Entregáveis, Hard Skills, Soft Skills e Metas
    hard_skills_prioritarias = [
        f"{b['title']} ({b.get('deliverable_format', 'Entregável')})"
        for b in selected_blocks if b.get("eixo") == "hard_skills"
    ]
    soft_skills_essenciais = [
        f"{b['title']} (Competência: {b.get('competency_mej', '').replace('_', ' ').title()})"
        for b in selected_blocks if b.get("eixo") == "soft_skills"
    ]
    acoes_praticas = [
        f"[{b['code']}] {b['title']}: {b['description']} [Formato: {b.get('deliverable_format', 'Entregável')}]"
        for b in selected_blocks
    ]

    # Se houver foco adicional, incorporar nas ações práticas e skills prioritárias para compatibilidade total
    if foco_adicional and foco_adicional.strip():
        foco_clean = foco_adicional.strip()
        interp_corp_prev = analise_foco.get("interpretacao_corporativa", foco_clean)
        acoes_praticas.append(f"Foco de Desenvolvimento: {foco_clean} (Interpretação MEJ: {interp_corp_prev})")
        if analise_foco.get("eixo_predominante") == "hard_skills":
            hard_skills_prioritarias.append(f"{foco_clean} (Foco Prioritário Customizado)")
        elif analise_foco.get("eixo_predominante") == "soft_skills":
            soft_skills_essenciais.append(f"{foco_clean} (Foco Comportamental Customizado)")

    # Ordenar metas por prazo sugerido
    sorted_by_deadline = sorted(selected_blocks, key=lambda x: x.get("suggested_deadline_days", 30))
    metas_com_prazos = [
        {
            "marco": f"Conclusão do Bloco {b['code']}: {b['title']}",
            "prazo_dias": b.get("suggested_deadline_days", 30),
            "formato": b.get("deliverable_format", "Relatório"),
            "complexidade": b.get("complexity", 2)
        }
        for b in sorted_by_deadline
    ]

    # Objetivos sugeridos contextualizados
    comp_mais_critica = matriz["competencia_mais_critica"].replace("_", " ").title()
    interp_corp = analise_foco.get("interpretacao_corporativa")
    
    objetivos_sugeridos = [
        f"Superar a defasagem prioritária na competência de {comp_mais_critica} (Score de Urgência: {scores_urgencia.get(matriz['competencia_mais_critica'], 0.0)}).",
        f"Executar {len(selected_blocks)} micro-entregáveis atômicos garantindo 100% de conformidade com os SLAs operacionais de {user_area}.",
        f"Consolidar foco estratégico em: {interp_corp} com aplicação prática no ciclo de gestão."
    ]

    if user_role == "presidente":
        diretriz_hierarquica = "Liderança de conselho, governança executiva, representação institucional no MEJ nacional e PE 25-27."
    elif user_role == "diretor":
        diretriz_hierarquica = "Liderança de diretoria, gestão de equipes, cumprimento de metas do PE e alinhamento cross-setorial."
    elif user_role == "gerente":
        diretriz_hierarquica = "Gestão tática direta de projetos, garantia de prazos críticos do INPI/SLA, delegação e condução de ritos."
    else:
        diretriz_hierarquica = f"Execução com excelência técnica na área de {user_area}, protagonismo operacional e evolução para liderança."

    sig_hash = gerar_hash_singularidade(user_email, scores_urgencia, [b["code"] for b in selected_blocks])

    return {
        "membro": {
            "nome": user_nome,
            "email": user_email,
            "area": user_area,
            "cargo": member.get("cargo") or f"{user_role.capitalize()} de {user_area}",
            "role": user_role
        },
        "diretriz_hierarquica": diretriz_hierarquica,
        "analise_foco_semantico": analise_foco,
        "matriz_combinatoria": {
            "vetor_g_gaps_360": matriz["vetor_g_gaps_360"],
            "vetor_h_hard_data": matriz["vetor_h_hard_data"],
            "vetor_f_foco": matriz["vetor_f_foco"],
            "scores_urgencia": scores_urgencia,
            "competencias_ordenadas": competencias_ordenadas,
            "competencia_mais_critica": matriz["competencia_mais_critica"]
        },
        "micro_blocos_selecionados": selected_blocks,
        "total_microblocos": len(selected_blocks),
        "singularidade_hash": sig_hash,
        "objetivos_sugeridos": objetivos_sugeridos,
        "hard_skills_prioritarias": hard_skills_prioritarias,
        "soft_skills_essenciais": soft_skills_essenciais,
        "acoes_praticas_edv": acoes_praticas,
        "metas_com_prazos": metas_com_prazos
    }
