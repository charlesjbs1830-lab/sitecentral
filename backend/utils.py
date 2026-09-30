"""
EDbrain - Utilitários de Inteligência de Mercado, Normalização Léxica e FTS5
EDV Jr. - Gestão 2026
"""

import re
import unicodedata
from typing import Optional, List, Set

# Sufixos societários, naturezas jurídicas e termos empresariais comuns que geram ruído na busca
CORPORATE_NOISE_TOKENS: Set[str] = {
    # Tipos societários e regimes
    "ltda", "limitada",
    "sa", "s/a", "s.a", "ss", "s/s",
    "me", "m.e", "epp", "e.p.p",
    "eireli", "slu", "slau",
    "ei", "mei",
    # Atividades genéricas
    "comercio", "comercial", "com",
    "servicos", "servico", "serv", "prestacao",
    "industria", "industrial", "ind",
    "cia", "companhia",
    "sociedade", "unipessoal", "simples",
    "holding", "participacoes", "participacao",
    "matriz", "filial",
    "consultoria", "assessoria",
    # Conectivos e preposições
    "et", "e", "&", "de", "do", "da", "dos", "das", "em", "para", "com"
}

def clean_cnpj(cnpj: Optional[str]) -> str:
    """Extrai apenas os dígitos numéricos de um CNPJ."""
    if not cnpj:
        return ""
    return re.sub(r"\D", "", str(cnpj))

def format_cnpj(clean_digits: Optional[str]) -> str:
    """Formata CNPJ limpo de 14 dígitos no padrão oficial XX.XXX.XXX/YYYY-ZZ."""
    c = clean_cnpj(clean_digits)
    if len(c) == 14:
        return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}"
    return c or ""

def normalize_company_name(name: Optional[str]) -> str:
    """
    Normalizador de Strings Corporativas:
    1. Converte todo o texto para minúsculas e remove acentos/diacríticos.
    2. Expurga sufixos e naturezas jurídicas comuns que geram ruído na busca
       (ex: ltda, s/a, sa, me, epp, eireli, comercio, servicos, industria, et, cia).
    3. Remove pontuações excessivas, garantindo correspondência tolerante a variações.
    """
    if not name or not isinstance(name, str):
        return ""

    # 1. Minúsculas e remoção de acentos/diacríticos (NFKD)
    text = name.lower().strip()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))

    # 2. Tratamento prévio de abreviações compostas com barras ou pontos
    text = re.sub(r"\bs[./\\]?a\b", " sa ", text)
    text = re.sub(r"\bs[./\\]?s\b", " ss ", text)
    text = re.sub(r"\bm[./\\]?e\b", " me ", text)
    text = re.sub(r"\be[./\\]?p[./\\]?p\b", " epp ", text)
    text = re.sub(r"\be[./\\]?i[./\\]?r[./\\]?e[./\\]?l[./\\]?i\b", " eireli ", text)

    # 3. Remoção de pontuações excessivas e caracteres especiais (mantém apenas letras, números e espaços)
    text = re.sub(r"[^\w\s]", " ", text)

    # 4. Tokenização e purga de ruído societário
    raw_tokens = text.split()
    filtered_tokens = [t for t in raw_tokens if t not in CORPORATE_NOISE_TOKENS]

    # Salvaguarda: se todos os tokens forem filtrados (ex: 'Comércio e Serviços LTDA'), mantém os tokens brutos
    if not filtered_tokens:
        filtered_tokens = raw_tokens

    return " ".join(filtered_tokens)

def build_fts5_wildcard_query(search_query: Optional[str]) -> str:
    """
    Construtor de Consulta FTS5 com Injeção Automática de Wildcards (*):
    Intercepta o termo de busca textual, fragmenta por espaços ou tokens alfanuméricos,
    aplica normalização para expurgar ruído quando apropriado, e anexa o operador de prefixo (*)
    a cada token (ex: 'tec' -> 'tec*', 'padaria ze' -> 'padaria* ze*').
    """
    if not search_query or not search_query.strip():
        return ""

    sq = search_query.strip()

    # Se for uma busca numérica (ex: CNPJ parcial ou completo)
    digits = re.sub(r"\D", "", sq)
    if len(digits) >= 8 and digits in sq:
        # Se for CNPJ formatado ou quase completo, extrai os blocos numéricos
        parts = re.findall(r"\d+", sq)
        if parts:
            return " ".join(f"{p}*" for p in parts)

    # Normalizar para obter os termos nucleares sem sufixos societários
    norm = normalize_company_name(sq)
    tokens: List[str] = norm.split() if norm else []

    # Se a normalização resultou em vazio ou removeu demais, usa tokens alfanuméricos do input bruto
    if not tokens:
        tokens = re.findall(r"\w+", sq)

    if not tokens:
        return ""

    # Anexa o operador wildcard (*) do FTS5 a cada token
    clean_regex = re.compile(r"""[*"':()]""")
    clean_regex = re.compile(r"""[*"':()]""")
    return " ".join(sanitized_terms)

def build_address_from_brasilapi(data: dict) -> Optional[str]:
    """Constrói endereço formatado a partir dos metadados da BrasilAPI."""
    addr_parts = []
    if data.get("logradouro"):
        l = data.get("logradouro")
        if data.get("numero"):
            l += f", {data.get('numero')}"
        if data.get("complemento"):
            l += f" ({data.get('complemento')})"
        addr_parts.append(l)
    if data.get("bairro"):
        addr_parts.append(data.get("bairro"))
    if data.get("municipio") and data.get("uf"):
        addr_parts.append(f"{data.get('municipio')} - {data.get('uf')}")
    if data.get("cep"):
        addr_parts.append(f"CEP {data.get('cep')}")
    return " • ".join(addr_parts) if addr_parts else None

def generate_commercial_pitch(lead: dict) -> dict:
    """
    Gerador Dinâmico de Pitches de Abordagem Consultiva (EDV Jr. Scripting Engine):
    Processa metadados corporativos (CNAE, porte, razão social, nome fantasia, tags e notas)
    para redigir abordagens de alta conversão para WhatsApp, Instagram DM e E-mail.
    """
    nome_exibicao = lead.get("nome_fantasia") or lead.get("client_name") or lead.get("razao_social") or "sua empresa"
    contato = lead.get("contact_person") or "Gestor(a)"
    cnae = lead.get("cnae") or "sua área de atuação"
    porte = lead.get("company_size") or "empresa"
    notes = lead.get("notes") or ""
    tags = lead.get("tags") or ""

    # Determinar segmento aproximado a partir do CNAE ou tags
    segmento = "comércio e serviços"
    cnae_lower = str(cnae).lower()
    if any(k in cnae_lower for k in ["panific", "alimento", "restaurante", "bar", "cafe", "pizzaria"]):
        segmento = "alimentação e gastronomia"
    elif any(k in cnae_lower for k in ["estetica", "beleza", "salao", "odonto", "clinica", "saude"]):
        segmento = "saúde e estética"
    elif any(k in cnae_lower for k in ["mecanica", "veiculo", "auto", "pecas", "oficina"]):
        segmento = "automotivo e mecânica"
    elif any(k in cnae_lower for k in ["metalurg", "industria", "fabrica"]):
        segmento = "indústria e manufatura"
    elif any(k in cnae_lower for k in ["roupa", "moda", "calcado", "vestuario"]):
        segmento = "moda e vestuário"
    elif any(k in cnae_lower for k in ["tecnologia", "software", "ti", "digital", "comunic"]):
        segmento = "tecnologia e inovação"

    tese_juridica = (
        f"A {nome_exibicao} atua no segmento de {segmento} ({porte}), onde a identidade de marca "
        f"e a clientela fiel constituem os ativos intangíveis mais valiosos do negócio. Sob a Lei nº 9.279/96 (LPI), "
        f"a propriedade sobre o nome e logotipo só se consolida pelo registro deferido no INPI (princípio da anterioridade). "
        f"Operar sem o registro na classe específica expõe a empresa ao risco de notificação extrajudicial, "
        f"perda definitiva do nome comercial e pagamento de indenizações a terceiros com registro prévio."
    )

    pitch_whatsapp = (
        f"Olá, {contato}! Tudo bem? Aqui é da EDV Jr., consultoria jurídica da faculdade de Direito.\n\n"
        f"Acompanhamos o destaque da *{nome_exibicao}* no setor de {segmento} e, em nosso levantamento semanal de mercado, "
        f"identificamos que o nome e a marca de vocês podem estar desprotegidos perante o INPI nesta classe de atividade.\n\n"
        f"Como empresa júnior do Movimento Empresa Júnior (MEJ), realizamos uma **pesquisa prévia de anterioridade e viabilidade de marca 100% gratuita** "
        f"para apoiar o empresariado capixaba.\n\n"
        f"Você teria 5 minutinhos hoje ou amanhã para enviarmos o relatório resumido de proteção da *{nome_exibicao}* sem nenhum compromisso?"
    )

    pitch_instagram = (
        f"Olá, equipe da @{nome_exibicao}! Tudo bem com vocês?\n\n"
        f"Admiro muito o trabalho e posicionamento que vocês construíram no mercado de {segmento}! 👏\n\n"
        f"Faço parte da EDV Jr., a consultoria jurídica dos alunos de Direito, e notamos que a marca de vocês ainda não possui processo de registro formal averbado no INPI na classe de produtos/serviços principal.\n\n"
        f"No Direito Marcário, quem registra primeiro é o dono da marca. Para prevenir que qualquer concorrente copie o nome de vocês, rodamos um diagnóstico gratuito de anterioridade para empresas da nossa região.\n\n"
        f"Podemos enviar o resultado do diagnóstico para vocês darem uma olhada sem nenhum custo? Abraço!"
    )

    pitch_email = (
        f"Prezado(a) {contato},\n\n"
        f"Espero que este e-mail o encontre bem.\n\n"
        f"Meu nome é da equipe comercial da EDV Jr., a empresa júnior de consultoria jurídica vinculada à Faculdade de Direito e federada à Brasil Júnior (MEJ).\n\n"
        f"Identificamos que a {nome_exibicao} ({porte}) desempenha papel relevante no segmento de {segmento} ({cnae}). "
        f"Contudo, em nossa varredura analítica de conformidade, observamos a ausência de registro marcário deferido para a sua denominação comercial junto ao Instituto Nacional da Propriedade Industrial (INPI).\n\n"
        f"De acordo com a Lei de Propriedade Industrial (Lei 9.279/96), o registro é o único instrumento legal que assegura a exclusividade nacional do uso do nome e impede que concorrentes usem identidade similar.\n\n"
        f"Gostaríamos de disponibilizar para a {nome_exibicao} um Relatório Técnico de Viabilidade Marcária Gratuito, acompanhado de supervisão técnica.\n\n"
        f"Podemos agendar uma breve apresentação de 15 minutos nesta quinta ou sexta-feira?\n\n"
        f"Atenciosamente,\n"
        f"Equipe de Relações Comerciais & Propriedade Intelectual\n"
        f"EDV Jr. • Consultoria Jurídica de Direito"
    )

    return {
        "client_name": nome_exibicao,
        "segmento": segmento,
        "tese_juridica": tese_juridica,
        "whatsapp": pitch_whatsapp,
        "instagram": pitch_instagram,
        "email": pitch_email
    }
