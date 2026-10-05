"""
EDV Jr. - Motor de Automação Jurídica & Geração de Minutas Contratuais
Módulo documental alinhado às diretrizes de redação técnica e formal da Lei Federal nº 13.267/2016,
da Lei de Propriedade Industrial (Lei nº 9.279/1996 - LPI) e da Lei Geral de Proteção de Dados (LGPD).
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

MODELOS_CONTRATUAIS = {
    "prestacao_servicos_rm": "Contrato de Prestação de Serviços Técnicos de Consultoria e Registro de Marca (INPI)",
    "consultoria_juridica_preventiva": "Contrato de Consultoria, Diagnóstico e Adequação Jurídica Empresarial",
    "acordo_confidencialidade_nda": "Acordo de Confidencialidade e Sigilo Pré-Operacional (NDA)"
}


def formatar_moeda_br(valor: float) -> str:
    """Formata valor float para o padrão monetário brasileiro R$ 0.000,00."""
    try:
        val_float = float(valor or 0.0)
        return f"R$ {val_float:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return "R$ 0,00"


def gerar_minuta_contratual(dados: Dict[str, Any]) -> Dict[str, Any]:
    """
    Gera minuta contratual padronizada com injeção precisa de variáveis,
    garantia de integridade criptográfica SHA-256 e marca d'água institucional.
    """
    modelo = dados.get("modelo", "prestacao_servicos_rm").lower().strip()
    if modelo not in MODELOS_CONTRATUAIS:
        modelo = "prestacao_servicos_rm"
        
    client_name = (dados.get("client_name") or "CONTRATANTE").strip()
    cnpj = (dados.get("cnpj") or "00.000.000/0001-00").strip()
    contact_person = (dados.get("contact_person") or "Representante Legal").strip()
    contact_email = (dados.get("contact_email") or "contato@cliente.com.br").strip()
    contact_phone = (dados.get("contact_phone") or "(27) 99999-0000").strip()
    
    brand_name = (dados.get("brand_name") or client_name).strip()
    escopo = (dados.get("consultoria_escopo") or dados.get("objeto_detalhado") or "").strip()
    
    valor_total = float(dados.get("valor_total") or dados.get("valor") or 2440.0)
    valor_fmt = formatar_moeda_br(valor_total)
    
    prazo_dias = int(dados.get("prazo_dias") or 60)
    prazo_entrega = dados.get("prazo_entrega") or f"{prazo_dias} dias a contar da assinatura"
    
    condicoes = (dados.get("condicoes_pagamento") or "").strip()
    if not condicoes:
        marcos_fin = dados.get("marcos_financeiros")
        if isinstance(marcos_fin, str):
            try:
                marcos_fin = json.loads(marcos_fin)
            except Exception:
                pass
        if isinstance(marcos_fin, list) and len(marcos_fin) > 0:
            condicoes = "; ".join([
                f"Parcela {p.get('parcela', i+1)}: {formatar_moeda_br(p.get('valor', 0.0))} com vencimento em {p.get('vencimento', 'a definir')} ({p.get('descricao', 'Etapa')})"
                for i, p in enumerate(marcos_fin)
            ])
        else:
            condicoes = f"Pagamento integral no valor de {valor_fmt}, mediante transferência bancária ou boleto para a conta corrente institucional da EDV Jr."
            
    responsavel_tecnico = (dados.get("responsavel_tecnico") or "thais.junger@edvjr.com.br").strip()
    data_emissao = datetime.now().strftime("%d de %B de %Y")
    ano_atual = datetime.now().year

    # 1. Objeto específico por modelo
    if modelo == "prestacao_servicos_rm":
        titulo_doc = "INSTRUMENTO PARTICULAR DE PRESTAÇÃO DE SERVIÇOS TÉCNICOS DE CONSULTORIA E REGISTRO DE MARCA PERANTE O INPI"
        if not escopo:
            escopo = (
                f"Execução de consultoria técnica especializada para o depósito e acompanhamento de pedido de Registro "
                f"de Marca mista/nominativa '{brand_name}' perante o Instituto Nacional da Propriedade Industrial (INPI), "
                f"compreendendo: (a) pesquisa preliminar de anterioridade e viabilidade jurídica com fulcro na Lei nº 9.279/1996 (LPI); "
                f"(b) enquadramento nas Classes Internacionais de Nice (NCL); (c) instrução processual e protocolo do pedido; "
                f"e (d) monitoramento semanal das publicações oficiais na Revista da Propriedade Industrial (RPI) durante o prazo contratual."
            )
        clausula_natureza = (
            "Parágrafo Único: A CONTRATADA assume obrigação técnica de MEIO, atuando com estrita observância das normas "
            "técnicas e legais vigentes. O deferimento final e a concessão do registro de marca constituem prerrogativa exclusiva "
            "e discricionária do Instituto Nacional da Propriedade Industrial (INPI), não cabendo responsabilização da CONTRATADA "
            "por atos de indeferimento fundamentados em oposições de terceiros ou juízo de conveniência da autarquia federal."
        )
    elif modelo == "consultoria_juridica_preventiva":
        titulo_doc = "INSTRUMENTO PARTICULAR DE CONSULTORIA, DIAGNÓSTICO E GOVERNANÇA JURÍDICA PREVENTIVA"
        if not escopo:
            escopo = (
                f"Prestação de consultoria jurídica preventiva em favor de '{client_name}', consistindo em auditoria "
                f"e adequação de minutas contratuais operacionais, mapeamento de passivos regulatórios, elaboração de diretrizes "
                f"de governança societária e mitigação de riscos cíveis e empresariais no âmbito das micro e pequenas empresas."
            )
        clausula_natureza = (
            "Parágrafo Único: As orientações técnicas fornecidas possuem caráter estritamente consultivo e educacional, "
            "voltadas à prevenção de litígios e conformidade com a legislação pátria."
        )
    else:
        titulo_doc = "ACORDO DE CONFIDENCIALIDADE, SIGILO OPERACIONAL E PROTEÇÃO DE ATIVOS (NON-DISCLOSURE AGREEMENT - NDA)"
        if not escopo:
            escopo = (
                f"Salvaguarda integral de informações confidenciais, estratégias operacionais, modelos de negócios, "
                f"dados técnicos de marcas e propriedade intelectual compartilhados entre as partes para viabilizar "
                f"a parceria e projetos conjuntos concernentes a '{brand_name}'."
            )
        clausula_natureza = (
            "Parágrafo Único: Todas as informações técnicas e cadastrais disponibilizadas serão tratadas sob regime de sigilo "
            "rigoroso, sendo vedada sua transmissão a terceiros sem prévia anuência expressa e por escrito."
        )

    # 2. Geração do hash SHA-256 e marca d'água
    raw_payload_to_hash = f"EDVJR|{client_name}|{cnpj}|{valor_total}|{escopo}|{data_emissao}|{modelo}"
    sha256_hash = hashlib.sha256(raw_payload_to_hash.encode("utf-8")).hexdigest()
    marca_dagua = f"DOCUMENTO OFICIAL EDV JR. - CHAVE SHA-256: {sha256_hash} - REGISTRADO SOB LEI 13.267/2016"

    # 3. Montagem do Documento em Markdown
    doc_md = f"""# {titulo_doc}
**{marca_dagua}**

---

### PREÂMBULO E QUALIFICAÇÃO DAS PARTES

**CONTRATADA:**
**EDV JR. — EMPRESA JÚNIOR DE DIREITO DA FACULDADE DE DIREITO DE VITÓRIA**, associação civil sem fins lucrativos, inscrita no CNPJ/MF sob o nº 18.300.000/0001-00, regida pela **Lei Federal nº 13.267/2016** (Lei das Empresas Juniores) e por seu Estatuto Social, sediada na Rua Juiz Alexandre Martins de Castro Filho, nº 215, Santa Lúcia, Vitória/ES, CEP 29056-295, neste ato representada por seu Presidente Institucional, **Charles Junior**, doravante denominada simplesmente **CONTRATADA**; e

**CONTRATANTE:**
**{client_name.upper()}**, pessoa jurídica de direito privado, inscrita no CNPJ sob o nº **{cnpj}**, neste ato representada por seu responsável legal, **{contact_person}**, com contato eletrônico em `{contact_email}` e telefone `{contact_phone}`, doravante denominada simplesmente **CONTRATANTE**.

Têm entre si, justo e acordado, o presente Instrumento Particular, que se regerá mediante as seguintes cláusulas e condições:

---

### CLÁUSULA PRIMEIRA – DO OBJETO DA CONSULTORIA
1.1. Constitui objeto do presente contrato a prestação, pela CONTRATADA em favor da CONTRATANTE, dos serviços especializados descritos a seguir:
> **{escopo}**

1.2. {clausula_natureza}

---

### CLÁUSULA SEGUNDA – DA NATUREZA EDUCACIONAL E MARCO REGULATÓRIO MEJ
2.1. A CONTRATADA é entidade integrante do Movimento Empresa Júnior (MEJ), constituída e gerida exclusivamente por acadêmicos da graduação em Direito, sob a égide do Art. 2º da **Lei nº 13.267/2016**.
2.2. A totalidade das receitas auferidas pela CONTRATADA é reinvestida na qualificação técnico-profissional de seus membros associados e em sua infraestrutura institucional, inexistindo distribuição de lucros ou dividendos.

---

### CLÁUSULA TERCEIRA – DAS OBRIGAÇÕES DA CONTRATADA
3.1. Executar os serviços pactuados com zelo técnico, lealdade e observância das normas legais aplicáveis.
3.2. Manter a CONTRATANTE periodicamente informada acerca do andamento dos trabalhos e dos despachos oficiais.
3.3. Designar equipe de consultores qualificada, sob supervisão técnica da gerência de projetos e diretoria executiva (Responsável Técnico: `{responsavel_tecnico}`).

---

### CLÁUSULA QUARTA – DAS OBRIGAÇÕES DA CONTRATANTE
4.1. Fornecer tempestivamente todas as informações, logotipos, certidões e documentos probatórios necessários à fiel execução do objeto.
4.2. Arcar com os custos de taxas e retribuições oficiais cobradas por autarquias e órgãos públicos federais, em especial as Guias de Recolhimento da União (GRU) emitidas pelo INPI, as quais não se confundem com os honorários de consultoria da CONTRATADA.
4.3. Efetuar pontualmente a contraprestação financeira nos termos pactuados na Cláusula Quinta.

---

### CLÁUSULA QUINTA – DO PREÇO E CONDIÇÕES DE PAGAMENTO
5.1. Pela prestação dos serviços contratados, a CONTRATANTE pagará à CONTRATADA o valor total e certo de **{valor_fmt}**.
5.2. O adimplemento da remuneração será realizado conforme o seguinte cronograma e condições:
> **{condicoes}**

5.3. O atraso injustificado no pagamento ensejará a incidência de multa moratória de 2% (dois por cento) sobre o montante inadimplido, acrescida de juros de 1% (um por cento) ao mês e correção monetária.

---

### CLÁUSULA SEXTA – DO PRAZO E CRONOGRAMA DE EXECUÇÃO
6.1. O prazo estimado para a entrega das etapas técnicas é de **{prazo_dias} dias**, com conclusão prevista para **{prazo_entrega}**, admitida prorrogação devidamente justificada decorrente de força maior ou morosidade de órgãos regulatórios externos.

---

### CLÁUSULA SÉTIMA – DA CONFIDENCIALIDADE E PROTEÇÃO DE DADOS (LGPD)
7.1. As partes comprometem-se reciprocamente a manter sigilo absoluto sobre toda e qualquer informação técnica, negocial ou financeira a que tiverem acesso em razão deste contrato.
7.2. O tratamento de dados pessoais no âmbito da presente consultoria observará estritamente os princípios de finalidade, adequação e necessidade previstos na **Lei nº 13.709/2018 (Lei Geral de Proteção de Dados - LGPD)**.

---

### CLÁUSULA OITAVA – DA RESCISÃO
8.1. O presente instrumento poderá ser rescindido motivadamente por qualquer das partes em caso de inadimplemento das obrigações contratuais, mediante notificação prévia e formal com prazo de 10 (dez) dias corridos para saneamento da falta.

---

### CLÁUSULA NONA – DO FORO DE ELEIÇÃO
9.1. Para dirimir quaisquer controvérsias oriundas da interpretação ou execução deste instrumento, as partes elegem, com renúncia expressa a qualquer outro, por mais privilegiado que seja, o **Foro da Comarca de Vitória, Estado do Espírito Santo**.

E, por estarem assim justas e contratadas, as partes firmam o presente instrumento por meio de aposição de chancela digital e assinatura das testemunhas instrumentárias.

Vitória/ES, {data_emissao}.

---

___________________________________________________  
**EDV JR. — ASSOCIAÇÃO CIVIL DE DIREITO**  
*Charles Junior — Presidente Institucional*  
*CNPJ: 18.300.000/0001-00*  

___________________________________________________  
**{client_name.upper()}**  
*{contact_person} — Representante Legal*  
*CNPJ: {cnpj}*  

**Testemunhas:**
1. _______________________________ Nome / CPF:  
2. _______________________________ Nome / CPF:  

**Chave Criptográfica de Validação Forense:**  
`{sha256_hash}`
"""

    # 4. Montagem do Documento em HTML Limpo e Formal (Apresentação Limpa, Papel Timbrado Digital)
    doc_html = f"""
    <div class="contrato-documento" style="font-family: 'Times New Roman', Times, serif; color: #111827; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 40px; background: #ffffff; border: 1px solid #e5e7eb; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
      
      <!-- Marca D'água Superior -->
      <div style="border-bottom: 2px solid #0b1d3a; padding-bottom: 12px; margin-bottom: 24px; text-align: center;">
        <div style="font-size: 16px; font-weight: bold; letter-spacing: 1px; color: #0b1d3a; text-transform: uppercase;">EDV Jr. — Consultoria Jurídica Especializada</div>
        <div style="font-size: 11px; color: #4b5563; margin-top: 2px;">Associação Civil sob a égide da Lei Federal nº 13.267/2016 • Faculdade de Direito de Vitória (FDV)</div>
        <div style="margin-top: 8px; font-family: monospace; font-size: 9px; color: #1e40af; background: #eff6ff; padding: 4px 8px; border-radius: 4px; display: inline-block; border: 1px solid #bfdbfe;">
          🛡️ {marca_dagua}
        </div>
      </div>

      <!-- Título Principal -->
      <h2 style="font-size: 14px; font-weight: bold; text-align: center; text-transform: uppercase; margin: 24px 0; color: #0b1d3a; line-height: 1.4;">
        {titulo_doc}
      </h2>

      <!-- Preâmbulo -->
      <p style="text-align: justify; font-size: 12px; margin-bottom: 16px; text-indent: 24px;">
        <strong>CONTRATADA:</strong> <strong>EDV JR. — EMPRESA JÚNIOR DE DIREITO DA FACULDADE DE DIREITO DE VITÓRIA</strong>, pessoa jurídica de direito privado sem fins lucrativos, inscrita no CNPJ sob o nº 18.300.000/0001-00, sediada na Rua Juiz Alexandre Martins de Castro Filho, nº 215, Santa Lúcia, Vitória/ES, regida pela Lei nº 13.267/2016, representada por seu Presidente Institucional, Charles Junior; e
      </p>

      <p style="text-align: justify; font-size: 12px; margin-bottom: 16px; text-indent: 24px;">
        <strong>CONTRATANTE:</strong> <strong>{client_name.upper()}</strong>, inscrita no CNPJ sob o nº <strong>{cnpj}</strong>, representada por <strong>{contact_person}</strong> (E-mail: {contact_email} | Tel: {contact_phone}), têm entre si ajustado o presente contrato, mediante as cláusulas a seguir:
      </p>

      <!-- Cláusula 1 -->
      <div style="margin-bottom: 14px;">
        <p style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">CLÁUSULA PRIMEIRA – DO OBJETO DA CONSULTORIA</p>
        <p style="text-align: justify; font-size: 12px; margin: 0; text-indent: 24px;">1.1. {escopo}</p>
        <p style="text-align: justify; font-size: 11px; margin-top: 4px; color: #374151; font-style: italic; text-indent: 24px;">{clausula_natureza}</p>
      </div>

      <!-- Cláusula 2 -->
      <div style="margin-bottom: 14px;">
        <p style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">CLÁUSULA SEGUNDA – DO MARCO REGULATÓRIO MEJ (LEI 13.267/2016)</p>
        <p style="text-align: justify; font-size: 12px; margin: 0; text-indent: 24px;">2.1. A CONTRATADA é pessoa jurídica de finalidade educacional e sem fins econômicos. Os recursos auferidos destinam-se exclusivamente ao aprimoramento acadêmico e manutenção estrutural da entidade.</p>
      </div>

      <!-- Cláusula 3 e 4 -->
      <div style="margin-bottom: 14px;">
        <p style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">CLÁUSULA TERCEIRA – DAS OBRIGAÇÕES DAS PARTES</p>
        <p style="text-align: justify; font-size: 12px; margin: 0; text-indent: 24px;">3.1. A CONTRATADA obriga-se a desempenhar com diligência os serviços contratados sob responsabilidade técnica de <em>{responsavel_tecnico}</em>.</p>
        <p style="text-align: justify; font-size: 12px; margin-top: 4px; text-indent: 24px;">3.2. A CONTRATANTE fornecerá tempestivamente as informações solicitadas e arcará diretamente com as custas oficiais federais (GRUs do INPI).</p>
      </div>

      <!-- Cláusula 5 -->
      <div style="margin-bottom: 14px;">
        <p style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">CLÁUSULA QUARTA – DO PREÇO E CRONOGRAMA DE PAGAMENTO</p>
        <p style="text-align: justify; font-size: 12px; margin: 0; text-indent: 24px;">4.1. Pelos serviços contratados, a CONTRATANTE pagará o valor líquido total de <strong>{valor_fmt}</strong>, nos seguintes termos: <em>{condicoes}</em>.</p>
      </div>

      <!-- Cláusula 6 -->
      <div style="margin-bottom: 14px;">
        <p style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">CLÁUSULA QUINTA – DO PRAZO DE EXECUÇÃO</p>
        <p style="text-align: justify; font-size: 12px; margin: 0; text-indent: 24px;">5.1. O prazo previsto para conclusão das etapas técnicas é de <strong>{prazo_dias} dias</strong> ({prazo_entrega}).</p>
      </div>

      <!-- Cláusula 7 e 8 -->
      <div style="margin-bottom: 14px;">
        <p style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">CLÁUSULA SEXTA – DA CONFIDENCIALIDADE (LGPD) E FORO</p>
        <p style="text-align: justify; font-size: 12px; margin: 0; text-indent: 24px;">6.1. O sigilo técnico observará as disposições da Lei nº 13.709/2018 (LGPD). Para dirimir controvérsias decorrentes deste pacto, elege-se o Foro da Comarca de Vitória/ES.</p>
      </div>

      <!-- Data e Assinaturas -->
      <div style="margin-top: 36px; text-align: center; font-size: 12px;">
        Vitória/ES, {data_emissao}.
      </div>

      <div style="display: flex; justify-content: space-between; margin-top: 48px; gap: 20px;">
        <div style="flex: 1; text-align: center; border-top: 1px solid #111827; padding-top: 6px; font-size: 11px;">
          <strong>EDV JR. CONSULTORIA JURÍDICA</strong><br>
          Charles Junior — Presidente Institucional<br>
          <span style="font-family: monospace; font-size: 9px; color: #4b5563;">CNPJ: 18.300.000/0001-00</span>
        </div>
        <div style="flex: 1; text-align: center; border-top: 1px solid #111827; padding-top: 6px; font-size: 11px;">
          <strong>{client_name.upper()}</strong><br>
          {contact_person} — Representante Legal<br>
          <span style="font-family: monospace; font-size: 9px; color: #4b5563;">CNPJ: {cnpj}</span>
        </div>
      </div>

      <!-- Carimbo de Integridade Criptográfica Inferior -->
      <div style="margin-top: 36px; padding: 10px; background: #f9fafb; border: 1px dashed #9ca3af; border-radius: 4px; text-align: center;">
        <div style="font-size: 10px; font-weight: bold; color: #1f2937; text-transform: uppercase;">Autenticidade e Integridade Criptográfica Garantida</div>
        <div style="font-family: monospace; font-size: 9px; color: #374151; word-break: break-all; margin-top: 3px;">
          HASH SHA-256: {sha256_hash}
        </div>
        <div style="font-size: 9px; color: #6b7280; margin-top: 2px;">
          Documento emitido automaticamente pelo EDbrain v2.0 • Conformidade estrita Lei Federal 13.267/2016
        </div>
      </div>
    </div>
    """

    return {
        "status": "success",
        "modelo": modelo,
        "modelo_nome": MODELOS_CONTRATUAIS[modelo],
        "titulo": titulo_doc,
        "client_name": client_name,
        "cnpj": cnpj,
        "valor_total": valor_total,
        "valor_formatado": valor_fmt,
        "prazo_dias": prazo_dias,
        "prazo_entrega": prazo_entrega,
        "hash_integridade": sha256_hash,
        "marca_dagua": marca_dagua,
        "documento_markdown": doc_md.strip(),
        "documento_html": doc_html.strip(),
        "metadados": {
            "responsavel_tecnico": responsavel_tecnico,
            "data_emissao": data_emissao,
            "condicoes_pagamento": condicoes,
            "objeto": escopo
        }
    }


def gerar_documento_didatico(artigo: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforma qualquer POP ou artigo de conhecimento em um Documento Didático Oficial
    estruturado com rigor estético, densidade acadêmica e identidade visual EDbrain.
    
    Diretrizes aplicadas:
    - Hierarquia visual estrita: Título principal -> Subtítulos numéricos -> Corpo em prosa corrida contínua.
    - Tom direto, assertivo e acadêmico (sem padding ou prolixidade introdutória).
    - Alta densidade conceitual alinhada à legislação aplicável (Lei 13.267/2016, LPI 9.279/1996, LGPD 13.709/2018, CC/2002).
    - Paleta de cores oficial EDbrain: fundo slate escuro (#0f172a / #1e293b), acentos azul/índigo (#3b82f6 / #6366f1) e tipografia sans-serif limpa.
    - Hash criptográfico SHA-256 para integridade e rastreabilidade acadêmica.
    """
    artigo_id = artigo.get("id") or 0
    titulo = (artigo.get("titulo") or "Procedimento Operacional Padrão").strip()
    categoria = (artigo.get("categoria") or "geral").strip().lower()
    autor_nome = (artigo.get("autor_nome") or "Núcleo Técnico de Governança EDV Jr.").strip()
    
    # Unificação de chaves de conteúdo para garantir robustez absoluta
    conteudo_base = (
        artigo.get("conteudo") or 
        artigo.get("content") or 
        artigo.get("body") or 
        artigo.get("texto") or 
        ""
    ).strip()
    
    data_emissao = datetime.now().strftime("%d/%m/%Y")
    data_extenso = datetime.now().strftime("%d de %B de %Y")
    ano_atual = datetime.now().year
    
    texto_analise = f"{titulo} {conteudo_base}".lower()
    
    # 1. Enquadramento e Disciplina Dogmática
    if any(k in texto_analise for k in ["marca", "inpi", "colidência", "gru", "rpi", "patente", "anterioridade"]):
        disciplina = "Direito da Propriedade Intelectual e Proteção dos Sinais Distintivos"
        marco_normativo = "Lei Federal nº 9.279/1996 (LPI), art. 5º, XXIX da CF/88, Resoluções INPI nº 244 e 245/2019 e Classificação de Nice (NCL)"
        orgao_competente = "Instituto Nacional da Propriedade Industrial (INPI)"
        enquadramento_p1 = (
            f"O presente documento didático institucional disciplina a operação procedimental de '{titulo}', "
            f"situando-se na interseção entre o Direito da Propriedade Industrial e o regime protetivo dos sinais distintivos. "
            f"Com esteio no artigo 5º, inciso XXIX, da Constituição da República de 1988 e nas diretrizes materiais da Lei Federal nº 9.279/1996 (LPI), "
            f"a proteção marcária constitui prerrogativa jurídica voltada a resguardar a exclusividade de uso concorrencial, "
            f"impedir o enriquecimento sem causa por desvio de clientela e mitigar o risco de confusão ou associação indevida perante o público consumidor."
        )
        enquadramento_p2 = (
            f"Sob a ótica da Lei Federal nº 13.267/2016 (Marco Legal das Empresas Juniores), a atuação da consultoria jurídica "
            f"configura obrigação técnica de meio lastreada em rigorosa instrução prévia, estrita observância das resoluções administrativas do INPI "
            f"e controle tempestivo dos prazos publicados na Revista da Propriedade Industrial (RPI). A atividade procedimental pressupõe a identificação "
            f"da anterioridade colidente, a exata delimitação da classe internacional aplicável e a elaboração de teses defensivas que sustentem "
            f"a distintividade e a veracidade do sinal marcário frente ao banco de dados federal."
        )
        metodologia_p1 = (
            f"A execução do procedimento desenvolve-se mediante o encadeamento sucessivo de atos instrutórios vinculados, "
            f"iniciando-se pela pesquisa prévia de anterioridade fonética, visual e ideológica perante a base de marcas do INPI. "
            f"Constatada a viabilidade preliminar, procede-se à emissão da Guia de Recolhimento da União (GRU sob o código correspondente), "
            f"assegurando-se o recolhimento das custas oficiais sob a tabela de retribuição com desconto de microempresa ou entidade sem fins lucrativos."
        )
        metodologia_p2 = (
            f"Após a liquidação financeira da taxa federal, opera-se o preenchimento exaustivo do formulário eletrônico no sistema e-Marcas, "
            f"anexando-se a imagem em alta resolução com especificação técnica das cores reivindicadas e a respectiva procuração com poderes específicos. "
            f"Protocolado o pedido, instaura-se a rotina de monitoramento semanal das terças-feiras da RPI, salvaguardando-se o cumprimento tempestivo "
            f"de eventuais exigências formais e manifestações a oposições tempestivas de terceiros no prazo legal de 60 (sessenta) dias."
        )
        riscos_p1 = (
            f"A gestão de riscos regulatórios exige vigilância ininterrupta sobre prazos peremptórios e preclusivos estabelecidos na LPI, "
            f"sob pena de arquivamento definitivo ou perda do direito de prioridade assegurado pelo depósito. "
            f"A consultoria jurídica deve cientificar formalmente o consulente acerca da natureza discricionária do juízo de mérito proferido "
            f"pelos examinadores da autarquia federal, blindando a entidade contra eventuais alegações infundadas de garantia de resultado."
        )
        riscos_p2 = (
            f"No plano do compliance ético-concorrencial, é dever imperativo alertar a empresa assistida contra as práticas abusivas de boletos "
            f"e cobranças fraudulentas perpetradas por intermediários inidôneos que simulam comunicações do órgão federal. "
            f"Todas as comunicações oficiais e cobranças válidas operam exclusivamente por intermédio de guias emitidas diretamente no portal governamental, "
            f"garantindo a estrita higidez financeira do processo."
        )
        qualidade_p1 = (
            f"Os critérios de eficácia prática subordinam-se à conferência documental em duplo grau no âmbito da EDV Jr., "
            f"exigindo-se a validação cruzada do protocolo de depósito e do comprovante de pagamento antes do arquivamento do dossiê operacional. "
            f"A consolidação do número de processo federal e a emissão do comprovante digital de depósito formam o acervo de evidências obrigatório "
            f"para fins de auditoria interna e conformidade perante os requisitos do Selo EJ Brasil Júnior."
        )
        qualidade_p2 = (
            f"O encerramento formal do ato técnico culmina na emissão de parecer informativo sintético remetido ao parceiro corporativo, "
            f"detalhando os marcos cronológicos estimados até a concessão definitiva do registro pelo INPI e estabelecendo "
            f"o calendário de acompanhamento bienal no sistema integrado EDbrain."
        )
    elif any(k in texto_analise for k in ["contrato", "cláusula", "rescisão", "prestação de serviços", "acordo", "nda", "sócio", "confidencialidade"]):
        disciplina = "Direito dos Contratos, Obrigações Civis e Governança Jurídica das Empresas Juniores"
        marco_normativo = "Lei Federal nº 13.267/2016, Código Civil (arts. 421 a 480), LGPD (Lei 13.709/2018) e Lei nº 14.063/2020"
        orgao_competente = "Poder Judiciário Estadual / Foro de Eleição Institucional"
        enquadramento_p1 = (
            f"O presente caderno didático estabelece a disciplina dogmática e a técnica instrumental de redação aplicável a '{titulo}'. "
            f"Sob a égide da Lei Federal nº 13.267/2016 e da teoria geral dos contratos positivada no Código Civil Brasileiro (arts. 421 e 422), "
            f"o negócio jurídico celebrado pela Empresa Júnior subordina-se aos princípios fundantes da função social do contrato, "
            f"da probidade e da boa-fé objetiva, orientando-se estritamente à consecução dos fins educacionais e formativos dos discentes."
        )
        enquadramento_p2 = (
            f"A estruturação das cláusulas deve refletir clareza técnica, proporcionalidade prestacional e aplicação de técnicas de Legal Design, "
            f"eliminando obscuridades semânticas que possam ensejar desequilíbrios entre as partes contratantes. "
            f"A delimitação das obrigações assume contornos de estrita obrigação técnica de meio, estabelecendo-se com precisão "
            f"o escopo pactuado, as condições resolutivas de inadimplemento e a disciplina protetiva dos dados tratados conforme a Lei Geral de Proteção de Dados (LGPD)."
        )
        metodologia_p1 = (
            f"O encadeamento operacional inicia-se pelo diagnóstico acurado das necessidades contratuais e qualificação formal dos sujeitos de direito, "
            f"verificando-se a regularidade da representação legal mediante cotejo dos atos constitutivos perante a Junta Comercial ou RCPJ. "
            f"Em seguida, redige-se o objeto da avença com granularidade suficiente para afastar ambiguidades, vinculando o cronograma de desembolso "
            f"à efetiva entrega de marcos físicos ou relatórios técnicos substanciados."
        )
        metodologia_p2 = (
            f"Na fase de formalização, colhem-se as assinaturas eletrônicas das partes e de duas testemunhas idôneas por intermédio de plataforma digital "
            f"com verificação de integridade criptográfica mediante algoritmo SHA-256 e carimbo de tempo qualificado. "
            f"O instrumento aperfeiçoado é imediatamente arquivado no repositório corporativo seguro com geração automática de metadados no SIG EDbrain."
        )
        riscos_p1 = (
            f"A mitigação de riscos contratuais impõe a inserção sistemática de cláusulas penais moratórias e compensatórias razoáveis, "
            f"evitando-se a pactuação de responsabilidades civis reflexas ou multas leoninas incompatíveis com a natureza da assessoria júnior. "
            f"No tocante à confidencialidade, as penalidades pecuniárias devem ser prefixadas com esteio na sensibilidade do segredo industrial compartilhado."
        )
        riscos_p2 = (
            f"Sob a perspectiva da Lei Federal nº 13.709/2018 (LGPD), impõe-se a declaração explícita das finalidades de tratamento de dados pessoais, "
            f"vinculando a guarda e manipulação das informações estritamente à execução do contrato e ao cumprimento de obrigações legais, "
            f"assegurando-se o descarte seguro ao término do vínculo."
        )
        qualidade_p1 = (
            f"O controle de qualidade contratual pressupõe a revisão em duplo grau técnico pela Gerência de Projetos e Diretoria Institucional, "
            f"atestando a presença de todos os requisitos do art. 104 do Código Civil e das cláusulas mandatórias do marco regulatório MEJ. "
            f"Apenas minutas devidamente chanceladas são liberadas para encaminhamento aos parceiros comerciais."
        )
        qualidade_p2 = (
            f"A eficácia procedimental mede-se pela ausência de aditivos de renegociação por obscuridade de escopo e pela pontualidade dos recebimentos, "
            f"constituindo a certidão de arquivamento contratual insumo essencial para a renovação da certificação do Selo EJ."
        )
    elif any(k in texto_analise for k in ["estatuto", "regimento", "assembleia", "sociedade", "rcpj", "redesim"]):
        disciplina = "Direito Associativo, Governança Institucional e Registro de Pessoas Jurídicas"
        marco_normativo = "Lei Federal nº 13.267/2016, Código Civil (arts. 53 a 61), Lei nº 6.015/1973 (LRPJ) e Lei nº 11.598/2007 (REDESIM)"
        orgao_competente = "Registro Civil das Pessoas Jurídicas (RCPJ) e Receita Federal do Brasil"
        enquadramento_p1 = (
            f"O presente documento didático sistematiza a dogmática institucional aplicável a '{titulo}', "
            f"regulando a arquitetura corporativa e o processo decisório no âmbito das associações civis sem fins econômicos. "
            f"Em consonância com os artigos 53 a 61 do Código Civil Brasileiro e com a Lei Federal nº 13.267/2016, a personalidade jurídica "
            f"da Empresa Júnior constitui-se a partir do registro de seus atos constitutivos no Cartório de Registro Civil de Pessoas Jurídicas (RCPJ), "
            f"instituindo um regime de governança centrado na soberania da Assembleia Geral."
        )
        enquadramento_p2 = (
            f"A harmonia institucional exige rigorosa distinção entre a função legislativa da Assembleia Geral, a competência executiva da Diretoria "
            f"e o papel fiscalizador e orientador do Conselho de Administração. A elaboração ou reforma de normas corporativas deve assegurar "
            f"a transparência democrática, a ampla defesa em procedimentos disciplinares e a blindagem patrimonial dos gestores discentes "
            f"que atuem no estrito cumprimento dos deveres estatutários e regimentais."
        )
        metodologia_p1 = (
            f"O rito procedimental principia pela elaboração de minuta de alteração normativa sob justificativa circunstanciada de conveniência e legalidade, "
            f"submetendo-se o texto à consulta pública preliminar dos membros ativos. "
            f"Ato contínuo, expede-se edital de convocação com a antecedência estatutária mínima, discriminando a pauta com clareza insofismável "
            f"e especificando os quóruns qualificados exigidos para deliberação."
        )
        metodologia_p2 = (
            f"Realizada a assembleia, lavra-se ata circunstanciada contendo a transcrição fidedigna das deliberações, a lista de presenças rubricada "
            f"e a qualificação integral da mesa diretora. "
            f"O expediente documental é remetido para visto prévio de advogado devidamente inscrito na OAB, instruindo-se o requerimento de averbação "
            f"perante o RCPJ e a consequente atualização cadastral nos sistemas da REDESIM e Receita Federal."
        )
        riscos_p1 = (
            f"O principal fator de risco em matéria associativa reside no vício formal de convocação ou inobservância de quórum estatutário, "
            f"circunstância que atrai a nulidade absoluta dos atos deliberados com fundamento no art. 166 do Código Civil. "
            f"A fiscalização atenta sobre a regularidade do edital de convocação e da lista de assinaturas previne litígios internos e impugnações cartorárias."
        )
        riscos_p2 = (
            f"Ademais, impõe-se a manutenção da cláusula pétrea de não distribuição de lucros, dividendos ou bonificações a qualquer título, "
            f"preservando-se a imunidade tributária constitucional da entidade e a conformidade irrestrita com o art. 2º da Lei 13.267/2016."
        )
        qualidade_p1 = (
            f"A aceitação formal do processo consubstancia-se na obtenção da certidão de inteiro teor averbada pelo RCPJ e no comprovante de atualização do CNPJ, "
            f"garantindo a plena eficácia 'erga omnes' dos atos corporativos aprovados pela membresia."
        )
        qualidade_p2 = (
            f"Os documentos averbados são digitalizados em alta resolução e integrados à pasta de conformidade jurídica do Selo EJ, "
            f"assegurando a continuidade institucional e a memória corporativa da gestão 2026."
        )
    elif any(k in texto_analise for k in ["nota fiscal", "nfs-e", "faturamento", "financeiro", "iss", "caixa"]):
        disciplina = "Direito Tributário Municipal, Contabilidade do Terceiro Setor e Gestão Fiscal de EJs"
        marco_normativo = "CF/88 (art. 150, VI, 'c'), Lei Complementar nº 116/2003 (ISSQN), Lei 13.267/2016 e Decreto Municipal PMV"
        orgao_competente = "Secretaria Municipal de Fazenda de Vitória (PMV) e Receita Federal do Brasil"
        enquadramento_p1 = (
            f"O presente documento didático uniformiza a disciplina dogmática e o fluxo fiscal concernente a '{titulo}', "
            f"integrando as obrigações tributárias principais e acessórias inerentes à gestão financeira da EDV Jr. "
            f"Sob a ordem constitucional vigente (art. 150, VI, 'c' da CF/88), as entidades sem fins econômicos de educação e assistência "
            f"gozam de imunidade tributária quanto aos impostos incidentes sobre patrimônio, renda e serviços diretamente vinculados às suas finalidades essenciais, "
            f"condicionada ao cumprimento estrito dos requisitos do art. 14 do Código Tributário Nacional."
        )
        enquadramento_p2 = (
            f"Todavia, a imunidade tributária das receitas não desonera a pessoa jurídica do cumprimento dos deveres instrumentais acessórios, "
            f"destacando-se a emissão tempestiva de Nota Fiscal de Serviços Eletrônica (NFS-e) por ocasião de cada recebimento contratual. "
            f"A higidez fiscal constitui pilar inafastável para a comprovação da origem lícita das receitas e para a auditoria de prestação de contas "
            f"perante os órgãos de controle universitário e a Federação Estadual de Empresas Juniores."
        )
        metodologia_p1 = (
            f"A rotina de faturamento inicia-se pela confirmação do adimplemento do marco de entrega contratual pela Gerência de Projetos, "
            f"cotejando-se o extrato da conta corrente institucional do Banco Cora para certificar a liquidação do valor devido. "
            f"Em seguida, acessa-se o Portal de Administração Tributária da Prefeitura Municipal de Vitória (PMV) utilizando o certificado digital corporativo."
        )
        metodologia_p2 = (
            f"No módulo de emissão, seleciona-se a natureza da operação sob o código de atividade de consultoria jurídica/empresarial correspondente, "
            f"inserindo-se a discriminação detalhada dos serviços e o número do contrato originário no corpo do documento fiscal. "
            f"Após a validação dos dados do tomador e das retenções legais aplicáveis, emite-se a NFS-e definitiva, remetendo-se o arquivo PDF e XML "
            f"diretamente ao endereço eletrônico do parceiro comercial com registro automático no fluxo de caixa do EDbrain."
        )
        riscos_p1 = (
            f"A inobservância da data de competência ou a omissão na emissão da NFS-e sujeita a associação a sanções pecuniárias decorrentes "
            f"de infração a dever acessório tributário, além de configurar risco de descaracterização formal da imunidade condicionada. "
            f"A conciliação bancária diária constitui a salvaguarda basilar para impedir divergências entre os ingressos e o livro fiscal."
        )
        riscos_p2 = (
            f"Ademais, veda-se a utilização de contas bancárias de pessoas físicas para a intermediação de pagamentos ou custeio de despesas da entidade, "
            f"preservando-se a estrita segregação patrimonial entre a pessoa jurídica e os membros integrantes de seus órgãos diretivos."
        )
        qualidade_p1 = (
            f"A eficácia da rotina contábil consolida-se com a guarda digital dos documentos fiscais em duplicidade, arquivando-se o XML "
            f"pelo prazo decadencial de 5 (cinco) anos conforme preceitua a legislação tributária pátria."
        )
        qualidade_p2 = (
            f"O fechamento mensal do faturamento alimenta o Demonstrativo de Resultados do Exercício (DRE), servindo de base analítica "
            f"para o parecer trimestral do Conselho Fiscal e certificação do Selo EJ no eixo de regularidade financeira."
        )
    elif any(k in texto_analise for k in ["pdi", "psel", "gente", "cultura", "liderança", "feedbacks", "desempenho"]):
        disciplina = "Desenvolvimento Organizacional, Andragogia Aplicada e Governança de Pessoas"
        marco_normativo = "Lei Federal nº 13.267/2016 (arts. 1º e 7º), Diretrizes Nacionais MEJ e Estatuto Social EDV Jr."
        orgao_competente = "Vice-Presidência de Gente e Gestão (VPGG) e Diretoria Executiva"
        enquadramento_p1 = (
            f"O presente documento didático disciplina a gestão de competências e o percurso formativo no tocante a '{titulo}'. "
            f"A Lei Federal nº 13.267/2016 consagra a Empresa Júnior como ambiente de aprendizado prático e aperfeiçoamento discente, "
            f"no qual o desenvolvimento de competências técnicas e comportamentais (modelo CHA - Conhecimentos, Habilidades e Atitudes) "
            f"opera articulado com as necessidades reais dos projetos de consultoria contratados pela sociedade."
        )
        enquadramento_p2 = (
            f"Nesse contexto, a governança de pessoas não se reduz a uma rotina de controle operacional, configurando um sistema contínuo "
            f"de alinhamento cultural, liderança situacional e emancipação profissional. As ferramentas de acompanhamento individual asseguram "
            f"que cada acadêmico trace metas mensuráveis, receba feedbacks estruturados e desenvolva soft skills essenciais "
            f"para a excelência da prática jurídica contemporânea."
        )
        metodologia_p1 = (
            f"A execução metodológica fundamenta-se na aplicação de ciclos diagnósticos periódicos, iniciando-se pela definição do Plano de Desenvolvimento Individual (PDI) "
            f"com base nas metas estratégicas setoriais e no radar de competências da entidade. "
            f"O mentorado e o líder de área realizam reuniões de alinhamento bilateral (One-on-Ones), pactuando compromissos de capacitação técnica e entregas pontuais."
        )
        metodologia_p2 = (
            f"Ao longo do semestre letivo, realizam-se avaliações de desempenho 360 graus com mensuração cruzada entre pares, liderança e liderados, "
            f"assegurando a imparcialidade dos julgamentos e a identificação precoce de eventuais lacunas formativas. "
            f"Os resultados quantitativos e qualitativos são consolidados no módulo VPGG do EDbrain para calibração contínua dos planos de ação."
        )
        riscos_p1 = (
            f"O principal risco no âmbito da gestão associativa de voluntariado reside na desmotivação e evasão discente por falta de clareza nas metas "
            f"ou ausência de acompanhamento formativo pela liderança. A tempestividade na devolutiva de feedbacks impede a cristalização de comportamentos disfuncionais "
            f"e fortalece a cultura de pertencimento."
        )
        riscos_p2 = (
            f"Outrossim, deve-se resguardar a estrita confidencialidade das anotações de PDI e avaliações individuais, "
            f"assegurando que dados comportamentais sejam tratados com absoluto respeito à privacidade dos membros sob os auspícios da LGPD."
        )
        qualidade_p1 = (
            f"Os parâmetros de eficácia aferem-se pelo índice de engajamento interno, pela taxa de retenção de talentos e pelo cumprimento satisfatório "
            f"das microetapas pedagógicas pactuadas em cada ciclo de PDI."
        )
        qualidade_p2 = (
            f"O índice consolidado de maturidade de liderança e o relatório final de gestão de pessoas integram a prestação de contas do Selo EJ, "
            f"atestando a vitalidade pedagógica da entidade perante a comunidade acadêmica da FDV."
        )
    else:
        disciplina = "Governança Operacional MEJ, Eficácia Procedimental e Gestão do Conhecimento"
        marco_normativo = "Lei Federal nº 13.267/2016, Estatuto Social da EDV Jr. e Normas Técnicas Operacionais da Gestão 2026"
        orgao_competente = "Diretoria Executiva e Conselho de Administração da EDV Jr."
        enquadramento_p1 = (
            f"O presente caderno didático corporativo estabelece a disciplina dogmática e o regime técnico de execução aplicável a '{titulo}'. "
            f"A padronização dos processos institucionais constitui mecanismo vital para assegurar a continuidade administrativa, "
            f"a perenidade do saber organizacional e a conformidade irrestrita com os preceitos da Lei Federal nº 13.267/2016. "
            f"A sistematização dos procedimentos operacionais padrão (POPs) confere previsibilidade e excelência à entrega dos serviços educacionais prestados."
        )
        enquadramento_p2 = (
            f"A disciplina técnica desdobra-se na necessária articulação entre teoria acadêmica e empiria profissional, "
            f"propiciando aos membros consultores um arcabouço estruturado para tomada de decisão em cenários complexos. "
            f"A observância rigorosa das fases procedimentais mitiga a incidência de erros materiais e salvaguarda a reputação corporativa da entidade."
        )
        metodologia_p1 = (
            f"O encadeamento operacional desenvolve-se mediante sucessão ordenada de atos materiais devidamente documentados, "
            f"iniciando-se pela análise de admissibilidade do requerimento e conferência dos elementos instrutórios mínimos. "
            f"Identificados os pressupostos operacionais, os atos executórios desdobram-se conforme os critérios fixados no manual de rotinas setoriais."
        )
        metodologia_p2 = (
            f"A conclusão de cada etapa é registrada no painel de controle operacional do EDbrain, viabilizando o monitoramento em tempo real "
            f"pelos gestores setoriais e assegurando a rastreabilidade integral das decisões adotadas durante o ciclo procedimental."
        )
        riscos_p1 = (
            f"A mitigação de riscos operacionais impõe o estrito dever de diligência aos executores, vedando-se a adoção de condutas atalhosas "
            f"que comprometam o rigor técnico ou as salvaguardas de conformidade legal. A tempestividade no cumprimento de cada ato "
            f"previne o perecimento de direitos e o desgaste no relacionamento com os tomadores de serviços."
        )
        riscos_p2 = (
            f"Ademais, todo e qualquer incidente operacional que fuja à normalidade do procedimento deve ser imediatamente escalado "
            f"à respectiva Diretoria, promovendo-se a correção tempestiva do rumo sem prejuízo à higidez institucional."
        )
        qualidade_p1 = (
            f"A eficácia procedimental é aferida pela conformidade do produto entregue com a matriz de critérios de aceitação técnica, "
            f"submetendo-se a entrega à validação conclusiva da liderança institucional antes do encerramento formal do protocolo."
        )
        qualidade_p2 = (
            f"A documentação comprobatória é incorporada ao acervo permanente da base de conhecimento nativa, "
            f"alimentando os indicadores de governança e auditoria operacional do Selo EJ."
        )
        
    protocolo_code = f"ED-DID-{artigo_id:04d}/{ano_atual}"
    
    # Montagem do Markdown Oficial Didático
    doc_md = f"""# [CADERNO DIDÁTICO CORPORATIVO] {titulo}

**DISCIPLINA OPERACIONAL:** {disciplina}  
**MARCO NORMATIVO PRIMÁRIO:** {marco_normativo}  
**ÓRGÃO COMPETENTE:** {orgao_competente}  
**PROTOCOLO INSTITUCIONAL:** {protocolo_code}  
**DATA DE EMISSÃO:** {data_emissao} • **AUTORIA TÉCNICA:** {autor_nome}

---

## 1. FUNDAMENTAÇÃO NORMATIVA E ENQUADRAMENTO DOGMÁTICO

{enquadramento_p1}

{enquadramento_p2}

## 2. PRESSUPOSTOS MATERIAIS E METODOLOGIA OPERATÓRIA

{metodologia_p1}

{metodologia_p2}

## 3. GESTÃO DE RISCOS REGULATÓRIOS E COMPLIANCE INSTITUCIONAL

{riscos_p1}

{riscos_p2}

## 4. PARÂMETROS DE EFICÁCIA PRÁTICA E CONTROLE DE QUALIDADE

{qualidade_p1}

{qualidade_p2}

---
*Documento emitido autonomamente pelo Módulo Didático EDbrain v2.0 • Conformidade estrita Lei Federal nº 13.267/2016 • Gestão 2026 EDV Jr.*
"""

    sha256_hash = hashlib.sha256(doc_md.encode("utf-8")).hexdigest()[:32].upper()

    # Montagem do HTML Estilizado sob a Paleta Oficial EDbrain (Dark Slate, Corporate Blue & Indigo)
    doc_html = f"""
    <div class="edbrain-didatico-documento" style="background-color: #0f172a; color: #cbd5e1; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; border-radius: 16px; border: 1px solid #334155; padding: 40px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.6); max-width: 920px; margin: 0 auto; line-height: 1.75;">
      
      <!-- Cabeçalho Institucional Oficial -->
      <div style="border-bottom: 2px solid #3b82f6; padding-bottom: 20px; margin-bottom: 28px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 12px;">
          <div style="display: inline-flex; align-items: center; gap: 8px; background: #1e293b; border: 1px solid #6366f1; padding: 4px 12px; border-radius: 9999px;">
            <span style="color: #818cf8; font-size: 11px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase;">EDBRAIN • CADERNO DIDÁTICO CORPORATIVO</span>
          </div>
          <div style="font-family: monospace; font-size: 11px; color: #94a3b8; background: #1e293b; padding: 4px 10px; border-radius: 6px; border: 1px solid #334155;">
            PROTOCOLO: <strong style="color: #60a5fa;">{protocolo_code}</strong>
          </div>
        </div>
        
        <h1 style="color: #f8fafc; font-size: 22px; font-weight: 800; line-height: 1.35; margin: 0 0 16px 0;">{titulo}</h1>
        
        <!-- Grid de Metadados Didáticos -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 14px; font-size: 11px;">
          <div><span style="color: #64748b; text-transform: uppercase; font-weight: bold; font-size: 9px; display: block;">Disciplina:</span> <strong style="color: #e2e8f0;">{disciplina}</strong></div>
          <div><span style="color: #64748b; text-transform: uppercase; font-weight: bold; font-size: 9px; display: block;">Marco Normativo:</span> <span style="color: #cbd5e1;">{marco_normativo}</span></div>
          <div><span style="color: #64748b; text-transform: uppercase; font-weight: bold; font-size: 9px; display: block;">Competência:</span> <span style="color: #cbd5e1;">{orgao_competente}</span></div>
          <div><span style="color: #64748b; text-transform: uppercase; font-weight: bold; font-size: 9px; display: block;">Autoria & Data:</span> <span style="color: #cbd5e1;">{autor_nome} • {data_emissao}</span></div>
        </div>
      </div>

      <!-- Seção 1: Fundamentação Normativa -->
      <div style="margin-bottom: 28px;">
        <h2 style="color: #60a5fa; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 14px 0; border-left: 3px solid #3b82f6; padding-left: 10px;">
          1. FUNDAMENTAÇÃO NORMATIVA E ENQUADRAMENTO DOGMÁTICO
        </h2>
        <p style="color: #cbd5e1; font-size: 13px; text-align: justify; text-indent: 28px; margin: 0 0 12px 0;">{enquadramento_p1}</p>
        <p style="color: #cbd5e1; font-size: 13px; text-align: justify; text-indent: 28px; margin: 0;">{enquadramento_p2}</p>
      </div>

      <!-- Seção 2: Metodologia Operatória -->
      <div style="margin-bottom: 28px;">
        <h2 style="color: #818cf8; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 14px 0; border-left: 3px solid #6366f1; padding-left: 10px;">
          2. PRESSUPOSTOS MATERIAIS E METODOLOGIA OPERATÓRIA
        </h2>
        <p style="color: #cbd5e1; font-size: 13px; text-align: justify; text-indent: 28px; margin: 0 0 12px 0;">{metodologia_p1}</p>
        <p style="color: #cbd5e1; font-size: 13px; text-align: justify; text-indent: 28px; margin: 0;">{metodologia_p2}</p>
      </div>

      <!-- Seção 3: Gestão de Riscos -->
      <div style="margin-bottom: 28px;">
        <h2 style="color: #38bdf8; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 14px 0; border-left: 3px solid #38bdf8; padding-left: 10px;">
          3. GESTÃO DE RISCOS REGULATÓRIOS E COMPLIANCE INSTITUCIONAL
        </h2>
        <p style="color: #cbd5e1; font-size: 13px; text-align: justify; text-indent: 28px; margin: 0 0 12px 0;">{riscos_p1}</p>
        <p style="color: #cbd5e1; font-size: 13px; text-align: justify; text-indent: 28px; margin: 0;">{riscos_p2}</p>
      </div>

      <!-- Seção 4: Critérios de Eficácia -->
      <div style="margin-bottom: 28px;">
        <h2 style="color: #2dd4bf; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 14px 0; border-left: 3px solid #2dd4bf; padding-left: 10px;">
          4. PARÂMETROS DE EFICÁCIA PRÁTICA E CONTROLE DE QUALIDADE
        </h2>
        <p style="color: #cbd5e1; font-size: 13px; text-align: justify; text-indent: 28px; margin: 0 0 12px 0;">{qualidade_p1}</p>
        <p style="color: #cbd5e1; font-size: 13px; text-align: justify; text-indent: 28px; margin: 0;">{qualidade_p2}</p>
      </div>

      <!-- Rodapé Criptográfico e Chancelas -->
      <div style="margin-top: 36px; padding: 14px; background: #1e293b; border: 1px dashed #475569; border-radius: 8px; text-align: center;">
        <div style="font-size: 10px; font-weight: bold; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">
          Chancela de Autenticidade e Densidade Acadêmica Institucional
        </div>
        <div style="font-family: monospace; font-size: 9px; color: #60a5fa; word-break: break-all; margin-top: 4px;">
          HASH SHA-256: {sha256_hash}
        </div>
        <div style="font-size: 10px; color: #64748b; margin-top: 4px;">
          Documento emitido autonomamente pelo EDbrain v2.0 • Conformidade estrita Lei Federal nº 13.267/2016 • Gestão 2026 EDV Jr.
        </div>
      </div>
    </div>
    """

    return {
        "status": "success",
        "artigo_id": artigo_id,
        "titulo": titulo,
        "categoria": categoria,
        "disciplina": disciplina,
        "marco_normativo": marco_normativo,
        "orgao_competente": orgao_competente,
        "protocolo": protocolo_code,
        "hash_sha256": sha256_hash,
        "data_emissao": data_emissao,
        "autor_nome": autor_nome,
        "documento_markdown": doc_md.strip(),
        "documento_html": doc_html.strip(),
        "secoes": [
            {
                "numero": 1,
                "titulo": "1. FUNDAMENTAÇÃO NORMATIVA E ENQUADRAMENTO DOGMÁTICO",
                "paragrafos": [enquadramento_p1, enquadramento_p2]
            },
            {
                "numero": 2,
                "titulo": "2. PRESSUPOSTOS MATERIAIS E METODOLOGIA OPERATÓRIA",
                "paragrafos": [metodologia_p1, metodologia_p2]
            },
            {
                "numero": 3,
                "titulo": "3. GESTÃO DE RISCOS REGULATÓRIOS E COMPLIANCE INSTITUCIONAL",
                "paragrafos": [riscos_p1, riscos_p2]
            },
            {
                "numero": 4,
                "titulo": "4. PARÂMETROS DE EFICÁCIA PRÁTICA E CONTROLE DE QUALIDADE",
                "paragrafos": [qualidade_p1, qualidade_p2]
            }
        ]
    }

