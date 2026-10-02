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
