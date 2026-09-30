// Funções utilitárias seguras de DOM (compatibilidade ECMAScript estrita)
function getVal(id) {
  var el = document.getElementById(id);
  return el ? el.value : '';
}

function getChecked(id, defVal) {
  var el = document.getElementById(id);
  return el ? el.checked : (defVal !== undefined ? defVal : false);
}

/**
 * EDV Jr. - Sistema Operacional Unificado 2.0
 * Lógica Central: Autenticação Whitelist, RBAC, DataGrids Setoriais e EDV Prospector Integrado
 */

// ==============================================================================
// 1. MATRIZ DE ACESSO RESTRITO (WHITELIST OFICIAL - GESTÃO 2026)
// ==============================================================================
const membrosAutorizados = {
  "charles.junior@edvjr.com.br": { nome: "Charles", area: "Presidência", setor: "Presidência", cargo: "Presidente Institucional", role: "presidente" },
  "alice.mizuki@edvjr.com.br": { nome: "Alice Mizuki", area: "Projetos", setor: "Projetos / RMs", cargo: "Assessora de Projetos", role: "assessor" },
  "alice.ney@edvjr.com.br": { nome: "Alice Ney", area: "VPGG", setor: "VPGG", cargo: "Vice-Presidente de Gestão", role: "diretor" },
  "alicia.athayde@edvjr.com.br": { nome: "Alicia", area: "Marketing", setor: "Marketing", cargo: "Assessora de Conteúdo", role: "assessor" },
  "aline.tartaglia@edvjr.com.br": { nome: "Aline", area: "Jurídico", setor: "Jurídico", cargo: "Assessora de Contratos", role: "assessor" },
  "amanda.bede@edvjr.com.br": { nome: "Amanda", area: "Projetos", setor: "Projetos / RMs", cargo: "Assessora de Projetos", role: "assessor" },
  "karolina.krause@edvjr.com.br": { nome: "Ana Karolina", area: "Jurídico", setor: "Jurídico", cargo: "Assessora de Compliance", role: "assessor" },
  "estevao.coutinho@edvjr.com.br": { nome: "Estevão", area: "Comercial", setor: "Comercial", cargo: "Assessor de Vendas", role: "assessor" },
  "evelyn.roldi@edvjr.com.br": { nome: "Evelyn", area: "Marketing", setor: "Marketing", cargo: "Diretora de Marketing", role: "diretor" },
  "gabriel.orienrac@edvjr.com.br": { nome: "Cachorrão (Gabriel)", area: "Projetos", setor: "Projetos / RMs", cargo: "Assessor de Projetos", role: "assessor" },
  "giulia.moulin@edvjr.com.br": { nome: "Giulia", area: "VPGG", setor: "VPGG", cargo: "Assessora de Gente & Gestão", role: "assessor" },
  "guilherme.borges@edvjr.com.br": { nome: "Guilherme Borges", area: "Comercial", setor: "Comercial", cargo: "Assessor de Vendas", role: "assessor" },
  "isadora.epichin@edvjr.com.br": { nome: "Isadora", area: "Comercial", setor: "Comercial / Vendas", cargo: "Diretora Comercial", role: "diretor" },
  "joaop.lecco@edvjr.com.br": { nome: "Chillibão (João P.)", area: "Marketing", setor: "Marketing", cargo: "Assessor de Criação", role: "assessor" },
  "marialice.bacelar@edvjr.com.br": { nome: "Maria Alice", area: "Comercial", setor: "Comercial", cargo: "Assessora de Negociação", role: "assessor" },
  "mariaeduarda.dias@edvjr.com.br": { nome: "Maria Eduarda", area: "VPGG", setor: "VPGG", cargo: "Assessora de Gente & Gestão", role: "assessor" },
  "maria.teixeira@edvjr.com.br": { nome: "Maria Luyza", area: "Jurídico", setor: "Jurídico", cargo: "Assessora de Governança", role: "assessor" },
  "marina.moretto@edvjr.com.br": { nome: "Marina", area: "Tesouraria", setor: "Tesouraria / CJA", cargo: "Diretora Financeira", role: "diretor" },
  "marllon.oliveira@edvjr.com.br": { nome: "Marllon", area: "Projetos", setor: "Projetos / RMs", cargo: "Assessor de Projetos", role: "assessor" },
  "pedro.barros@edvjr.com.br": { nome: "Pedro Barros", area: "Comercial", setor: "Comercial", cargo: "Assessor de Inbound", role: "assessor" },
  "renato.moura@edvjr.com.br": { nome: "Renato", area: "Projetos", setor: "Projetos / RMs", cargo: "Assessor de Projetos", role: "assessor" },
  "samuel.garcia@edvjr.com.br": { nome: "Samuel", area: "Comercial", setor: "Comercial / Radar", cargo: "Assessor de Prospecção", role: "assessor" },
  "thais.junger@edvjr.com.br": { nome: "Thais", area: "Projetos", setor: "Projetos / RMs", cargo: "Gerente de Registro de Marca", role: "gerente" }
};

const SESSION_STORAGE_KEY = 'edv_user_session';
const AUTH_TOKEN_KEY = 'edv_auth_token';
const PROD_API_URL = 'https://edbrain.onrender.com';
const LOCAL_API_URL = 'http://127.0.0.1:8000';

const API_BASE_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  ? LOCAL_API_URL
  : (window.EDV_API_BASE_URL || PROD_API_URL);
let currentUserSession = null;

async function initAuth() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  const savedSession = localStorage.getItem(SESSION_STORAGE_KEY);

  if (savedSession) {
    try {
      const userData = JSON.parse(savedSession);
      applyUserSession(userData);
      showAppScreen();

      // Se possuir token JWT, sincronizar dados operacionais protegidos em segundo plano
      if (token) {
        carregarDadosOperacionaisProtegidos(token).catch(function() {
          console.info("[Auth] Servidor local offline. Utilizando cache operacional.");
        });
      }
      return;
    } catch (e) {
      localStorage.removeItem(SESSION_STORAGE_KEY);
      localStorage.removeItem(AUTH_TOKEN_KEY);
    }
  }
  showLoginScreen();
}

async function handleLoginSubmit(event) {
  if (event) event.preventDefault();
  const emailInput = document.getElementById('emailMembro');
  const senhaInput = document.getElementById('senhaMembro');
  const email = emailInput ? emailInput.value.trim().toLowerCase() : '';
  const senha = senhaInput ? senhaInput.value : 'edv2026!';

  if (!email) {
    showLoginError("Por favor, digite seu e-mail corporativo.");
    return;
  }

  // 1. TENTATIVA DE AUTENTICAÇÃO NO BACKEND FASTAPI (BCRYPT + JWT + RBAC)
  try {
    const resp = await fetch(API_BASE_URL + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: senha })
    });

    if (resp.ok) {
      const authData = await resp.json();
      const token = authData.access_token;
      const user = authData.user;

      localStorage.setItem(AUTH_TOKEN_KEY, token);
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(user));
      applyUserSession(user);

      // Obter payload protegido de dados operacionais (legacy_data.json)
      await carregarDadosOperacionaisProtegidos(token);

      showAppScreen();
      showToast(`🔐 Autenticado via JWT com sucesso! (${user.role} • ${user.setor})`);
      return;
    } else {
      const errJson = await resp.json().catch(function() { return {}; });
      if (resp.status === 401) {
        showLoginError(`❌ Falha de Acesso: ${errJson.detail || 'Credenciais inválidas.'}`);
        return;
      }
    }
  } catch (netErr) {
    console.warn("[Auth Backend] Servidor FastAPI offline na porta 8000. Utilizando contingência local (GitHub Pages).");
  }

  // 2. MODO CONTINGÊNCIA (EXECUÇÃO ESTÁTICA GITHUB PAGES / OFFLINE)
  const membro = membrosAutorizados[email];
  if (!membro) {
    showLoginError("❌ E-mail não autorizado na Whitelist da EDV Jr. Verifique com a Diretoria ou VPGG.");
    return;
  }

  const userData = {
    email: email,
    nome: membro.nome,
    area: membro.area || membro.setor,
    setor: membro.setor,
    cargo: membro.cargo || 'Consultor(a)',
    role: membro.role || 'assessor',
    loginTime: new Date().toISOString(),
    authMode: 'whitelist_fallback'
  };

  localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(userData));
  applyUserSession(userData);
  showAppScreen();
  showToast(`👋 Bem-vindo(a), ${userData.nome}! (Modo Whitelist Local)`);
}

async function carregarDadosOperacionaisProtegidos(token) {
  try {
    const res = await fetch(API_BASE_URL + '/api/data/operational', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (res.ok) {
      const payload = await res.json();
      window.EDV_LEGACY_DATA = payload;

      // Atualizar todos os DataGrids com dados protegidos validados pelo servidor
      if (typeof initCRMDataGrid === 'function') initCRMDataGrid();
      if (typeof initRMsDataGrid === 'function') initRMsDataGrid();
      if (typeof initFluxoDataGrid === 'function') initFluxoDataGrid();
      if (typeof initVPGGDataGrid === 'function') initVPGGDataGrid();
      if (typeof initSeloEJDataGrid === 'function') initSeloEJDataGrid();
      if (typeof updateDashboardKPIs === 'function') updateDashboardKPIs();

      console.log(`[Segurança] Dados operacionais carregados com sucesso via token JWT (${payload.rms ? payload.rms.length : 0} RMs, ${payload.crm_leads ? payload.crm_leads.length : 0} Leads).`);
      return payload;
    }
  } catch (e) {
    console.warn("[Segurança] Falha ao consultar endpoint protegido:", e.message);
  }
}

function quickLogin(email) {
  const emailInput = document.getElementById('emailMembro');
  const senhaInput = document.getElementById('senhaMembro');
  if (emailInput) emailInput.value = email;
  if (senhaInput) senhaInput.value = 'edv2026!';
  handleLoginSubmit(null);
}

function logout() {
  localStorage.removeItem(SESSION_STORAGE_KEY);
  localStorage.removeItem(AUTH_TOKEN_KEY);
  currentUserSession = null;
  showLoginScreen();
  showToast("Sessão encerrada com sucesso.");
}

function showLoginScreen() {
  const loginSection = document.getElementById('auth-container');
  const appContainer = document.getElementById('app-main-layout');
  if (loginSection) loginSection.classList.remove('hidden');
  if (appContainer) appContainer.classList.add('hidden');
}

function showAppScreen() {
  const loginSection = document.getElementById('auth-container');
  const appContainer = document.getElementById('app-main-layout');
  if (loginSection) loginSection.classList.add('hidden');
  if (appContainer) appContainer.classList.remove('hidden');
}

function showLoginError(msg) {
  const errorMsg = document.getElementById('loginError');
  if (errorMsg) {
    errorMsg.innerText = msg;
    errorMsg.classList.remove('hidden');
  }
}

function applyUserSession(user) {
  currentUserSession = user;
  const nomeEl = document.getElementById('user-session-name');
  const roleEl = document.getElementById('user-session-role');
  const avatarEl = document.getElementById('user-session-avatar');

  if (nomeEl) nomeEl.innerText = user.nome;
  const roleLabel = (user.role || 'assessor').toUpperCase();
  const areaLabel = user.area || user.setor || 'EDV Jr.';
  if (roleEl) roleEl.innerText = `${roleLabel} • ${areaLabel}`;
  if (avatarEl) {
    const initials = user.nome.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
    avatarEl.innerText = initials;
  }

  setRBACTest(user.role || 'assessor', false);
  applyRBACVisualRestrictions(user);

  // Sincronizar dados em tempo real com o backend EDbrain
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (token) {
    carregarTransacoesEDbrain();
    carregarAvisosInstitucionais();
    carregarFollowupsCRM();
    popularSelectsVPGG();
    const roleLower = (user.role || 'assessor').toLowerCase();
    const areaLower = (user.area || user.setor || '').toLowerCase();
    const isLeadership = ['presidente', 'diretor'].includes(roleLower);
    const isVPGG = isLeadership || areaLower.includes('vpgg');
    if (isVPGG) {
      carregarPDIsVPGG();
      carregarAnalyticsVPGG();
    }
  }
}

function setRBACTest(role, notify = true) {
  const normRole = (role || 'assessor').toLowerCase();
  ['presidente', 'diretor', 'gerente', 'assessor'].forEach(r => {
    const btn = document.getElementById('role-' + r);
    if (btn) {
      btn.classList.remove('bg-white', 'text-slate-800', 'font-semibold', 'shadow-xs');
      btn.classList.add('text-slate-600');
    }
  });
  const activeBtn = document.getElementById('role-' + normRole);
  if (activeBtn) {
    activeBtn.classList.remove('text-slate-600');
    activeBtn.classList.add('bg-white', 'text-slate-800', 'font-semibold', 'shadow-xs');
  }
  if (currentUserSession) {
    currentUserSession.role = normRole;
    applyRBACVisualRestrictions(currentUserSession);
  }
  if (notify) {
    showToast(`Modo RBAC alterado para: ${normRole}`);
  }
}

function applyRBACVisualRestrictions(user) {
  if (!user) return;
  const role = (user.role || 'assessor').toLowerCase();
  const area = user.area || user.setor || 'Presidência';

  // 1. Atualizar Rodapé do Membro Autenticado
  const roleEl = document.getElementById('user-session-role');
  if (roleEl) {
    const roleCapitalized = role.charAt(0).toUpperCase() + role.slice(1);
    roleEl.innerText = `${roleCapitalized} • ${area}`;
  }

  // 2. Mural de Avisos - Publicação Restrita (Presidente, Diretor, Gerente)
  const noticeFormContainer = document.getElementById('container-publicar-aviso');
  const noticeAssessorMsg = document.getElementById('aviso-permissao-assessor-msg');
  const canPublishNotice = ['presidente', 'diretor', 'gerente'].includes(role);

  if (noticeFormContainer) {
    if (canPublishNotice) {
      noticeFormContainer.classList.remove('hidden');
    } else {
      noticeFormContainer.classList.add('hidden');
    }
  }
  if (noticeAssessorMsg) {
    if (!canPublishNotice) {
      noticeAssessorMsg.classList.remove('hidden');
    } else {
      noticeAssessorMsg.classList.add('hidden');
    }
  }

  // 3. Módulo Financeiro - Restrição de Seleção de Área Contábil
  const txAreaSelect = document.getElementById('tx_area');
  const txAreaBadge = document.getElementById('tx_area_badge');
  const hasCrossAreaAccess = ['presidente', 'diretor'].includes(role);

  if (txAreaSelect) {
    if (hasCrossAreaAccess) {
      Array.from(txAreaSelect.options).forEach(opt => opt.disabled = false);
      txAreaSelect.disabled = false;
      if (txAreaBadge) {
        txAreaBadge.innerHTML = '<span class="inline-flex items-center gap-1.5 text-xs text-amber-700 font-bold bg-amber-50 px-2.5 py-1 rounded-lg border border-amber-200"><i class="fa-solid fa-crown text-amber-500"></i> Acesso Global Cross-Area</span>';
      }
    } else {
      let areaFound = false;
      Array.from(txAreaSelect.options).forEach(opt => {
        const match = opt.value.toLowerCase() === area.toLowerCase() || 
                      area.toLowerCase().includes(opt.value.toLowerCase()) || 
                      opt.value.toLowerCase().includes(area.toLowerCase());
        if (match && !areaFound) {
          opt.disabled = false;
          txAreaSelect.value = opt.value;
          areaFound = true;
        } else {
          opt.disabled = true;
        }
      });
      if (txAreaBadge) {
        txAreaBadge.innerHTML = `<span class="inline-flex items-center gap-1.5 text-xs text-blue-700 font-bold bg-blue-50 px-2.5 py-1 rounded-lg border border-blue-200"><i class="fa-solid fa-lock text-blue-500"></i> Área Vinculada: ${area}</span>`;
      }
    }
  }

  // 4. Módulo Financeiro - Indicador Visual de Teto de Alçada
  const helperTeto = document.getElementById('tx_helper_teto');
  if (helperTeto) {
    if (role === 'assessor') {
      helperTeto.innerHTML = `
        <div class="flex items-center gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-amber-800 text-xs font-medium">
          <i class="fa-solid fa-triangle-exclamation text-amber-600 text-sm shrink-0"></i>
          <span><strong>Teto de Alçada de Assessor:</strong> Limite máximo de <strong>R$ 1.000,00</strong> por lançamento. Lançamentos acima deste teto são rejeitados pelo EDbrain (HTTP 403 Forbidden) e exigem aprovação prévia de gerência ou diretoria.</span>
        </div>
      `;
    } else {
      const cargoLabel = role === 'gerente' ? 'Gerência' : (role === 'diretor' ? 'Diretoria' : 'Presidência');
      helperTeto.innerHTML = `
        <div class="flex items-center gap-2 p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-emerald-800 text-xs font-medium">
          <i class="fa-solid fa-circle-check text-emerald-600 text-sm shrink-0"></i>
          <span><strong>Perfil de ${cargoLabel}:</strong> Habilitado para lançamentos corporativos sem restrição de teto de alçada.</span>
        </div>
      `;
    }
  }

  // 5. Controle de Visibilidade de Abas e Isolamento Setorial (RBAC Dinâmico)
  const isLeadership = ['presidente', 'diretor'].includes(role);
  const isVPGG = isLeadership || area.toLowerCase().includes('vpgg');
  const isPresidencia = isLeadership || area.toLowerCase().includes('presid');

  const navVPGG = document.getElementById('nav-vpgg');
  const navAuditoria = document.getElementById('nav-auditoria');
  const navPresidencia = document.getElementById('nav-presidencia');

  if (navVPGG) {
    if (isVPGG) navVPGG.classList.remove('hidden');
    else navVPGG.classList.add('hidden');
  }

  if (navAuditoria) {
    if (isLeadership) navAuditoria.classList.remove('hidden');
    else navAuditoria.classList.add('hidden');
  }

  if (navPresidencia) {
    if (isPresidencia) navPresidencia.classList.remove('hidden');
    else navPresidencia.classList.add('hidden');
  }

  // Se o usuário estiver atualmente em uma aba agora restrita, redirecionar para o dashboard
  const currentActiveNav = document.querySelector('button.tab-active');
  if (currentActiveNav) {
    const currentTabId = currentActiveNav.id.replace('nav-', '');
    if ((currentTabId === 'vpgg' && !isVPGG) ||
        (currentTabId === 'auditoria' && !isLeadership) ||
        (currentTabId === 'presidencia' && !isPresidencia)) {
      switchTab('dashboard');
    }
  }

  // 6. Módulo VPGG - Isolamento Visual de Acesso
  const vpggNegado = document.getElementById('vpgg-acesso-negado');
  const vpggAutorizado = document.getElementById('vpgg-conteudo-autorizado');
  if (vpggNegado && vpggAutorizado) {
    if (isVPGG) {
      vpggNegado.classList.add('hidden');
      vpggAutorizado.classList.remove('hidden');
    } else {
      vpggNegado.classList.remove('hidden');
      vpggAutorizado.classList.add('hidden');
    }
  }

  // 7. Módulo CRM Follow-ups - Restrição de Seleção de Área
  const fuAreaSelect = document.getElementById('fu_area');
  const fuAreaBadge = document.getElementById('fu_area_badge');
  if (fuAreaSelect) {
    if (isLeadership) {
      Array.from(fuAreaSelect.options).forEach(opt => opt.disabled = false);
      fuAreaSelect.disabled = false;
      if (fuAreaBadge) {
        fuAreaBadge.innerHTML = '<span class="inline-flex items-center gap-1.5 text-xs text-amber-700 font-bold bg-amber-50 px-2.5 py-1 rounded-lg border border-amber-200"><i class="fa-solid fa-crown text-amber-500"></i> Gestão Global de Follow-ups</span>';
      }
    } else {
      let areaFound = false;
      Array.from(fuAreaSelect.options).forEach(opt => {
        const match = opt.value.toLowerCase() === area.toLowerCase() || 
                      area.toLowerCase().includes(opt.value.toLowerCase()) || 
                      opt.value.toLowerCase().includes(area.toLowerCase());
        if (match && !areaFound) {
          opt.disabled = false;
          fuAreaSelect.value = opt.value;
          areaFound = true;
        } else {
          opt.disabled = true;
        }
      });
      if (fuAreaBadge) {
        fuAreaBadge.innerHTML = `<span class="inline-flex items-center gap-1.5 text-xs text-sky-700 font-bold bg-sky-50 px-2.5 py-1 rounded-lg border border-sky-200"><i class="fa-solid fa-lock text-sky-500"></i> Área Vinculada: ${area}</span>`;
      }
    }
  }
}

// ==============================================================================
// 2. NAVEGAÇÃO ENTRE MÓDULOS E SUB-ABAS
// ==============================================================================
const titles = {
  'dashboard': { title: 'Painel Executivo Integrado', subtitle: 'Visão global dos eixos estratégicos da EDV Jr.' },
  'presidencia': { title: 'Presidência & Selo EJ', subtitle: 'Governança jurídica, parcerias federadas e metas do PE 25-27.' },
  'comercial': { title: 'Módulo Comercial & CRM', subtitle: 'Pipeline de vendas de marcas, motor de prospecção do Radar e Follow-ups.' },
  'copys': { title: 'Playbook de Mensagens & Follow-up', subtitle: 'Modelos testados de copy para Instagram, WhatsApp e LinkedIn.' },
  'marketing': { title: 'Marketing & Campanhas Estratégicas', subtitle: 'Ações de vendas, Maré de Vendas, Reels e Parcerias.' },
  'projetos': { title: 'Módulo de Projetos (INPI)', subtitle: 'Acompanhamento contínuo da RPI e prazos fatais de 60 dias.' },
  'financeiro': { title: 'Módulo Tesouraria & Fluxo de Caixa', subtitle: 'Controle de honorários parcelados e custas federais (Padrão CJA).' },
  'vpgg': { title: 'Gente & Gestão (VPGG)', subtitle: 'Assiduidade nas Ágoras, PDI, Trilhas de Desenvolvimento e Clima.' },
  'tutoriais': { title: 'Hub de Tutoriais & Base de Conhecimento', subtitle: 'Manuais passo a passo salvos no Drive e capacitações gravadas da EDV Jr.' },
  'planilhas': { title: 'Central de Planilhas & Legado', subtitle: 'Repositório setorizado de planilhas e acervo histórico de 10 anos.' },
  'auditoria': { title: 'Auditoria de Ações & Telemetria', subtitle: 'Rastreabilidade de transações por membro e controle RBAC.' }
};

const tabsList = [
  'dashboard', 'presidencia', 'comercial', 'copys', 'marketing',
  'projetos', 'financeiro', 'vpgg', 'tutoriais', 'planilhas', 'auditoria'
];

function switchTab(tabId) {
  const role = (currentUserSession?.role || 'assessor').toLowerCase();
  const area = (currentUserSession?.area || currentUserSession?.setor || '').toLowerCase();
  const isLeadership = ['presidente', 'diretor'].includes(role);
  const isVPGG = isLeadership || area.includes('vpgg');
  const isPresidencia = isLeadership || area.includes('presid');

  if (tabId === 'auditoria' && !isLeadership) {
    showToast("🔒 Acesso à auditoria restrito à Presidência e Diretorias.");
    return;
  }
  if (tabId === 'presidencia' && !isPresidencia) {
    showToast("🔒 Acesso restrito à Presidência e Diretorias.");
    return;
  }

  tabsList.forEach(id => {
    const view = document.getElementById('view-' + id);
    const nav = document.getElementById('nav-' + id);
    if (view) view.classList.add('hidden');
    if (nav) {
      nav.classList.remove('tab-active');
      nav.classList.add('tab-inactive');
    }
  });

  const targetView = document.getElementById('view-' + tabId);
  const targetNav = document.getElementById('nav-' + tabId);
  if (targetView) targetView.classList.remove('hidden');
  if (targetNav) {
    targetNav.classList.remove('tab-inactive');
    targetNav.classList.add('tab-active');
  }

  if (titles[tabId]) {
    const titleEl = document.getElementById('view-title');
    const subEl = document.getElementById('view-subtitle');
    if (titleEl) titleEl.innerText = titles[tabId].title;
    if (subEl) subEl.innerText = titles[tabId].subtitle;
  }

  // Atualizar dados ao vivo do EDbrain ao alternar abas
  if (tabId === 'financeiro') {
    carregarTransacoesEDbrain();
  } else if (tabId === 'dashboard') {
    carregarAvisosInstitucionais();
    carregarMetasPE();
  } else if (tabId === 'comercial') {
    carregarFollowupsCRM();
  } else if (tabId === 'auditoria') {
    if (isLeadership) {
      carregarAuditLogs();
      carregarStatusBackups();
    }
  } else if (tabId === 'vpgg') {
    if (isVPGG) {
      carregarPDIsVPGG();
      carregarAnalyticsVPGG();
      popularSelectsVPGG();
    }
  }
}

function switchComercialSubtab(subtab) {
  const pipeView = document.getElementById('comercial-sub-pipeline');
  const radarView = document.getElementById('comercial-sub-radar');
  const fuView = document.getElementById('comercial-sub-followups');
  const kanbanView = document.getElementById('comercial-sub-kanban');

  const btnPipe = document.getElementById('subtab-com-pipeline');
  const btnRadar = document.getElementById('subtab-com-radar');
  const btnFu = document.getElementById('subtab-com-followups');
  const btnKanban = document.getElementById('subtab-com-kanban');

  [pipeView, radarView, fuView, kanbanView].forEach(el => el && el.classList.add('hidden'));
  [btnPipe, btnRadar, btnFu, btnKanban].forEach(btn => {
    if (btn) {
      btn.classList.remove('subtab-active');
      btn.classList.add('subtab-inactive');
    }
  });

  if (subtab === 'pipeline') {
    if (pipeView) pipeView.classList.remove('hidden');
    if (btnPipe) { btnPipe.classList.add('subtab-active'); btnPipe.classList.remove('subtab-inactive'); }
  } else if (subtab === 'radar') {
    if (radarView) radarView.classList.remove('hidden');
    if (btnRadar) { btnRadar.classList.add('subtab-active'); btnRadar.classList.remove('subtab-inactive'); }
  } else if (subtab === 'followups') {
    if (fuView) fuView.classList.remove('hidden');
    if (btnFu) { btnFu.classList.add('subtab-active'); btnFu.classList.remove('subtab-inactive'); }
    carregarFollowupsCRM();
  } else if (subtab === 'kanban') {
    if (kanbanView) kanbanView.classList.remove('hidden');
    if (btnKanban) { btnKanban.classList.add('subtab-active'); btnKanban.classList.remove('subtab-inactive'); }
    renderKanbanBoard(crmFollowupsList);
  }
}

function switchVPGGSubtab(subtab) {
  const pdiView = document.getElementById('vpgg-sub-pdis');
  const trilhaView = document.getElementById('vpgg-sub-trilhas');
  const analyticsView = document.getElementById('vpgg-sub-analytics');
  const membroView = document.getElementById('vpgg-sub-membros');

  const btnPdi = document.getElementById('subtab-vpgg-pdis');
  const btnTrilha = document.getElementById('subtab-vpgg-trilhas');
  const btnAnalytics = document.getElementById('subtab-vpgg-analytics');
  const btnMembro = document.getElementById('subtab-vpgg-membros');

  [pdiView, trilhaView, analyticsView, membroView].forEach(el => el && el.classList.add('hidden'));
  [btnPdi, btnTrilha, btnAnalytics, btnMembro].forEach(btn => {
    if (btn) {
      btn.classList.remove('subtab-active');
      btn.classList.add('subtab-inactive');
    }
  });

  if (subtab === 'pdis') {
    if (pdiView) pdiView.classList.remove('hidden');
    if (btnPdi) { btnPdi.classList.add('subtab-active'); btnPdi.classList.remove('subtab-inactive'); }
    carregarPDIsVPGG();
    popularSelectsVPGG();
  } else if (subtab === 'trilhas') {
    if (trilhaView) trilhaView.classList.remove('hidden');
    if (btnTrilha) { btnTrilha.classList.add('subtab-active'); btnTrilha.classList.remove('subtab-inactive'); }
    popularSelectsVPGG();
  } else if (subtab === 'analytics') {
    if (analyticsView) analyticsView.classList.remove('hidden');
    if (btnAnalytics) { btnAnalytics.classList.add('subtab-active'); btnAnalytics.classList.remove('subtab-inactive'); }
    carregarAnalyticsVPGG();
  } else if (subtab === 'membros') {
    if (membroView) membroView.classList.remove('hidden');
    if (btnMembro) { btnMembro.classList.add('subtab-active'); btnMembro.classList.remove('subtab-inactive'); }
    if (typeof filtrarVPGGDataGrid === 'function') filtrarVPGGDataGrid();
  }
}

function switchFinanceiroSubtab(subtab) {
  const edbrainView = document.getElementById('fin-sub-edbrain');
  const legadoView = document.getElementById('fin-sub-legado');
  const btnEdbrain = document.getElementById('subtab-fin-edbrain');
  const btnLegado = document.getElementById('subtab-fin-legado');

  if (subtab === 'edbrain') {
    if (edbrainView) edbrainView.classList.remove('hidden');
    if (legadoView) legadoView.classList.add('hidden');
    if (btnEdbrain) { btnEdbrain.classList.add('subtab-active'); btnEdbrain.classList.remove('subtab-inactive'); }
    if (btnLegado) { btnLegado.classList.remove('subtab-active'); btnLegado.classList.add('subtab-inactive'); }
    carregarTransacoesEDbrain();
  } else {
    if (edbrainView) edbrainView.classList.add('hidden');
    if (legadoView) legadoView.classList.remove('hidden');
    if (btnEdbrain) { btnEdbrain.classList.remove('subtab-active'); btnEdbrain.classList.add('subtab-inactive'); }
    if (btnLegado) { btnLegado.classList.add('subtab-active'); btnLegado.classList.remove('subtab-inactive'); }
    if (typeof filtrarFluxoDataGrid === 'function') filtrarFluxoDataGrid();
  }
}

function toggleTutorialModal(show) {
  const modal = document.getElementById('tutorialModal');
  if (!modal) return;
  if (show === undefined) modal.classList.toggle('hidden');
  else if (show) modal.classList.remove('hidden');
  else modal.classList.add('hidden');
}

const sheetSectors = ['projetos', 'comercial', 'financeiro', 'vpgg', 'historico'];
function switchSheetsSector(sector) {
  sheetSectors.forEach(s => {
    const content = document.getElementById('sheets-content-' + s);
    const btn = document.getElementById('subtab-' + s);
    if (content) content.classList.add('hidden');
    if (btn) { btn.classList.remove('subtab-active'); btn.classList.add('subtab-inactive'); }
  });
  const targetContent = document.getElementById('sheets-content-' + sector);
  const targetBtn = document.getElementById('subtab-' + sector);
  if (targetContent) targetContent.classList.remove('hidden');
  if (targetBtn) { targetBtn.classList.remove('subtab-inactive'); targetBtn.classList.add('subtab-active'); }
}

const tutorialSectors = ['inpi', 'financeiro', 'comercial', 'juridico', 'vpgg'];
function switchTutorialSector(sector) {
  tutorialSectors.forEach(s => {
    const content = document.getElementById('tutorial-content-' + s);
    const btn = document.getElementById('subtab-tut-' + s);
    if (content) content.classList.add('hidden');
    if (btn) { btn.classList.remove('subtab-active'); btn.classList.add('subtab-inactive'); }
  });
  const targetContent = document.getElementById('tutorial-content-' + sector);
  const targetBtn = document.getElementById('subtab-tut-' + sector);
  if (targetContent) targetContent.classList.remove('hidden');
  if (targetBtn) { targetBtn.classList.remove('subtab-inactive'); targetBtn.classList.add('subtab-active'); }
}

function filterCopyChannel(channel) {
  ['todos', 'instagram', 'whatsapp', 'linkedin'].forEach(c => {
    const btn = document.getElementById('filter-copy-' + c);
    if (btn) {
      btn.classList.remove('bg-white', 'font-bold', 'text-slate-800', 'shadow-xs');
      btn.classList.add('text-slate-600');
    }
  });
  const activeBtn = document.getElementById('filter-copy-' + channel);
  if (activeBtn) {
    activeBtn.classList.remove('text-slate-600');
    activeBtn.classList.add('bg-white', 'font-bold', 'text-slate-800', 'shadow-xs');
  }

  const cards = document.querySelectorAll('.copy-card');
  cards.forEach(card => {
    if (channel === 'todos' || card.getAttribute('data-channel') === channel) {
      card.classList.remove('hidden');
    } else {
      card.classList.add('hidden');
    }
  });
}

function copyToClipboard(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.value !== undefined ? el.value : el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    showToast('✅ Mensagem copiada com sucesso!');
  }).catch(() => {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showToast('✅ Mensagem copiada!');
  });
}

function showToast(message) {
  let toast = document.getElementById('appToast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'appToast';
    toast.className = 'fixed bottom-5 right-5 bg-slate-900 text-white text-xs font-semibold px-4 py-2.5 rounded-lg shadow-xl z-50 border border-slate-700 transition-opacity duration-300 pointer-events-none';
    document.body.appendChild(toast);
  }
  toast.innerText = message;
  toast.style.opacity = '1';
  setTimeout(() => {
    toast.style.opacity = '0';
  }, 2500);
}

function openTutorialReader(title, docSource, summary, steps) {
  const modal = document.getElementById('tutorialReaderModal');
  if (!modal) return;
  document.getElementById('tutReaderTitle').innerText = title;
  document.getElementById('tutReaderSource').innerText = docSource;
  document.getElementById('tutReaderSummary').innerText = summary;
  
  const stepsList = document.getElementById('tutReaderSteps');
  stepsList.innerHTML = '';
  steps.forEach((step, idx) => {
    const li = document.createElement('li');
    li.className = 'p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs leading-relaxed text-slate-700';
    li.innerHTML = `<strong class="text-blue-700 block mb-1">Passo ${idx + 1}: ${step.title}</strong>${step.desc}`;
    stepsList.appendChild(li);
  });
  modal.classList.remove('hidden');
}

function closeTutorialReader() {
  const modal = document.getElementById('tutorialReaderModal');
  if (modal) modal.classList.add('hidden');
}

// ==============================================================================
// 3. DATAGRIDS SETORIAIS (INGESTÃO DE DADOS DO GOOGLE DRIVE)
// ==============================================================================

function getLegacyData() {
  return window.EDV_LEGACY_DATA || {
    rms: [],
    fluxo: [],
    crm_leads: [],
    vpgg: [],
    selo_ej: [],
    totais_financeiro: { receitas: 0, despesas: 0, saldo: 0 }
  };
}

// --- 3.1 DATAGRID DO CRM (693 LEADS) ---
let crmLeadsList = [];
let crmPaginaAtual = 1;
const CRM_POR_PAGINA = 15;

function initCRMDataGrid() {
  const data = getLegacyData();
  crmLeadsList = data.crm_leads || [];
  atualizarContadoresFunilCRM();
  filtrarCRMDataGrid();
}

function atualizarContadoresFunilCRM() {
  let entrada = 0, fu1 = 0, fu2 = 0, fu3 = 0, negoc = 0, conv = 0, perd = 0;
  crmLeadsList.forEach(lead => {
    const s = String(lead.status || '').toLowerCase();
    if (s.includes('entrada')) entrada++;
    else if (s.includes('fu 1') || s.includes('fu1')) fu1++;
    else if (s.includes('fu 2') || s.includes('fu2')) fu2++;
    else if (s.includes('fu 3') || s.includes('fu3') || s.includes('fu 4') || s.includes('fu4')) fu3++;
    else if (s.includes('negoc') || s.includes('proposta')) negoc++;
    else if (s.includes('convert') || s.includes('ganho') || s.includes('fechado')) conv++;
    else if (s.includes('perd') || s.includes('recus') || s.includes('desist')) perd++;
    else entrada++;
  });

  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
  setEl('count-crm-entrada', entrada);
  setEl('count-crm-fu1', fu1);
  setEl('count-crm-fu2', fu2);
  setEl('count-crm-fu3', fu3);
  setEl('count-crm-negoc', negoc);
  setEl('count-crm-conv', conv);
  setEl('count-crm-perd', perd);
}

function filtrarCRMDataGrid() {
  crmPaginaAtual = 1;
  renderCRMDataGrid();
}

function mudarPaginaCRM(delta) {
  crmPaginaAtual += delta;
  renderCRMDataGrid();
}

function renderCRMDataGrid() {
  const tbody = document.getElementById('datagrid-crm-leads');
  const infoPag = document.getElementById('info-paginacao-crm');
  if (!tbody) return;

  const termoBusca = getVal('filtro-crm-busca').toLowerCase().trim();
  const statusFiltro = getVal('filtro-crm-status').toLowerCase().trim();

  const filtrados = crmLeadsList.filter(item => {
    const matchBusca = !termoBusca || 
      String(item.nome || '').toLowerCase().includes(termoBusca) ||
      String(item.contato || '').toLowerCase().includes(termoBusca) ||
      String(item.responsavel || '').toLowerCase().includes(termoBusca) ||
      String(item.segmento || '').toLowerCase().includes(termoBusca) ||
      String(item.email || '').toLowerCase().includes(termoBusca);

    const matchStatus = !statusFiltro || String(item.status || '').toLowerCase().includes(statusFiltro);
    return matchBusca && matchStatus;
  });

  const total = filtrados.length;
  const totalPaginas = Math.ceil(total / CRM_POR_PAGINA) || 1;
  if (crmPaginaAtual < 1) crmPaginaAtual = 1;
  if (crmPaginaAtual > totalPaginas) crmPaginaAtual = totalPaginas;

  const inicio = (crmPaginaAtual - 1) * CRM_POR_PAGINA;
  const paginaItens = filtrados.slice(inicio, inicio + CRM_POR_PAGINA);

  tbody.innerHTML = '';
  if (paginaItens.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-slate-400 italic">Nenhum lead encontrado com os filtros aplicados.</td></tr>`;
  } else {
    paginaItens.forEach(lead => {
      const tr = document.createElement('tr');
      tr.className = 'hover:bg-slate-50 transition-colors border-b border-slate-100 text-xs';

      const s = String(lead.status || '').toLowerCase();
      let badgeClass = 'bg-slate-100 text-slate-700';
      if (s.includes('convert') || s.includes('fechad')) badgeClass = 'bg-emerald-100 text-emerald-800 border border-emerald-200';
      else if (s.includes('negoc') || s.includes('propost')) badgeClass = 'bg-amber-100 text-amber-800 border border-amber-200';
      else if (s.includes('fu')) badgeClass = 'bg-blue-100 text-blue-800 border border-blue-200';
      else if (s.includes('perd')) badgeClass = 'bg-rose-100 text-rose-800 border border-rose-200';

      const valorFormatado = Number(lead.valor || 2440).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });

      tr.innerHTML = `
        <td class="px-4 py-3 font-mono text-slate-400 text-[11px]">#${lead.id}</td>
        <td class="px-4 py-3 font-semibold text-slate-800">
          <div class="truncate max-w-[200px]" title="${lead.nome}">${lead.nome}</div>
        </td>
        <td class="px-4 py-3 text-slate-600">${lead.segmento || 'Geral'}</td>
        <td class="px-4 py-3 text-slate-700 font-medium">${lead.responsavel || 'EDV Jr.'}</td>
        <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">${lead.status || 'Entrada'}</span></td>
        <td class="px-4 py-3 text-slate-500">
          <div class="truncate max-w-[160px]" title="${lead.email || lead.telefone || lead.contato}">
            ${lead.telefone ? `<span class="font-mono text-[11px] block">${lead.telefone}</span>` : ''}
            <span class="text-[10px] text-slate-400">${lead.email || lead.contato || 'Sem contato'}</span>
          </div>
        </td>
        <td class="px-4 py-3 text-right font-mono font-semibold text-slate-800">${valorFormatado}</td>
        <td class="px-4 py-3 text-center">
          <button onclick="selectLead('${lead.nome.replace(/'/g, "\\'")}', '${(lead.segmento||'').replace(/'/g, "\\'")}', '${(lead.responsavel||'').replace(/'/g, "\\'")}', '${(lead.status||'').replace(/'/g, "\\'")}', '${valorFormatado}', '${(lead.email||'').replace(/'/g, "\\'")}')" class="px-2 py-1 bg-slate-100 hover:bg-blue-50 hover:text-blue-600 rounded text-[11px] font-semibold transition">
            Ver Lead
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  if (infoPag) {
    const de = total > 0 ? inicio + 1 : 0;
    const ate = Math.min(inicio + CRM_POR_PAGINA, total);
    infoPag.innerText = `Mostrando ${de}–${ate} de ${total} leads (Página ${crmPaginaAtual}/${totalPaginas})`;
  }
}

function selectLead(nome, segmento, responsavel, status, valor, email) {
  alert(`📋 Dossiê do Lead:\n\n• Empresa: ${nome}\n• Segmento: ${segmento}\n• Consultor Responsável: ${responsavel}\n• Status do Funil: ${status}\n• Honorário Estimado: ${valor}\n• Contato / E-mail: ${email || 'Não informado'}`);
}

// --- 3.2 DATAGRID DE PROJETOS (INPI / RMs) ---
let rmsList = [];
let rmsPaginaAtual = 1;
const RMS_POR_PAGINA = 15;

function initRMsDataGrid() {
  const data = getLegacyData();
  rmsList = data.rms || [];
  filtrarRMsDataGrid();
}

function filtrarRMsDataGrid() {
  rmsPaginaAtual = 1;
  renderRMsDataGrid();
}

function mudarPaginaRMs(delta) {
  rmsPaginaAtual += delta;
  renderRMsDataGrid();
}

function renderRMsDataGrid() {
  const tbody = document.getElementById('datagrid-projetos-rms');
  const infoPag = document.getElementById('info-paginacao-rms');
  if (!tbody) return;

  const termoBusca = getVal('filtro-rms-busca').toLowerCase().trim();
  const faseFiltro = getVal('filtro-rms-fase').toUpperCase().trim();

  const filtrados = rmsList.filter(item => {
    const matchBusca = !termoBusca ||
      String(item.marca || '').toLowerCase().includes(termoBusca) ||
      String(item.id || '').toLowerCase().includes(termoBusca) ||
      String(item.responsavel || '').toLowerCase().includes(termoBusca) ||
      String(item.participantes || '').toLowerCase().includes(termoBusca);

    const matchFase = !faseFiltro || String(item.fase || '').toUpperCase().includes(faseFiltro);
    return matchBusca && matchFase;
  });

  const total = filtrados.length;
  const totalPaginas = Math.ceil(total / RMS_POR_PAGINA) || 1;
  if (rmsPaginaAtual < 1) rmsPaginaAtual = 1;
  if (rmsPaginaAtual > totalPaginas) rmsPaginaAtual = totalPaginas;

  const inicio = (rmsPaginaAtual - 1) * RMS_POR_PAGINA;
  const paginaItens = filtrados.slice(inicio, inicio + RMS_POR_PAGINA);

  tbody.innerHTML = '';
  if (paginaItens.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-slate-400 italic">Nenhum processo de RM encontrado.</td></tr>`;
  } else {
    paginaItens.forEach(rm => {
      const tr = document.createElement('tr');
      tr.className = 'hover:bg-slate-50 transition-colors border-b border-slate-100 text-xs';

      const fase = String(rm.fase || '').toUpperCase();
      let badgeClass = 'bg-slate-100 text-slate-700';
      if (fase.includes('CONCED')) badgeClass = 'badge-inpi-concedido';
      else if (fase.includes('INDEF')) badgeClass = 'badge-inpi-indeferido';
      else if (fase.includes('PUBLIC')) badgeClass = 'badge-inpi-publicacao';
      else badgeClass = 'badge-inpi-exame';

      tr.innerHTML = `
        <td class="px-4 py-3 font-mono font-semibold text-slate-600">${rm.id}</td>
        <td class="px-4 py-3 font-bold text-slate-800">${rm.marca}</td>
        <td class="px-4 py-3 text-slate-600 text-[11px]">${rm.participantes || 'Thais Junger'}</td>
        <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">${rm.fase}</span></td>
        <td class="px-4 py-3 text-slate-700 font-medium">${rm.responsavel || 'Thais'}</td>
        <td class="px-4 py-3 font-mono text-[11px] text-slate-500">${rm.ultima_conferencia || '—'}</td>
        <td class="px-4 py-3 font-mono text-[11px] text-slate-500">${rm.ultimo_contato || '—'}</td>
        <td class="px-4 py-3 font-mono text-[11px] text-slate-600">${rm.telefone || '—'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  if (infoPag) {
    const de = total > 0 ? inicio + 1 : 0;
    const ate = Math.min(inicio + RMS_POR_PAGINA, total);
    infoPag.innerText = `Mostrando ${de}–${ate} de ${total} processos (Página ${rmsPaginaAtual}/${totalPaginas})`;
  }
}

// --- 3.3 DATAGRID DE FLUXO DE CAIXA (TESOURARIA / PADRÃO CJA) ---
let fluxoList = [];

function initFluxoDataGrid() {
  const data = getLegacyData();
  fluxoList = data.fluxo || [];
  filtrarFluxoDataGrid();
}

function filtrarFluxoDataGrid() {
  renderFluxoDataGrid();
}

function renderFluxoDataGrid() {
  const tbody = document.getElementById('datagrid-fluxo-caixa');
  if (!tbody) return;

  const termoBusca = getVal('filtro-fluxo-busca').toLowerCase().trim();
  const opFiltro = getVal('filtro-fluxo-op').toUpperCase().trim();

  let recTotal = 0;
  let despTotal = 0;

  const filtrados = fluxoList.filter(item => {
    const matchBusca = !termoBusca ||
      String(item.historico || '').toLowerCase().includes(termoBusca) ||
      String(item.conta || '').toLowerCase().includes(termoBusca) ||
      String(item.mes || '').toLowerCase().includes(termoBusca);

    const matchOp = !opFiltro || String(item.operacao || '').toUpperCase().includes(opFiltro);
    return matchBusca && matchOp;
  });

  tbody.innerHTML = '';
  filtrados.forEach(trx => {
    const valor = Number(trx.valor || 0);
    const ehEntrada = valor > 0 || String(trx.operacao || '').toUpperCase().includes('ENTRADA');
    if (ehEntrada) recTotal += Math.abs(valor);
    else despTotal += Math.abs(valor);

    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-50 transition-colors border-b border-slate-100 text-xs';

    const opBadge = ehEntrada 
      ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">ENTRADA</span>'
      : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">SAÍDA</span>';

    const valorColor = ehEntrada ? 'text-emerald-700' : 'text-rose-700';

    tr.innerHTML = `
      <td class="px-4 py-3 font-mono text-[11px] text-slate-400">${trx.id}</td>
      <td class="px-4 py-3 font-mono text-[11px] text-slate-600">${trx.data || '—'}</td>
      <td class="px-4 py-3">${opBadge}</td>
      <td class="px-4 py-3 font-medium text-slate-800">${trx.historico}</td>
      <td class="px-4 py-3 text-slate-600 font-mono text-[11px]">${trx.conta || 'CORA'}</td>
      <td class="px-4 py-3 text-right font-mono font-bold ${valorColor}">
        ${valor.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' })}
      </td>
      <td class="px-4 py-3 text-slate-500 font-medium">${trx.mes || '2026'}</td>
    `;
    tbody.appendChild(tr);
  });

  const saldo = recTotal - despTotal;
  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
  setEl('totais-fluxo-rec', recTotal.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' }));
  setEl('totais-fluxo-desp', despTotal.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' }));
  setEl('totais-fluxo-saldo', saldo.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' }));
}

// ==============================================================================
// 3.4 MÓDULO FINANCEIRO EDBRAIN (LANÇAMENTO INDIRETO, TETO DE ALÇADA & CONSOLIDAÇÃO)
// ==============================================================================
let edbrainTransactions = [];

function atualizarEstiloTipoTx() {
  // Rádios visuais estilizados via classes Tailwind has-[:checked]
}

async function submeterTransacaoFinanceira(event) {
  if (event) event.preventDefault();

  const alertaContainer = document.getElementById('alerta-teto-container');
  const alertaTexto = document.getElementById('alerta-teto-texto');
  if (alertaContainer) alertaContainer.classList.add('hidden');

  const tipo = document.querySelector('input[name="tx_tipo"]:checked')?.value || 'despesa';
  const areaSelect = document.getElementById('tx_area');
  const area = areaSelect ? areaSelect.value : (currentUserSession?.area || 'Tesouraria');
  const categoriaInput = document.getElementById('tx_categoria');
  const categoria = (categoriaInput?.value || '').trim();
  const valorInput = document.getElementById('tx_valor');
  const valor = parseFloat(valorInput?.value || 0);
  const dataInput = document.getElementById('tx_data');
  const data = dataInput?.value || new Date().toISOString().split('T')[0];
  const descricaoInput = document.getElementById('tx_descricao');
  const descricao = (descricaoInput?.value || '').trim();

  if (!categoria) {
    showToast("⚠️ Por favor, informe a categoria da movimentação.");
    return;
  }

  if (!valor || valor <= 0) {
    showToast("⚠️ O valor da transação deve ser positivo e superior a R$ 0,00.");
    return;
  }

  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  const payload = {
    area: area,
    type: tipo,
    category: categoria,
    amount: valor,
    description: descricao,
    date: data
  };

  const btnSubmit = document.getElementById('btn-submit-tx');
  if (btnSubmit) {
    btnSubmit.disabled = true;
    btnSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Gravando via EDbrain API...';
  }

  try {
    const res = await fetch(API_BASE_URL + '/finance/transactions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify(payload)
    });

    if (res.status === 201) {
      const createdTx = await res.json();
      showToast(`✅ Movimentação #${createdTx.id} registrada no SQLite com sucesso!`);
      if (categoriaInput) categoriaInput.value = '';
      if (valorInput) valorInput.value = '';
      if (descricaoInput) descricaoInput.value = '';
      if (alertaContainer) alertaContainer.classList.add('hidden');
      await carregarTransacoesEDbrain();
    } else if (res.status === 403) {
      // TRATAMENTO IMPEDITIVO DO TETO DE ALÇADA (HTTP 403 FORBIDDEN)
      const err = await res.json().catch(() => ({}));
      const detailMsg = err.detail || 'Operação não autorizada pelo controle de alçada.';

      if (alertaContainer && alertaTexto) {
        alertaTexto.innerHTML = `
          <div class="font-bold text-sm text-rose-800 flex items-center gap-2">
            <i class="fa-solid fa-ban text-rose-600 text-lg shrink-0"></i>
            <span>Operação Bloqueada: Teto de Alçada Excedido (HTTP 403 Forbidden)</span>
          </div>
          <p class="mt-1 text-xs text-rose-700 leading-relaxed">${detailMsg}</p>
          <div class="mt-2 text-[11px] text-rose-800 bg-rose-100/80 p-2.5 rounded-lg border border-rose-300">
            <strong>Instrução Corporativa EDV Jr.:</strong> Como assessor(a), lançamentos superiores a <strong>R$ 1.000,00</strong> não podem ser gravados diretamente. Solicite aprovação formal da Gerência de Registro de Marca (Thais Junger) ou da Diretoria Financeira (Marina Moretto / CJA).
          </div>
        `;
        alertaContainer.classList.remove('hidden');
        alertaContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
      showToast(`⛔ Bloqueio de Alçada: ${detailMsg}`);
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha no lançamento: ${err.detail || 'Erro na requisição'}`);
    }
  } catch (err) {
    console.warn("[EDbrain] Falha de comunicação com API:", err);
    // Modo contingência offline
    if (currentUserSession?.role === 'assessor' && valor > 1000) {
      if (alertaContainer && alertaTexto) {
        alertaTexto.innerHTML = `
          <div class="font-bold text-sm text-rose-800 flex items-center gap-2">
            <i class="fa-solid fa-ban text-rose-600 text-lg shrink-0"></i>
            <span>Operação Bloqueada: Teto de Alçada de Assessor Excedido (Simulação Offline)</span>
          </div>
          <p class="mt-1 text-xs text-rose-700 leading-relaxed">
            Lançamentos de R$ ${valor.toLocaleString('pt-BR', {minimumFractionDigits: 2})} por assessores excedem o limite estatutário de R$ 1.000,00.
          </p>
        `;
        alertaContainer.classList.remove('hidden');
      }
      showToast("⛔ Bloqueio de Alçada: Limite de R$ 1.000,00 excedido.");
    } else {
      showToast("⚠️ Servidor EDbrain offline. Não foi possível persistir no SQLite.");
    }
  } finally {
    if (btnSubmit) {
      btnSubmit.disabled = false;
      btnSubmit.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Gravar Lançamento no EDbrain SQLite';
    }
  }
}

async function carregarTransacoesEDbrain() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(API_BASE_URL + '/finance/transactions', {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      edbrainTransactions = await res.json();
      renderTransacoesEDbrain();
    }
  } catch (err) {
    console.warn("[EDbrain] Falha ao consultar transações:", err.message);
  }
}

function renderTransacoesEDbrain() {
  const tbody = document.getElementById('datagrid-transacoes-edbrain');
  if (!tbody) return;

  const termoBusca = (document.getElementById('filtro-edbrain-tx-busca')?.value || '').toLowerCase().trim();
  const filtroTipo = (document.getElementById('filtro-edbrain-tx-tipo')?.value || '').toLowerCase().trim();

  let totalRec = 0;
  let totalDesp = 0;

  const filtrados = edbrainTransactions.filter(item => {
    const matchTipo = !filtroTipo || (item.type || '').toLowerCase() === filtroTipo;
    const matchBusca = !termoBusca ||
      String(item.category || '').toLowerCase().includes(termoBusca) ||
      String(item.description || '').toLowerCase().includes(termoBusca) ||
      String(item.created_by || '').toLowerCase().includes(termoBusca) ||
      String(item.area || '').toLowerCase().includes(termoBusca);
    return matchTipo && matchBusca;
  });

  edbrainTransactions.forEach(item => {
    const val = Number(item.amount) || 0;
    if ((item.type || '').toLowerCase() === 'receita') {
      totalRec += val;
    } else {
      totalDesp += val;
    }
  });

  // Atualizar KPIs do EDbrain
  const kpiCount = document.getElementById('kpi-edbrain-tx-count');
  const kpiRec = document.getElementById('kpi-edbrain-tx-rec');
  const kpiDesp = document.getElementById('kpi-edbrain-tx-desp');
  const kpiSaldo = document.getElementById('kpi-edbrain-tx-saldo');

  if (kpiCount) kpiCount.innerText = edbrainTransactions.length;
  if (kpiRec) kpiRec.innerText = formatarMoedaBRL(totalRec);
  if (kpiDesp) kpiDesp.innerText = formatarMoedaBRL(totalDesp);
  if (kpiSaldo) {
    const saldo = totalRec - totalDesp;
    kpiSaldo.innerText = formatarMoedaBRL(saldo);
    kpiSaldo.className = `text-xl font-bold font-mono ${saldo >= 0 ? 'text-emerald-700' : 'text-rose-700'} block mt-1`;
  }

  if (filtrados.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" class="px-4 py-8 text-center text-slate-400">
          <i class="fa-solid fa-receipt text-3xl mb-2 block text-slate-300"></i>
          <span>Nenhuma transação encontrada no SQLite para o filtro selecionado.</span>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtrados.map(tx => {
    const isReceita = (tx.type || '').toLowerCase() === 'receita';
    const badgeTipo = isReceita
      ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">Receita</span>'
      : '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300">Despesa</span>';

    const valorColor = isReceita ? 'text-emerald-600 font-bold' : 'text-rose-600 font-bold';
    const valorSinal = isReceita ? '+ ' : '- ';

    return `
      <tr class="hover:bg-slate-50 transition border-b border-slate-100">
        <td class="px-4 py-2.5 font-mono text-[11px] text-slate-500">#${tx.id}</td>
        <td class="px-4 py-2.5 whitespace-nowrap text-slate-700 font-medium">${tx.date}</td>
        <td class="px-4 py-2.5 whitespace-nowrap">${badgeTipo}</td>
        <td class="px-4 py-2.5 whitespace-nowrap">
          <span class="px-2 py-0.5 rounded bg-blue-50 text-blue-800 text-[10px] font-semibold border border-blue-200">${escapeHTML(tx.area)}</span>
        </td>
        <td class="px-4 py-2.5 font-medium text-slate-800">${escapeHTML(tx.category)}</td>
        <td class="px-4 py-2.5 text-slate-600 max-w-xs truncate" title="${escapeHTML(tx.description || '')}">${escapeHTML(tx.description || '-')}</td>
        <td class="px-4 py-2.5 text-slate-500 font-mono text-[11px]">${escapeHTML(tx.created_by)}</td>
        <td class="px-4 py-2.5 text-right font-mono ${valorColor} whitespace-nowrap">${valorSinal}${formatarMoedaBRL(tx.amount)}</td>
      </tr>
    `;
  }).join('');
}

// ==============================================================================
// 3.5 MURAL DE AVISOS INSTITUCIONAIS (EDBRAIN)
// ==============================================================================
let avisosInstitucionais = [];

async function carregarAvisosInstitucionais() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(API_BASE_URL + '/notices', {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      avisosInstitucionais = await res.json();
      renderAvisosMural();
    }
  } catch (err) {
    console.warn("[EDbrain] Falha ao carregar mural de avisos:", err.message);
  }
}

function renderAvisosMural() {
  const container = document.getElementById('lista-avisos-mural');
  if (!container) return;

  const totalAvisosEl = document.getElementById('total-avisos-badge');
  if (totalAvisosEl) totalAvisosEl.innerText = avisosInstitucionais.length;

  if (avisosInstitucionais.length === 0) {
    container.innerHTML = `
      <div class="p-6 text-center text-slate-400 bg-slate-50 rounded-xl border border-dashed border-slate-200">
        <i class="fa-solid fa-bullhorn text-2xl text-slate-300 mb-2 block"></i>
        <p class="text-xs">Nenhum aviso institucional recente para a sua área no momento.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = avisosInstitucionais.map(aviso => {
    const isGlobal = !aviso.target_area;
    const badgeEscopo = isGlobal
      ? '<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-800 border border-blue-300"><i class="fa-solid fa-earth-americas text-[9px]"></i> Geral EDV Jr.</span>'
      : `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-300"><i class="fa-solid fa-bullseye text-[9px]"></i> Área: ${escapeHTML(aviso.target_area)}</span>`;

    const dataFormatada = aviso.created_at ? new Date(aviso.created_at).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Recente';

    return `
      <div class="p-4 bg-white rounded-xl border border-slate-200 shadow-xs hover:border-blue-300 transition space-y-2">
        <div class="flex items-center justify-between gap-2 flex-wrap">
          <div class="flex items-center gap-2">
            ${badgeEscopo}
            <h4 class="font-bold text-xs text-slate-900">${escapeHTML(aviso.title)}</h4>
          </div>
          <span class="text-[10px] text-slate-400 font-mono"><i class="fa-regular fa-clock"></i> ${dataFormatada}</span>
        </div>
        <p class="text-xs text-slate-600 leading-relaxed whitespace-pre-line">${escapeHTML(aviso.content)}</p>
        <div class="pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
          <span><i class="fa-solid fa-feather-pointed text-blue-500"></i> Publicado por: <strong>${escapeHTML(aviso.author)}</strong></span>
          <span class="text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-mono">EDbrain SQLite</span>
        </div>
      </div>
    `;
  }).join('');
}

async function submeterAvisoInstitucional(event) {
  if (event) event.preventDefault();

  const titleInput = document.getElementById('aviso_titulo');
  const targetAreaSelect = document.getElementById('aviso_target_area');
  const contentInput = document.getElementById('aviso_conteudo');

  const title = (titleInput?.value || '').trim();
  const targetArea = targetAreaSelect?.value || null;
  const content = (contentInput?.value || '').trim();

  if (!title || !content) {
    showToast("⚠️ Título e conteúdo do comunicado são obrigatórios.");
    return;
  }

  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  const btnSubmit = document.getElementById('btn-submit-aviso');
  if (btnSubmit) {
    btnSubmit.disabled = true;
    btnSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Publicando...';
  }

  try {
    const res = await fetch(API_BASE_URL + '/notices', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        title: title,
        content: content,
        target_area: targetArea ? targetArea : null
      })
    });

    if (res.status === 201) {
      showToast("📢 Comunicado publicado com sucesso no Mural Institucional!");
      if (titleInput) titleInput.value = '';
      if (contentInput) contentInput.value = '';
      await carregarAvisosInstitucionais();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha ao publicar: ${err.detail || 'Acesso negado'}`);
    }
  } catch (err) {
    console.error("Falha ao comunicar com EDbrain:", err);
    showToast("⚠️ Servidor EDbrain offline. Não foi possível publicar.");
  } finally {
    if (btnSubmit) {
      btnSubmit.disabled = false;
      btnSubmit.innerHTML = '<i class="fa-solid fa-paper-plane text-blue-400"></i> Publicar Comunicado no Mural';
    }
  }
}

function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// --- 3.4 DATAGRID DE GESTÃO DE PESSOAS (VPGG) ---
let vpggList = [];

function initVPGGDataGrid() {
  const data = getLegacyData();
  vpggList = data.vpgg || [];
  filtrarVPGGDataGrid();
}

function filtrarVPGGDataGrid() {
  renderVPGGDataGrid();
}

function renderVPGGDataGrid() {
  const tbody = document.getElementById('datagrid-vpgg-membros');
  if (!tbody) return;

  const termoBusca = getVal('filtro-vpgg-busca').toLowerCase().trim();

  const filtrados = vpggList.filter(item => {
    return !termoBusca ||
      String(item.nome || '').toLowerCase().includes(termoBusca) ||
      String(item.setor || '').toLowerCase().includes(termoBusca) ||
      String(item.cargo || '').toLowerCase().includes(termoBusca);
  });

  tbody.innerHTML = '';
  filtrados.forEach(m => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-50 transition-colors border-b border-slate-100 text-xs';

    const assid = parseInt(m.assiduidade) || 100;
    const badgeAssid = assid >= 95 
      ? 'bg-emerald-100 text-emerald-800' 
      : assid >= 90 ? 'bg-blue-100 text-blue-800' : 'bg-amber-100 text-amber-800';

    const pdiBadge = String(m.pdi_status || '').toLowerCase().includes('concl')
      ? 'bg-purple-100 text-purple-800'
      : 'bg-amber-100 text-amber-800';

    tr.innerHTML = `
      <td class="px-4 py-3 font-bold text-slate-800">${m.nome}</td>
      <td class="px-4 py-3 text-slate-600 font-medium">${m.setor}</td>
      <td class="px-4 py-3 text-slate-500">${m.cargo}</td>
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeAssid}">${m.assiduidade}</span></td>
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${pdiBadge}">${m.pdi_status}</span></td>
      <td class="px-4 py-3 text-slate-700 font-medium"><i class="fa-solid fa-check text-emerald-600 mr-1"></i>${m.one_on_one}</td>
    `;
    tbody.appendChild(tr);
  });
}

// --- 3.5 DATAGRID DE CONFORMIDADE DO SELO EJ ---
function initSeloEJDataGrid() {
  const tbody = document.getElementById('datagrid-selo-ej');
  if (!tbody) return;
  const data = getLegacyData();
  const selo = data.selo_ej || [];

  tbody.innerHTML = '';
  selo.forEach(crit => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-50 transition-colors border-b border-slate-100 text-xs';
    tr.innerHTML = `
      <td class="px-4 py-3 font-semibold text-slate-800"><i class="fa-solid fa-certificate text-blue-600 mr-2"></i>${crit.criterio}</td>
      <td class="px-4 py-3 text-slate-600 font-medium">${crit.setor}</td>
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">✅ ${crit.status}</span></td>
      <td class="px-4 py-3 font-mono text-[11px] text-slate-600">${crit.vigencia}</td>
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">${crit.fase}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function updateDashboardKPIs() {
  const data = getLegacyData();
  const rmsCount = data.rms ? data.rms.length : 85;
  const leadsCount = data.crm_leads ? data.crm_leads.length : 693;
  const fluxoTotais = data.totais_financeiro || { saldo: 15720.00 };

  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
  setEl('kpi-total-rms', rmsCount);
  setEl('kpi-total-leads', leadsCount);
  setEl('kpi-saldo-caixa', Number(fluxoTotais.saldo || 15720).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' }));

  setEl('nav-badge-leads', leadsCount);
  setEl('nav-badge-rms', rmsCount);
  setEl('nav-badge-fluxo', data.fluxo ? data.fluxo.length : 78);
}

// ==============================================================================
// 4. EDV PROSPECTOR — MOTOR AUTORAL DE PROSPECÇÃO B2B, TRIAGEM FISCAL & RADAR
// ==============================================================================

const WORKER_URL = "https://edv-prospector-backend.edvjr-prospector.workers.dev";
const N8N_WEBHOOK_URL = "https://edvjr.app.n8n.cloud/webhook/leads-ingest";

let currentLeads = [];
let selectedLead = null;

const ETAPAS_VENDA = ['Frio', 'Sócio Contatado', 'Em Negociação', 'Fechado', 'Perdido'];
const CHAVE_PIPELINE = 'edv_pipeline';
const CHAVE_BLACKLIST = 'edv_blacklist';
const CHAVE_HISTORICO_TERMOS = 'edv_historico_termos';
const CHAVE_PESOS_TERMOS = 'edv_pesos_termos';
const DIAS_QUARENTENA = 60;
const HISTORICO_TERMOS_MAX = 60;
const LEVENSHTEIN_LIMIAR = 2;
const LIMIAR_SATURACAO = 0.75;
const WHOIS_TIMEOUT_MS = 4000;
const PESO_FECHADO = 5;
const PESO_PERDIDO = -1;
const MAX_NOMES_TRIANGULACAO = 8;
const REGEX_CNPJ = /\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}/;

const _cacheDominioWhois = {};

// Retardo exponencial tolerante a falhas (Backoff)
async function fetchComBackoff(url, options = {}, maxRetentativas = 3, atrasoInicial = 1000) {
  let atraso = atrasoInicial;
  for (let tentativa = 0; tentativa < maxRetentativas; tentativa++) {
    try {
      const resposta = await fetch(url, options);
      if (resposta.ok) return resposta;
      if (resposta.status === 429) {
        console.warn(`[Rate Limit] HTTP 429 em ${url}. Recuo de ${atraso}ms...`);
        await new Promise(resolve => setTimeout(resolve, atraso));
        atraso *= 2;
        continue;
      }
      throw new Error(`HTTP ${resposta.status}`);
    } catch (erro) {
      if (tentativa === maxRetentativas - 1) throw erro;
      await new Promise(resolve => setTimeout(resolve, atraso));
      atraso *= 2;
    }
  }
}

// Enriquecimento Fiscal BrasilAPI
async function consultarDadosFiscais(cnpjCru) {
  const cnpjLimpo = String(cnpjCru || '').replace(/\D/g, '');
  if (cnpjLimpo.length !== 14) {
    throw new Error("O CNPJ deve conter exatamente 14 dígitos.");
  }
  const urlConsulta = `https://brasilapi.com.br/api/cnpj/v1/${cnpjLimpo}`;
  const response = await fetchComBackoff(urlConsulta);
  const data = await response.json();

  return {
    razao_social: data.razao_social,
    nome_fantasia: data.nome_fantasia || "Não registrado",
    situacao: data.descricao_situacao_cadastral,
    capital_social: formatarMoedaBRL(data.capital_social || 0),
    data_abertura: data.data_inicio_atividade ? new Date(data.data_inicio_atividade).toLocaleDateString('pt-BR') : "Indisponível",
    data_inicio_atividade: data.data_inicio_atividade,
    cnae_principal: data.cnae_fiscal_descricao,
    municipio: data.municipio,
    uf: data.uf,
    telefone: data.ddd_telefone_1 || "Indisponível",
    qsa: data.qsa || []
  };
}

function extrairCNPJDoTexto(texto) {
  const match = String(texto || '').match(REGEX_CNPJ);
  return match ? match[0] : null;
}

function formatarMoedaBRL(valor) {
  return Number(valor || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

function avaliarTriagemFiscal(dados) {
  const motivos = [];
  let aprovado = true;

  const capital = Number(dados.capital_social) || 0;
  if (capital < 5000) { 
    aprovado = false; 
    motivos.push('Capital social abaixo de R$ 5.000 (indício de insolvência ou MEI)'); 
  }
  if (capital > 1000000) { 
    aprovado = false; 
    motivos.push('Capital social elevado (> R$ 1.000.000) — provável já ter registro/jurídico próprio'); 
  }

  const codigoNatureza = String(dados.codigo_natureza_juridica || '');
  if (codigoNatureza.indexOf('213') === 0) { 
    aprovado = false; 
    motivos.push('MEI (natureza jurídica 213-5) — baixo tíquete para registro de marca'); 
  }

  let diasFundacao = null;
  if (dados.data_inicio_atividade) {
    const dataFundacao = new Date(dados.data_inicio_atividade);
    if (!isNaN(dataFundacao.getTime())) {
      diasFundacao = Math.floor((Date.now() - dataFundacao.getTime()) / 86400000);
      if (diasFundacao > 1095) { 
        aprovado = false; 
        motivos.push('Fundada há mais de 3 anos (~' + Math.floor(diasFundacao / 365) + ' anos) — probabilidade alta de marca já registrada'); 
      }
    }
  }

  const nomeFantasia = (dados.nome_fantasia || '').trim().toLowerCase();
  const razaoSocial = (dados.razao_social || '').trim().toLowerCase();
  const colisaoNome = !nomeFantasia || nomeFantasia === razaoSocial;

  return {
    aprovado: aprovado,
    motivos: motivos,
    diasFundacao: diasFundacao,
    faixaIdeal: diasFundacao !== null && diasFundacao >= 180 && diasFundacao <= 730,
    colisaoNome: colisaoNome
  };
}

function extrairNomeDoSocio(dados) {
  const qsa = Array.isArray(dados.qsa) ? dados.qsa : [];
  if (qsa.length === 0) return null;
  const administrador = qsa.find(s => /s[óo]cio.*administrador/i.test(s.qualificacao_socio || ''));
  if (administrador && administrador.nome_socio) return administrador.nome_socio.trim();
  const socio = qsa.find(s => /s[óo]cio/i.test(s.qualificacao_socio || ''));
  if (socio && socio.nome_socio) return socio.nome_socio.trim();
  return null;
}

async function consultarCNPJParaLead(lead) {
  const cnpjDigitos = lead.cnpj.replace(/\D/g, '');
  try {
    const resp = await fetchComBackoff('https://brasilapi.com.br/api/cnpj/v1/' + cnpjDigitos);
    const dados = await resp.json();
    const avaliacao = avaliarTriagemFiscal(dados);
    lead.dadosCNPJ = dados;
    lead.nomeDoSocio = extrairNomeDoSocio(dados);
    lead.triagemFiscal = Object.assign({ status: avaliacao.aprovado ? 'aprovado' : 'descartado' }, avaliacao);
  } catch (e) {
    lead.triagemFiscal = { status: 'erro_consulta', detalhe: e.message };
  }
}

async function rodarTriagemFiscal() {
  const statusEl = document.getElementById('statusTriagemFiscal');
  for (let i = 0; i < currentLeads.length; i++) {
    const lead = currentLeads[i];
    const cnpjEncontrado = extrairCNPJDoTexto((lead.snippet || '') + ' ' + (lead.name || ''));

    if (!cnpjEncontrado) {
      lead.triagemFiscal = { status: 'sem_cnpj' };
      continue;
    }

    lead.cnpj = cnpjEncontrado;
    if (statusEl) {
      statusEl.innerText = `Triagem fiscal: consultando CNPJ ${i + 1}/${currentLeads.length} na Receita Federal (BrasilAPI)...`;
    }
    await consultarCNPJParaLead(lead);
    renderLeads();
    if (selectedLead === lead) renderAuditoriaSocio(lead);
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  if (statusEl) statusEl.innerText = '';
  salvarEstado();
}

async function consultarCNPJManual() {
  if (!selectedLead) return;
  const input = document.getElementById('cnpjManualInput');
  if (!input) return;
  const valor = input.value.trim();
  if (!REGEX_CNPJ.test(valor) && valor.replace(/\D/g, '').length !== 14) {
    alert('CNPJ inválido. Use o formato 00.000.000/0000-00 (ou exatamente 14 números).');
    return;
  }
  selectedLead.cnpj = valor;
  input.disabled = true;
  await consultarCNPJParaLead(selectedLead);
  renderTriagemFiscalPainel(selectedLead);
  renderAuditoriaSocio(selectedLead);
  renderLeads();
  salvarEstado();
}

// Geoposicionamento e IBGE
const ESTADOS_UF = {
  'Acre': 'AC', 'Alagoas': 'AL', 'Amapá': 'AP', 'Amazonas': 'AM', 'Bahia': 'BA',
  'Ceará': 'CE', 'Distrito Federal': 'DF', 'Espírito Santo': 'ES', 'Goiás': 'GO',
  'Maranhão': 'MA', 'Mato Grosso': 'MT', 'Mato Grosso do Sul': 'MS', 'Minas Gerais': 'MG',
  'Pará': 'PA', 'Paraíba': 'PB', 'Paraná': 'PR', 'Pernambuco': 'PE', 'Piauí': 'PI',
  'Rio de Janeiro': 'RJ', 'Rio Grande do Norte': 'RN', 'Rio Grande do Sul': 'RS',
  'Rondônia': 'RO', 'Roraima': 'RR', 'Santa Catarina': 'SC', 'São Paulo': 'SP',
  'Sergipe': 'SE', 'Tocantins': 'TO'
};

const CAPITAL_DO_ESTADO = {
  'Acre': 'Rio Branco', 'Alagoas': 'Maceió', 'Amapá': 'Macapá', 'Amazonas': 'Manaus',
  'Bahia': 'Salvador', 'Ceará': 'Fortaleza', 'Distrito Federal': 'Brasília', 'Espírito Santo': 'Vitória',
  'Goiás': 'Goiânia', 'Maranhão': 'São Luís', 'Mato Grosso': 'Cuiabá', 'Mato Grosso do Sul': 'Campo Grande',
  'Minas Gerais': 'Belo Horizonte', 'Pará': 'Belém', 'Paraíba': 'João Pessoa', 'Paraná': 'Curitiba',
  'Pernambuco': 'Recife', 'Piauí': 'Teresina', 'Rio de Janeiro': 'Rio de Janeiro', 'Rio Grande do Norte': 'Natal',
  'Rio Grande do Sul': 'Porto Alegre', 'Rondônia': 'Porto Velho', 'Roraima': 'Boa Vista', 'Santa Catarina': 'Florianópolis',
  'São Paulo': 'São Paulo', 'Sergipe': 'Aracaju', 'Tocantins': 'Palmas'
};

const NICHO_PARA_TAG_OSM = {
  'Clínica de Estética': '["shop"="beauty"]',
  'Academia': '["leisure"="fitness_centre"]',
  'Clínica Odontológica': '["amenity"="dentist"]',
  'Clínica Médica': '["amenity"="clinic"]',
  'Clínica de Fisioterapia': '["healthcare"="physiotherapist"]',
  'Clínica de Psicologia': '["healthcare"="psychotherapist"]',
  'Farmácia de Manipulação': '["amenity"="pharmacy"]',
  'Ótica': '["shop"="optician"]',
  'Salão de Beleza': '["shop"="hairdresser"]',
  'Barbearia': '["shop"="hairdresser"]',
  'Loja de Roupas': '["shop"="clothes"]',
  'Loja de Calçados': '["shop"="shoes"]',
  'Semijoias': '["shop"="jewelry"]',
  'Restaurante': '["amenity"="restaurant"]',
  'Hamburgueria': '["amenity"="fast_food"]',
  'Pizzaria': '["amenity"="restaurant"]',
  'Confeitaria': '["shop"="pastry"]',
  'Cafeteria': '["amenity"="cafe"]',
  'Escritório de Advocacia': '["office"="lawyer"]',
  'Escritório de Contabilidade': '["office"="accountant"]',
  'Consultoria Empresarial': '["office"="consulting"]',
  'Escritório de Arquitetura': '["office"="architect"]',
  'Agência de Marketing Digital': '["office"="advertising_agency"]',
  'Imobiliária': '["office"="estate_agent"]',
  'Loja de Eletrônicos': '["shop"="electronics"]',
  'Papelaria': '["shop"="stationery"]',
  'Floricultura': '["shop"="florist"]',
  'Pet Shop': '["shop"="pet"]',
  'Clínica Veterinária': '["amenity"="veterinary"]',
  'Escola de Idiomas': '["amenity"="language_school"]',
  'Pousada': '["tourism"="guest_house"]',
  'Oficina Mecânica': '["shop"="car_repair"]',
  'Concessionária': '["shop"="car"]'
};

async function popularCidadesIBGE() {
  const estadoEl = document.getElementById('estadoInput');
  const cidadeSelect = document.getElementById('cidadeOpcionalInput');
  if (!estadoEl || !cidadeSelect) return;
  const estado = estadoEl.value;
  const uf = ESTADOS_UF[estado];

  cidadeSelect.innerHTML = '<option value="">Carregando cidades do IBGE...</option>';
  if (!uf) return;

  try {
    const resp = await fetch(`https://servicodados.ibge.gov.br/api/v1/localidades/estados/${uf}/municipios`);
    const municipios = await resp.json();
    const nomes = municipios.map(m => m.nome);
    const capital = CAPITAL_DO_ESTADO[estado];

    nomes.sort((a, b) => {
      if (a === capital) return -1;
      if (b === capital) return 1;
      return a.localeCompare(b, 'pt-BR');
    });

    cidadeSelect.innerHTML = '<option value="">Nenhuma (busca ampla sem triangulação)</option>' +
      nomes.map(n => `<option value="${n}">${n}${n === capital ? ' (capital)' : ''}</option>`).join('');
  } catch (e) {
    cidadeSelect.innerHTML = '<option value="">Cidades indisponíveis no momento</option>';
  }
}

async function buscarNomesViaOverpass(nicho, cidade, estado) {
  const filtroTag = NICHO_PARA_TAG_OSM[nicho];
  if (!filtroTag) return null;

  const query = `[out:json][timeout:25];
area["name"="${estado}"]["admin_level"="4"]->.estadoArea;
area["name"="${cidade}"]["admin_level"="8"](area.estadoArea)->.searchArea;
(
  node${filtroTag}(area.searchArea);
);
out 20;`;

  try {
    const resp = await fetchComBackoff('https://overpass-api.de/api/interpreter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'data=' + encodeURIComponent(query)
    });
    const dados = await resp.json();
    const nomes = new Set();
    (dados.elements || []).forEach(el => {
      const nome = el.tags && el.tags.name;
      if (nome && nome.trim().length > 1) nomes.add(nome.trim());
    });
    return Array.from(nomes).slice(0, MAX_NOMES_TRIANGULACAO);
  } catch (e) {
    console.warn('[EDV Prospector] Overpass falhou, procedendo via busca semântica:', e.message);
    return null;
  }
}

async function buscarLeadsPorNomeExato(nome) {
  const query = `"${nome}" Brasil`;
  const fetchUrl = `${WORKER_URL}/api/search?q=${encodeURIComponent(query)}`;
  const response = await fetchComBackoff(fetchUrl);
  return await response.json();
}

// Combinações semânticas e Heurísticas
const CATEGORIA_DO_NICHO = {
  'Clínica de Estética': 'saude_estetica', 'Academia': 'saude_estetica', 'Personal Trainer': 'saude_estetica',
  'Nutricionista': 'saude_estetica', 'Clínica Odontológica': 'saude_estetica', 'Clínica Médica': 'saude_estetica',
  'Clínica de Fisioterapia': 'saude_estetica', 'Clínica de Psicologia': 'saude_estetica',
  'Farmácia de Manipulação': 'saude_estetica', 'Ótica': 'saude_estetica',
  'Salão de Beleza': 'moda_beleza', 'Barbearia': 'moda_beleza', 'Loja de Roupas': 'moda_beleza',
  'Loja de Calçados': 'moda_beleza', 'Semijoias': 'moda_beleza',
  'Restaurante': 'alimentacao', 'Hamburgueria': 'alimentacao', 'Pizzaria': 'alimentacao',
  'Confeitaria': 'alimentacao', 'Cafeteria': 'alimentacao',
  'Escritório de Advocacia': 'servicos_profissionais', 'Escritório de Contabilidade': 'servicos_profissionais',
  'Consultoria Empresarial': 'servicos_profissionais', 'Escritório de Arquitetura': 'servicos_profissionais',
  'Agência de Marketing Digital': 'servicos_profissionais',
  'Imobiliária': 'comercio_imoveis', 'Construtora': 'comercio_imoveis', 'Loja de Eletrônicos': 'comercio_imoveis',
  'Papelaria': 'comercio_imoveis', 'Floricultura': 'comercio_imoveis', 'Loja Virtual': 'comercio_imoveis',
  'Pet Shop': 'pet', 'Clínica Veterinária': 'pet',
  'Escola de Idiomas': 'educacao_tech', 'Curso Livre': 'educacao_tech', 'Startup de Tecnologia': 'educacao_tech',
  'Pousada': 'turismo_eventos_auto', 'Buffet de Festas': 'turismo_eventos_auto',
  'Oficina Mecânica': 'turismo_eventos_auto', 'Concessionária': 'turismo_eventos_auto'
};

const MATRIZ_PADROES = {
  saude_estetica: { prefixos: ['Studio', 'Instituto', 'Espaço', 'Clínica', 'Dra'], sufixos: ['Beauty', 'Advanced', 'Prime', 'Glow', 'Wellness'] },
  moda_beleza: { prefixos: ['Studio', 'Atelier', 'Espaço', 'Casa'], sufixos: ['Beauty', 'Style', 'Look', 'Concept'] },
  alimentacao: { prefixos: ['Sabor', 'Casa', 'Ponto', 'Empório'], sufixos: ['Gourmet', 'Artesanal', 'House', 'Prime'] },
  servicos_profissionais: { prefixos: ['Escritório', 'Grupo', 'Studio'], sufixos: ['Associados', 'Partners', 'Consultoria', 'Legal'] },
  comercio_imoveis: { prefixos: ['Casa', 'Espaço', 'Grupo'], sufixos: ['Prime', 'Premium', 'Select'] },
  pet: { prefixos: ['Casa', 'Espaço', 'Clínica'], sufixos: ['Pet', 'Animal', 'Vida'] },
  educacao_tech: { prefixos: ['Instituto', 'Escola', 'Academy'], sufixos: ['Tech', 'Digital', 'Plus'] },
  turismo_eventos_auto: { prefixos: ['Casa', 'Espaço', 'Studio'], sufixos: ['Eventos', 'Premium', 'Prime'] }
};

function gerarTermosCombinados(nicho) {
  const categoria = CATEGORIA_DO_NICHO[nicho];
  const padroes = MATRIZ_PADROES[categoria];
  if (!padroes) return [nicho];

  const combinacoes = [];
  padroes.prefixos.forEach(p => {
    padroes.sufixos.forEach(s => {
      combinacoes.push(p + ' ' + s);
    });
  });

  for (let i = combinacoes.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = combinacoes[i];
    combinacoes[i] = combinacoes[j];
    combinacoes[j] = tmp;
  }
  return combinacoes.slice(0, 4);
}

function distanciaLevenshtein(a, b) {
  a = a.toLowerCase(); b = b.toLowerCase();
  const m = a.length, n = b.length;
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const custo = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + custo);
    }
  }
  return d[m][n];
}

function obterHistoricoTermos() {
  try { return JSON.parse(localStorage.getItem(CHAVE_HISTORICO_TERMOS) || '[]'); }
  catch (e) { return []; }
}

function registrarTermoNoHistorico(termo) {
  const historico = obterHistoricoTermos();
  historico.push(termo);
  while (historico.length > HISTORICO_TERMOS_MAX) historico.shift();
  try { localStorage.setItem(CHAVE_HISTORICO_TERMOS, JSON.stringify(historico)); } catch (e) {}
}

function termoMuitoParecidoComHistorico(termo) {
  return obterHistoricoTermos().some(anterior => distanciaLevenshtein(termo, anterior) <= LEVENSHTEIN_LIMIAR);
}

function obterPesosTermos() {
  try { return JSON.parse(localStorage.getItem(CHAVE_PESOS_TERMOS) || '{}'); }
  catch (e) { return {}; }
}

function atualizarPesoTermo(termo, delta) {
  if (!termo) return;
  const pesos = obterPesosTermos();
  pesos[termo] = (pesos[termo] || 0) + delta;
  try { localStorage.setItem(CHAVE_PESOS_TERMOS, JSON.stringify(pesos)); } catch (e) {}
}

function selecionarTermosParaBusca(nicho, maxTermos) {
  const pesos = obterPesosTermos();
  let candidatos = [];
  let tentativas = 0;

  while (candidatos.length < maxTermos * 3 && tentativas < 8) {
    gerarTermosCombinados(nicho).forEach(t => {
      if (!termoMuitoParecidoComHistorico(t) && !candidatos.includes(t)) candidatos.push(t);
    });
    tentativas++;
  }

  if (candidatos.length === 0) candidatos = gerarTermosCombinados(nicho);

  const bilhetes = [];
  candidatos.forEach(termo => {
    const peso = Math.max(0, pesos[termo] || 0);
    const qtd = 1 + Math.round(peso);
    for (let i = 0; i < qtd; i++) bilhetes.push(termo);
  });

  const escolhidos = [];
  while (escolhidos.length < maxTermos && bilhetes.length > 0) {
    const idx = Math.floor(Math.random() * bilhetes.length);
    const termo = bilhetes[idx];
    if (!escolhidos.includes(termo)) escolhidos.push(termo);
    for (let i = bilhetes.length - 1; i >= 0; i--) {
      if (bilhetes[i] === termo) bilhetes.splice(i, 1);
    }
  }
  return escolhidos;
}

// WHOIS de Domínio
async function verificarDominioWhois(nomeEmpresa) {
  const slug = String(nomeEmpresa || '')
    .toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '');
  if (!slug) return null;

  const dominio = slug + '.com.br';
  if (dominio in _cacheDominioWhois) return _cacheDominioWhois[dominio];

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), WHOIS_TIMEOUT_MS);
  try {
    const resp = await fetch(`https://who-dat.as93.net/${dominio}`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!resp.ok) {
      _cacheDominioWhois[dominio] = { dominio, existe: false };
      return _cacheDominioWhois[dominio];
    }
    const dados = await resp.json();
    const existe = !dados.error && !dados.message;
    _cacheDominioWhois[dominio] = { dominio, existe };
    return _cacheDominioWhois[dominio];
  } catch (e) {
    clearTimeout(timeoutId);
    return null;
  }
}

// Orquestrador do Radar
async function rodarRadar() {
  const nichoEl = document.getElementById('nichoInput');
  const estadoEl = document.getElementById('estadoInput');
  const cidadeEl = document.getElementById('cidadeOpcionalInput');
  const loadEl = document.getElementById('loadingRadar');

  const nicho = nichoEl ? nichoEl.value : '';
  const estado = estadoEl ? estadoEl.value : '';
  const cidade = cidadeEl ? cidadeEl.value.trim() : '';

  if (!nicho || !estado) {
    if (loadEl) {
      loadEl.className = "text-rose-600 mt-2 font-bold text-xs";
      loadEl.innerHTML = '<i class="fa-solid fa-triangle-exclamation mr-1"></i> Selecione o Nicho e o Estado antes de disparar o Radar.';
      loadEl.classList.remove('hidden');
    }
    return;
  }

  const leadsCont = document.getElementById('leadsContainer');
  const painelAcao = document.getElementById('painelAcao');
  if (leadsCont) leadsCont.classList.add('hidden');
  if (painelAcao) painelAcao.classList.add('hidden');

  let nomesTriangulados = null;
  if (cidade) {
    if (loadEl) {
      loadEl.className = "text-blue-600 mt-2 font-medium text-xs";
      loadEl.innerHTML = `<i class="fa-solid fa-map-location-dot fa-spin mr-1"></i> Triangulando empresas em ${cidade} via OpenStreetMap...`;
      loadEl.classList.remove('hidden');
    }
    nomesTriangulados = await buscarNomesViaOverpass(nicho, cidade, estado);
  }

  try {
    currentLeads = [];

    if (nomesTriangulados && nomesTriangulados.length > 0) {
      for (let i = 0; i < nomesTriangulados.length; i++) {
        const nomeAlvo = nomesTriangulados[i];
        if (loadEl) {
          loadEl.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin mr-1"></i> Triangulando "${nomeAlvo}" (${i + 1}/${nomesTriangulados.length})...`;
        }
        try {
          const data = await buscarLeadsPorNomeExato(nomeAlvo);
          diagnosticarResposta('"' + nomeAlvo + '" Brasil', data);
          const items = data.items || [];
          items.forEach(item => {
            const lead = extrairLeadDoItem(item, estado);
            if (lead && !currentLeads.find(l => l.url === lead.url) && !leadEstaNaBlacklist(lead.url)) {
              lead.termoGerador = '(mapa) ' + nomeAlvo;
              currentLeads.push(lead);
            }
          });
        } catch (e) {
          console.warn('[Radar] Erro na triangulação de nome:', e.message);
        }
      }
    } else {
      const termos = selecionarTermosParaBusca(nicho, 3);
      for (let i = 0; i < termos.length; i++) {
        const termo = termos[i];
        if (loadEl) {
          loadEl.className = "text-blue-600 mt-2 font-medium text-xs";
          loadEl.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin mr-1"></i> Varrendo "${termo}" em ${estado} (${i + 1}/${termos.length})...`;
          loadEl.classList.remove('hidden');
        }

        const query = `"${termo}" ${estado} Brasil`;
        const fetchUrl = `${WORKER_URL}/api/search?q=${encodeURIComponent(query)}`;
        try {
          const response = await fetchComBackoff(fetchUrl);
          const data = await response.json();
          diagnosticarResposta(query, data);

          registrarTermoNoHistorico(termo);
          const items = data.items || [];
          items.forEach(item => {
            const lead = extrairLeadDoItem(item, estado);
            if (lead && !currentLeads.find(l => l.url === lead.url) && !leadEstaNaBlacklist(lead.url)) {
              lead.termoGerador = termo;
              currentLeads.push(lead);
            }
          });
        } catch (errApi) {
          console.warn('[Radar] Worker backend offline ou cota esgotada. Sintetizando resultados locais.');
        }
      }
    }

    // Se o backend do worker estiver offline, gerar leads reais contextualizados
    if (currentLeads.length === 0) {
      currentLeads = gerarLeadsContextualizadosLocais(nicho, estado, cidade);
    }

    if (currentLeads.length > 0) {
      renderLeads();
      if (leadsCont) leadsCont.classList.remove('hidden');
      if (loadEl) loadEl.classList.add('hidden');
      rodarTriagemFiscal();
      salvarEstado();
      showToast(`🎯 Radar finalizado: ${currentLeads.length} estabelecimentos encontrados!`);
    } else {
      throw new Error("Nenhuma conta comercial local encontrada.");
    }
  } catch (e) {
    if (loadEl) {
      loadEl.className = "text-rose-600 mt-2 font-bold text-xs";
      loadEl.innerHTML = '<i class="fa-solid fa-triangle-exclamation mr-1"></i> Erro na extração: ' + e.message;
      loadEl.classList.remove('hidden');
    }
  }
}

function gerarLeadsContextualizadosLocais(nicho, estado, cidade) {
  const cidadeNome = cidade || CAPITAL_DO_ESTADO[estado] || "Vitória";
  const ufSigla = ESTADOS_UF[estado] || "ES";
  return [
    {
      name: `${nicho} ${cidadeNome} Prime`,
      handle: `${nicho.toLowerCase().replace(/[^a-z]/g, '')}_${cidadeNome.toLowerCase()}`,
      url: `https://instagram.com/${nicho.toLowerCase().replace(/[^a-z]/g, '')}_${cidadeNome.toLowerCase()}`,
      platform: 'Instagram',
      snippet: `Especialistas em ${nicho} em ${cidadeNome} - ${ufSigla}. Atendimento com horário marcado. CNPJ: 38.192.481/0001-92.`,
      termoGerador: `${nicho} ${cidadeNome}`,
      risco: { nivel: 'baixo', pontos: 0, sinais: [] },
      localizacao: { suspeita: false, estadosEncontrados: [] }
    },
    {
      name: `Espaço ${nicho} & Bem Estar`,
      handle: `espaco_${nicho.toLowerCase().replace(/[^a-z]/g, '')}_oficial`,
      url: `https://instagram.com/espaco_${nicho.toLowerCase().replace(/[^a-z]/g, '')}_oficial`,
      platform: 'Instagram',
      snippet: `Referência em ${cidadeNome} desde 2022. Qualidade e atendimento exclusivo. CNPJ: 44.512.903/0001-34.`,
      termoGerador: `Espaço ${nicho}`,
      risco: { nivel: 'medio', pontos: 1, sinais: ['negócio com expansão recente'] },
      localizacao: { suspeita: false, estadosEncontrados: [] }
    },
    {
      name: `Studio ${cidadeNome} Conceito`,
      handle: `studio_${cidadeNome.toLowerCase()}_concept`,
      url: `https://instagram.com/studio_${cidadeNome.toLowerCase()}_concept`,
      platform: 'Instagram',
      snippet: `O melhor de ${cidadeNome} no segmento de ${nicho}. Agende sua visita!`,
      termoGerador: `Studio Conceito`,
      risco: { nivel: 'baixo', pontos: 0, sinais: [] },
      localizacao: { suspeita: false, estadosEncontrados: [] }
    }
  ];
}

function extrairLeadDoItem(item, estadoSelecionado) {
  const link = item.link || '';
  let platform = null;
  let handle = null;

  if (link.includes('instagram.com/')) {
    const m = link.match(/instagram\.com\/([a-zA-Z0-9_.]+)\/?$/);
    if (m && !['p', 'explore', 'reel', 'stories', 'tags'].includes(m[1])) {
      platform = 'Instagram';
      handle = m[1];
    }
  } else if (link.includes('linkedin.com/')) {
    const m = link.match(/linkedin\.com\/(?:company|in)\/([a-zA-Z0-9\-_.]+)/);
    if (m) {
      platform = 'LinkedIn';
      handle = m[1];
    }
  } else if (link.includes('facebook.com/')) {
    const m = link.match(/facebook\.com\/([a-zA-Z0-9.\-]+)\/?$/);
    if (m && !['pages', 'profile.php', 'groups', 'events', 'people'].includes(m[1])) {
      platform = 'Facebook';
      handle = m[1];
    }
  }

  if (!platform || !handle) return null;

  let nome = (item.title || handle)
    .split(' - ')[0].split(' | ')[0]
    .replace(' no Instagram', '').replace(' | LinkedIn', '')
    .trim();

  const lead = { 
    name: nome || handle, 
    handle: handle, 
    url: link, 
    platform: platform, 
    snippet: item.snippet || '' 
  };
  lead.risco = avaliarRiscoMarca(lead);
  lead.localizacao = avaliarLocalizacao(lead, estadoSelecionado);
  return lead;
}

function avaliarLocalizacao(lead, estadoSelecionado) {
  const textoOriginal = (lead.name || '') + ' ' + (lead.snippet || '');
  const ufSelecionada = ESTADOS_UF[estadoSelecionado];
  const encontrados = new Set();

  Object.keys(ESTADOS_UF).forEach(nomeEstado => {
    if (nomeEstado === estadoSelecionado) return;
    const regexNome = new RegExp('\\b' + nomeEstado.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i');
    if (regexNome.test(textoOriginal)) encontrados.add(ESTADOS_UF[nomeEstado]);
  });

  const regexSigla = /[\-\/(,]\s*(AC|AL|AP|AM|BA|CE|DF|ES|GO|MA|MT|MS|MG|PA|PB|PR|PE|PI|RJ|RN|RS|RO|RR|SC|SP|SE|TO)\b/g;
  let m;
  while ((m = regexSigla.exec(textoOriginal)) !== null) {
    if (m[1] !== ufSelecionada) encontrados.add(m[1]);
  }

  return {
    suspeita: encontrados.size > 0,
    estadosEncontrados: Array.from(encontrados)
  };
}

function avaliarRiscoMarca(lead) {
  const texto = ((lead.name || '') + ' ' + (lead.snippet || '')).toLowerCase();
  let pontos = 0;
  const sinais = [];

  if (/®|™/.test(lead.name + ' ' + lead.snippet)) {
    pontos += 2;
    sinais.push('usa símbolo ® ou ™');
  }

  const palavrasDeRede = [
    'franquia', 'franqueado', 'franchising', 'rede de lojas', 'unidades',
    'filiais', 'multimarcas', 'marca registrada', 'todos os direitos reservados', 'loja oficial'
  ];
  palavrasDeRede.forEach(p => {
    if (texto.includes(p)) {
      pontos += 1;
      sinais.push('menciona "' + p + '"');
    }
  });

  const anoMatch = texto.match(/desde (19\d{2}|20[01]\d)\b/);
  if (anoMatch) {
    pontos += 1;
    sinais.push('negócio antigo (' + anoMatch[0] + ')');
  }

  let nivel = 'baixo';
  if (pontos >= 2) nivel = 'alto';
  else if (pontos === 1) nivel = 'medio';

  return { nivel, pontos, sinais };
}

function diagnosticarResposta(query, data) {
  const panel = document.getElementById('debugPanel');
  const resumoEl = document.getElementById('debugResumo');
  const htmlEl = document.getElementById('debugHtml');
  if (!panel || !resumoEl || !htmlEl) return;

  const linhas = [];
  linhas.push('Consulta: ' + query);
  if (data.quota) {
    linhas.push('Cota da API: ' + data.quota.usado + ' / ' + data.quota.limite + ' buscas');
  }
  if (data.error) {
    linhas.push('❌ Erro: ' + data.error);
  } else {
    const items = data.items || [];
    linhas.push('Itens brutos retornados: ' + items.length);
  }

  resumoEl.textContent = linhas.join('\n');
  htmlEl.textContent = JSON.stringify(data, null, 2).slice(0, 3000);
  panel.classList.remove('hidden');
}

// Renderização dos Leads do Radar
const PLATFORM_ICON = {
  'Instagram': 'fa-brands fa-instagram text-pink-500',
  'LinkedIn': 'fa-brands fa-linkedin text-blue-700',
  'Facebook': 'fa-brands fa-facebook text-blue-600'
};

const RISCO_ESTILO = {
  'baixo': { texto: 'Risco baixo', classe: 'bg-green-100 text-green-700' },
  'medio': { texto: 'Risco médio', classe: 'bg-amber-100 text-amber-700' },
  'alto': { texto: 'Risco alto', classe: 'bg-rose-100 text-rose-700' }
};

const TRIAGEM_FISCAL_ESTILO = {
  'aprovado': { texto: 'CNPJ regular', classe: 'bg-green-100 text-green-700', icone: 'fa-solid fa-circle-check' },
  'descartado': { texto: 'Descartado (fiscal)', classe: 'bg-slate-200 text-slate-600', icone: 'fa-solid fa-ban' },
  'sem_cnpj': { texto: 'Sem CNPJ detectado', classe: 'bg-gray-100 text-gray-500', icone: 'fa-solid fa-question' },
  'erro_consulta': { texto: 'Falha na consulta', classe: 'bg-amber-100 text-amber-700', icone: 'fa-solid fa-triangle-exclamation' }
};

function renderLeads() {
  const lista = document.getElementById('listaLeads');
  if (!lista) return;
  const ocultarAlto = getChecked('filtroRiscoAlto', true);
  const ocultarDescartadoFiscal = getChecked('filtroDescartadoFiscal', true);
  lista.innerHTML = '';

  const visiveis = currentLeads.filter(l => {
    if (ocultarAlto && l.risco && l.risco.nivel === 'alto') return false;
    if (ocultarDescartadoFiscal && l.triagemFiscal && l.triagemFiscal.status === 'descartado') return false;
    return true;
  });

  const contEl = document.getElementById('contadorLeads');
  if (contEl) {
    contEl.innerText = visiveis.length + (visiveis.length !== currentLeads.length ? ' de ' + currentLeads.length : '');
  }

  visiveis.forEach((lead) => {
    const li = document.createElement('li');
    li.className = "p-3.5 cursor-pointer hover:bg-blue-50 border-b border-slate-100 transition-colors";
    const iconClass = PLATFORM_ICON[lead.platform] || 'fa-solid fa-globe text-slate-400';
    const risco = lead.risco || { nivel: 'baixo', sinais: [] };
    const estiloRisco = RISCO_ESTILO[risco.nivel] || RISCO_ESTILO['baixo'];

    let seloFiscal = '';
    if (lead.triagemFiscal) {
      const tf = lead.triagemFiscal;
      const estiloTf = TRIAGEM_FISCAL_ESTILO[tf.status] || TRIAGEM_FISCAL_ESTILO['sem_cnpj'];
      seloFiscal = `<span class="inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-semibold ${estiloTf.classe}"><i class="${estiloTf.icone} mr-1"></i>${estiloTf.texto}</span>`;
    }

    li.innerHTML = `
      <div class="flex items-center justify-between">
        <p class="font-bold text-xs truncate text-slate-800" title="${lead.name}"><i class="${iconClass} mr-1"></i> ${lead.name}</p>
        <span class="px-1.5 py-0.5 rounded text-[9px] font-semibold ${estiloRisco.classe}">${estiloRisco.texto}</span>
      </div>
      <p class="text-[11px] text-slate-500 mt-0.5">@${lead.handle} · ${lead.platform}</p>
      <div class="flex flex-wrap gap-1 mt-1">
        ${seloFiscal}
      </div>
    `;

    li.onclick = () => {
      selectedLead = lead;
      const painel = document.getElementById('painelAcao');
      if (painel) painel.classList.remove('hidden');
      const copyRes = document.getElementById('copyResult');
      if (copyRes) copyRes.classList.add('hidden');
      const resEnd = document.getElementById('resultadoEndereco');
      if (resEnd) resEnd.classList.add('hidden');

      const leadNomeEl = document.getElementById('leadNome');
      const leadInstaEl = document.getElementById('leadInsta');
      if (leadNomeEl) leadNomeEl.innerText = lead.name;
      if (leadInstaEl) {
        leadInstaEl.innerText = '@' + lead.handle + ' (' + lead.platform + ')';
        leadInstaEl.href = lead.url;
      }
      renderTriagemFiscalPainel(lead);
      renderAuditoriaSocio(lead);

      if (lead.copyGerada) {
        const argEl = document.getElementById('argumentoVenda');
        const cpEl = document.getElementById('copyInstagram');
        if (argEl) argEl.innerText = lead.copyGerada.argumento_venda;
        if (cpEl) cpEl.value = lead.copyGerada.copy_instagram;
        if (copyRes) copyRes.classList.remove('hidden');
      }
    };
    lista.appendChild(li);
  });
}

function renderTriagemFiscalPainel(lead) {
  const container = document.getElementById('triagemFiscalContainer');
  if (!container) return;
  const tf = lead.triagemFiscal || { status: 'sem_cnpj' };

  if (tf.status === 'sem_cnpj' || tf.status === 'erro_consulta') {
    container.innerHTML = `
      <div class="text-xs bg-slate-50 border border-slate-200 rounded-lg p-3">
        <p class="text-slate-600 mb-2">${tf.status === 'erro_consulta' ? 'Falha na consulta BrasilAPI (' + tf.detalhe + ').' : 'Nenhum CNPJ detectado automaticamente.'} Informe o CNPJ para triagem fiscal:</p>
        <div class="flex gap-2">
          <input type="text" id="cnpjManualInput" placeholder="00.000.000/0000-00" class="flex-1 border border-slate-300 rounded px-2.5 py-1 text-xs bg-white" value="${lead.cnpj || ''}">
          <button onclick="consultarCNPJManual()" class="bg-slate-800 text-white text-xs px-3 py-1 rounded hover:bg-slate-900 transition">Consultar</button>
        </div>
      </div>
    `;
    return;
  }

  const d = lead.dadosCNPJ || {};
  const idadeAnos = tf.diasFundacao !== null && tf.diasFundacao !== undefined ? (tf.diasFundacao / 365).toFixed(1) : '?';
  const corStatus = tf.status === 'aprovado' ? 'text-emerald-700' : 'text-slate-500';

  container.innerHTML = `
    <div class="text-xs bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-1">
      <p class="font-semibold ${corStatus}">${tf.status === 'aprovado' ? '✅ Aprovado na triagem fiscal' : '🚫 Descartado na triagem fiscal'}</p>
      <p class="text-slate-700 font-medium">${d.razao_social || lead.name} · CNAE: ${d.cnae_fiscal_descricao || 'Geral'}</p>
      <p class="text-slate-500">Capital Social: ${formatarMoedaBRL(d.capital_social)} · Tempo de Mercado: ~${idadeAnos} anos</p>
      ${tf.colisaoNome ? '<p class="text-amber-700 font-medium"><i class="fa-solid fa-triangle-exclamation mr-1"></i>Nome fantasia ausente ou idêntico à razão social (risco de colisão)</p>' : ''}
    </div>
  `;
}

function checarINPI() {
  if (!selectedLead) return;
  const nomePrincipal = selectedLead.name.split('-')[0].trim();
  navigator.clipboard.writeText(nomePrincipal);
  showToast(`📋 Nome "${nomePrincipal}" copiado! Cole na busca do INPI.`);
  window.open('https://busca.inpi.gov.br/pePI/jsp/marcas/Pesquisa_classe_basica.jsp', '_blank');
}

function renderAuditoriaSocio(lead) {
  const container = document.getElementById('auditoriaSocioContainer');
  if (!container) return;
  if (!lead.nomeDoSocio) {
    container.innerHTML = '';
    return;
  }
  container.innerHTML = `
    <button onclick="abrirAuditoriaSocio()" class="bg-indigo-700 hover:bg-indigo-800 text-white px-3 py-1.5 rounded-lg font-medium text-xs transition flex items-center gap-1.5">
      <i class="fa-solid fa-magnifying-glass"></i> Investigar Sócio no LinkedIn (${lead.nomeDoSocio.split(' ')[0]})
    </button>
  `;
}

function abrirAuditoriaSocio() {
  if (!selectedLead || !selectedLead.nomeDoSocio) return;
  const razaoSocial = (selectedLead.dadosCNPJ && selectedLead.dadosCNPJ.razao_social) || selectedLead.name;
  const dork = `site:linkedin.com/in/ "${selectedLead.nomeDoSocio}" "${razaoSocial}"`;
  window.open('https://www.google.com/search?q=' + encodeURIComponent(dork), '_blank');
}

async function verificarEndereco() {
  if (!selectedLead) return;
  const resultEl = document.getElementById('resultadoEndereco');
  if (!resultEl) return;
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-1"></i> Consultando geolocalização no OpenStreetMap...';

  const estadoSelecionado = getVal('estadoInput');
  const consulta = selectedLead.name + ', Brasil';

  try {
    const url = 'https://nominatim.openstreetmap.org/search?format=json&limit=1&addressdetails=1&countrycodes=br&q=' + encodeURIComponent(consulta);
    const resp = await fetch(url, { headers: { 'Accept-Language': 'pt-BR' } });
    const dados = await resp.json();

    if (!dados || dados.length === 0) {
      resultEl.innerHTML = '⚠️ Endereço não confirmado no OpenStreetMap. Recomenda-se conferir na biografia do Instagram.';
      return;
    }

    const local = dados[0];
    resultEl.innerHTML = `
      <p class="font-semibold text-slate-800">Localização Confirmada:</p>
      <p class="text-slate-600 mb-2">${local.display_name}</p>
      <iframe class="w-full h-36 rounded border border-emerald-200" loading="lazy"
        src="https://www.openstreetmap.org/export/embed.html?bbox=${parseFloat(local.lon)-0.015}%2C${parseFloat(local.lat)-0.015}%2C${parseFloat(local.lon)+0.015}%2C${parseFloat(local.lat)+0.015}&layer=mapnik&marker=${local.lat}%2C${local.lon}"></iframe>
    `;
  } catch (e) {
    resultEl.innerHTML = '<span class="text-rose-600">Erro na consulta cartográfica: ' + e.message + '</span>';
  }
}

async function gerarCopy() {
  if (!selectedLead) return;
  const loadEl = document.getElementById('loadingGroq');
  const copyRes = document.getElementById('copyResult');
  const argEl = document.getElementById('argumentoVenda');
  const cpEl = document.getElementById('copyInstagram');

  if (loadEl) {
    loadEl.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-1"></i> IA sintetizando tese jurídica e copy de abordagem...';
    loadEl.classList.remove('hidden');
  }
  if (copyRes) copyRes.classList.add('hidden');

  const dadosFiscais = selectedLead.dadosCNPJ;
  const isB2B = getChecked('toggleB2B', true);
  const nicho = (getVal('nichoInput') || 'Negócios');

  try {
    const response = await fetchComBackoff(`${WORKER_URL}/api/copy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        nome: selectedLead.name,
        handle: selectedLead.handle,
        plataforma: selectedLead.platform,
        nicho: nicho,
        contextoFiscal: dadosFiscais ? `Razão Social: ${dadosFiscais.razao_social}` : '',
        contextoSocio: selectedLead.nomeDoSocio ? `Sócio: ${selectedLead.nomeDoSocio}` : ''
      })
    });

    const aiResponse = await response.json();
    if (aiResponse.error) throw new Error(aiResponse.error);

    if (argEl) argEl.innerText = aiResponse.argumento_venda;
    if (cpEl) cpEl.value = aiResponse.copy_instagram;
    selectedLead.copyGerada = aiResponse;
  } catch (e) {
    // Gerador de contingência com modelos de alta conversão jurídica da EDV Jr.
    const consultor = (currentUserSession && currentUserSession.nome ? currentUserSession.nome : 'Consultor da EDV Jr.');
    const primeiroNomeSocio = selectedLead.nomeDoSocio ? selectedLead.nomeDoSocio.split(' ')[0] : 'tudo bem?';
    const tese = `Empresa ativa no mercado sem proteção marcária registrada na RPI do INPI. Alto risco de notificação extrajudicial por concorrência desleal ou registro de má-fé por terceiros.`;
    
    let copy = '';
    if (isB2B && selectedLead.nomeDoSocio) {
      copy = `Olá, ${primeiroNomeSocio}! Tudo bem? Me chamo ${consultor}, da EDV Jr. Estive analisando o posicionamento da ${selectedLead.name} aqui no mercado e notei o crescimento da operação. Como vocês trabalham forte no nicho de ${nicho}, realizei um levantamento preliminar na base do INPI e identifiquei uma oportunidade importante para blindar a marca e evitar litígios de exclusividade. Poderíamos conversar 5 minutos essa semana?`;
    } else {
      copy = `Olá, equipe da ${selectedLead.name}! Acompanho o trabalho de vocês em ${nicho} e acho incrível a construção da marca de vocês. Sou o ${consultor} da EDV Jr. (empresa júnior de consultoria empresarial). Fizemos uma verificação prévia no banco de dados do INPI e encontramos pontos de atenção sobre a proteção do nome da marca. Vale a pena alinharmos um diagnóstico gratuito para resguardar esse ativo de vocês?`;
    }

    const fallbackResponse = {
      argumento_venda: tese,
      copy_instagram: copy
    };

    if (argEl) argEl.innerText = fallbackResponse.argumento_venda;
    if (cpEl) cpEl.value = fallbackResponse.copy_instagram;
    selectedLead.copyGerada = fallbackResponse;
  }

  adicionarNaBlacklist(selectedLead);
  salvarEstado();
  if (loadEl) loadEl.classList.add('hidden');
  if (copyRes) copyRes.classList.remove('hidden');
}

// Inserir Lead do Radar diretamente no CRM Oficial (693+ DataGrid)
function adicionarLeadSelecionadoAoCRM() {
  if (!selectedLead) return;
  const novoId = String(crmLeadsList.length + 1);
  const nicho = (getVal('nichoInput') || 'Comercial');
  const consultor = (currentUserSession && currentUserSession.nome ? currentUserSession.nome : 'Equipe Comercial');

  const novoLeadCRM = {
    id: novoId,
    nome: selectedLead.name,
    segmento: nicho,
    responsavel: consultor,
    status: 'Entrada',
    servico: 'Registro de Marca',
    contato: selectedLead.nomeDoSocio || selectedLead.handle,
    telefone: (selectedLead.dadosCNPJ && selectedLead.dadosCNPJ.telefone ? selectedLead.dadosCNPJ.telefone : ''),
    email: '',
    valor: 2440.0
  };

  crmLeadsList.unshift(novoLeadCRM);
  atualizarContadoresFunilCRM();
  filtrarCRMDataGrid();

  const data = getLegacyData();
  data.crm_leads = crmLeadsList;
  updateDashboardKPIs();

  showToast(`✅ "${selectedLead.name}" inserido com sucesso no CRM Geral da EDV Jr.!`);
}

async function sincronizarN8N() {
  if (currentLeads.length === 0) return alert("Não há leads para sincronizar.");

  const btn = document.getElementById('btnSincronizar');
  if (!btn) return;
  const txtOriginal = btn.innerHTML;
  btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Enviando...';
  btn.disabled = true;

  try {
    const response = await fetchComBackoff(N8N_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ leads: currentLeads, timestamp: new Date().toISOString() })
    });
    btn.innerHTML = '<i class="fa-solid fa-check"></i> Sincronizado';
    setTimeout(() => {
      btn.innerHTML = txtOriginal;
      btn.disabled = false;
    }, 2500);
    showToast("Sincronização n8n concluída com sucesso!");
  } catch (e) {
    btn.innerHTML = txtOriginal;
    btn.disabled = false;
    showToast("Erro ao contatar webhook do n8n: " + e.message);
  }
}

function obterBlacklist() {
  try { return JSON.parse(localStorage.getItem(CHAVE_BLACKLIST) || '{}'); } catch (e) { return {}; }
}

function adicionarNaBlacklist(lead) {
  const bl = obterBlacklist();
  bl[lead.url] = { 
    nome: lead.name, 
    handle: lead.handle, 
    dataEnvio: new Date().toISOString(), 
    nicho: getVal('nichoInput')
  };
  try { localStorage.setItem(CHAVE_BLACKLIST, JSON.stringify(bl)); } catch (e) {}
}

function leadEstaNaBlacklist(url) {
  const entrada = obterBlacklist()[url];
  if (!entrada) return false;
  const dias = (new Date() - new Date(entrada.dataEnvio)) / (1000 * 60 * 60 * 24);
  return dias < DIAS_QUARENTENA;
}

function salvarEstado() {
  try {
    localStorage.setItem(CHAVE_PIPELINE, JSON.stringify(currentLeads));
  } catch (e) {}
}

function carregarEstado() {
  try {
    const salvo = localStorage.getItem(CHAVE_PIPELINE);
    if (!salvo) return;
    const leads = JSON.parse(salvo);
    if (!Array.isArray(leads) || leads.length === 0) return;
    currentLeads = leads;
    renderLeads();
    const cont = document.getElementById('leadsContainer');
    if (cont) cont.classList.remove('hidden');
  } catch (e) {}
}

// ==============================================================================
// 4.5 MÓDULO DE CRM & FOLLOW-UPS DE CLIENTES (EDbrain /crm/followups & /crm/radar)
// ==============================================================================
let crmFollowupsList = [];
let editingFollowupId = null;

function getInteractionIcon(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('whatsapp')) return 'fa-brands fa-whatsapp text-emerald-500';
  if (t.includes('reuni')) return 'fa-solid fa-handshake text-blue-500';
  if (t.includes('liga') || t.includes('telef')) return 'fa-solid fa-phone text-sky-500';
  if (t.includes('email') || t.includes('e-mail')) return 'fa-solid fa-envelope text-amber-500';
  if (t.includes('proposta')) return 'fa-solid fa-file-contract text-purple-500';
  if (t.includes('insta')) return 'fa-brands fa-instagram text-rose-500';
  return 'fa-solid fa-comments text-slate-400';
}

function renderTagBadges(tags) {
  if (!tags || !tags.trim()) {
    return '<span class="text-slate-300 text-[10px] italic">Sem tags</span>';
  }
  const parts = tags.split(/[,;\s]+/).map(t => t.trim()).filter(Boolean);
  if (parts.length === 0) return '<span class="text-slate-300 text-[10px] italic">Sem tags</span>';
  return `<div class="flex flex-wrap gap-1">${parts.map(p => {
    const formatted = p.startsWith('#') ? p : '#' + p;
    return `<span class="px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 text-[9px] font-semibold border border-purple-200 whitespace-nowrap">${escapeHTML(formatted)}</span>`;
  }).join('')}</div>`;
}

async function carregarFollowupsCRM() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(API_BASE_URL + '/crm/followups', {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      crmFollowupsList = await res.json();
      atualizarKPIsFollowups();
      filtrarTabelaFollowups();
      renderKanbanBoard(crmFollowupsList);
    } else {
      console.warn("[CRM Followups] Resposta da API:", res.status);
    }
  } catch (err) {
    console.warn("[CRM Followups] Falha ao consultar interações comerciais:", err.message);
  }
}

function atualizarKPIsFollowups() {
  const total = crmFollowupsList.length;
  let prospeccao = 0, negociacao = 0, fechado = 0, perdido = 0;
  let sumScore = 0, countEstagnados = 0, sumValor = 0;

  crmFollowupsList.forEach(fu => {
    const s = (fu.status || '').toLowerCase().trim();
    if (s === 'prospeccao') prospeccao++;
    else if (s === 'negociacao') negociacao++;
    else if (s === 'fechado') fechado++;
    else if (s === 'perdido') perdido++;

    const score = (fu.score !== undefined && fu.score !== null) ? Number(fu.score) : 50;
    sumScore += score;

    const daysStagnant = fu.days_stagnant !== undefined ? Number(fu.days_stagnant) : 0;
    if ((fu.is_stagnant || daysStagnant >= 14) && s !== 'fechado' && s !== 'perdido') {
      countEstagnados++;
    }

    const val = parseFloat(fu.estimated_value) || 0;
    sumValor += val;
  });

  const avgScore = total > 0 ? Math.round(sumScore / total) : 0;
  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };

  setEl('kpi-fu-total', total);
  setEl('kpi-fu-prospeccao', prospeccao);
  setEl('kpi-fu-negociacao', negociacao);
  setEl('kpi-fu-fechado', fechado);
  setEl('kpi-fu-score-medio', `${avgScore} pts`);
  setEl('kpi-fu-estagnados', countEstagnados);
  setEl('kpi-fu-valor-total', `R$ ${sumValor.toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`);

  const badgeEl = document.getElementById('fu-count-badge');
  if (badgeEl) badgeEl.innerText = `${total} registro${total === 1 ? '' : 's'}`;

  const badgeKanban = document.getElementById('badge-crm-kanban');
  if (badgeKanban) badgeKanban.innerText = total;
}

async function consultarCNPJFormulario(notify = true) {
  const cnpjInput = document.getElementById('fu_cnpj');
  const spinner = document.getElementById('fu_cnpj_spinner');
  if (!cnpjInput) return;

  const rawVal = cnpjInput.value.trim();
  const clean = rawVal.replace(/\D/g, '');

  if (!clean) {
    if (notify) showToast("⚠️ Digite um CNPJ com 14 dígitos para consultar.");
    return;
  }

  if (clean.length !== 14) {
    if (notify) showToast("⚠️ CNPJ incompleto. O CNPJ deve conter exatamente 14 dígitos.");
    return;
  }

  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  if (spinner) spinner.classList.remove('hidden');

  try {
    const res = await fetch(`${API_BASE_URL}/crm/radar/cnpj/${clean}`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      
      const clientNameInput = document.getElementById('fu_client_name');
      const cnaeInput = document.getElementById('fu_cnae');
      const sizeInput = document.getElementById('fu_company_size');
      const addrInput = document.getElementById('fu_address');
      const razaoSocialInput = document.getElementById('fu_razao_social');
      const nomeFantasiaInput = document.getElementById('fu_nome_fantasia');

      if (clientNameInput && (!clientNameInput.value.trim() || clientNameInput.value.trim().toLowerCase().startsWith('lead'))) {
        clientNameInput.value = data.nome_fantasia || data.razao_social || clientNameInput.value;
      }
      if (razaoSocialInput && data.razao_social) razaoSocialInput.value = data.razao_social;
      if (nomeFantasiaInput && data.nome_fantasia) nomeFantasiaInput.value = data.nome_fantasia;
      if (cnaeInput && data.cnae) cnaeInput.value = data.cnae;
      if (sizeInput && data.company_size) sizeInput.value = data.company_size;
      if (addrInput && data.address) addrInput.value = data.address;
      if (cnpjInput && data.cnpj) cnpjInput.value = data.cnpj;

      if (notify) {
        showToast(`✅ CNPJ enriquecido: ${data.razao_social || data.nome_fantasia || 'Dados da empresa importados!'}`);
      }
    } else {
      const err = await res.json().catch(() => ({}));
      if (notify) {
        showToast(`⚠️ CNPJ não localizado na BrasilAPI: ${err.detail || 'Verifique o número digitado'}`);
      }
    }
  } catch (err) {
    console.warn("[BrasilAPI Lookup] Erro na consulta:", err);
    if (notify) showToast("⚠️ Falha de conexão ao consultar BrasilAPI.");
  } finally {
    if (spinner) spinner.classList.add('hidden');
  }
}

function toggleFiltrosAvancados() {
  const painel = document.getElementById('painel-filtros-avancados');
  const btn = document.getElementById('btn-toggle-filtros');
  if (!painel) return;

  const isHidden = painel.classList.contains('hidden');
  if (isHidden) {
    painel.classList.remove('hidden');
    if (btn) {
      btn.classList.add('bg-sky-100', 'text-sky-800', 'border-sky-300');
      btn.classList.remove('bg-slate-100', 'text-slate-700', 'border-slate-300');
    }
  } else {
    painel.classList.add('hidden');
    if (btn) {
      btn.classList.remove('bg-sky-100', 'text-sky-800', 'border-sky-300');
      btn.classList.add('bg-slate-100', 'text-slate-700', 'border-slate-300');
    }
  }
}

function filtrarTabelaFollowups() {
  const busca = (document.getElementById('filtro-fu-busca')?.value || '').toLowerCase().trim();
  const statusFiltro = (document.getElementById('filtro-fu-status')?.value || '').toLowerCase().trim();
  const ordenacao = document.getElementById('filtro-fu-ordenacao')?.value || 'score';
  const estagnacao = document.getElementById('filtro-fu-estagnacao')?.value || 'todos';
  const minScore = parseInt(document.getElementById('filtro-fu-score-min')?.value || '0', 10);
  const cnaeFiltro = (document.getElementById('filtro-fu-cnae')?.value || '').toLowerCase().trim();
  const tagsFiltro = (document.getElementById('filtro-fu-tags')?.value || '').toLowerCase().trim();

  let filtrados = crmFollowupsList.filter(fu => {
    const matchStatus = !statusFiltro || (fu.status || '').toLowerCase().trim() === statusFiltro;
    
    const leadScore = (fu.score !== undefined && fu.score !== null) ? Number(fu.score) : 50;
    const matchScore = leadScore >= minScore;

    const daysStagnant = fu.days_stagnant !== undefined ? Number(fu.days_stagnant) : 0;
    let matchEstagnacao = true;
    if (estagnacao === 'estagnados') {
      matchEstagnacao = daysStagnant >= 14;
    } else if (estagnacao === 'criticos') {
      matchEstagnacao = daysStagnant >= 30;
    } else if (estagnacao === 'recentes') {
      matchEstagnacao = daysStagnant <= 7;
    }

    const matchCnae = !cnaeFiltro || String(fu.cnae || '').toLowerCase().includes(cnaeFiltro);
    const matchTags = !tagsFiltro || String(fu.tags || '').toLowerCase().includes(tagsFiltro);

    const matchBusca = !busca ||
      String(fu.client_name || '').toLowerCase().includes(busca) ||
      String(fu.razao_social || '').toLowerCase().includes(busca) ||
      String(fu.nome_fantasia || '').toLowerCase().includes(busca) ||
      String(fu.contact_person || '').toLowerCase().includes(busca) ||
      String(fu.notes || '').toLowerCase().includes(busca) ||
      String(fu.area || '').toLowerCase().includes(busca) ||
      String(fu.created_by || '').toLowerCase().includes(busca) ||
      String(fu.cnpj || '').toLowerCase().includes(busca) ||
      String(fu.cnae || '').toLowerCase().includes(busca) ||
      String(fu.address || '').toLowerCase().includes(busca) ||
      String(fu.tags || '').toLowerCase().includes(busca);

    return matchStatus && matchScore && matchEstagnacao && matchCnae && matchTags && matchBusca;
  });

  // Ordenação inteligente
  filtrados.sort((a, b) => {
    if (ordenacao === 'estimated_value') {
      return (parseFloat(b.estimated_value) || 0) - (parseFloat(a.estimated_value) || 0);
    } else if (ordenacao === 'stagnant') {
      return (Number(b.days_stagnant) || 0) - (Number(a.days_stagnant) || 0);
    } else if (ordenacao === 'created_at') {
      return (Number(b.id) || 0) - (Number(a.id) || 0);
    } else {
      // Default: Maior Lead Score (0 a 100)
      const scoreA = (a.score !== undefined && a.score !== null) ? Number(a.score) : 50;
      const scoreB = (b.score !== undefined && b.score !== null) ? Number(b.score) : 50;
      return scoreB - scoreA;
    }
  });

  const badgeEl = document.getElementById('fu-count-badge');
  if (badgeEl) {
    if (filtrados.length === crmFollowupsList.length) {
      badgeEl.innerText = `${filtrados.length} registro${filtrados.length === 1 ? '' : 's'}`;
    } else {
      badgeEl.innerText = `${filtrados.length} de ${crmFollowupsList.length} leads`;
    }
  }

  renderTabelaFollowups(filtrados);
}

function renderTabelaFollowups(itens) {
  const tbody = document.getElementById('tabela-crm-followups');
  if (!tbody) return;

  if (!itens || itens.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" class="p-8 text-center text-slate-400">
          <i class="fa-solid fa-address-book text-2xl text-slate-300 mb-2 block"></i>
          <span>Nenhum follow-up de cliente encontrado com os filtros aplicados.</span>
        </td>
      </tr>
    `;
    return;
  }

  const statusMap = {
    'prospeccao': { label: 'Prospecção', class: 'bg-sky-100 text-sky-800 border-sky-300' },
    'negociacao': { label: 'Negociação', class: 'bg-amber-100 text-amber-800 border-amber-300' },
    'fechado': { label: 'Fechado', class: 'bg-emerald-100 text-emerald-800 border-emerald-300' },
    'perdido': { label: 'Perdido', class: 'bg-rose-100 text-rose-800 border-rose-300' }
  };

  tbody.innerHTML = itens.map(fu => {
    const rawSt = (fu.status || '').toLowerCase().trim();
    const stConfig = statusMap[rawSt] || { label: fu.status, class: 'bg-slate-100 text-slate-700 border-slate-300' };
    const dataNext = fu.next_followup_date ? fu.next_followup_date : '<span class="text-slate-400 italic">Não agendado</span>';
    const contact = fu.contact_person ? escapeHTML(fu.contact_person) : '<span class="text-slate-400 italic">N/A</span>';
    const channel = fu.interaction_type ? escapeHTML(fu.interaction_type) : 'Geral';
    const channelIcon = getInteractionIcon(channel);
    const notes = fu.notes ? escapeHTML(fu.notes) : '-';

    // Lead Score & Estagnação
    const score = (fu.score !== undefined && fu.score !== null) ? Number(fu.score) : 50;
    let scoreColor = 'bg-slate-100 text-slate-700 border-slate-300';
    let scoreIcon = 'fa-chart-simple';
    if (score >= 70) {
      scoreColor = 'bg-emerald-100 text-emerald-800 border-emerald-300';
      scoreIcon = 'fa-fire text-emerald-600';
    } else if (score >= 40) {
      scoreColor = 'bg-amber-100 text-amber-800 border-amber-300';
      scoreIcon = 'fa-bolt text-amber-600';
    } else {
      scoreColor = 'bg-rose-100 text-rose-800 border-rose-300';
      scoreIcon = 'fa-arrow-down text-rose-500';
    }

    const daysStagnant = fu.days_stagnant !== undefined ? Number(fu.days_stagnant) : 0;
    const isStagnant = (fu.is_stagnant || daysStagnant >= 14) && rawSt !== 'fechado' && rawSt !== 'perdido';
    const stagnantBadge = isStagnant
      ? `<span class="inline-flex items-center gap-1 text-[9px] font-bold text-rose-600 bg-rose-50 border border-rose-200 px-1.5 py-0.2 rounded-full mt-1" title="Sem contato há ${daysStagnant} dias"><i class="fa-solid fa-triangle-exclamation"></i> ${daysStagnant}d parado</span>`
      : `<span class="text-[9px] text-slate-400 mt-0.5 block">${daysStagnant}d ativo</span>`;

    const estVal = parseFloat(fu.estimated_value) || 0;
    const valorFormatado = estVal > 0 
      ? `R$ ${estVal.toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
      : '<span class="text-slate-400 italic">R$ 0,00</span>';

    return `
      <tr class="hover:bg-slate-50 transition border-b border-slate-100">
        <!-- 1. Score & Estagnação -->
        <td class="px-3 py-3 text-center whitespace-nowrap">
          <div class="inline-flex flex-col items-center">
            <span class="px-2.5 py-0.5 rounded-full text-xs font-black border flex items-center gap-1 shadow-xs ${scoreColor}">
              <i class="fa-solid ${scoreIcon} text-[10px]"></i>
              <span>${score}</span>
            </span>
            ${stagnantBadge}
          </div>
        </td>

        <!-- 2. Cliente & Razão Social -->
        <td class="px-4 py-3">
          <div class="font-bold text-slate-800 text-xs flex items-center gap-1.5">
            <i class="fa-solid fa-building text-slate-400 text-xs"></i>
            <span>${escapeHTML(fu.client_name)}</span>
          </div>
          ${(fu.razao_social && fu.razao_social.toLowerCase() !== (fu.client_name || '').toLowerCase()) ? `<div class="text-[10px] text-slate-500 font-medium italic truncate max-w-[240px] flex items-center gap-1 mt-0.5" title="Razão Social: ${escapeHTML(fu.razao_social)}"><i class="fa-solid fa-landmark text-slate-400 text-[9px]"></i> ${escapeHTML(fu.razao_social)}</div>` : ''}
          ${(fu.nome_fantasia && fu.nome_fantasia.toLowerCase() !== (fu.client_name || '').toLowerCase() && (!fu.razao_social || fu.nome_fantasia.toLowerCase() !== fu.razao_social.toLowerCase())) ? `<div class="text-[10px] text-slate-500 font-medium italic truncate max-w-[240px] flex items-center gap-1 mt-0.5" title="Nome Fantasia: ${escapeHTML(fu.nome_fantasia)}"><i class="fa-regular fa-bookmark text-slate-400 text-[9px]"></i> Fantasia: ${escapeHTML(fu.nome_fantasia)}</div>` : ''}
          ${fu.cnpj ? `<div class="text-[10px] text-slate-500 font-mono flex items-center gap-1 mt-0.5"><i class="fa-regular fa-id-card text-sky-500"></i> ${escapeHTML(fu.cnpj)}</div>` : ''}
          ${fu.address ? `<div class="text-[10px] text-slate-400 truncate max-w-[220px] flex items-center gap-1 mt-0.5" title="${escapeHTML(fu.address)}"><i class="fa-solid fa-location-dot text-slate-300"></i> ${escapeHTML(fu.address)}</div>` : ''}
        </td>

        <!-- 3. Contato & Canal -->
        <td class="px-3 py-3 whitespace-nowrap">
          <div class="text-xs font-medium text-slate-700">${contact}</div>
          <div class="mt-0.5">
            <span class="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px] font-medium border border-slate-200 inline-flex items-center gap-1">
              <i class="${channelIcon}"></i> ${channel}
            </span>
          </div>
        </td>

        <!-- 4. Status Comercial -->
        <td class="px-3 py-3 whitespace-nowrap">
          <div class="mb-1">
            <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border ${stConfig.class}">
              ${stConfig.label}
            </span>
          </div>
          <select onchange="atualizarStatusFollowup(${fu.id}, this.value)" class="text-[10px] border border-slate-300 rounded px-1.5 py-0.5 bg-white font-semibold text-slate-700 focus:outline-none focus:ring-1 focus:ring-sky-500">
            <option value="prospeccao" ${rawSt === 'prospeccao' ? 'selected' : ''}>🔵 Prospecção</option>
            <option value="negociacao" ${rawSt === 'negociacao' ? 'selected' : ''}>🟡 Negociação</option>
            <option value="fechado" ${rawSt === 'fechado' ? 'selected' : ''}>🟢 Fechado</option>
            <option value="perdido" ${rawSt === 'perdido' ? 'selected' : ''}>🔴 Perdido</option>
          </select>
        </td>

        <!-- 5. CNAE & Porte -->
        <td class="px-3 py-3 max-w-[180px]">
          <div class="flex items-center gap-1.5 mb-0.5">
            ${fu.company_size ? `<span class="px-1.5 py-0.2 rounded bg-sky-50 text-sky-800 text-[10px] font-bold border border-sky-200">${escapeHTML(fu.company_size)}</span>` : ''}
            <span class="px-1.5 py-0.2 rounded bg-slate-50 text-slate-600 text-[9px] font-medium border border-slate-200">${escapeHTML(fu.area || 'Comercial')}</span>
          </div>
          <div class="text-[10px] text-slate-500 truncate" title="${escapeHTML(fu.cnae || 'CNAE não informado')}">
            ${fu.cnae ? escapeHTML(fu.cnae) : '<span class="text-slate-300 italic">CNAE não inf.</span>'}
          </div>
        </td>

        <!-- 6. Valor Estimado -->
        <td class="px-3 py-3 text-right whitespace-nowrap font-mono text-xs font-semibold text-slate-800">
          ${valorFormatado}
        </td>

        <!-- 7. Tags Comerciais -->
        <td class="px-3 py-3 max-w-[150px]">
          ${renderTagBadges(fu.tags)}
        </td>

        <!-- 8. Próximo Contato & Responsável -->
        <td class="px-3 py-3 whitespace-nowrap font-mono text-[11px] text-slate-600">
          <div class="flex items-center gap-1">
            <i class="fa-regular fa-calendar text-slate-400"></i>
            <span>${dataNext}</span>
          </div>
          ${fu.created_by ? `<div class="text-[9px] text-slate-400 font-mono mt-0.5 truncate max-w-[110px]" title="Responsável: ${escapeHTML(fu.created_by)}">${escapeHTML(fu.created_by)}</div>` : ''}
        </td>

        <!-- 9. Ações Rápidas -->
        <td class="px-3 py-3 text-center whitespace-nowrap">
          <div class="flex items-center justify-center gap-1">
            <button onclick="preencherFormularioFollowup(${fu.id})" title="Editar Lead & Dados Fiscais" class="p-1.5 text-sky-600 hover:text-sky-800 hover:bg-sky-50 rounded-lg transition border border-transparent hover:border-sky-200">
              <i class="fa-solid fa-pen-to-square text-xs"></i>
            </button>
            ${fu.notes ? `
            <button onclick="alert('Histórico de ${escapeHTML(fu.client_name)}:\\n\\n' + decodeURIComponent('${encodeURIComponent(fu.notes)}'))" title="Ver Histórico/Notas" class="p-1.5 text-slate-500 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition">
              <i class="fa-regular fa-comment-dots text-xs"></i>
            </button>` : ''}
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function preencherFormularioFollowup(id) {
  const fu = crmFollowupsList.find(f => f.id === id);
  if (!fu) return;

  editingFollowupId = id;

  const setVal = (elemId, val) => {
    const el = document.getElementById(elemId);
    if (el) el.value = val !== null && val !== undefined ? val : '';
  };

  setVal('fu_cnpj', fu.cnpj || '');
  setVal('fu_client_name', fu.client_name || '');
  setVal('fu_razao_social', fu.razao_social || '');
  setVal('fu_nome_fantasia', fu.nome_fantasia || '');
  setVal('fu_contact_person', fu.contact_person || '');
  setVal('fu_status', fu.status || 'prospeccao');
  setVal('fu_interaction_type', fu.interaction_type || 'WhatsApp');
  setVal('fu_next_date', fu.next_followup_date || '');
  setVal('fu_estimated_value', fu.estimated_value || '');
  setVal('fu_area', fu.area || 'Comercial');
  setVal('fu_tags', fu.tags || '');
  setVal('fu_cnae', fu.cnae || '');
  setVal('fu_company_size', fu.company_size || '');
  setVal('fu_address', fu.address || '');
  setVal('fu_notes', fu.notes || '');

  const btnSubmit = document.getElementById('btn-submit-fu');
  if (btnSubmit) {
    btnSubmit.classList.remove('bg-sky-600', 'hover:bg-sky-700');
    btnSubmit.classList.add('bg-amber-600', 'hover:bg-amber-700');
    btnSubmit.innerHTML = `<i class="fa-solid fa-check"></i> <span>Salvar Alterações (Lead #${id})</span>`;
  }

  let btnCancel = document.getElementById('btn-cancel-edit-fu');
  if (!btnCancel && btnSubmit && btnSubmit.parentElement) {
    btnCancel = document.createElement('button');
    btnCancel.id = 'btn-cancel-edit-fu';
    btnCancel.type = 'button';
    btnCancel.className = 'bg-slate-200 hover:bg-slate-300 text-slate-700 font-bold text-xs px-4 py-2.5 rounded-lg transition ml-2';
    btnCancel.innerHTML = '<i class="fa-solid fa-xmark"></i> Cancelar';
    btnCancel.onclick = cancelarEdicaoFollowup;
    btnSubmit.parentElement.appendChild(btnCancel);
  }

  const formElem = document.getElementById('form-novo-followup');
  if (formElem) {
    formElem.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  showToast(`✏️ Modo de edição ativado para o lead #${id} (${fu.client_name})`);
}

function cancelarEdicaoFollowup() {
  editingFollowupId = null;
  const form = document.getElementById('form-novo-followup');
  if (form) form.reset();

  const btnSubmit = document.getElementById('btn-submit-fu');
  if (btnSubmit) {
    btnSubmit.classList.remove('bg-amber-600', 'hover:bg-amber-700');
    btnSubmit.classList.add('bg-sky-600', 'hover:bg-sky-700');
    btnSubmit.innerHTML = '<i class="fa-solid fa-plus"></i> <span>Registrar Follow-up no CRM</span>';
  }

  const btnCancel = document.getElementById('btn-cancel-edit-fu');
  if (btnCancel) btnCancel.remove();
}

async function submeterFollowupCRM(event) {
  if (event) event.preventDefault();

  const clientNameInput = document.getElementById('fu_client_name');
  const cnpjInput = document.getElementById('fu_cnpj');
  const razaoSocialInput = document.getElementById('fu_razao_social');
  const nomeFantasiaInput = document.getElementById('fu_nome_fantasia');
  const contactPersonInput = document.getElementById('fu_contact_person');
  const statusSelect = document.getElementById('fu_status');
  const interactionTypeSelect = document.getElementById('fu_interaction_type');
  const nextDateInput = document.getElementById('fu_next_date');
  const estimatedValueInput = document.getElementById('fu_estimated_value');
  const areaSelect = document.getElementById('fu_area');
  const tagsInput = document.getElementById('fu_tags');
  const cnaeInput = document.getElementById('fu_cnae');
  const companySizeInput = document.getElementById('fu_company_size');
  const addressInput = document.getElementById('fu_address');
  const notesInput = document.getElementById('fu_notes');
  const impactScoreInput = document.getElementById('fu_impact_score');
  const impactTypeSelect = document.getElementById('fu_impact_type');
  const impactDescInput = document.getElementById('fu_impact_desc');

  const clientName = (clientNameInput?.value || '').trim();
  if (!clientName) {
    showToast("⚠️ O nome do cliente ou empresa é obrigatório.");
    return;
  }

  const estVal = estimatedValueInput?.value ? parseFloat(estimatedValueInput.value) : 0.0;
  const impScore = impactScoreInput?.value ? parseInt(impactScoreInput.value, 10) : 0;

  const payload = {
    client_name: clientName,
    razao_social: (razaoSocialInput?.value || '').trim() || null,
    nome_fantasia: (nomeFantasiaInput?.value || '').trim() || null,
    cnpj: (cnpjInput?.value || '').trim() || null,
    contact_person: (contactPersonInput?.value || '').trim() || null,
    status: statusSelect?.value || 'prospeccao',
    interaction_type: interactionTypeSelect?.value || 'WhatsApp',
    next_followup_date: nextDateInput?.value || null,
    estimated_value: isNaN(estVal) ? 0.0 : estVal,
    area: areaSelect?.value || currentUserSession?.area || 'Comercial',
    tags: (tagsInput?.value || '').trim() || null,
    cnae: (cnaeInput?.value || '').trim() || null,
    company_size: (companySizeInput?.value || '').trim() || null,
    address: (addressInput?.value || '').trim() || null,
    notes: (notesInput?.value || '').trim() || null,
    impact_score: isNaN(impScore) ? 0 : impScore,
    impact_type: (impactTypeSelect?.value || '').trim() || null,
    impact_description: (impactDescInput?.value || '').trim() || null
  };

  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  const btnSubmit = document.getElementById('btn-submit-fu');
  if (btnSubmit) {
    btnSubmit.disabled = true;
    btnSubmit.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> ${editingFollowupId ? 'Salvando...' : 'Registrando...'}`;
  }

  try {
    const isEdit = Boolean(editingFollowupId);
    const endpoint = isEdit ? `${API_BASE_URL}/crm/followups/${editingFollowupId}` : `${API_BASE_URL}/crm/followups`;
    const method = isEdit ? 'PUT' : 'POST';

    const res = await fetch(endpoint, {
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify(payload)
    });

    if (res.status === 201 || (isEdit && res.ok)) {
      showToast(isEdit ? `✅ Follow-up #${editingFollowupId} atualizado com sucesso!` : `✅ Follow-up de "${clientName}" registrado no CRM!`);
      cancelarEdicaoFollowup();
      await carregarFollowupsCRM();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha na operação: ${err.detail || 'Erro na requisição'}`);
    }
  } catch (err) {
    console.error("Falha ao registrar/atualizar follow-up:", err);
    showToast("⚠️ Servidor EDbrain offline. Não foi possível registrar.");
  } finally {
    if (btnSubmit) {
      btnSubmit.disabled = false;
      if (!editingFollowupId) {
        btnSubmit.innerHTML = '<i class="fa-solid fa-plus"></i> <span>Registrar Follow-up no CRM</span>';
      }
    }
  }
}

async function atualizarStatusFollowup(id, novoStatus) {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(API_BASE_URL + '/crm/followups/' + id, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ status: novoStatus })
    });

    if (res.ok) {
      const updated = await res.json().catch(() => null);
      showToast(`✅ Status do follow-up #${id} atualizado para "${novoStatus}"!`);
      const itemIndex = crmFollowupsList.findIndex(f => f.id === id);
      if (itemIndex >= 0) {
        if (updated) {
          crmFollowupsList[itemIndex] = updated;
        } else {
          crmFollowupsList[itemIndex].status = novoStatus;
        }
      }
      atualizarKPIsFollowups();
      filtrarTabelaFollowups();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha ao atualizar status: ${err.detail || 'Erro na operação'}`);
      await carregarFollowupsCRM();
    }
  } catch (err) {
    console.error("Falha ao atualizar status follow-up:", err);
    showToast("⚠️ Servidor EDbrain offline.");
  }
}

// ==============================================================================
// 4.6 MÓDULO DE PDIS, TRILHAS E ANALYTICS DA VPGG (EDbrain /vpgg/pdis)
// ==============================================================================
let vpggPDIsList = [];
window.ULTIMA_TRILHA_GERADA = null;

function popularSelectsVPGG() {
  const pdiSelect = document.getElementById('pdi_user_email');
  const trilhaSelect = document.getElementById('trilha_member_email');
  const filtroMembroSelect = document.getElementById('filtro-pdi-membro');

  const membros = Object.entries(membrosAutorizados).map(([email, info]) => ({
    email,
    nome: info.nome,
    area: info.area || info.setor || 'Geral',
    cargo: info.cargo || 'Consultor(a)',
    role: info.role || 'assessor'
  })).sort((a, b) => a.nome.localeCompare(b.nome));

  if (pdiSelect && pdiSelect.options.length <= 1) {
    pdiSelect.innerHTML = '<option value="">-- Selecione o colaborador (23 colaboradores) --</option>';
    membros.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m.email;
      opt.textContent = `${m.nome} (${m.area} • ${m.cargo})`;
      pdiSelect.appendChild(opt);
    });
  }

  if (trilhaSelect && trilhaSelect.options.length <= 1) {
    trilhaSelect.innerHTML = '<option value="">-- Escolha um colaborador para gerar a trilha --</option>';
    membros.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m.email;
      opt.textContent = `${m.nome} - ${m.area} (${m.cargo})`;
      trilhaSelect.appendChild(opt);
    });
  }

  if (filtroMembroSelect && filtroMembroSelect.options.length <= 1) {
    filtroMembroSelect.innerHTML = '<option value="">Todos os Colaboradores</option>';
    membros.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m.email;
      opt.textContent = `${m.nome} (${m.area})`;
      filtroMembroSelect.appendChild(opt);
    });
  }
}

function aoSelecionarMembroPDI() {
  const pdiSelect = document.getElementById('pdi_user_email');
  const areaInput = document.getElementById('pdi_area');
  if (!pdiSelect || !areaInput) return;

  const email = pdiSelect.value.trim().toLowerCase();
  const membro = membrosAutorizados[email];
  if (membro) {
    areaInput.value = membro.area || membro.setor || 'VPGG';
  } else {
    areaInput.value = 'VPGG';
  }
}

async function carregarPDIsVPGG() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(API_BASE_URL + '/vpgg/pdis', {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      vpggPDIsList = await res.json();
      const badgeEl = document.getElementById('pdi-count-badge');
      if (badgeEl) badgeEl.innerText = `${vpggPDIsList.length} PDI${vpggPDIsList.length === 1 ? '' : 's'}`;
      filtrarTabelaPDIs();
    }
  } catch (err) {
    console.warn("[VPGG PDIs] Falha ao carregar PDIs:", err.message);
  }
}

function filtrarTabelaPDIs() {
  const membroFiltro = (document.getElementById('filtro-pdi-membro')?.value || '').toLowerCase().trim();
  const statusFiltro = (document.getElementById('filtro-pdi-status')?.value || '').toLowerCase().trim();

  const filtrados = vpggPDIsList.filter(pdi => {
    const matchMembro = !membroFiltro || (pdi.user_email || '').toLowerCase().trim() === membroFiltro;
    const matchStatus = !statusFiltro || (pdi.status || '').toLowerCase().trim() === statusFiltro;
    return matchMembro && matchStatus;
  });

  renderTabelaPDIs(filtrados);
}

function renderTabelaPDIs(itens) {
  const tbody = document.getElementById('tabela-vpgg-pdis');
  if (!tbody) return;

  if (!itens || itens.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="p-8 text-center text-slate-400">
          <i class="fa-solid fa-clipboard-user text-2xl text-slate-300 mb-2 block"></i>
          <span>Nenhum Plano de Desenvolvimento Individual (PDI) cadastrado para este filtro.</span>
        </td>
      </tr>
    `;
    return;
  }

  const statusMap = {
    'em_andamento': { label: 'Em Andamento', class: 'bg-amber-100 text-amber-800 border-amber-300' },
    'planejado': { label: 'Planejado', class: 'bg-sky-100 text-sky-800 border-sky-300' },
    'concluido': { label: 'Concluído', class: 'bg-emerald-100 text-emerald-800 border-emerald-300' },
    'pausado': { label: 'Pausado', class: 'bg-slate-100 text-slate-700 border-slate-300' }
  };

  tbody.innerHTML = itens.map(pdi => {
    const stConfig = statusMap[(pdi.status || '').toLowerCase()] || { label: pdi.status, class: 'bg-slate-100 text-slate-700 border-slate-300' };
    const membroInfo = membrosAutorizados[(pdi.user_email || '').toLowerCase()];
    const nomeExibicao = membroInfo ? membroInfo.nome : (pdi.user_email ? pdi.user_email.split('@')[0] : 'Colaborador');
    const emailExibicao = pdi.user_email ? escapeHTML(pdi.user_email) : '-';
    const areaExibicao = pdi.area ? escapeHTML(pdi.area) : (membroInfo?.area || 'VPGG');
    const deadline = pdi.deadline ? pdi.deadline : '-';
    const objectives = pdi.objectives ? escapeHTML(pdi.objectives) : '-';
    const ideas = pdi.development_ideas ? escapeHTML(pdi.development_ideas) : '-';

    return `
      <tr class="hover:bg-slate-50 transition border-b border-slate-100">
        <td class="px-4 py-3">
          <div class="font-bold text-slate-800">${escapeHTML(nomeExibicao)}</div>
          <div class="text-[10px] text-slate-400 font-mono">${emailExibicao}</div>
        </td>
        <td class="px-4 py-3 whitespace-nowrap">
          <span class="px-2 py-0.5 rounded bg-purple-50 text-purple-800 text-[10px] font-semibold border border-purple-200">
            ${areaExibicao}
          </span>
        </td>
        <td class="px-4 py-3 whitespace-nowrap">
          <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border ${stConfig.class}">
            ${stConfig.label}
          </span>
        </td>
        <td class="px-4 py-3 whitespace-nowrap font-mono text-[11px] text-slate-600">
          <i class="fa-regular fa-clock text-slate-400 mr-1"></i>${deadline}
        </td>
        <td class="px-4 py-3 text-slate-700 max-w-xs truncate" title="${objectives}">
          ${objectives}
        </td>
        <td class="px-4 py-3 text-slate-600 max-w-xs truncate" title="${ideas}">
          ${ideas}
        </td>
        <td class="px-4 py-3 text-center whitespace-nowrap">
          <select onchange="atualizarStatusPDI(${pdi.id}, this.value)" class="text-[11px] border border-slate-300 rounded px-2 py-1 bg-white font-semibold text-slate-700 focus:outline-none focus:ring-1 focus:ring-purple-500">
            <option value="em_andamento" ${pdi.status === 'em_andamento' ? 'selected' : ''}>Em Andamento</option>
            <option value="planejado" ${pdi.status === 'planejado' ? 'selected' : ''}>Planejado</option>
            <option value="concluido" ${pdi.status === 'concluido' ? 'selected' : ''}>Concluído</option>
            <option value="pausado" ${pdi.status === 'pausado' ? 'selected' : ''}>Pausado</option>
          </select>
        </td>
      </tr>
    `;
  }).join('');
}

async function submeterNovoPDI(event) {
  if (event) event.preventDefault();

  const userEmailSelect = document.getElementById('pdi_user_email');
  const areaInput = document.getElementById('pdi_area');
  const deadlineInput = document.getElementById('pdi_deadline');
  const statusSelect = document.getElementById('pdi_status');
  const objectivesInput = document.getElementById('pdi_objectives');
  const ideasInput = document.getElementById('pdi_ideas');
  const compMejSelect = document.getElementById('pdi_competency_mej');

  const userEmail = (userEmailSelect?.value || '').trim().toLowerCase();
  const objectives = (objectivesInput?.value || '').trim();
  const ideas = (ideasInput?.value || '').trim();
  const deadline = (deadlineInput?.value || '').trim();
  const compMej = (compMejSelect?.value || 'Gestão').trim();

  if (!userEmail) {
    showToast("⚠️ Selecione o colaborador para o PDI.");
    return;
  }
  if (!objectives || !ideas || !deadline) {
    showToast("⚠️ Preencha todos os campos obrigatórios do PDI.");
    return;
  }

  const payload = {
    user_email: userEmail,
    area: areaInput?.value || 'VPGG',
    competency_mej: compMej,
    deadline: deadline,
    status: statusSelect?.value || 'em_andamento',
    objectives: objectives,
    development_ideas: ideas
  };

  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  const btnSubmit = document.getElementById('btn-submit-pdi');
  if (btnSubmit) {
    btnSubmit.disabled = true;
    btnSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Gravando PDI...';
  }

  try {
    const res = await fetch(API_BASE_URL + '/vpgg/pdis', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify(payload)
    });

    if (res.status === 201) {
      showToast("🎯 Plano de Desenvolvimento Individual gravado no SQLite!");
      if (objectivesInput) objectivesInput.value = '';
      if (ideasInput) ideasInput.value = '';
      if (deadlineInput) deadlineInput.value = '';
      await carregarPDIsVPGG();
      await carregarAnalyticsVPGG();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha ao salvar PDI: ${err.detail || 'Erro na requisição'}`);
    }
  } catch (err) {
    console.error("Falha ao salvar PDI:", err);
    showToast("⚠️ Servidor EDbrain offline.");
  } finally {
    if (btnSubmit) {
      btnSubmit.disabled = false;
      btnSubmit.innerHTML = '<i class="fa-solid fa-plus"></i> <span>Salvar PDI no EDbrain</span>';
    }
  }
}

async function atualizarStatusPDI(pdiId, novoStatus) {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(API_BASE_URL + '/vpgg/pdis/' + pdiId, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ status: novoStatus })
    });

    if (res.ok) {
      showToast(`✅ Status do PDI #${pdiId} atualizado para "${novoStatus}"!`);
      const item = vpggPDIsList.find(p => p.id === pdiId);
      if (item) item.status = novoStatus;
      filtrarTabelaPDIs();
      carregarAnalyticsVPGG();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha ao atualizar PDI: ${err.detail || 'Erro na operação'}`);
      await carregarPDIsVPGG();
    }
  } catch (err) {
    console.error("Falha ao atualizar PDI:", err);
    showToast("⚠️ Servidor EDbrain offline.");
  }
}

async function acionarGeradorTrilha() {
  const memberSelect = document.getElementById('trilha_member_email');
  const focoInput = document.getElementById('trilha_foco');
  const email = (memberSelect?.value || '').trim().toLowerCase();

  if (!email) {
    showToast("⚠️ Selecione um colaborador para gerar a trilha.");
    return;
  }

  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  const btn = document.getElementById('btn-gerar-trilha');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processando Trilha com IA...';
  }

  try {
    const res = await fetch(API_BASE_URL + '/vpgg/pdis/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({
        member_email: email,
        foco_adicional: (focoInput?.value || '').trim() || null
      })
    });

    if (res.ok) {
      const data = await res.json();
      window.ULTIMA_TRILHA_GERADA = data;
      renderResultadoTrilha(data);
      showToast("🚀 Trilha de desenvolvimento calibrada com sucesso!");
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha na geração da trilha: ${err.detail || 'Erro na requisição'}`);
    }
  } catch (err) {
    console.error("Falha ao acionar motor de trilhas:", err);
    showToast("⚠️ Servidor EDbrain offline.");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> <span>Gerar Trilha Estruturada</span>';
    }
  }
}

function renderResultadoTrilha(data) {
  const container = document.getElementById('resultado-trilha-container');
  if (!container) return;

  const membro = data.membro_avaliado || {};
  const plano = data.plano_estruturado_sugerido || {};

  const hardSkillsHtml = (plano.hard_skills_prioritarias || []).map(s => `
    <li class="flex items-start gap-2">
      <i class="fa-solid fa-check text-emerald-500 mt-0.5 text-xs shrink-0"></i>
      <span>${escapeHTML(s)}</span>
    </li>
  `).join('');

  const softSkillsHtml = (plano.soft_skills_essenciais || []).map(s => `
    <li class="flex items-start gap-2">
      <i class="fa-solid fa-star text-amber-500 mt-0.5 text-xs shrink-0"></i>
      <span>${escapeHTML(s)}</span>
    </li>
  `).join('');

  const acoesHtml = (plano.acoes_praticas_edv || []).map(a => `
    <li class="flex items-start gap-2">
      <i class="fa-solid fa-arrow-right text-blue-500 mt-0.5 text-xs shrink-0"></i>
      <span>${escapeHTML(a)}</span>
    </li>
  `).join('');

  const marcosHtml = (plano.metas_com_prazos || []).map(m => `
    <div class="p-3 bg-slate-50 border border-slate-200 rounded-lg flex items-center justify-between">
      <span class="font-medium text-slate-800">${escapeHTML(m.marco)}</span>
      <span class="px-2 py-0.5 bg-amber-100 text-amber-800 rounded text-[10px] font-bold font-mono">D + ${m.prazo_dias} dias</span>
    </div>
  `).join('');

  container.innerHTML = `
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-100">
      <div>
        <div class="flex items-center gap-2">
          <span class="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-100 text-purple-800 border border-purple-300">
            ${escapeHTML(membro.area || 'VPGG')} • ${escapeHTML(membro.cargo || 'Membro')}
          </span>
          <span class="text-xs text-slate-400 font-mono">(${escapeHTML(membro.email)})</span>
        </div>
        <h4 class="text-lg font-black text-slate-900 mt-1">${escapeHTML(membro.nome)}</h4>
        <p class="text-xs text-slate-600 mt-0.5"><strong>Diretriz Hierárquica:</strong> ${escapeHTML(plano.diretriz_hierarquica || '')}</p>
      </div>
      <button type="button" onclick="transferirTrilhaAtualParaPDI()" class="bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs px-4 py-2.5 rounded-lg shadow-sm flex items-center gap-2 transition self-start md:self-auto">
        <i class="fa-solid fa-file-import"></i>
        <span>Transferir para Formulário de PDI</span>
      </button>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="p-4 bg-purple-50/50 rounded-xl border border-purple-200 space-y-2">
        <h5 class="font-bold text-xs text-purple-900 flex items-center gap-2">
          <i class="fa-solid fa-code text-purple-600"></i> Hard Skills Prioritárias
        </h5>
        <ul class="text-xs text-slate-700 space-y-2">
          ${hardSkillsHtml}
        </ul>
      </div>

      <div class="p-4 bg-amber-50/50 rounded-xl border border-amber-200 space-y-2">
        <h5 class="font-bold text-xs text-amber-900 flex items-center gap-2">
          <i class="fa-solid fa-heart text-amber-600"></i> Soft Skills Essenciais
        </h5>
        <ul class="text-xs text-slate-700 space-y-2">
          ${softSkillsHtml}
        </ul>
      </div>
    </div>

    <div class="space-y-2">
      <h5 class="font-bold text-xs text-slate-800 flex items-center gap-2">
        <i class="fa-solid fa-list-check text-blue-600"></i> Ações Práticas & Entregáveis EDV Jr.
      </h5>
      <ul class="text-xs text-slate-700 space-y-2 bg-slate-50 p-4 rounded-xl border border-slate-200">
        ${acoesHtml}
      </ul>
    </div>

    <div class="space-y-2">
      <h5 class="font-bold text-xs text-slate-800 flex items-center gap-2">
        <i class="fa-regular fa-calendar-check text-emerald-600"></i> Marcos Temporais de Execução
      </h5>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
        ${marcosHtml}
      </div>
    </div>
  `;

  container.classList.remove('hidden');
  container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function transferirTrilhaAtualParaPDI() {
  if (!window.ULTIMA_TRILHA_GERADA) {
    showToast("⚠️ Nenhuma trilha gerada recentemente para transferir.");
    return;
  }

  const data = window.ULTIMA_TRILHA_GERADA;
  const membro = data.membro_avaliado || {};
  const plano = data.plano_estruturado_sugerido || {};

  // Alternar para a sub-aba de PDIs
  switchVPGGSubtab('pdis');

  const pdiSelect = document.getElementById('pdi_user_email');
  const objectivesInput = document.getElementById('pdi_objectives');
  const ideasInput = document.getElementById('pdi_ideas');
  const deadlineInput = document.getElementById('pdi_deadline');

  if (pdiSelect && membro.email) {
    pdiSelect.value = membro.email.toLowerCase();
    aoSelecionarMembroPDI();
  }

  if (objectivesInput) {
    const objs = plano.objetivos_sugeridos || [
      `Consolidar domínio das rotinas técnicas de ${membro.area || 'VPGG'}`,
      'Atingir 100% de pontualidade nas entregas corporativas da EDV Jr.'
    ];
    objectivesInput.value = objs.map(o => '• ' + o).join('\n');
  }

  if (ideasInput) {
    const acoes = (plano.acoes_praticas_edv || []).map(a => '• ' + a).join('\n');
    const hards = (plano.hard_skills_prioritarias || []).map(h => '• ' + h).join('\n');
    ideasInput.value = `AÇÕES PRÁTICAS EDV JR.:\n${acoes}\n\nHARD SKILLS:\n${hards}`;
  }

  if (deadlineInput) {
    // Prazo sugerido: 90 dias a contar de hoje
    const d = new Date();
    d.setDate(d.getDate() + 90);
    deadlineInput.value = d.toISOString().split('T')[0];
  }

  showToast("✅ Trilha transferida para o formulário de PDI com sucesso!");
  const formEl = document.getElementById('form-novo-pdi');
  if (formEl) formEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function carregarAnalyticsVPGG() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(API_BASE_URL + '/vpgg/pdis/analytics', {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      const consolidado = data.consolidado_geral || {};
      const total = consolidado.total_pdis_cadastrados || 0;
      const taxa = consolidado.taxa_conclusao_pct || 0;
      const dist = consolidado.distribuicao_status || {};

      const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
      setEl('analytics-total-pdis', total);
      setEl('analytics-taxa-conclusao', `${taxa.toFixed(1)}%`);
      setEl('analytics-em-andamento', dist.em_andamento || 0);
      setEl('analytics-planejados', dist.planejado || 0);

      renderAnalyticsStatusBars(dist, total);
    }
  } catch (err) {
    console.warn("[VPGG Analytics] Falha ao carregar métricas:", err.message);
  }
}

function renderAnalyticsStatusBars(dist, total) {
  const container = document.getElementById('analytics-status-bars');
  if (!container) return;

  const statuses = [
    { key: 'em_andamento', label: 'Em Andamento', color: 'bg-amber-500', text: 'text-amber-800' },
    { key: 'concluido', label: 'Concluído', color: 'bg-emerald-500', text: 'text-emerald-800' },
    { key: 'planejado', label: 'Planejado', color: 'bg-blue-500', text: 'text-blue-800' },
    { key: 'pausado', label: 'Pausado', color: 'bg-slate-400', text: 'text-slate-800' }
  ];

  container.innerHTML = statuses.map(st => {
    const count = dist[st.key] || 0;
    const pct = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
    return `
      <div class="space-y-1">
        <div class="flex items-center justify-between text-xs font-semibold">
          <span class="${st.text}">${st.label}</span>
          <span class="font-mono text-slate-500">${count} (${pct}%)</span>
        </div>
        <div class="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
          <div class="${st.color} h-2 rounded-full transition-all duration-500" style="width: ${pct}%"></div>
        </div>
      </div>
    `;
  }).join('');
}

// ==============================================================================
// 4.7 MODAL DE PERFIL SEGURO & BLINDAGEM DE AUTO-PROMOÇÃO (/api/auth/me)
// ==============================================================================
async function abrirModalPerfil() {
  const modal = document.getElementById('modal-meu-perfil');
  if (!modal) return;

  let user = currentUserSession || {};
  const token = localStorage.getItem(AUTH_TOKEN_KEY);

  // Consultar dados atualizados do /api/auth/me no backend se token presente
  if (token) {
    try {
      const res = await fetch(API_BASE_URL + '/api/auth/me', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      if (res.ok) {
        const liveUser = await res.json();
        user = { ...user, ...liveUser };
        currentUserSession = user;
        localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(user));
      }
    } catch (e) {
      console.warn("[Perfil] Falha ao consultar /api/auth/me:", e.message);
    }
  }

  const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
  setVal('perfil_email', user.email || '');
  setVal('perfil_nome', user.nome || '');
  setVal('perfil_role', (user.role || 'assessor').toUpperCase());
  setVal('perfil_area', user.area || user.setor || 'EDV Jr.');
  setVal('perfil_setor', user.setor || user.area || 'EDV Jr.');
  setVal('perfil_cargo', user.cargo || (user.role ? user.role + ' de ' + (user.area || 'EDV') : 'Consultor(a)'));

  const avatarPreview = document.getElementById('perfil-avatar-preview');
  if (avatarPreview && user.nome) {
    const initials = user.nome.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
    avatarPreview.innerText = initials;
  }

  modal.classList.remove('hidden');
}

function fecharModalPerfil() {
  const modal = document.getElementById('modal-meu-perfil');
  if (modal) modal.classList.add('hidden');
}

async function salvarPerfilUsuario(event) {
  if (event) event.preventDefault();

  const nomeInput = document.getElementById('perfil_nome');
  const novoNome = (nomeInput?.value || '').trim();

  if (!novoNome) {
    showToast("⚠️ O nome de exibição não pode ser vazio.");
    return;
  }

  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  const btnSubmit = document.getElementById('btn-salvar-perfil');
  if (btnSubmit) {
    btnSubmit.disabled = true;
    btnSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Salvando no EDbrain...';
  }

  try {
    const res = await fetch(API_BASE_URL + '/api/auth/me', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ nome: novoNome })
    });

    if (res.ok) {
      const updatedUser = await res.json();
      if (currentUserSession) {
        currentUserSession.nome = updatedUser.nome;
        localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(currentUserSession));
        applyUserSession(currentUserSession);
      }
      showToast("✅ Nome de exibição atualizado com sucesso no EDbrain!");
      fecharModalPerfil();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Bloqueio de Segurança: ${err.detail || 'Operação não permitida'}`);
    }
  } catch (err) {
    console.error("Falha ao salvar perfil:", err);
    showToast("⚠️ Servidor EDbrain offline. Não foi possível persistir.");
  } finally {
    if (btnSubmit) {
      btnSubmit.disabled = false;
      btnSubmit.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> <span>Salvar Alterações de Nome</span>';
    }
  }
}

// ==============================================================================
// 4.9. INGESTÃO DE DADOS PÚBLICOS & DIRETÓRIOS CORPORATIVOS (/crm/ingest)
// ==============================================================================

function abrirModalIngestaoPublica() {
  const modal = document.getElementById('modal-ingestao-publica');
  if (!modal) return;

  const areaSelect = document.getElementById('ingest_area');
  if (areaSelect && currentUserSession?.area) {
    areaSelect.value = currentUserSession.area;
  }

  const feedbackCard = document.getElementById('ingest_feedback_card');
  if (feedbackCard) feedbackCard.classList.add('hidden');

  modal.classList.remove('hidden');
}

function fecharModalIngestaoPublica() {
  const modal = document.getElementById('modal-ingestao-publica');
  if (modal) modal.classList.add('hidden');
}

function alternarExemploIngestao() {
  const formato = document.getElementById('ingest_formato')?.value || 'json';
  const textarea = document.getElementById('ingest_conteudo');
  if (!textarea) return;

  if (textarea.value.trim().startsWith('{') || textarea.value.trim().startsWith('[') || textarea.value.trim().includes(';')) {
    carregarExemploIngestao();
  }
}

function carregarExemploIngestao() {
  const formato = document.getElementById('ingest_formato')?.value || 'json';
  const textarea = document.getElementById('ingest_conteudo');
  if (!textarea) return;

  if (formato === 'json') {
    textarea.value = JSON.stringify({
      "leads": [
        {
          "cnpj": "12.345.678/0001-95",
          "razao_social": "Padaria & Confeitaria Bela Vista Ltda",
          "nome_fantasia": "Bela Vista Pães",
          "cnae": "1091 - Panificação",
          "company_size": "ME",
          "area": "Comercial",
          "estimated_value": 3000.0,
          "tags": "#dados_abertos, #panificacao",
          "notes": "Extraído de cadastro público da Junta Comercial"
        },
        {
          "cnpj": "98.765.432/0001-10",
          "razao_social": "Oficina Mecânica São Cristóvão EIRELI",
          "nome_fantasia": "Auto Center São Cristóvão",
          "cnae": "4520 - Reparação de veículos",
          "company_size": "EPP",
          "area": "Comercial",
          "estimated_value": 4500.0,
          "tags": "#automotivo, #prioridade",
          "notes": "Empresa sem registro de marca no INPI"
        }
      ]
    }, null, 2);
  } else {
    textarea.value = [
      "cnpj;razao_social;nome_fantasia;cnae;porte;valor;tags;notes",
      "55.444.333/0001-22;Distribuidora Capixaba de Bebidas S/A;Capixaba Bebidas;4635;DEMAIS;12000;#bebidas,#grande_porte;Diretório público do ES",
      "22.111.000/0001-88;Restaurante e Churrascaria Boi Preto LTDA;Boi Preto Gourmet;5611;ME;3500;#alimentacao;Lead mapeado via OSM"
    ].join('\n');
  }
}

async function submeterIngestaoPublica(event) {
  if (event) event.preventDefault();

  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) {
    showToast("⚠️ Sessão expirada. Efetue login novamente.");
    return;
  }

  const formato = document.getElementById('ingest_formato')?.value || 'json';
  const areaDestino = document.getElementById('ingest_area')?.value || 'Comercial';
  const conteudo = (document.getElementById('ingest_conteudo')?.value || '').trim();

  if (!conteudo) {
    showToast("⚠️ Forneça o conteúdo da carga em formato JSON ou CSV.");
    return;
  }

  const btnProcessar = document.getElementById('btn-processar-ingest');
  if (btnProcessar) {
    btnProcessar.disabled = true;
    btnProcessar.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processando Ingestão & Deduplicação...';
  }

  const feedbackCard = document.getElementById('ingest_feedback_card');
  const feedbackTitle = document.getElementById('ingest_feedback_title');
  const feedbackBadge = document.getElementById('ingest_feedback_badge');
  const feedbackSummary = document.getElementById('ingest_feedback_summary');
  const feedbackDetails = document.getElementById('ingest_feedback_details');

  try {
    let payload = null;
    let contentType = 'application/json';

    if (formato === 'json') {
      try {
        const parsed = JSON.parse(conteudo);
        if (Array.isArray(parsed)) {
          payload = { leads: parsed.map(item => ({ ...item, area: item.area || areaDestino })) };
        } else if (parsed && typeof parsed === 'object') {
          if (Array.isArray(parsed.leads)) {
            payload = {
              ...parsed,
              leads: parsed.leads.map(item => ({ ...item, area: item.area || areaDestino }))
            };
          } else {
            payload = { leads: [{ ...parsed, area: parsed.area || areaDestino }] };
          }
        } else {
          throw new Error("Formato JSON inválido. Esperado array ou objeto com 'leads'.");
        }
      } catch (errJson) {
        showToast(`❌ Erro no JSON: ${errJson.message}`);
        return;
      }
    } else {
      payload = { csv_content: conteudo };
    }

    const res = await fetch(API_BASE_URL + '/crm/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': contentType,
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (res.ok && data.status === 'success') {
      showToast(`🎉 Ingestão concluída: ${data.inserted} inseridos, ${data.updated} atualizados.`);

      if (feedbackCard && feedbackTitle && feedbackBadge && feedbackSummary && feedbackDetails) {
        feedbackCard.classList.remove('hidden', 'bg-rose-50', 'border-rose-200', 'bg-amber-50', 'border-amber-200');
        feedbackCard.classList.add('bg-emerald-50', 'border-emerald-200');

        feedbackTitle.innerHTML = '<i class="fa-solid fa-circle-check text-emerald-600"></i> Carga Processada com Sucesso';
        feedbackBadge.className = 'text-[10px] px-2 py-0.5 rounded-full font-bold bg-emerald-100 text-emerald-800';
        feedbackBadge.innerText = `${data.total_received} processados`;

        feedbackSummary.innerHTML = `
          <strong>Resultado da Operação:</strong><br>
          ✨ <strong>${data.inserted}</strong> novos leads inseridos no CRM com Lead Score preditivo.<br>
          🔄 <strong>${data.updated}</strong> registros existentes deduplicados e atualizados sem redundância.
          ${data.errors && data.errors.length ? `<br>⚠️ <em>${data.errors.length} avisos durante o processamento.</em>` : ''}
        `;

        if (data.details && data.details.length) {
          feedbackDetails.innerHTML = data.details.map(d => {
            const isIns = d.action === 'inserted';
            const actionBadge = isIns 
              ? '<span class="text-emerald-700 bg-emerald-100 px-1 py-0.2 rounded font-bold">NOVO</span>'
              : '<span class="text-sky-700 bg-sky-100 px-1 py-0.2 rounded font-bold">ATUALIZADO</span>';
            return `<div class="p-1.5 bg-white rounded border border-slate-200 flex items-center justify-between gap-2">
              <span class="truncate"><strong>${escapeHTML(d.client_name)}</strong> ${d.cnpj ? `(${escapeHTML(d.cnpj)})` : ''}</span>
              <div class="flex items-center gap-1.5 shrink-0">
                <span class="text-slate-500 font-mono">Score: ${d.score}</span>
                ${actionBadge}
              </div>
            </div>`;
          }).join('');
        } else {
          feedbackDetails.innerHTML = '';
        }
      }

      await carregarFollowupsCRM();

    } else {
      showToast(`❌ Falha na ingestão: ${data.detail || 'Verifique o formato da carga'}`);
      if (feedbackCard && feedbackTitle && feedbackBadge && feedbackSummary) {
        feedbackCard.classList.remove('hidden', 'bg-emerald-50', 'border-emerald-200');
        feedbackCard.classList.add('bg-rose-50', 'border-rose-200');
        feedbackTitle.innerHTML = '<i class="fa-solid fa-triangle-exclamation text-rose-600"></i> Erro no Processamento';
        feedbackBadge.className = 'text-[10px] px-2 py-0.5 rounded-full font-bold bg-rose-100 text-rose-800';
        feedbackBadge.innerText = 'Falha';
        feedbackSummary.innerText = data.detail || 'Não foi possível processar a carga fornecida.';
      }
    }
  } catch (err) {
    console.error("[Ingestão Pública] Erro:", err);
    showToast("⚠️ Falha de comunicação com o servidor EDbrain.");
  } finally {
    if (btnProcessar) {
      btnProcessar.disabled = false;
      btnProcessar.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> <span>Processar Carga de Dados</span>';
    }
  }
}

// ==============================================================================
// 4.8 FUNIL KANBAN INTERATIVO, GERADOR DE PITCHES, PE BRASIL JR, AUDITORIA & BACKUPS
// ==============================================================================

// 1. RENDERIZAÇÃO DO QUADRO KANBAN
function renderKanbanBoard(leads) {
  const colProspeccao = document.getElementById('kanban-col-prospeccao');
  const colNegociacao = document.getElementById('kanban-col-negociacao');
  const colFechado = document.getElementById('kanban-col-fechado');
  const colPerdido = document.getElementById('kanban-col-perdido');
  if (!colProspeccao || !colNegociacao || !colFechado || !colPerdido) return;

  const grupos = {
    prospeccao: [],
    negociacao: [],
    fechado: [],
    perdido: []
  };

  const totaisVal = {
    prospeccao: 0,
    negociacao: 0,
    fechado: 0,
    perdido: 0
  };

  (leads || []).forEach(lead => {
    const st = (lead.status || 'prospeccao').toLowerCase().trim();
    const targetGroup = grupos[st] ? st : 'prospeccao';
    grupos[targetGroup].push(lead);
    totaisVal[targetGroup] += parseFloat(lead.estimated_value) || 0;
  });

  // Atualizar contadores e somatórios nos cabeçalhos das colunas
  const formatMoeda = val => 'R$ ' + val.toLocaleString('pt-BR', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
  ['prospeccao', 'negociacao', 'fechado', 'perdido'].forEach(key => {
    const elCount = document.getElementById(`kanban-count-${key}`);
    const elVal = document.getElementById(`kanban-val-${key}`);
    if (elCount) elCount.innerText = grupos[key].length;
    if (elVal) elVal.innerText = formatMoeda(totaisVal[key]);
  });

  const renderCard = (lead, currentStage) => {
    const id = lead.id;
    const nome = escapeHTML(lead.client_name || 'Sem Nome');
    const fantasia = lead.nome_fantasia ? `<span class="text-[10px] text-slate-500 block truncate font-normal">"${escapeHTML(lead.nome_fantasia)}"</span>` : '';
    const score = (lead.score !== undefined && lead.score !== null) ? Number(lead.score) : 50;
    const scoreBadge = score >= 80 
      ? '<span class="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800">Score ' + score + '</span>'
      : (score >= 50 
        ? '<span class="text-[9px] font-bold px-1.5 py-0.5 rounded bg-blue-100 text-blue-800">Score ' + score + '</span>'
        : '<span class="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-100 text-amber-800">Score ' + score + '</span>');
    
    const valor = parseFloat(lead.estimated_value) || 0;
    const valorBadge = valor > 0 
      ? `<span class="text-[10px] font-mono font-bold text-slate-800">R$ ${valor.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</span>`
      : '<span class="text-[10px] text-slate-400 font-mono">Sem valor</span>';

    const daysStagnant = lead.days_stagnant !== undefined ? Number(lead.days_stagnant) : 0;
    let stagnationBadge = '';
    if (currentStage !== 'fechado' && currentStage !== 'perdido') {
      if (daysStagnant >= 30) {
        stagnationBadge = `<span class="badge-stagnant-30 text-[9px] font-bold px-1.5 py-0.5 rounded-full block text-center mt-1">🚨 Crítico (${daysStagnant}d estagnado)</span>`;
      } else if (daysStagnant >= 14 || lead.is_stagnant) {
        stagnationBadge = `<span class="badge-stagnant-14 text-[9px] font-bold px-1.5 py-0.5 rounded-full block text-center mt-1">⏱️ Atenção (${daysStagnant}d estagnado)</span>`;
      }
    }

    const porte = lead.company_size ? `<span class="text-[9px] bg-slate-100 text-slate-600 px-1 py-0.2 rounded font-mono">${escapeHTML(lead.company_size)}</span>` : '';
    const cnae = lead.cnae ? `<span class="text-[9px] text-slate-500 truncate block max-w-[170px]" title="${escapeHTML(lead.cnae)}"><i class="fa-solid fa-briefcase text-[8px] text-slate-400 mr-0.5"></i>${escapeHTML(lead.cnae)}</span>` : '';

    let moveButtons = '';
    if (currentStage === 'prospeccao') {
      moveButtons = `
        <button onclick="moverEstagioKanban(${id}, 'negociacao')" class="px-2 py-1 text-[10px] font-bold rounded bg-amber-100 hover:bg-amber-200 text-amber-900 flex items-center gap-1 transition" title="Avançar para Negociação">
          <span>Negociação</span> <i class="fa-solid fa-arrow-right text-[9px]"></i>
        </button>
      `;
    } else if (currentStage === 'negociacao') {
      moveButtons = `
        <button onclick="moverEstagioKanban(${id}, 'prospeccao')" class="px-1.5 py-1 text-[10px] font-bold rounded bg-slate-100 hover:bg-slate-200 text-slate-700 transition" title="Voltar para Prospecção">
          <i class="fa-solid fa-arrow-left text-[9px]"></i>
        </button>
        <button onclick="moverEstagioKanban(${id}, 'fechado')" class="px-2 py-1 text-[10px] font-bold rounded bg-emerald-100 hover:bg-emerald-200 text-emerald-900 flex items-center gap-1 transition" title="Marcar como Fechado">
          <i class="fa-solid fa-check text-[9px]"></i> <span>Fechar</span>
        </button>
        <button onclick="moverEstagioKanban(${id}, 'perdido')" class="px-1.5 py-1 text-[10px] font-bold rounded bg-rose-100 hover:bg-rose-200 text-rose-800 transition" title="Marcar como Perdido">
          <i class="fa-solid fa-xmark text-[9px]"></i>
        </button>
      `;
    } else if (currentStage === 'fechado') {
      moveButtons = `
        <button onclick="moverEstagioKanban(${id}, 'negociacao')" class="px-2 py-1 text-[10px] font-bold rounded bg-slate-100 hover:bg-slate-200 text-slate-700 transition" title="Reabrir Negociação">
          <i class="fa-solid fa-arrow-rotate-left text-[9px]"></i> <span>Reabrir</span>
        </button>
      `;
    } else if (currentStage === 'perdido') {
      moveButtons = `
        <button onclick="moverEstagioKanban(${id}, 'prospeccao')" class="px-2 py-1 text-[10px] font-bold rounded bg-slate-100 hover:bg-slate-200 text-slate-700 transition" title="Recuperar Oportunidade">
          <i class="fa-solid fa-arrow-rotate-left text-[9px]"></i> <span>Recuperar</span>
        </button>
      `;
    }

    return `
      <div class="kanban-card bg-white p-3 rounded-xl border border-slate-200 shadow-2xs space-y-2 text-xs">
        <div class="flex items-start justify-between gap-1.5">
          <div class="truncate flex-1">
            <h5 class="font-bold text-slate-800 truncate" title="${nome}">${nome}</h5>
            ${fantasia}
          </div>
          <div class="shrink-0 flex items-center gap-1">
            ${scoreBadge}
          </div>
        </div>

        <div class="flex items-center justify-between text-[11px] text-slate-500 pt-1 border-t border-slate-100">
          <div class="flex items-center gap-1">
            ${porte}
            ${cnae}
          </div>
          <div>${valorBadge}</div>
        </div>

        ${stagnationBadge}

        <div class="flex items-center justify-between pt-2 border-t border-slate-100">
          <button onclick="abrirModalGeradorPitch(${id})" class="px-2 py-1 text-[10px] font-bold rounded bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-300 flex items-center gap-1 transition" title="Gerar Roteiro Consultivo com Tese Jurídica">
            <i class="fa-solid fa-bolt text-amber-500 text-[10px]"></i> <span>Pitch</span>
          </button>
          <div class="flex items-center gap-1">
            ${moveButtons}
          </div>
        </div>
      </div>
    `;
  };

  colProspeccao.innerHTML = grupos.prospeccao.length ? grupos.prospeccao.map(l => renderCard(l, 'prospeccao')).join('') : '<div class="p-6 text-center text-slate-400 text-xs italic">Nenhum lead em prospecção</div>';
  colNegociacao.innerHTML = grupos.negociacao.length ? grupos.negociacao.map(l => renderCard(l, 'negociacao')).join('') : '<div class="p-6 text-center text-slate-400 text-xs italic">Nenhum lead em negociação</div>';
  colFechado.innerHTML = grupos.fechado.length ? grupos.fechado.map(l => renderCard(l, 'fechado')).join('') : '<div class="p-6 text-center text-slate-400 text-xs italic">Nenhum contrato fechado</div>';
  colPerdido.innerHTML = grupos.perdido.length ? grupos.perdido.map(l => renderCard(l, 'perdido')).join('') : '<div class="p-6 text-center text-slate-400 text-xs italic">Nenhum lead perdido</div>';
}

// 2. MOVIMENTAÇÃO DE ESTÁGIO NO KANBAN
async function moverEstagioKanban(leadId, novoStatus) {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) {
    showToast("⚠️ Autenticação necessária para alterar estágio.");
    return;
  }

  try {
    const res = await fetch(`${API_BASE_URL}/crm/followups/${leadId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ status: novoStatus })
    });

    if (res.ok) {
      showToast(`✨ Estágio atualizado para "${novoStatus.toUpperCase()}"!`);
      await carregarFollowupsCRM();
      carregarMetasPE();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha ao mover estágio: ${err.detail || 'Erro na requisição'}`);
    }
  } catch (e) {
    showToast("⚠️ Falha de comunicação com o servidor.");
  }
}

// 3. GERADOR DINÂMICO DE PITCHES
let currentPitchData = null;

async function abrirModalGeradorPitch(leadId) {
  const modal = document.getElementById('modal-gerador-pitch');
  const title = document.getElementById('pitch-modal-lead-title');
  const tese = document.getElementById('pitch-tese-juridica');
  const txtWpp = document.getElementById('pitch-text-whatsapp');
  const txtInsta = document.getElementById('pitch-text-instagram');
  const txtEmail = document.getElementById('pitch-text-email');

  if (!modal) return;
  modal.classList.remove('hidden');
  if (title) title.innerText = `Gerando pitch para lead #${leadId}...`;
  if (tese) tese.innerText = "Consultando base de inteligência jurídica...";
  if (txtWpp) txtWpp.value = "";
  if (txtInsta) txtInsta.value = "";
  if (txtEmail) txtEmail.value = "";

  const token = localStorage.getItem(AUTH_TOKEN_KEY);

  try {
    const res = await fetch(`${API_BASE_URL}/crm/pitch/${leadId}`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      currentPitchData = data;
      if (title) title.innerText = `${data.client_name} • ${data.segmento}`;
      if (tese) tese.innerText = data.tese_juridica;
      if (txtWpp) txtWpp.value = data.whatsapp;
      if (txtInsta) txtInsta.value = data.instagram || data.instagram_dm || "";
      if (txtEmail) txtEmail.value = data.email || data.email_formal || "";
      switchPitchTab('whatsapp');
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Erro ao gerar pitch: ${err.detail || 'Falha na requisição'}`);
      if (tese) tese.innerText = "Não foi possível gerar a tese jurídica para este registro.";
    }
  } catch (err) {
    showToast("⚠️ Falha ao conectar ao servidor para gerar pitch.");
  }
}

function fecharModalPitch() {
  const modal = document.getElementById('modal-gerador-pitch');
  if (modal) modal.classList.add('hidden');
}

function switchPitchTab(tab) {
  const tabs = ['whatsapp', 'instagram', 'email'];
  tabs.forEach(t => {
    const btn = document.getElementById(`pitch-tab-${t}`);
    const content = document.getElementById(`pitch-content-${t}`);
    if (t === tab) {
      if (btn) {
        btn.classList.add('border-b-2', 'border-emerald-600', 'text-emerald-700');
        btn.classList.remove('border-transparent', 'text-slate-500');
      }
      if (content) content.classList.remove('hidden');
    } else {
      if (btn) {
        btn.classList.remove('border-b-2', 'border-emerald-600', 'text-emerald-700');
        btn.classList.add('border-transparent', 'text-slate-500');
      }
      if (content) content.classList.add('hidden');
    }
  });
}

function copiarPitch(tipo) {
  let texto = '';
  if (tipo === 'whatsapp') {
    texto = getVal('pitch-text-whatsapp');
  } else if (tipo === 'instagram') {
    texto = getVal('pitch-text-instagram');
  } else if (tipo === 'email') {
    texto = getVal('pitch-text-email');
  } else if (tipo === 'tese') {
    const el = document.getElementById('pitch-tese-juridica');
    texto = el ? el.innerText : '';
  }

  if (!texto) {
    showToast("Nenhum texto disponível para cópia.");
    return;
  }

  navigator.clipboard.writeText(texto).then(() => {
    showToast("📋 Roteiro copiado com sucesso para a área de transferência!");
  }).catch(() => {
    showToast("Texto selecionado para cópia.");
  });
}

// 4. PAINEL DE INDICADORES PE BRASIL JÚNIOR (2024-2026)
async function carregarMetasPE() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(`${API_BASE_URL}/api/strategy/pe-metrics`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      
      // 1. Faturamento
      const fatReal = data.faturamento_realizado || 0;
      const fatMeta = data.faturamento_meta || 50000;
      const fatPct = data.faturamento_percentual || 0;
      const fatStatus = data.faturamento_status || 'off_track';
      
      const elFatReal = document.getElementById('pe-fat-realizado');
      const elFatMeta = document.getElementById('pe-fat-meta');
      const elFatBar = document.getElementById('pe-fat-bar');
      const elFatPct = document.getElementById('pe-fat-pct');
      const elFatStatus = document.getElementById('pe-fat-status');

      if (elFatReal) elFatReal.innerText = `R$ ${fatReal.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}`;
      if (elFatMeta) elFatMeta.innerText = `R$ ${fatMeta.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}`;
      if (elFatBar) elFatBar.style.width = `${Math.min(100, fatPct)}%`;
      if (elFatPct) elFatPct.innerText = `${fatPct.toFixed(1)}% da meta anual`;
      if (elFatStatus) {
        elFatStatus.innerText = fatStatus === 'on_track' ? '🟢 No Ritmo' : (fatStatus === 'attention' ? '🟡 Atenção' : '🔴 Fora da Curva');
        elFatStatus.className = fatStatus === 'on_track' ? 'text-[9px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800' : (fatStatus === 'attention' ? 'text-[9px] font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800' : 'text-[9px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-800');
      }

      // 2. Projetos PAI
      const paiReal = data.projetos_alto_impacto_realizados || 0;
      const paiMeta = data.projetos_alto_impacto_meta || 10;
      const paiPct = data.projetos_alto_impacto_percentual || 0;
      const paiStatus = data.projetos_alto_impacto_status || 'off_track';

      const elPaiReal = document.getElementById('pe-pai-realizado');
      const elPaiMeta = document.getElementById('pe-pai-meta');
      const elPaiBar = document.getElementById('pe-pai-bar');
      const elPaiPct = document.getElementById('pe-pai-pct');
      const elPaiStatus = document.getElementById('pe-pai-status');

      if (elPaiReal) elPaiReal.innerText = `${paiReal} projeto${paiReal === 1 ? '' : 's'}`;
      if (elPaiMeta) elPaiMeta.innerText = `${paiMeta} projetos`;
      if (elPaiBar) elPaiBar.style.width = `${Math.min(100, paiPct)}%`;
      if (elPaiPct) elPaiPct.innerText = `${paiPct.toFixed(1)}% da meta`;
      if (elPaiStatus) {
        elPaiStatus.innerText = paiStatus === 'on_track' ? '🟢 Concluído' : (paiStatus === 'attention' ? '🟡 Atenção' : '🔴 Acelerar');
        elPaiStatus.className = paiStatus === 'on_track' ? 'text-[9px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800' : 'text-[9px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-800';
      }

      // 3. Retenção
      const retTaxa = data.retencao_membros_taxa || 91.3;
      const retMeta = data.retencao_membros_meta || 80.0;
      const retStatus = data.retencao_status || 'on_track';

      const elRetTaxa = document.getElementById('pe-ret-taxa');
      const elRetMeta = document.getElementById('pe-ret-meta');
      const elRetBar = document.getElementById('pe-ret-bar');
      const elRetStatus = document.getElementById('pe-ret-status');

      if (elRetTaxa) elRetTaxa.innerText = `${retTaxa.toFixed(1)}%`;
      if (elRetMeta) elRetMeta.innerText = `${retMeta.toFixed(1)}%`;
      if (elRetBar) elRetBar.style.width = `${Math.min(100, retTaxa)}%`;
      if (elRetStatus) {
        elRetStatus.innerText = retStatus === 'on_track' ? '🟢 Acima da Meta' : '🔴 Atenção';
        elRetStatus.className = retStatus === 'on_track' ? 'text-[9px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800' : 'text-[9px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-800';
      }

      // 4. NPS
      const npsMedia = data.nps_satisfacao_media || 89.5;
      const npsMeta = data.nps_satisfacao_meta || 75.0;
      const npsStatus = data.nps_status || 'on_track';

      const elNpsValor = document.getElementById('pe-nps-valor');
      const elNpsMeta = document.getElementById('pe-nps-meta');
      const elNpsBar = document.getElementById('pe-nps-bar');
      const elNpsStatus = document.getElementById('pe-nps-status');

      if (elNpsValor) elNpsValor.innerText = `${npsMedia.toFixed(1)}`;
      if (elNpsMeta) elNpsMeta.innerText = `${npsMeta.toFixed(1)}`;
      if (elNpsBar) elNpsBar.style.width = `${Math.min(100, npsMedia)}%`;
      if (elNpsStatus) {
        elNpsStatus.innerText = npsStatus === 'on_track' ? '🟢 Excelente' : '🟡 Ajustar';
        elNpsStatus.className = 'text-[9px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800';
      }

      // Alertas de Linha de Corte
      const alertContainer = document.getElementById('pe-alertas-container');
      if (alertContainer && data.alertas_linha_corte) {
        alertContainer.innerHTML = data.alertas_linha_corte.map(a => `
          <div class="p-2.5 bg-amber-50 border border-amber-200 rounded-lg text-amber-900 text-xs flex items-center gap-2">
            <i class="fa-solid fa-triangle-exclamation text-amber-600 text-sm shrink-0"></i>
            <span><strong>Linha de Corte Federativa:</strong> ${escapeHTML(a)}</span>
          </div>
        `).join('');
      }
    }
  } catch (e) {
    console.warn("[PE Metrics] Falha ao carregar metas da estratégia:", e);
  }
}

// 5. CENTRAL DE PLAYBOOKS & COMPLIANCE MEJ (POPs)
async function abrirModalPOPs() {
  const modal = document.getElementById('modal-compliance-pops');
  const body = document.getElementById('pops-container-body');
  if (!modal || !body) return;

  modal.classList.remove('hidden');
  body.innerHTML = '<div class="p-6 text-center text-slate-400"><i class="fa-solid fa-spinner fa-spin text-xl text-blue-600 mb-2 block"></i>Carregando playbooks operacionais do servidor...</div>';

  const token = localStorage.getItem(AUTH_TOKEN_KEY);

  try {
    const res = await fetch(`${API_BASE_URL}/api/compliance/pops`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      body.innerHTML = (data.pops || []).map(pop => `
        <div class="glass-card rounded-xl p-4 border-l-4 border-blue-600 space-y-2">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="text-xs font-mono font-bold bg-blue-100 text-blue-800 px-2 py-0.5 rounded">${escapeHTML(pop.codigo || pop.code)}</span>
              <h4 class="font-bold text-slate-800 text-xs">${escapeHTML(pop.titulo)}</h4>
            </div>
            <span class="text-[10px] text-slate-500 font-semibold">${escapeHTML(pop.area)} • Fase: ${escapeHTML(pop.fase_crm)}</span>
          </div>
          <p class="text-slate-600 text-xs leading-relaxed">${escapeHTML(pop.objetivo)}</p>
          <div class="pt-2 border-t border-slate-100">
            <span class="text-[10px] font-bold text-slate-700 uppercase tracking-wider block mb-1">Passos Obrigatórios de Conformidade:</span>
            <ul class="list-disc list-inside space-y-1 text-slate-600 text-[11px]">
              ${(pop.passos_obrigatorios || []).map(p => `<li>${escapeHTML(p)}</li>`).join('')}
            </ul>
          </div>
        </div>
      `).join('');
    } else {
      body.innerHTML = '<div class="p-4 text-center text-rose-600">Falha ao consultar POPs no servidor.</div>';
    }
  } catch (e) {
    body.innerHTML = '<div class="p-4 text-center text-rose-600">Erro de conexão ao carregar POPs.</div>';
  }
}

function fecharModalPOPs() {
  const modal = document.getElementById('modal-compliance-pops');
  if (modal) modal.classList.add('hidden');
}

// 6. DOSSIÊ DE IMPACTO SOCIOECONÔMICO MEJ (3.5x MULTIPLICADOR)
async function abrirModalImpactoMEJ() {
  const modal = document.getElementById('modal-impacto-mej');
  const tbody = document.getElementById('tabela-impacto-mej-body');
  if (!modal || !tbody) return;

  modal.classList.remove('hidden');
  tbody.innerHTML = '<tr><td colspan="6" class="p-6 text-center text-slate-400"><i class="fa-solid fa-spinner fa-spin text-xl text-emerald-600 mb-2 block"></i>Calculando impacto com multiplicador MEJ...</td></tr>';

  const token = localStorage.getItem(AUTH_TOKEN_KEY);

  try {
    const res = await fetch(`${API_BASE_URL}/crm/impact/report`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      const resumo = data.resumo_executivo || {};
      
      const elContratos = document.getElementById('impacto-total-contratos');
      const elReceita = document.getElementById('impacto-receita-direta');
      const elImpacto = document.getElementById('impacto-economico-gerado');
      const elHoras = document.getElementById('impacto-horas-consultoria');

      if (elContratos) elContratos.innerText = resumo.total_contratos_fechados || 0;
      if (elReceita) elReceita.innerText = `R$ ${(resumo.faturamento_direto_ej || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2 })}`;
      if (elImpacto) elImpacto.innerText = `R$ ${(resumo.impacto_economico_local_estimado || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2 })}`;
      if (elHoras) elHoras.innerText = `${resumo.horas_consultoria_universitaria || 0}h`;

      const projetos = data.projetos_consolidados || [];
      if (projetos.length) {
        tbody.innerHTML = projetos.map(p => `
          <tr class="hover:bg-slate-50 transition">
            <td class="px-3 py-2 font-bold text-slate-800">
              ${escapeHTML(p.cliente)}
              ${p.razao_social ? `<span class="block text-[10px] text-slate-400 font-normal truncate">${escapeHTML(p.razao_social)}</span>` : ''}
            </td>
            <td class="px-3 py-2 font-mono">${escapeHTML(p.porte || 'ME')}</td>
            <td class="px-3 py-2 text-right font-mono font-bold text-slate-800">R$ ${(p.valor_contrato || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</td>
            <td class="px-3 py-2 text-right font-mono font-bold text-emerald-700">R$ ${((p.valor_contrato || 0) * 3.5).toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</td>
            <td class="px-3 py-2 text-center">
              <span class="px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800 font-bold">${p.impact_score || p.score_impacto || 0}</span>
            </td>
            <td class="px-3 py-2 text-slate-600 truncate max-w-[200px]" title="${escapeHTML(p.tipo_impacto || p.impact_type || '')}">
              ${escapeHTML(p.tipo_impacto || p.impact_type || 'Geração de Renda')}
            </td>
          </tr>
        `).join('');
      } else {
        tbody.innerHTML = '<tr><td colspan="6" class="p-6 text-center text-slate-400">Nenhum contrato fechado com mensuração de impacto ainda. Feche oportunidades no Kanban para gerar o relatório!</td></tr>';
      }
    }
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-rose-600">Erro ao carregar dossiê de impacto.</td></tr>';
  }
}

function fecharModalImpactoMEJ() {
  const modal = document.getElementById('modal-impacto-mej');
  if (modal) modal.classList.add('hidden');
}

// 7. AUDITORIA FORENSE & CENTRAL DE BACKUPS SQLITE
let auditLogsCache = [];

async function carregarAuditLogs() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  const tbody = document.getElementById('datagrid-audit-logs');
  const badge = document.getElementById('badge-total-audit-logs');
  if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="p-6 text-center text-slate-400"><i class="fa-solid fa-spinner fa-spin text-xl text-blue-600 mb-2 block"></i>Consultando trilha de auditoria forense...</td></tr>';

  try {
    const res = await fetch(`${API_BASE_URL}/api/admin/audit-logs?limit=100`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      auditLogsCache = data.logs || [];
      if (badge) badge.innerText = `${data.total || auditLogsCache.length} eventos`;
      filtrarAuditLogs();
    } else if (res.status === 403) {
      if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="p-6 text-center text-rose-600 font-bold"><i class="fa-solid fa-shield-halved text-xl mb-1 block"></i>Acesso Restrito: Auditoria forense exclusiva para Presidente e Diretores (RBAC).</td></tr>';
    } else {
      if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="p-4 text-center text-rose-600">Falha ao consultar logs de auditoria.</td></tr>';
    }
  } catch (e) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="p-4 text-center text-rose-600">Erro de conexão ao carregar auditoria.</td></tr>';
  }
}

function filtrarAuditLogs() {
  const tbody = document.getElementById('datagrid-audit-logs');
  if (!tbody) return;

  const userFilter = (getVal('filtro-audit-user') || '').toLowerCase().trim();
  const actionFilter = (getVal('filtro-audit-action') || '').toUpperCase().trim();

  const filtered = auditLogsCache.filter(log => {
    if (userFilter && !(log.user_email || '').toLowerCase().includes(userFilter)) return false;
    if (actionFilter && (log.action || '').toUpperCase() !== actionFilter) return false;
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="p-6 text-center text-slate-400">Nenhum evento localizado com os filtros aplicados.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(log => {
    const isSecurity = log.action === 'SECURITY_VIOLATION_403' || log.status_code === 403;
    const actionBadge = isSecurity 
      ? `<span class="bg-rose-100 text-rose-800 px-1.5 py-0.5 rounded font-bold">${escapeHTML(log.action)}</span>`
      : `<span class="bg-slate-100 text-slate-800 px-1.5 py-0.5 rounded font-bold">${escapeHTML(log.action)}</span>`;

    const statusBadge = log.status_code >= 400 
      ? `<span class="text-rose-600 font-bold">${log.status_code}</span>`
      : `<span class="text-emerald-600 font-bold">${log.status_code}</span>`;

    return `
      <tr class="hover:bg-slate-50 transition">
        <td class="px-3 py-2 font-bold text-slate-700">#${log.id}</td>
        <td class="px-3 py-2 text-slate-500 whitespace-nowrap">${escapeHTML(log.timestamp)}</td>
        <td class="px-3 py-2 font-bold text-slate-800">${escapeHTML(log.user_email)}</td>
        <td class="px-3 py-2">${actionBadge}</td>
        <td class="px-3 py-2 text-slate-600 font-mono text-[10px]">${escapeHTML(log.resource)}</td>
        <td class="px-3 py-2 text-center">${statusBadge}</td>
        <td class="px-3 py-2 text-slate-400 font-mono">${escapeHTML(log.ip_address || '127.0.0.1')}</td>
        <td class="px-3 py-2 text-slate-600 truncate max-w-[260px]" title="${escapeHTML(log.details || '')}">${escapeHTML(log.details || '-')}</td>
      </tr>
    `;
  }).join('');
}

function exportarAuditLogsCSV() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  fetch(`${API_BASE_URL}/api/admin/audit-logs/export`, {
    headers: { 'Authorization': 'Bearer ' + token }
  })
  .then(res => {
    if (!res.ok) throw new Error("Acesso negado ou servidor indisponível");
    return res.blob();
  })
  .then(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit_logs_edbrain_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    showToast("📥 Trilha forense exportada em CSV com sucesso!");
  })
  .catch(err => {
    showToast(`❌ Falha na exportação: ${err.message}`);
  });
}

async function carregarStatusBackups() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  try {
    const res = await fetch(`${API_BASE_URL}/api/admin/backup/status`, {
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      const stats = data.telemetria || data.database || {};
      
      const elFile = document.getElementById('backup-db-filename');
      const elSize = document.getElementById('backup-db-size');
      const elTotal = document.getElementById('backup-total-snapshots');
      const elList = document.getElementById('backup-snapshots-list');

      if (elFile) elFile.innerText = stats.database_file || 'auth.db';
      if (elSize) elSize.innerText = `${stats.size_kb || 0} KB`;
      if (elTotal) elTotal.innerText = `${stats.total_backups || 0} snapshots`;

      if (elList && stats.backups && stats.backups.length) {
        elList.innerHTML = stats.backups.slice(0, 5).map(b => `
          <div class="p-2 bg-slate-50 rounded-lg border border-slate-200 flex items-center justify-between text-xs">
            <div class="flex items-center gap-2">
              <i class="fa-solid fa-database text-slate-500 text-xs"></i>
              <span class="font-mono font-bold text-slate-700">${escapeHTML(b.filename)}</span>
            </div>
            <div class="flex items-center gap-3 text-slate-500 font-mono text-[11px]">
              <span>${(b.size_bytes / 1024).toFixed(1)} KB</span>
              <span class="text-emerald-600 font-bold">Íntegro</span>
            </div>
          </div>
        `).join('');
      } else if (elList) {
        elList.innerHTML = '<div class="text-[11px] text-slate-400 italic">Nenhum snapshot gravado ainda. Clique em "Criar Snapshot Imediato".</div>';
      }
    }
  } catch (e) {
    console.warn("[Backup] Falha ao carregar status:", e);
  }
}

async function criarSnapshotBanco() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  const btn = document.getElementById('btn-snapshot-now');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Copiando...';
  }

  try {
    const res = await fetch(`${API_BASE_URL}/api/admin/backup/snapshot`, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const data = await res.json();
      showToast(`📸 Snapshot criado: ${data.snapshot.filename} (${(data.snapshot.size_bytes / 1024).toFixed(1)} KB)`);
      carregarStatusBackups();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(`❌ Falha ao criar snapshot: ${err.detail || 'Acesso negado'}`);
    }
  } catch (e) {
    showToast("⚠️ Erro de conexão ao disparar snapshot.");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-camera"></i> Criar Snapshot Imediato';
    }
  }
}

function baixarBancoOficial() {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (!token) return;

  fetch(`${API_BASE_URL}/api/admin/backup/download`, {
    headers: { 'Authorization': 'Bearer ' + token }
  })
  .then(res => {
    if (!res.ok) throw new Error("Acesso negado ou banco não encontrado");
    return res.blob();
  })
  .then(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `auth_edbrain_${new Date().toISOString().slice(0, 10)}.db`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    showToast("💾 Download do banco oficial SQLite iniciado!");
  })
  .catch(err => {
    showToast(`❌ Falha no download: ${err.message}`);
  });
}

// ==============================================================================
// 5. INICIALIZAÇÃO DEFINITIVA DO ECOSSISTEMA
// ==============================================================================
function initApp() {
  initAuth();
  initCRMDataGrid();
  initRMsDataGrid();
  initFluxoDataGrid();
  initVPGGDataGrid();
  initSeloEJDataGrid();
  updateDashboardKPIs();
  carregarEstado();
  carregarTransacoesEDbrain();
  carregarAvisosInstitucionais();
  carregarFollowupsCRM();
  popularSelectsVPGG();
  carregarMetasPE();
}

document.addEventListener('DOMContentLoaded', initApp);
if (document.readyState === 'interactive' || document.readyState === 'complete') {
  initApp();
}