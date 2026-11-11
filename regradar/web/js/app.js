// RegRadar Web Studio - Core Application Controller

const AppState = {
  currentWorkspace: "healthcare_hipaa_aws",
  workspaces: [],
  activeTab: "topology",
  settings: {
    current_provider: "mock",
    available_providers: ["mock", "openai", "anthropic", "gemini", "deepseek", "ollama"],
    has_openai_key: false,
    has_anthropic_key: false,
    has_gemini_key: false,
    has_deepseek_key: false,
    ollama_url: "http://localhost:11434"
  },
  topologyData: null,
  reviewData: null,
  complianceData: null,
  benchmarkData: null
};

// API Helper
async function apiCall(endpoint, method = "GET", body = null) {
  const options = {
    method,
    headers: { "Content-Type": "application/json" }
  };
  if (body) {
    options.body = JSON.stringify(body);
  }
  const response = await fetch(endpoint, options);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Request failed with status ${response.status}`);
  }
  return response.json();
}

// Show Toast Notification
function showToast(message, type = "info") {
  const toastContainer = document.getElementById("toastContainer");
  if (!toastContainer) return;

  const toast = document.createElement("div");
  const bgClass = type === "success" ? "bg-emerald-600" : type === "error" ? "bg-rose-600" : "bg-slate-700";
  toast.className = `p-3 rounded-lg shadow-xl text-white text-sm font-medium flex items-center space-x-2 transition-all transform duration-300 opacity-0 translate-y-2 ${bgClass}`;
  toast.innerHTML = `<span>${message}</span>`;

  toastContainer.appendChild(toast);
  requestAnimationFrame(() => {
    toast.classList.remove("opacity-0", "translate-y-2");
  });

  setTimeout(() => {
    toast.classList.add("opacity-0", "translate-y-2");
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Initialize Application
document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation();
  setupSettingsModal();
  setupThemeToggle();
  await loadWorkspaces();
  await loadSettings();
  switchTab("topology");
});

// Setup Navigation Tabs
function setupNavigation() {
  const navItems = document.querySelectorAll("[data-tab]");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const tabId = item.getAttribute("data-tab");
      switchTab(tabId);
    });
  });
}

function switchTab(tabId) {
  AppState.activeTab = tabId;

  // Update nav item active states
  document.querySelectorAll("[data-tab]").forEach(item => {
    if (item.getAttribute("data-tab") === tabId) {
      item.classList.add("bg-cyan-500/10", "text-cyan-400", "border-cyan-400");
      item.classList.remove("text-slate-400", "border-transparent", "hover:text-slate-200");
    } else {
      item.classList.remove("bg-cyan-500/10", "text-cyan-400", "border-cyan-400");
      item.classList.add("text-slate-400", "border-transparent", "hover:text-slate-200");
    }
  });

  // Toggle view containers
  document.querySelectorAll(".view-container").forEach(view => {
    if (view.id === `view-${tabId}`) {
      view.classList.remove("hidden");
    } else {
      view.classList.add("hidden");
    }
  });

  // Trigger view data loading
  onTabActivated(tabId);
}

function onTabActivated(tabId) {
  switch (tabId) {
    case "topology":
      if (window.TopologyModule) window.TopologyModule.load();
      break;
    case "compliance":
      if (window.ComplianceModule) window.ComplianceModule.load();
      break;
    case "review":
      if (window.ReviewModule) window.ReviewModule.load();
      break;
    case "swarm":
      if (window.SwarmModule) window.SwarmModule.load();
      break;
    case "sandbox":
      if (window.SandboxModule) window.SandboxModule.load();
      break;
    case "benchmark":
      if (window.BenchmarkModule) window.BenchmarkModule.load();
      break;
    case "github":
      if (window.GitHubModule) window.GitHubModule.init();
      break;
  }
}

// Load Workspaces List
async function loadWorkspaces() {
  try {
    const workspaces = await apiCall("/api/workspaces");
    AppState.workspaces = workspaces;

    const selector = document.getElementById("workspaceSelector");
    if (!selector) return;

    selector.innerHTML = "";
    const activeWs = workspaces.find(w => w.id === "active_workspace");
    const defaultWsPath = activeWs ? activeWs.path : (workspaces[0] ? workspaces[0].path : null);

    workspaces.forEach((ws, idx) => {
      const opt = document.createElement("option");
      opt.value = ws.path;
      opt.textContent = `${ws.name} (${ws.resource_count} resources)`;
      if (ws.path === defaultWsPath) {
        opt.selected = true;
        AppState.currentWorkspace = ws.path;
      }
      selector.appendChild(opt);
    });

    selector.addEventListener("change", (e) => {
      AppState.currentWorkspace = e.target.value;
      showToast(`Switched target: ${e.target.options[e.target.selectedIndex].text}`, "info");
      onTabActivated(AppState.activeTab);
    });
  } catch (err) {
    console.error("Failed to load workspaces:", err);
  }
}

// Load and Manage LLM Settings
async function loadSettings() {
  try {
    const settings = await apiCall("/api/settings");
    AppState.settings = settings;
    updateProviderBadge(settings.current_provider, settings.current_model);
  } catch (err) {
    console.error("Failed to load settings:", err);
  }
}

function getModelDisplayName(provider, modelId) {
  if (!AppState.settings || !AppState.settings.available_models) return modelId || provider;
  const list = AppState.settings.available_models[provider] || [];
  const found = list.find(m => m.id === modelId);
  return found ? found.name : (modelId || provider);
}

function updateProviderBadge(provider, model) {
  const badge = document.getElementById("providerBadge");
  const headerTag = document.getElementById("providerHeaderTag");
  if (!badge) return;

  const currentModel = model || (AppState.settings && AppState.settings.current_model) || "";
  const displayModel = getModelDisplayName(provider, currentModel);

  const providerTags = {
    mock: "MOCK",
    openai: "OPENAI",
    anthropic: "CLAUDE",
    gemini: "GEMINI",
    deepseek: "DEEPSEEK",
    ollama: "OLLAMA"
  };

  if (headerTag) {
    headerTag.textContent = providerTags[provider] || provider.toUpperCase();
    headerTag.className = provider === "mock"
      ? "text-[9px] font-bold uppercase px-1 rounded bg-slate-700 text-slate-300"
      : "text-[9px] font-bold uppercase px-1 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40";
  }

  badge.textContent = displayModel;

  if (provider === "mock") {
    badge.className = "text-xs font-semibold text-slate-300";
  } else {
    badge.className = "text-xs font-bold text-cyan-400";
  }

  // Update Swarm Tab badges if present
  const swarmBadge = document.getElementById("swarmActiveModelBadge");
  const swarmContext = document.getElementById("swarmModelContextBadge");
  if (swarmBadge) {
    swarmBadge.textContent = `${displayModel} (${providerTags[provider] || provider})`;
  }
  if (swarmContext && AppState.settings && AppState.settings.available_models) {
    const list = AppState.settings.available_models[provider] || [];
    const found = list.find(m => m.id === currentModel);
    swarmContext.textContent = found ? found.context : "Frontier Reasoning";
  }

  // Update Review Tab badge if present
  const reviewTag = document.getElementById("reviewActiveModelTag");
  if (reviewTag) {
    reviewTag.textContent = `Engine: ${displayModel}`;
  }
}

function populateModelOptions(provider, selectedModel) {
  const modelSelect = document.getElementById("modelSelect");
  if (!modelSelect) return;

  modelSelect.innerHTML = "";
  const models = (AppState.settings && AppState.settings.available_models && AppState.settings.available_models[provider]) || [];

  models.forEach(m => {
    const opt = document.createElement("option");
    opt.value = m.id;
    opt.textContent = `${m.name} — ${m.tagline}`;
    modelSelect.appendChild(opt);
  });

  if (selectedModel && models.some(m => m.id === selectedModel)) {
    modelSelect.value = selectedModel;
  } else if (AppState.settings && AppState.settings.provider_models && AppState.settings.provider_models[provider]) {
    modelSelect.value = AppState.settings.provider_models[provider];
  } else if (models.length > 0) {
    modelSelect.value = models[0].id;
  }

  updateModelCapabilitiesCard(provider, modelSelect.value);
}

function updateModelCapabilitiesCard(provider, modelId) {
  const nameEl = document.getElementById("cardModelName");
  const tierEl = document.getElementById("cardModelTier");
  const taglineEl = document.getElementById("cardModelTagline");
  const contextEl = document.getElementById("cardModelContext");

  const models = (AppState.settings && AppState.settings.available_models && AppState.settings.available_models[provider]) || [];
  const found = models.find(m => m.id === modelId) || models[0];

  if (!found) return;

  if (nameEl) nameEl.textContent = `${found.name} (${found.id})`;
  if (tierEl) tierEl.textContent = found.tier || "Frontier Model";
  if (taglineEl) taglineEl.textContent = found.tagline || "Autonomous IaC Governance & Zero-Destruction Remediation";
  if (contextEl) contextEl.textContent = found.context || "Standard Context Window";
}

function updateCredentialStatusPills() {
  const s = AppState.settings || {};
  const setPill = (id, hasKey) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (hasKey) {
      el.innerHTML = `<span class="inline-flex items-center gap-1">${window.RegIcons.svg('check', 'w-3 h-3')} Key Active</span>`;
      el.className = "text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
    } else {
      el.textContent = "Not Configured";
      el.className = "text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-500";
    }
  };

  setPill("openaiKeyStatus", s.has_openai_key);
  setPill("anthropicKeyStatus", s.has_anthropic_key);
  setPill("geminiKeyStatus", s.has_gemini_key);
  setPill("deepseekKeyStatus", s.has_deepseek_key);
}

function setupSettingsModal() {
  const openBtn = document.getElementById("openSettingsBtn");
  const modal = document.getElementById("settingsModal");
  const closeBtn = document.getElementById("closeSettingsBtn");
  const cancelBtn = document.getElementById("cancelSettingsBtn");
  const saveBtn = document.getElementById("saveSettingsBtn");
  const providerSelect = document.getElementById("providerSelect");
  const modelSelect = document.getElementById("modelSelect");

  if (!modal) return;

  if (openBtn) {
    openBtn.addEventListener("click", () => {
      const p = AppState.settings.current_provider || "gemini";
      if (providerSelect) providerSelect.value = p;
      populateModelOptions(p, AppState.settings.current_model);
      updateCredentialStatusPills();
      const ollamaInput = document.getElementById("ollamaUrlInput");
      if (ollamaInput) ollamaInput.value = AppState.settings.ollama_url || "http://localhost:11434";
      modal.classList.remove("hidden");
    });
  }

  if (providerSelect) {
    providerSelect.addEventListener("change", () => {
      populateModelOptions(providerSelect.value);
    });
  }

  if (modelSelect) {
    modelSelect.addEventListener("change", () => {
      updateModelCapabilitiesCard(providerSelect.value, modelSelect.value);
    });
  }

  const closeModal = () => modal.classList.add("hidden");
  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (cancelBtn) cancelBtn.addEventListener("click", closeModal);

  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      const provider = providerSelect ? providerSelect.value : "mock";
      const model = modelSelect ? modelSelect.value : undefined;
      const openaiKey = document.getElementById("openaiKeyInput")?.value.trim();
      const anthropicKey = document.getElementById("anthropicKeyInput")?.value.trim();
      const geminiKey = document.getElementById("geminiKeyInput")?.value.trim();
      const deepseekKey = document.getElementById("deepseekKeyInput")?.value.trim();
      const ollamaUrl = document.getElementById("ollamaUrlInput")?.value.trim();

      saveBtn.disabled = true;
      saveBtn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('spinner', 'w-3.5 h-3.5')} Saving...</span>`;

      try {
        const updated = await apiCall("/api/settings", "POST", {
          provider,
          model,
          openai_key: openaiKey || undefined,
          anthropic_key: anthropicKey || undefined,
          gemini_key: geminiKey || undefined,
          deepseek_key: deepseekKey || undefined,
          ollama_url: ollamaUrl || undefined
        });
        AppState.settings = updated;
        updateProviderBadge(updated.current_provider, updated.current_model);
        closeModal();
        showToast(`AI Engine updated: ${getModelDisplayName(updated.current_provider, updated.current_model)}`, "success");
      } catch (err) {
        showToast(`Failed to update settings: ${err.message}`, "error");
      } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Save & Apply Engine</span>`;
      }
    });
  }
}

// 4-Palette Theme System (Obsidian, Midnight, Polar, Alabaster)
function applyTheme(themeName) {
  const allowed = ["obsidian", "midnight", "polar", "alabaster"];
  const target = allowed.includes(themeName) ? themeName : "obsidian";
  document.documentElement.setAttribute("data-theme", target);

  if (target === "polar" || target === "alabaster") {
    document.documentElement.classList.remove("dark");
  } else {
    document.documentElement.classList.add("dark");
  }

  localStorage.setItem("regradar-theme", target);

  document.querySelectorAll(".theme-pill-btn").forEach(btn => {
    if (btn.getAttribute("data-theme-val") === target) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });
}

function setupThemeToggle() {
  const saved = localStorage.getItem("regradar-theme") || "obsidian";
  applyTheme(saved);

  document.querySelectorAll(".theme-pill-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const t = btn.getAttribute("data-theme-val");
      applyTheme(t);
    });
  });
}
