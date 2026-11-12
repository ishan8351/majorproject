// RegRadar Web Studio - Core Application Controller

const AppState = {
  currentWorkspace: null,
  workspaces: [],
  activeTab: "topology",
  settings: {
    current_provider: "gemini",
    available_providers: ["gemini", "openai", "anthropic", "deepseek", "ollama"],
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
    let msg = `Request failed with status ${response.status}`;
    if (errorData && errorData.detail) {
      if (Array.isArray(errorData.detail)) {
        msg = errorData.detail
          .map(d => {
            if (typeof d === "string") return d;
            if (d && d.msg) {
              const loc = Array.isArray(d.loc) ? d.loc.filter(x => x !== "body").join(".") : "";
              return loc ? `${loc}: ${d.msg}` : d.msg;
            }
            return JSON.stringify(d);
          })
          .join("; ");
      } else if (typeof errorData.detail === "object") {
        msg = JSON.stringify(errorData.detail);
      } else {
        msg = String(errorData.detail);
      }
    } else if (errorData && errorData.message) {
      msg = String(errorData.message);
    }
    throw new Error(msg);
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
  setupInteractiveDemo();
  setupScrollEffects();
  await loadWorkspaces();
  await loadSettings();

  // Hash-based routing for Landing Page vs Dashboard
  if (window.location.hash === "#dashboard") {
    showView("dashboard");
  } else {
    showView("landing");
  }

  window.addEventListener("hashchange", () => {
    if (window.location.hash === "#dashboard") {
      showView("dashboard");
    } else {
      showView("landing");
    }
  });
});

// View Navigation: Landing Page vs Dashboard
function showView(viewName) {
  const landing = document.getElementById("landingView");
  const dashboard = document.getElementById("dashboardView");
  if (!landing || !dashboard) return;

  if (viewName === "dashboard") {
    landing.classList.add("hidden");
    dashboard.classList.remove("hidden");
    window.location.hash = "dashboard";
    switchTab(AppState.activeTab || "topology");
  } else {
    dashboard.classList.add("hidden");
    landing.classList.remove("hidden");
    window.location.hash = "";
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}
window.showView = showView;

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
    AppState.workspaces = workspaces || [];

    const selector = document.getElementById("workspaceSelector");
    if (!selector) return;

    selector.innerHTML = "";

    if (!workspaces || workspaces.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No Remote Repositories Connected";
      selector.appendChild(opt);
      AppState.currentWorkspace = null;
      return;
    }

    const defaultWs = workspaces[0];
    workspaces.forEach((ws) => {
      const opt = document.createElement("option");
      opt.value = ws.path;
      opt.textContent = `${ws.name} (${ws.resource_count} resources)`;
      if (ws.path === (AppState.currentWorkspace || defaultWs.path)) {
        opt.selected = true;
        AppState.currentWorkspace = ws.path;
      }
      selector.appendChild(opt);
    });

    selector.onchange = (e) => {
      AppState.currentWorkspace = e.target.value;
      showToast(`Switched target: ${e.target.options[e.target.selectedIndex].text}`, "info");
      onTabActivated(AppState.activeTab);
    };
  } catch (err) {
    console.error("Failed to load workspaces:", err);
  }
}
window.loadWorkspaces = loadWorkspaces;

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
  if (!badge) return;

  const currentModel = model || (AppState.settings && AppState.settings.current_model) || "";
  const displayModel = getModelDisplayName(provider, currentModel);

  badge.textContent = displayModel;
  badge.className = "text-xs font-semibold text-slate-200";

  // Update Swarm Tab badges if present
  const swarmBadge = document.getElementById("swarmActiveModelBadge");
  if (swarmBadge) {
    swarmBadge.textContent = displayModel;
  }

  // Update Review Tab badge if present
  const reviewTag = document.getElementById("reviewActiveModelTag");
  if (reviewTag) {
    reviewTag.textContent = displayModel;
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
    opt.textContent = m.name;
    modelSelect.appendChild(opt);
  });

  if (selectedModel && models.some(m => m.id === selectedModel)) {
    modelSelect.value = selectedModel;
  } else if (AppState.settings && AppState.settings.provider_models && AppState.settings.provider_models[provider]) {
    modelSelect.value = AppState.settings.provider_models[provider];
  } else if (models.length > 0) {
    modelSelect.value = models[0].id;
  }

  const valBadge = document.getElementById("modelValidationBadge");
  if (valBadge) {
    valBadge.textContent = "Unverified";
    valBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400";
  }
  const valMsg = document.getElementById("modelValidationMsg");
  if (valMsg) valMsg.textContent = "";
}

async function validateActiveModel() {
  const providerSelect = document.getElementById("providerSelect");
  const modelSelect = document.getElementById("modelSelect");
  const badge = document.getElementById("modelValidationBadge");
  const msg = document.getElementById("modelValidationMsg");
  const btn = document.getElementById("btnTestActiveModel");

  const provider = providerSelect ? providerSelect.value : "gemini";
  const model = modelSelect ? modelSelect.value : "";
  const openaiKey = document.getElementById("openaiKeyInput")?.value.trim();
  const anthropicKey = document.getElementById("anthropicKeyInput")?.value.trim();
  const geminiKey = document.getElementById("geminiKeyInput")?.value.trim();
  const deepseekKey = document.getElementById("deepseekKeyInput")?.value.trim();
  const ollamaUrl = document.getElementById("ollamaUrlInput")?.value.trim();

  let activeKey = undefined;
  if (provider === "openai") activeKey = openaiKey;
  else if (provider === "anthropic") activeKey = anthropicKey;
  else if (provider === "gemini") activeKey = geminiKey;
  else if (provider === "deepseek") activeKey = deepseekKey;

  if (badge) {
    badge.textContent = "Testing...";
    badge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 animate-pulse";
  }
  if (msg) {
    msg.innerHTML = `<span class="text-amber-400 font-mono text-[11px]">${window.RegIcons.svg('spinner', 'w-3 h-3')} Testing model availability with 1-token probe...</span>`;
  }
  if (btn) btn.disabled = true;

  try {
    const res = await apiCall("/api/models/validate", "POST", {
      provider,
      model,
      api_key: activeKey || undefined,
      ollama_url: ollamaUrl || undefined
    });

    if (res.valid) {
      if (badge) {
        const lat = res.latency_ms ? ` (${Math.round(res.latency_ms)}ms)` : "";
        badge.textContent = `Active${lat}`;
        badge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
      }
      if (msg) {
        msg.innerHTML = `<span class="text-emerald-400 font-medium">${res.message}</span>`;
      }
      return true;
    } else {
      if (badge) {
        badge.textContent = "Failed";
        badge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40";
      }
      if (msg) {
        msg.innerHTML = `<span class="text-rose-400 font-medium">${res.error || res.message}</span>`;
      }
      return false;
    }
  } catch (err) {
    if (badge) {
      badge.textContent = "Error";
      badge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40";
    }
    if (msg) {
      msg.innerHTML = `<span class="text-rose-400 font-medium">${err.message}</span>`;
    }
    return false;
  } finally {
    if (btn) btn.disabled = false;
  }
}
window.validateActiveModel = validateActiveModel;

async function validateOllamaConnection() {
  const urlInput = document.getElementById("ollamaUrlInput");
  const badgeEl = document.getElementById("ollamaHealthBadge");
  const msgEl = document.getElementById("ollamaValidationMsg");
  const discoveredDiv = document.getElementById("ollamaDiscoveredModels");
  const chipsContainer = document.getElementById("ollamaModelChips");
  const btn = document.getElementById("validateOllamaBtn");
  const providerSelect = document.getElementById("providerSelect");
  const modelSelect = document.getElementById("modelSelect");

  const rawUrl = (urlInput && urlInput.value.trim()) || "http://localhost:11434";

  if (badgeEl) {
    badgeEl.textContent = "Connecting...";
    badgeEl.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse";
  }
  if (msgEl) {
    msgEl.innerHTML = `<span class="inline-flex items-center gap-1.5 text-amber-400 font-mono text-xs">${window.RegIcons.svg('spinner', 'w-3 h-3')} Querying Ollama daemon at ${rawUrl}...</span>`;
  }
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="inline-flex items-center gap-1">${window.RegIcons.svg('spinner', 'w-3 h-3')} <span>Verifying...</span></span>`;
  }

  try {
    const res = await apiCall("/api/ollama/validate", "POST", { url: rawUrl });

    if (res.connected) {
      if (badgeEl) {
        badgeEl.textContent = `Connected ${res.version ? 'v' + res.version : ''}`;
        badgeEl.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
      }
      if (msgEl) {
        msgEl.innerHTML = `<span class="text-emerald-400 font-medium">${res.message}</span>`;
      }

      if (res.models && res.models.length > 0) {
        if (discoveredDiv) discoveredDiv.classList.remove("hidden");
        if (chipsContainer) {
          chipsContainer.innerHTML = "";
          res.models.forEach(m => {
            const chip = document.createElement("button");
            chip.type = "button";
            chip.className = "px-2.5 py-1 rounded bg-slate-900 hover:bg-amber-500/20 border border-slate-700 hover:border-amber-500/50 text-slate-200 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer";
            chip.innerHTML = `<span>${m.name}</span>${m.size ? `<span class="text-[10px] text-slate-400">(${m.size})</span>` : ''}`;
            chip.onclick = () => {
              if (providerSelect) {
                providerSelect.value = "ollama";
              }
              if (!AppState.settings) AppState.settings = {};
              if (!AppState.settings.available_models) AppState.settings.available_models = {};
              if (!AppState.settings.available_models.ollama) AppState.settings.available_models.ollama = [];
              if (!AppState.settings.available_models.ollama.some(x => x.id === m.id)) {
                AppState.settings.available_models.ollama.push({
                  id: m.id,
                  name: m.name,
                  tagline: `Local Ollama Model (${m.size || 'Quantized'})`,
                  context: "128k tokens",
                  tier: "Local Dynamic",
                  docs_url: "https://ollama.com",
                  capabilities: "Air-gapped local execution"
                });
              }
              populateModelOptions("ollama", m.id);
              if (modelSelect) modelSelect.value = m.id;
              showToast(`Selected Ollama model: ${m.name}`, "info");
            };
            chipsContainer.appendChild(chip);
          });
        }

        if (!AppState.settings) AppState.settings = {};
        if (!AppState.settings.available_models) AppState.settings.available_models = {};
        if (!AppState.settings.available_models.ollama) AppState.settings.available_models.ollama = [];
        res.models.forEach(m => {
          if (!AppState.settings.available_models.ollama.some(x => x.id === m.id)) {
            AppState.settings.available_models.ollama.push({
              id: m.id,
              name: m.name,
              tagline: `Local Ollama Model (${m.size || 'Quantized'})`,
              context: "128k tokens",
              tier: "Local Dynamic",
              docs_url: "https://ollama.com",
              capabilities: "Air-gapped local execution"
            });
          }
        });

        if (providerSelect && providerSelect.value === "ollama") {
          populateModelOptions("ollama", modelSelect ? modelSelect.value : undefined);
        }
      } else {
        if (discoveredDiv) discoveredDiv.classList.add("hidden");
      }
    } else {
      if (badgeEl) {
        badgeEl.textContent = "Offline";
        badgeEl.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40";
      }
      if (msgEl) {
        msgEl.innerHTML = `<span class="text-rose-400 font-medium">${res.error || res.message || "Failed to reach Ollama daemon"}</span>`;
      }
      if (discoveredDiv) discoveredDiv.classList.add("hidden");
    }
  } catch (err) {
    if (badgeEl) {
      badgeEl.textContent = "Offline";
      badgeEl.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40";
    }
    if (msgEl) {
      msgEl.innerHTML = `<span class="text-rose-400 font-medium">${err.message}</span>`;
    }
    if (discoveredDiv) discoveredDiv.classList.add("hidden");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg><span>Verify Ollama</span>`;
    }
  }
}
window.validateOllamaConnection = validateOllamaConnection;

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

  const closeModal = () => modal.classList.add("hidden");
  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (cancelBtn) cancelBtn.addEventListener("click", closeModal);

  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      const provider = providerSelect ? providerSelect.value : "gemini";
      const model = modelSelect ? modelSelect.value : undefined;
      const openaiKey = document.getElementById("openaiKeyInput")?.value.trim();
      const anthropicKey = document.getElementById("anthropicKeyInput")?.value.trim();
      const geminiKey = document.getElementById("geminiKeyInput")?.value.trim();
      const deepseekKey = document.getElementById("deepseekKeyInput")?.value.trim();
      const ollamaUrl = document.getElementById("ollamaUrlInput")?.value.trim();

      saveBtn.disabled = true;
      saveBtn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('spinner', 'w-3.5 h-3.5')} Validating Model...</span>`;

      try {
        const isValid = await validateActiveModel();
        if (!isValid) {
          throw new Error("Model validation failed. Ensure the model is available and credentials are valid.");
        }

        saveBtn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('spinner', 'w-3.5 h-3.5')} Applying...</span>`;

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
        showToast(`AI Model updated: ${getModelDisplayName(updated.current_provider, updated.current_model)}`, "success");
      } catch (err) {
        showToast(`Configuration error: ${err.message}`, "error");
      } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Save & Apply Model</span>`;
      }
    });
  }
}

// Two Curated Professional Themes: "dark" and "light"
function applyTheme(themeName) {
  const allowed = ["dark", "light"];
  const target = allowed.includes(themeName) ? themeName : "dark";
  document.documentElement.setAttribute("data-theme", target);

  if (target === "light") {
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

  if (window.TopologyModule && typeof window.TopologyModule.updateTheme === "function") {
    window.TopologyModule.updateTheme();
  }
}

function setupScrollEffects() {
  const headerWrapper = document.getElementById("landingHeaderWrapper");
  if (!headerWrapper) return;

  function onScroll() {
    if (window.scrollY > 25) {
      headerWrapper.classList.add("scrolled");
    } else {
      headerWrapper.classList.remove("scrolled");
    }
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
}

function setupThemeToggle() {
  const saved = localStorage.getItem("regradar-theme") || "dark";
  // Migrate any previous theme names
  const effectiveTheme = (saved === "polar" || saved === "alabaster" || saved === "light") ? "light" : "dark";
  applyTheme(effectiveTheme);

  document.querySelectorAll(".theme-pill-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const t = btn.getAttribute("data-theme-val");
      applyTheme(t);
    });
  });
}

// Interactive Landing Page Demonstration Controller
const DEMO_STEPS = [
  {
    step: 1,
    title: "1. Policy and Linter Scan",
    badge: "STATIC ANALYSIS",
    badgeClass: "badge-intermediate",
    description: "Checkov parses the Terraform AST and flags resources that violate compliance policies.",
    codeTitle: "Flagged Resource in main.tf",
    codeContent: `resource "aws_s3_bucket" "patient_records" {
  bucket        = "acme-health-patient-vault"
  force_destroy = false
  # CKV_AWS_19: S3 Bucket SSE (Server Side Encryption) is not configured
  # CKV_AWS_144: S3 Bucket Cross-Region Replication not enabled
}`,
    statusLabel: "Policy Finding",
    statusDetail: "Check ID: CKV_AWS_19 (S3 bucket server-side encryption disabled)",
    statusClass: "text-amber-400"
  },
  {
    step: 2,
    title: "2. Dependency Centrality Gate",
    badge: "GRAPH ANALYSIS",
    badgeClass: "badge-critical",
    description: "NetworkX builds a dependency graph of all resources to measure betweenness centrality and prevent changes to foundational infrastructure.",
    codeTitle: "Calculated Centrality Metrics",
    codeContent: `[GATE 1 ANALYSIS]:
  - aws_vpc.production_network:
      Betweenness Centrality: 0.6842 (CRITICAL_ROOT)
      Cascading Descendants:  9 child resources
      Decision: ROUTE TO HUMAN OPERATOR (High blast radius)

  - aws_s3_bucket.patient_records:
      Betweenness Centrality: 0.0000 (LEAF_SAFE)
      Cascading Descendants:  0 child resources
      Decision: APPROVED FOR AUTOMATED PATCH SYNTHESIS`,
    statusLabel: "Gate 1 Decision",
    statusDetail: "Target bucket is a leaf node (centrality 0.00). Safe for automated patch synthesis.",
    statusClass: "text-emerald-400"
  },
  {
    step: 3,
    title: "3. Collaborative Patch Synthesis",
    badge: "AGENT SYNTHESIS",
    badgeClass: "badge-leaf",
    description: "Agents draft an additive Terraform resource block to satisfy the policy without modifying existing bucket arguments in-place.",
    codeTitle: "Drafted Additive Configuration",
    codeContent: `// Additive attachment: creates a standalone resource without modifying the bucket in place
resource "aws_s3_bucket_server_side_encryption_configuration" "patient_records_crypto" {
  bucket = aws_s3_bucket.patient_records.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.patient_data_key.arn
    }
  }
}`,
    statusLabel: "Strategy Selected",
    statusDetail: "Standalone encryption block attached to the existing bucket ID",
    statusClass: "text-cyan-400"
  },
  {
    step: 4,
    title: "4. Ephemeral Plan Simulation",
    badge: "SANDBOX VERIFICATION",
    badgeClass: "badge-leaf",
    description: "The patch is tested in an isolated workspace with a dry-run tofu plan. The engine verifies that no existing resource is destroyed or replaced.",
    codeTitle: "OpenTofu Plan Evaluation",
    codeContent: `OpenTofu Plan Summary:
  + aws_s3_bucket_server_side_encryption_configuration.patient_records_crypto
      action: create
      replaces_existing: false

Validation Checks:
  - Additive resources:  1
  - Resource updates:    0
  - Resource deletions:  0
  - Resource replaces:   0
  - Invariant check:     PASSED (No destructive actions)`,
    statusLabel: "Gate 2 Decision",
    statusDetail: "Clean plan. Zero deletions or replacements detected.",
    statusClass: "text-emerald-400"
  },
  {
    step: 5,
    title: "5. Pull Request Generation",
    badge: "VERSION CONTROL",
    badgeClass: "badge-leaf",
    description: "The verified patch is prepared as a pull request including the diff, compliance checks, and plan output for final review.",
    codeTitle: "Prepared Pull Request",
    codeContent: `PR #142: Enable default SSE encryption for patient vault
Branch: regradar/fix-s3-encryption -> main
Policy: HIPAA §164.312 / NIST SP 800-53 SC-28
Plan verification: 1 to add, 0 to change, 0 to destroy`,
    statusLabel: "Ready for Merge",
    statusDetail: "Verified patch ready for operator sign-off and deployment.",
    statusClass: "text-emerald-400"
  }
];

let activeDemoStep = 1;

function setupInteractiveDemo() {
  renderDemoStep(1);
}

function renderDemoStep(stepNumber) {
  activeDemoStep = stepNumber;
  const data = DEMO_STEPS.find(s => s.step === stepNumber) || DEMO_STEPS[0];

  const titleEl = document.getElementById("demoStepTitle");
  const badgeEl = document.getElementById("demoStepBadge");
  const descEl = document.getElementById("demoStepDesc");
  const codeTitleEl = document.getElementById("demoStepCodeTitle");
  const codeEl = document.getElementById("demoStepCode");
  const statusLabelEl = document.getElementById("demoStatusLabel");
  const statusDetailEl = document.getElementById("demoStatusDetail");

  if (titleEl) titleEl.textContent = data.title;
  if (badgeEl) {
    badgeEl.textContent = data.badge;
    badgeEl.className = `px-2 py-0.5 rounded text-[10px] font-bold ${data.badgeClass}`;
  }
  if (descEl) descEl.textContent = data.description;
  if (codeTitleEl) codeTitleEl.textContent = data.codeTitle;
  if (codeEl) codeEl.textContent = data.codeContent;
  if (statusLabelEl) {
    statusLabelEl.textContent = data.statusLabel;
    statusLabelEl.className = `text-xs font-bold ${data.statusClass}`;
  }
  if (statusDetailEl) statusDetailEl.textContent = data.statusDetail;

  // Update step buttons
  document.querySelectorAll("[data-demo-step]").forEach(btn => {
    const s = parseInt(btn.getAttribute("data-demo-step"), 10);
    if (s === stepNumber) {
      btn.classList.add("border-amber-500", "bg-amber-500/10", "text-amber-500", "active-step");
      btn.classList.remove("border-slate-800", "text-slate-400", "text-slate-500");
    } else {
      btn.classList.remove("border-amber-500", "bg-amber-500/10", "text-amber-300", "text-amber-500", "active-step");
      btn.classList.add("border-slate-800", "text-slate-400");
    }
  });
}
window.renderDemoStep = renderDemoStep;

let RAW_MERMAID_SRC = null;

function toggleArchView(view) {
  const bp = document.getElementById("archBlueprintView");
  const mm = document.getElementById("mermaidContainer");
  const btnBp = document.getElementById("btnArchBlueprint");
  const btnMm = document.getElementById("btnArchMermaid");
  if (!bp || !mm) return;

  if (view === "mermaid") {
    bp.classList.add("hidden");
    mm.classList.remove("hidden");
    if (btnBp) {
      btnBp.className = "px-3 py-1.5 rounded-lg text-slate-400 hover:text-slate-200 transition cursor-pointer";
    }
    if (btnMm) {
      btnMm.className = "px-3 py-1.5 rounded-lg bg-amber-600 text-white font-semibold transition cursor-pointer";
    }
    const el = document.getElementById("mermaidDiagramEl");
    if (el) {
      if (!RAW_MERMAID_SRC) {
        RAW_MERMAID_SRC = el.textContent.trim();
      }
      if (window.mermaid) {
        try {
          const isLight = document.documentElement.getAttribute("data-theme") === "light";
          el.removeAttribute("data-processed");
          el.innerHTML = RAW_MERMAID_SRC;
          mermaid.initialize({
            startOnLoad: false,
            theme: isLight ? "neutral" : "dark",
            securityLevel: "loose"
          });
          mermaid.run({ nodes: [el] });
        } catch (err) {
          console.warn("Mermaid render error:", err);
        }
      }
    }
  } else {
    mm.classList.add("hidden");
    bp.classList.remove("hidden");
    if (btnMm) {
      btnMm.className = "px-3 py-1.5 rounded-lg text-slate-400 hover:text-slate-200 transition cursor-pointer";
    }
    if (btnBp) {
      btnBp.className = "px-3 py-1.5 rounded-lg bg-amber-600 text-white font-semibold transition cursor-pointer";
    }
  }
}
window.toggleArchView = toggleArchView;
