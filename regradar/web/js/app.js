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
  setupLandingMicroInteractions();
  setupMetricExplanations();
  await loadWorkspaces();
  await loadSettings();

  // Routing initialization
  if (document.getElementById("dashboardView") && !document.getElementById("landingView")) {
    switchTab(AppState.activeTab || "topology");
  } else if (window.location.hash === "#dashboard") {
    showView("dashboard");
  } else {
    showView("landing", false);
    if (window.location.hash && window.location.hash.startsWith("#") && window.location.hash.length > 1) {
      setTimeout(() => {
        const target = document.querySelector(window.location.hash);
        if (target) {
          target.scrollIntoView({ behavior: "smooth" });
        }
      }, 150);
    }
  }

  window.addEventListener("hashchange", () => {
    const hash = window.location.hash;
    if (hash === "#dashboard") {
      showView("dashboard");
    } else if (hash && hash.startsWith("#") && hash.length > 1) {
      const landing = document.getElementById("landingView");
      const dashboard = document.getElementById("dashboardView");
      if (dashboard && !dashboard.classList.contains("hidden")) {
        dashboard.classList.add("hidden");
        if (landing) landing.classList.remove("hidden");
      }
      const target = document.querySelector(hash);
      if (target) {
        target.scrollIntoView({ behavior: "smooth" });
      }
    } else {
      showView("landing", false);
    }
  });

  // Attach smooth scrolling to all in-page anchor hyperlinks (including navbar)
  document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener("click", function(e) {
      const targetId = this.getAttribute("href");
      if (targetId === "#dashboard") return;
      if (targetId && targetId.length > 1) {
        const target = document.querySelector(targetId);
        if (target) {
          e.preventDefault();
          const landing = document.getElementById("landingView");
          const dashboard = document.getElementById("dashboardView");
          if (dashboard && !dashboard.classList.contains("hidden")) {
            dashboard.classList.add("hidden");
            if (landing) landing.classList.remove("hidden");
          }
          history.pushState(null, null, targetId);
          target.scrollIntoView({ behavior: "smooth" });
        }
      }
    });
  });
});

// View Navigation: Landing Page vs Dashboard
function showView(viewName, shouldScroll = true) {
  const landing = document.getElementById("landingView");
  const dashboard = document.getElementById("dashboardView");
  const isFile = window.location.protocol === "file:";

  if (viewName === "dashboard") {
    if (!dashboard) {
      window.location.href = isFile ? "dashboard.html" : "/dashboard";
      return;
    }
    if (landing) landing.classList.add("hidden");
    dashboard.classList.remove("hidden");
    switchTab(AppState.activeTab || "topology");
  } else {
    if (!landing) {
      window.location.href = isFile ? "index.html" : "/";
      return;
    }
    if (dashboard) dashboard.classList.add("hidden");
    landing.classList.remove("hidden");
    if (shouldScroll) {
      window.location.hash = "";
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
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
  if (AppState.isConnectingRepo) {
    showToast("Repository connection in progress. Please wait until loading completes.", "info");
    return;
  }
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
    case "queue":
      if (window.GitHubModule) window.GitHubModule.loadPRs();
      break;
  }
}
window.onTabActivated = onTabActivated;

// Global Blurred Loader Utility
function showBlurredLoader(containerEl, title = "Loading...", subtitle = "Please wait while data is processed...") {
  if (!containerEl) return null;
  let loader = containerEl.querySelector(".custom-blurred-loader");
  if (!loader) {
    loader = document.createElement("div");
    loader.className = "custom-blurred-loader blurred-loader-overlay absolute inset-0 flex flex-col items-center justify-center z-30";
    loader.innerHTML = `
      <div class="relative flex flex-col items-center p-6 rounded-2xl bg-slate-900/85 border border-slate-800/90 shadow-2xl backdrop-blur-xl max-w-sm text-center mx-4">
        <div class="relative w-12 h-12 mb-3 flex items-center justify-center">
          <div class="absolute inset-0 rounded-full bg-amber-500/20 animate-ping"></div>
          <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500/20 to-cyan-500/20 border border-amber-500/40 flex items-center justify-center shadow-lg shadow-amber-500/10">
            <svg class="w-5 h-5 text-amber-400 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
            </svg>
          </div>
        </div>
        <div class="loader-title text-sm font-bold text-white mb-1 text-fusion">${title}</div>
        <p class="loader-subtitle text-xs text-slate-400 mb-3 max-w-xs leading-relaxed">${subtitle}</p>
        <div class="w-40 h-1 rounded-full bg-slate-800 overflow-hidden relative">
          <div class="h-full bg-gradient-to-r from-amber-500 to-cyan-500 w-1/2 rounded-full animate-loader-bar"></div>
        </div>
      </div>
    `;
    if (getComputedStyle(containerEl).position === "static") {
      containerEl.style.position = "relative";
    }
    containerEl.appendChild(loader);
  } else {
    const t = loader.querySelector(".loader-title");
    const s = loader.querySelector(".loader-subtitle");
    if (t) t.textContent = title;
    if (s) s.textContent = subtitle;
    loader.style.opacity = "1";
    loader.classList.remove("hidden");
  }
  return loader;
}

function hideBlurredLoader(containerEl, delayMs = 0) {
  if (!containerEl) return;
  const loader = containerEl.querySelector(".custom-blurred-loader");
  if (!loader) return;
  setTimeout(() => {
    loader.style.opacity = "0";
    setTimeout(() => {
      loader.remove();
    }, 350);
  }, delayMs);
}

window.showBlurredLoader = showBlurredLoader;
window.hideBlurredLoader = hideBlurredLoader;

// Organic Workspace Selector with Built-in Realtime Search
let isOrganicDropdownInitialized = false;

function setupOrganicWorkspaceDropdown() {
  const container = document.getElementById("workspaceDropdownContainer");
  const trigger = document.getElementById("workspaceDropdownTrigger");
  const menu = document.getElementById("workspaceDropdownMenu");
  const searchInput = document.getElementById("workspaceSearchInput");
  const clearBtn = document.getElementById("workspaceSearchClear");
  const listEl = document.getElementById("workspaceDropdownList");
  const emptyEl = document.getElementById("workspaceDropdownEmpty");
  const chevron = document.getElementById("workspaceDropdownChevron");

  if (!container || !trigger || !menu || !listEl) return;

  function openMenu() {
    menu.classList.remove("hidden");
    trigger.classList.add("is-open");
    if (chevron) chevron.style.transform = "rotate(180deg)";
    if (searchInput) {
      searchInput.value = "";
      filterList("");
      setTimeout(() => searchInput.focus(), 60);
    }
  }

  function closeMenu() {
    menu.classList.add("hidden");
    trigger.classList.remove("is-open");
    if (chevron) chevron.style.transform = "rotate(0deg)";
  }

  function toggleMenu() {
    if (menu.classList.contains("hidden")) {
      openMenu();
    } else {
      closeMenu();
    }
  }

  function filterList(query) {
    const q = (query || "").trim().toLowerCase();
    if (clearBtn) {
      clearBtn.classList.toggle("hidden", !q);
    }
    const items = listEl.querySelectorAll(".workspace-dropdown-item");
    let matchCount = 0;
    items.forEach(item => {
      const text = item.getAttribute("data-search") || item.textContent.toLowerCase();
      if (!q || text.includes(q)) {
        item.classList.remove("hidden");
        matchCount++;
      } else {
        item.classList.add("hidden");
      }
    });
    if (emptyEl) {
      emptyEl.classList.toggle("hidden", matchCount > 0);
    }
  }

  if (!isOrganicDropdownInitialized) {
    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleMenu();
    });

    document.addEventListener("click", (e) => {
      if (!container.contains(e.target)) {
        closeMenu();
      }
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !menu.classList.contains("hidden")) {
        closeMenu();
        trigger.focus();
      }
    });

    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        filterList(e.target.value);
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        if (searchInput) {
          searchInput.value = "";
          searchInput.focus();
          filterList("");
        }
      });
    }

    isOrganicDropdownInitialized = true;
  }

  // Populate list from AppState.workspaces
  const workspaces = AppState.workspaces || [];
  const activeWsPath = AppState.currentWorkspace;
  const labelEl = document.getElementById("workspaceDropdownLabel");
  const countEl = document.getElementById("workspaceDropdownCount");

  if (!workspaces || workspaces.length === 0) {
    if (labelEl) labelEl.textContent = "No Repositories";
    if (countEl) countEl.textContent = "0 res";
    listEl.innerHTML = `<div class="p-3 text-center text-xs text-slate-500 font-mono">No repositories connected.</div>`;
    return;
  }

  const activeWs = workspaces.find(w => w.path === activeWsPath) || workspaces[0];
  if (labelEl) labelEl.textContent = activeWs.name || activeWs.path;
  if (countEl) countEl.textContent = `${activeWs.resource_count ?? 0} res`;

  listEl.innerHTML = workspaces.map(ws => {
    const isSelected = ws.path === activeWs.path;
    const isGitLab = (ws.name && ws.name.toLowerCase().includes("gitlab")) || (ws.path && ws.path.toLowerCase().includes("gitlab"));
    const badgeText = isGitLab ? "GitLab" : "GitHub";
    const badgeClass = isGitLab
      ? "bg-orange-500/10 text-orange-400 border border-orange-500/30"
      : "bg-slate-700/40 text-slate-300 border border-slate-600/30";

    return `
      <div class="workspace-dropdown-item flex items-center justify-between p-2.5 rounded-xl cursor-pointer text-xs border border-transparent ${isSelected ? 'is-selected' : ''}"
           data-path="${ws.path}"
           data-search="${(ws.name + ' ' + ws.path).toLowerCase()}">
        <div class="flex items-center space-x-2.5 min-w-0">
          <div class="min-w-0">
            <div class="font-mono font-bold text-slate-200 truncate ${isSelected ? 'text-amber-300' : ''}">${ws.name}</div>
            <div class="font-mono text-[10px] text-slate-400 truncate">${ws.path}</div>
          </div>
        </div>
        <div class="flex items-center space-x-2 shrink-0 ml-2">
          <span class="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded uppercase ${badgeClass}">${badgeText}</span>
          <span class="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">${ws.resource_count ?? 0} res</span>
          ${isSelected ? `<span class="text-amber-400 text-xs font-bold">&#10003;</span>` : ''}
        </div>
      </div>
    `;
  }).join("");

  listEl.querySelectorAll(".workspace-dropdown-item").forEach(item => {
    item.addEventListener("click", () => {
      const selectedPath = item.getAttribute("data-path");
      if (!selectedPath) return;

      AppState.currentWorkspace = selectedPath;
      const selector = document.getElementById("workspaceSelector");
      if (selector) selector.value = selectedPath;

      const wsObj = workspaces.find(w => w.path === selectedPath);
      if (wsObj) {
        if (labelEl) labelEl.textContent = wsObj.name || wsObj.path;
        if (countEl) countEl.textContent = `${wsObj.resource_count ?? 0} res`;
        showToast(`Switched target: ${wsObj.name}`, "info");
      }

      closeMenu();
      setupOrganicWorkspaceDropdown();
      onTabActivated(AppState.activeTab);
    });
  });
}
window.setupOrganicWorkspaceDropdown = setupOrganicWorkspaceDropdown;

// Load Workspaces List
async function loadWorkspaces() {
  try {
    const workspaces = await apiCall("/api/workspaces");
    AppState.workspaces = workspaces || [];

    const selector = document.getElementById("workspaceSelector");
    if (selector) {
      selector.innerHTML = "";

      if (!workspaces || workspaces.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "No Remote Repositories Connected";
        selector.appendChild(opt);
        AppState.currentWorkspace = null;
      } else {
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
          setupOrganicWorkspaceDropdown();
          onTabActivated(AppState.activeTab);
        };
      }
    }

    // Initialize custom organic dropdown
    setupOrganicWorkspaceDropdown();
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

function isModelConfigured() {
  const s = AppState.settings;
  if (!s || !s.current_provider) return false;
  const p = s.current_provider.toLowerCase();
  if (p === "gemini") return !!s.has_gemini_key;
  if (p === "openai") return !!s.has_openai_key;
  if (p === "anthropic") return !!s.has_anthropic_key;
  if (p === "deepseek") return !!s.has_deepseek_key;
  if (p === "ollama") return !!(s.ollama_url);
  return false;
}
window.isModelConfigured = isModelConfigured;

const DEFAULT_FRONTIER_MODELS = {
  gemini: [
    {
      id: "gemini-4-argon",
      name: "Gemini 4 Argon",
      tagline: "Flagship Fast Frontier Reasoning for Autonomous Agentic Workflows & IaC Synthesis",
      context: "1M tokens",
      tier: "Frontier Reasoning Flagship",
      docs_url: "https://ai.google.dev/gemini-api/docs/models/gemini",
      capabilities: "1M Token Context, Configurable Thinking Levels (LOW/MEDIUM/HIGH), High Logic Accuracy & Synthesis",
    },
    {
      id: "gemini-4-carbon",
      name: "Gemini 4 Carbon",
      tagline: "Frontier Reasoning & Complex Software Engineering Flagship",
      context: "1M tokens",
      tier: "Heavy-Duty Reasoning",
      docs_url: "https://ai.google.dev/gemini-api/docs/models/gemini",
      capabilities: "Deep Reasoning Chains, 1M Context, Cyber Defense & Complex Multi-Module Refactoring",
    },
    {
      id: "gemini-4-hydrogen",
      name: "Gemini 4 Hydrogen",
      tagline: "High-Velocity Frontier Engine for Rapid Agent Loops & Code Generation",
      context: "1M tokens",
      tier: "High-Velocity Frontier",
      docs_url: "https://ai.google.dev/gemini-api/docs/models/gemini",
      capabilities: "Sub-Second Latency, 1M Context, Rapid Remediation & Invariant Verification",
    },
    {
      id: "gemini-3.8-flash",
      name: "Gemini 3.8 Flash",
      tagline: "High-Performance Production Workhorse for Agent Swarms",
      context: "1M tokens (64k Output)",
      tier: "Production Workhorse",
      docs_url: "https://ai.google.dev/gemini-api/docs/models/gemini",
      capabilities: "Fast Inference, 64k Output Decodes, Configurable Thinking Features",
    },
    {
      id: "gemini-3.5-flash-lite",
      name: "Gemini 3.5 Flash-Lite",
      tagline: "Ultra-Low Latency & High-Throughput CI/CD Invariant Gating",
      context: "1M tokens",
      tier: "Economy High-Throughput",
      docs_url: "https://ai.google.dev/gemini-api/docs/models/gemini",
      capabilities: "Fastest Sub-Second Gating, Minimal Token Footprint",
    },
    {
      id: "gemini-2.5-pro",
      name: "Gemini 2.5 Pro",
      tagline: "Deep Reasoning & 2M Context Invariant Verification",
      context: "2M tokens",
      tier: "Deep Reasoning",
      docs_url: "https://ai.google.dev/gemini-api/docs/models/gemini",
      capabilities: "Extended Thinking Levels, 2M Token Context, Strict JSON Schema",
    },
    {
      id: "gemini-2.5-flash",
      name: "Gemini 2.5 Flash",
      tagline: "Balanced Multimodal & Fast Reasoning Engine",
      context: "1M tokens",
      tier: "Fast Production",
      docs_url: "https://ai.google.dev/gemini-api/docs/models/gemini",
      capabilities: "Adaptive Reasoning, Fast Token Generation",
    },
  ],
  openai: [
    {
      id: "gpt-6-astra",
      name: "GPT-6 Astra",
      tagline: "Frontier Flagship for Agentic Workflows, Computer Use & Deep Cybersecurity",
      context: "1M tokens",
      tier: "Frontier Flagship",
      docs_url: "https://platform.openai.com/docs/models",
      capabilities: "1M Context Window, Multimodal Reasoning, Autonomous Coding & Cyber Research",
    },
    {
      id: "gpt-6.1-sol",
      name: "GPT-6.1 Sol",
      tagline: "Advanced Logic & STEM Coding Reasoning with Configurable Effort",
      context: "1M tokens",
      tier: "Coding Reasoning Flagship",
      docs_url: "https://platform.openai.com/docs/models",
      capabilities: "Configurable reasoning_effort, Near-Astra Technical Benchmarks, Cost-Effective",
    },
    {
      id: "gpt-6.1-terra",
      name: "GPT-6.1 Terra",
      tagline: "Fast High-Throughput Reasoning, Visual Proofs & IaC Analysis",
      context: "1M tokens",
      tier: "High-Velocity Reasoning",
      docs_url: "https://platform.openai.com/docs/models",
      capabilities: "Fast Decodes, 1M Context Window, Precise Syntactic Patch Generation",
    },
    {
      id: "gpt-6-sol",
      name: "GPT-6 Sol",
      tagline: "Balanced Intelligence & Multi-Step Agent Coordination Workhorse",
      context: "1M tokens",
      tier: "Production Workhorse",
      docs_url: "https://platform.openai.com/docs/models",
      capabilities: "High Factuality, Low Latency, Agentic Function Calling",
    },
    {
      id: "gpt-6-luna",
      name: "GPT-6 Luna",
      tagline: "High-Speed, Cost-Sensitive Invariant Checking & Gating",
      context: "1M tokens",
      tier: "Economy Fast",
      docs_url: "https://platform.openai.com/docs/models",
      capabilities: "High-Throughput Streaming, Low Cost Token Execution",
    },
    {
      id: "gpt-oss-120b",
      name: "GPT-OSS (120B)",
      tagline: "Open-Weights Deep Reasoning Architecture (Apache 2.0)",
      context: "128k tokens",
      tier: "Open Flagship",
      docs_url: "https://platform.openai.com/docs/models",
      capabilities: "Deep Chain-of-Thought, Zero Data Egress, Self-Hostable",
    },
    {
      id: "gpt-oss-20b",
      name: "GPT-OSS (20B)",
      tagline: "Compact Open-Weights Reasoning Engine for Edge & Local Runners",
      context: "128k tokens",
      tier: "Open Lightweight",
      docs_url: "https://platform.openai.com/docs/models",
      capabilities: "MXFP4 Quantized Execution, Low Resource Overhead",
    },
    {
      id: "o3-mini",
      name: "o3-mini",
      tagline: "STEM & Coding Reasoning with Tunable Effort",
      context: "200k tokens",
      tier: "Coding Reasoning",
      docs_url: "https://platform.openai.com/docs/models/o3-mini",
      capabilities: "Tunable reasoning_effort (low/medium/high), Invariant Proofs",
    },
    {
      id: "gpt-4o",
      name: "GPT-4o",
      tagline: "Omnimodal Workhorse for Standard Patch Generation",
      context: "128k tokens",
      tier: "Legacy Production",
      docs_url: "https://platform.openai.com/docs/models/gpt-4o",
      capabilities: "Function Calling, Structured JSON Output",
    },
  ],
  anthropic: [
    {
      id: "claude-fable-5-2",
      name: "Claude Fable 5.2",
      tagline: "Mythos-Class Architecture for Demanding Reasoning & Long-Horizon Agents",
      context: "500k tokens",
      tier: "Frontier Reasoning Flagship",
      docs_url: "https://docs.anthropic.com/en/docs/about-claude/models",
      capabilities: "Adaptive Thinking Always Active, Formal Proofs, Long-Horizon Multi-File Agents",
    },
    {
      id: "claude-opus-5-5",
      name: "Claude Opus 5.5",
      tagline: "Enterprise Agentic Coding & Deep Invariant Verification Flagship",
      context: "500k tokens",
      tier: "Deep Agentic Flagship",
      docs_url: "https://docs.anthropic.com/en/docs/about-claude/models",
      capabilities: "Deep Context Retention, Dense Chart/AST Analysis, Computer & Tool Use",
    },
    {
      id: "claude-sonnet-5-5",
      name: "Claude Sonnet 5.5",
      tagline: "Balanced Coding Workhorse with Dynamic Thinking Effort Control",
      context: "200k tokens",
      tier: "Production Workhorse",
      docs_url: "https://docs.anthropic.com/en/docs/about-claude/models",
      capabilities: "Fine-Grained Thinking Effort, Low Mutation Error Rates, Fast AST Synthesis",
    },
    {
      id: "claude-haiku-5-5",
      name: "Claude Haiku 5.5",
      tagline: "Sub-Second Latency & High-Throughput Request Routing",
      context: "200k tokens",
      tier: "Ultra-Fast Economy",
      docs_url: "https://docs.anthropic.com/en/docs/about-claude/models",
      capabilities: "Maximum Speed, High-Frequency Pre-Flight Validation",
    },
    {
      id: "claude-3-7-sonnet-20250219",
      name: "Claude 3.7 Sonnet",
      tagline: "Hybrid Reasoning Engine with Dynamic Extended Thinking",
      context: "200k tokens",
      tier: "Hybrid Reasoning",
      docs_url: "https://docs.anthropic.com/en/docs/about-claude/models",
      capabilities: "Extended Thinking, 128k Max Output Decodes",
    },
  ],
  deepseek: [
    {
      id: "deepseek-v4-pro",
      name: "DeepSeek-V4 Pro",
      tagline: "Heavy Reasoning & Advanced Agentic Multi-Tool Orchestration",
      context: "1M tokens",
      tier: "Frontier Reasoning Flagship",
      docs_url: "https://api-docs.deepseek.com",
      capabilities: "1M Context Window, Deep Invariant Proofs, Native Context Caching",
    },
    {
      id: "deepseek-flash",
      name: "DeepSeek-V4.1 Flash",
      tagline: "Native Multimodal High-Velocity Agentic Remediation Engine",
      context: "1M tokens",
      tier: "High-Velocity Agentic",
      docs_url: "https://api-docs.deepseek.com",
      capabilities: "Multimodal Inputs, High-Speed Token Generation, Sub-Second Gating",
    },
    {
      id: "deepseek-reasoner",
      name: "DeepSeek-R1 Reasoner",
      tagline: "Pure Reinforcement Learning Mathematical & Invariant Reasoner",
      context: "128k tokens",
      tier: "RL Reasoning",
      docs_url: "https://platform.deepseek.com/docs",
      capabilities: "Native Chain-of-Thought Reflection, Formal Invariant Proofs",
    },
    {
      id: "deepseek-chat",
      name: "DeepSeek-V3",
      tagline: "671B MoE Architecture High-Speed Agentic Remediation",
      context: "128k tokens",
      tier: "MoE Workhorse",
      docs_url: "https://platform.deepseek.com/docs",
      capabilities: "MoE Sparse Reasoning, Low Cost API",
    },
  ],
  ollama: [
    {
      id: "qwen3-coder",
      name: "Qwen 3 Coder",
      tagline: "Alibaba Frontier MoE Coding Model with 256K Context Window",
      context: "256k tokens",
      tier: "Local Coding Flagship",
      docs_url: "https://ollama.com/library/qwen3-coder",
      capabilities: "Native MoE Coding, Syntactic HCL AST Parsing, 256K Context",
    },
    {
      id: "qwen3.8",
      name: "Qwen 3.8",
      tagline: "Advanced Multimodal & Deep Technical Logic Engine",
      context: "256k tokens",
      tier: "Local Multimodal Flagship",
      docs_url: "https://ollama.com/library/qwen3.8",
      capabilities: "Vision & Code Reasoning, Massive Context Retention",
    },
    {
      id: "gpt-oss:120b",
      name: "GPT-OSS (120B Local)",
      tagline: "OpenAI Flagship Open-Weights Model with Native MXFP4 Quantization",
      context: "128k tokens",
      tier: "Local Deep Reasoning",
      docs_url: "https://ollama.com/library/gpt-oss",
      capabilities: "Complex Chain-of-Thought, Air-Gapped High Security",
    },
    {
      id: "gpt-oss:20b",
      name: "GPT-OSS (20B Local)",
      tagline: "Fast Open-Weights Reasoning for Local Desktop Workstations",
      context: "128k tokens",
      tier: "Local Fast Reasoning",
      docs_url: "https://ollama.com/library/gpt-oss",
      capabilities: "Lightweight Memory Footprint, Fast Invariant Simulation",
    },
    {
      id: "nemotron-3.5-lightning",
      name: "NVIDIA Nemotron 3.5 Lightning",
      tagline: "High-Efficiency MoE Architecture Engineered for Low-Latency Agents",
      context: "128k tokens",
      tier: "Local High-Velocity",
      docs_url: "https://ollama.com/library/nemotron",
      capabilities: "Ultra-Low Latency, Constant Agent Loop Performance",
    },
    {
      id: "gemma4",
      name: "Google Gemma 4",
      tagline: "Google Latest Compact Open Weights for Fast Policy Checks",
      context: "64k tokens",
      tier: "Local Compact",
      docs_url: "https://ollama.com/library/gemma4",
      capabilities: "Minimal Parameter Footprint, Fast Local Token Generation",
    },
    {
      id: "deepseek-v4.1-flash",
      name: "DeepSeek V4.1 Flash (Local/Cloud)",
      tagline: "Fast Multimodal Agent Engine with 1M Token Context",
      context: "1M tokens",
      tier: "Local/Cloud Hybrid",
      docs_url: "https://ollama.com/library/deepseek-v4.1-flash",
      capabilities: "Multimodal Inputs, High Token Velocity",
    },
    {
      id: "llama3.3",
      name: "Llama 3.3 (70B)",
      tagline: "Meta Open-Weights Enterprise Local Flagship",
      context: "128k tokens",
      tier: "Local Workhorse",
      docs_url: "https://ollama.com/library/llama3.3",
      capabilities: "Air-Gapped Offline Execution, Zero Egress Policy",
    },
  ],
};
window.DEFAULT_FRONTIER_MODELS = DEFAULT_FRONTIER_MODELS;

function getAvailableModelsForProvider(provider) {
  if (AppState.settings && AppState.settings.available_models && Array.isArray(AppState.settings.available_models[provider]) && AppState.settings.available_models[provider].length > 0) {
    return AppState.settings.available_models[provider];
  }
  return DEFAULT_FRONTIER_MODELS[provider] || [];
}
window.getAvailableModelsForProvider = getAvailableModelsForProvider;

function getModelDisplayName(provider, modelId) {
  const list = getAvailableModelsForProvider(provider);
  const found = list.find(m => m.id === modelId);
  return found ? found.name : (modelId || provider);
}
window.getModelDisplayName = getModelDisplayName;

function renderSelectedModelDetails(provider, modelId) {
  const p = provider || (document.getElementById("providerSelect")?.value) || "gemini";
  const mId = modelId || (document.getElementById("modelSelect")?.value);
  const models = getAvailableModelsForProvider(p);
  const m = models.find(x => x.id === mId) || models[0];
  if (!m) return;

  const card = document.getElementById("modelDetailsCard");
  const nameEl = document.getElementById("modelCardName");
  const tierEl = document.getElementById("modelCardTier");
  const ctxEl = document.getElementById("modelCardContext");
  const tagEl = document.getElementById("modelCardTagline");
  const capEl = document.getElementById("modelCardCapabilities");
  const docsLink = document.getElementById("modelCardDocsLink");

  if (card) card.classList.remove("hidden");
  if (nameEl) nameEl.textContent = m.name;
  if (tierEl) tierEl.textContent = m.tier || "Frontier Model";
  if (ctxEl) ctxEl.textContent = m.context ? `${m.context} Context` : "Standard Context";
  if (tagEl) tagEl.textContent = m.tagline || "";
  if (capEl) capEl.textContent = m.capabilities || "Full Tool & Invariant Verification";
  if (docsLink) {
    docsLink.href = m.docs_url || "https://ai.google.dev";
  }
}
window.renderSelectedModelDetails = renderSelectedModelDetails;

function updateAiGatedButtons(configured) {
  const swarmBtn = document.getElementById("runSwarmBtn");
  if (swarmBtn) {
    if (!configured) {
      swarmBtn.classList.add("opacity-50");
      swarmBtn.setAttribute("data-model-disabled", "true");
      swarmBtn.title = "No AI model configured. Click Model Settings in header to configure your API key.";
    } else {
      swarmBtn.classList.remove("opacity-50");
      swarmBtn.removeAttribute("data-model-disabled");
      swarmBtn.title = "Launch Closed-Loop Multi-Agent Swarm";
    }
  }

  const bmBtn = document.getElementById("runBenchmarkBtn");
  if (bmBtn) {
    if (!configured) {
      bmBtn.classList.add("opacity-50");
      bmBtn.setAttribute("data-model-disabled", "true");
      bmBtn.title = "No AI model configured. Click Model Settings in header to configure your API key.";
    } else {
      bmBtn.classList.remove("opacity-50");
      bmBtn.removeAttribute("data-model-disabled");
      bmBtn.title = "Run Frontier LLM Comparative Ablation";
    }
  }
}

function updateProviderBadge(provider, model) {
  const badge = document.getElementById("providerBadge");
  if (!badge) return;

  const configured = isModelConfigured();
  const currentProvider = provider || (AppState.settings && AppState.settings.current_provider) || "gemini";
  const currentModel = model || (AppState.settings && AppState.settings.current_model) || "gemini-4-argon";
  const displayModel = getModelDisplayName(currentProvider, currentModel) || "Gemini 4 Argon";

  if (configured) {
    badge.innerHTML = `<span class="inline-flex items-center gap-1.5"><span class="text-xs font-semibold text-slate-200">${displayModel}</span></span>`;
  } else {
    badge.innerHTML = `<span class="inline-flex items-center gap-1.5 text-amber-400 font-semibold text-xs" title="Click to configure API credentials"><span>${displayModel} (Key Required)</span></span>`;
  }

  // Update Swarm Tab badges if present
  const swarmBadge = document.getElementById("swarmActiveModelBadge");
  if (swarmBadge) {
    swarmBadge.textContent = configured ? displayModel : `${displayModel} (Unconfigured)`;
  }

  // Update Review Tab badge if present
  const reviewTag = document.getElementById("reviewActiveModelTag");
  if (reviewTag) {
    reviewTag.textContent = configured ? displayModel : `${displayModel} (Unconfigured)`;
  }

  updateAiGatedButtons(configured);
}

function populateModelOptions(provider, selectedModel) {
  const modelSelect = document.getElementById("modelSelect");
  if (!modelSelect) return;

  modelSelect.innerHTML = "";
  const models = getAvailableModelsForProvider(provider);

  models.forEach(m => {
    const opt = document.createElement("option");
    opt.value = m.id;
    const tierPart = m.tier ? ` — ${m.tier}` : "";
    const ctxPart = m.context ? ` (${m.context})` : "";
    opt.textContent = `${m.name}${tierPart}${ctxPart}`;
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

  renderSelectedModelDetails(provider, modelSelect.value);
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

  if (modelSelect) {
    modelSelect.addEventListener("change", () => {
      const p = providerSelect ? providerSelect.value : "gemini";
      renderSelectedModelDetails(p, modelSelect.value);
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
        saveBtn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Save & Apply Engine</span>`;
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

  const mm = document.getElementById("mermaidContainer");
  if (mm && !mm.classList.contains("hidden") && typeof toggleArchView === "function") {
    toggleArchView("mermaid");
  }

  if (typeof renderDemoStep === "function") {
    renderDemoStep(activeDemoStep);
  }
}

// =========================================================================
// SMOOTH COLLAPSING NAVBAR & ACTIVE SECTION SPY
// =========================================================================
function setupScrollEffects() {
  const headerWrapper = document.getElementById("landingHeaderWrapper");
  if (!headerWrapper) return;

  function updateNavbar() {
    const scrollY = window.scrollY || window.pageYOffset || 0;
    const isScrolled = scrollY > 20;

    if (isScrolled) {
      headerWrapper.classList.add("scrolled", "is-compact");
    } else {
      headerWrapper.classList.remove("scrolled", "is-compact");
    }

    const docHeight = Math.max(
      document.documentElement.scrollHeight - window.innerHeight,
      1
    );
    const scrollRatio = Math.min(Math.max(scrollY / docHeight, 0), 1);
    const headerProgress = Math.min(Math.max(scrollY / 180, 0), 1);
    headerWrapper.style.setProperty("--scroll-ratio", scrollRatio.toFixed(4));
    headerWrapper.style.setProperty("--header-progress", headerProgress.toFixed(4));
  }

  window.addEventListener("scroll", updateNavbar, { passive: true });
  window.addEventListener("resize", updateNavbar, { passive: true });
  updateNavbar();

  // Active Section Spy for Navbar Links
  const navLinks = document.querySelectorAll(".landing-nav-link[data-nav-target]");
  const trackedSections = Array.from(navLinks)
    .map(link => document.getElementById(link.getAttribute("data-nav-target")))
    .filter(Boolean);

  if (trackedSections.length > 0 && "IntersectionObserver" in window) {
    const sectionObserver = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const id = entry.target.id;
            navLinks.forEach(link => {
              link.classList.toggle("nav-active", link.getAttribute("data-nav-target") === id);
            });
          }
        });
      },
      { rootMargin: "-25% 0px -55% 0px", threshold: 0.05 }
    );
    trackedSections.forEach(sec => sectionObserver.observe(sec));
  }
}

// =========================================================================
// SUBTLE VIEWPORT REVEALS & CURSOR SPECULAR SPOTLIGHT
// =========================================================================
function setupLandingMicroInteractions() {
  // 1. Staggered Viewport Reveal Observer
  const revealEls = document.querySelectorAll("[data-reveal]");
  if ("IntersectionObserver" in window && revealEls.length > 0) {
    const revealObserver = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            revealObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.1, rootMargin: "0px 0px -30px 0px" }
    );
    revealEls.forEach(el => revealObserver.observe(el));
  } else {
    revealEls.forEach(el => el.classList.add("is-visible"));
  }

  // 2. Cursor-Tracking Specular Spotlight across Cards
  const spotlightEls = document.querySelectorAll("[data-spotlight]");
  spotlightEls.forEach(card => {
    let rect = null;
    let pending = false;
    let clientX = 0;
    let clientY = 0;

    card.addEventListener("mouseenter", () => {
      rect = card.getBoundingClientRect();
      card.style.setProperty("--spotlight-opacity", "1");
    });

    card.addEventListener("mousemove", e => {
      clientX = e.clientX;
      clientY = e.clientY;
      if (!pending) {
        pending = true;
        requestAnimationFrame(() => {
          if (!rect) rect = card.getBoundingClientRect();
          const x = clientX - rect.left;
          const y = clientY - rect.top;
          card.style.setProperty("--mouse-x", `${x.toFixed(1)}px`);
          card.style.setProperty("--mouse-y", `${y.toFixed(1)}px`);
          pending = false;
        });
      }
    }, { passive: true });

    card.addEventListener("mouseleave", () => {
      card.style.setProperty("--spotlight-opacity", "0");
      rect = null;
    });
  });
}

// =========================================================================
// INTERACTIVE BENCHMARK TABLE EXPLANATIONS & COMPARISON DETAILS
// =========================================================================
const BENCHMARK_ROW_EXPLANATIONS = [
  {
    metric: "Dependency check",
    ungated: "Treats leaf storage rules the same as root network configurations without checking dependencies.",
    regradar: "Calculates dependency trees in the code and flags high-risk core resources for human review."
  },
  {
    metric: "Dry-run plan test",
    ungated: "Outputs unverified code directly without testing execution plans in a real environment.",
    regradar: "Runs proposed patches in an isolated sandbox and checks the plan diff before saving."
  },
  {
    metric: "State protection",
    ungated: "Misses settings that trigger resource recreations, risking accidental infrastructure loss.",
    regradar: "Inspects plan actions and rejects any change that would delete or recreate existing resources."
  },
  {
    metric: "Zero deletions",
    ungated: "Tries to fix settings by replacing whole resources, risking downtime.",
    regradar: "Enforces non-destructive patterns like standalone policy attachments with a zero-deletion rule."
  },
  {
    metric: "Core resource oversight",
    ungated: "Applies changes directly without flagging sensitive root infrastructure for operator review.",
    regradar: "Holds changes to core resources like VPCs and root keys until an operator approves them."
  }
];

function setupMetricExplanations() {
  // Ensure any existing drawer below hero capability cards is removed
  const existingDrawer = document.getElementById("heroMetricExplanationDrawer");
  if (existingDrawer) existingDrawer.remove();

  // Wire Benchmark Table Rows with Expandable Technical Explanations
  const bmRows = document.querySelectorAll("#benchmarks tbody .benchmark-row");
  let openDetailRow = null;
  let openSourceRow = null;

  bmRows.forEach((row, idx) => {
    const info = BENCHMARK_ROW_EXPLANATIONS[idx];
    if (!info) return;

    row.title = "Click to toggle technical governance comparison breakdown";
    row.addEventListener("click", () => {
      if (openDetailRow) {
        openDetailRow.remove();
        openDetailRow = null;
      }
      if (openSourceRow === row) {
        row.classList.remove("bm-row-active");
        openSourceRow = null;
        return;
      }
      bmRows.forEach(r => r.classList.remove("bm-row-active"));
      row.classList.add("bm-row-active");
      openSourceRow = row;

      const detailTr = document.createElement("tr");
      detailTr.className = "bg-slate-950/75 border-b border-slate-800 stage-fade-enter";
      detailTr.innerHTML = `
        <td colspan="4" class="px-5 py-3.5 text-xs">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div class="p-2.5 rounded-lg bg-rose-500/5 border border-rose-500/20">
              <div class="text-[10px] font-mono font-bold uppercase text-rose-400 mb-0.5">Ungated Baseline Risk</div>
              <div class="text-slate-300 leading-relaxed">${info.ungated}</div>
            </div>
            <div class="p-2.5 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
              <div class="text-[10px] font-mono font-bold uppercase text-emerald-400 mb-0.5">RegRadar Mechanism &amp; Guarantee</div>
              <div class="text-slate-300 leading-relaxed">${info.regradar}</div>
            </div>
          </div>
        </td>
      `;
      row.insertAdjacentElement("afterend", detailTr);
      openDetailRow = detailTr;
    });
  });
}

function setupThemeToggle() {
  const saved = localStorage.getItem("regradar-theme") || "dark";
  const effectiveTheme = (saved === "polar" || saved === "alabaster" || saved === "light") ? "light" : "dark";
  applyTheme(effectiveTheme);

  document.querySelectorAll(".theme-pill-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const t = btn.getAttribute("data-theme-val");
      applyTheme(t);
    });
  });
}

// =========================================================================
// 5-STAGE COMPLIANCE LIFECYCLE INTERACTIVE GRAPHICAL CONTROLLER
// =========================================================================
const DEMO_STEPS = [
  {
    step: 1,
    title: "1. Policy Scan",
    badge: "SCAN",
    badgeClass: "badge-intermediate",
    description: "Scans Terraform files with Checkov and flags resources missing required security rules.",
    filename: "main.tf",
    codeTitle: "Flagged Resource in main.tf",
    codeContent: `resource "aws_s3_bucket" "patient_records" {
  bucket        = "acme-health-patient-vault"
  force_destroy = false
  # CKV_AWS_19: S3 Bucket default encryption is not enabled
  # CKV_AWS_144: S3 Bucket cross-region replication is not enabled
}`,
    statusLabel: "Issue Found",
    statusDetail: "Rule CKV_AWS_19: Default encryption is disabled on this S3 bucket.",
    statusClass: "text-amber-400",
    visualHtml: `
      <div class="space-y-4 stage-fade-enter">
        <div class="flex items-center justify-between pb-2 border-b border-slate-800/80">
          <div class="flex items-center space-x-2">
            <span class="text-xs font-bold uppercase tracking-wider text-amber-400 font-mono">Security Scan</span>
          </div>
          <span class="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">Checkov</span>
        </div>

        <!-- Radar graphic & target card -->
        <div class="relative p-4 rounded-xl bg-slate-900 border border-amber-500/30 overflow-hidden flex items-center space-x-4 shadow-lg shadow-amber-500/5">
          <div class="relative w-16 h-16 rounded-full border border-amber-500/40 flex items-center justify-center shrink-0 bg-amber-500/5">
            <div class="absolute inset-0 rounded-full border border-amber-500/20 active-pulse-ring"></div>
            <div class="absolute w-8 h-8 rounded-full border border-dashed border-amber-500/40"></div>
            <div class="absolute top-1/2 left-1/2 w-8 h-[2px] bg-gradient-to-r from-amber-400 to-transparent origin-left animate-radar-sweep"></div>
          </div>

          <div class="flex-1 min-w-0 space-y-1">
            <div class="flex items-center justify-between">
              <span class="text-xs font-bold text-white truncate font-mono">aws_s3_bucket.patient_records</span>
              <span class="text-[10px] font-bold text-rose-400 font-mono px-1.5 py-0.2 rounded bg-rose-500/10 border border-rose-500/30">FAILED</span>
            </div>
            <div class="text-[11px] text-amber-300 font-mono">Rule: CKV_AWS_19 (Encryption)</div>
            <div class="text-[10px] text-slate-400">Missing default encryption configuration.</div>
          </div>
        </div>

        <!-- Compliance standard badges -->
        <div class="grid grid-cols-2 gap-2 text-[10px] font-mono">
          <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <span class="text-rose-400 font-bold">HIPAA</span>
            <span class="text-slate-400">&sect; 164.312</span>
          </div>
          <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <span class="text-amber-400 font-bold">NIST</span>
            <span class="text-slate-400">SP 800-53</span>
          </div>
        </div>
      </div>
    `
  },
  {
    step: 2,
    title: "2. Blast Radius Check",
    badge: "DEPENDENCY CHECK",
    badgeClass: "badge-critical",
    description: "Checks dependencies before editing. Only safe leaf nodes proceed to automated fixes; core resources require manual review.",
    filename: "blast_radius.json",
    codeTitle: "Dependency Analysis",
    codeContent: `[DEPENDENCY ANALYSIS]:
  - aws_vpc.production_network:
      Dependents: 9 child resources
      Action:     ROUTE TO HUMAN REVIEW (Core resource)

  - aws_s3_bucket.patient_records:
      Dependents: 0 child resources
      Action:     APPROVE FOR AUTOMATED FIX (Safe leaf node)`,
    statusLabel: "Approved to Fix",
    statusDetail: "Bucket has no child dependencies. Safe to generate an automatic fix.",
    statusClass: "text-emerald-400",
    visualHtml: `
      <div class="space-y-4 stage-fade-enter">
        <div class="flex items-center justify-between pb-2 border-b border-slate-800/80">
          <div class="flex items-center space-x-2">
            <span class="text-xs font-bold uppercase tracking-wider text-emerald-400 font-mono">Dependency Filter</span>
          </div>
          <span class="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">Core Gate</span>
        </div>

        <div class="space-y-2.5">
          <div class="p-3 rounded-xl bg-slate-900 border border-rose-500/40 flex items-center justify-between text-xs">
            <div class="space-y-0.5">
              <div class="font-bold text-white flex items-center space-x-1.5 font-mono">
                <span>aws_vpc.production_network</span>
              </div>
              <div class="text-[10px] text-slate-400 font-mono">Core network &bull; 9 dependencies</div>
            </div>
            <span class="text-[10px] font-bold text-rose-400 bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded whitespace-nowrap">MANUAL REVIEW</span>
          </div>

          <div class="p-3 rounded-xl bg-slate-900 border border-emerald-500/50 flex items-center justify-between text-xs shadow-md shadow-emerald-500/10">
            <div class="space-y-0.5">
              <div class="font-bold text-emerald-300 flex items-center space-x-1.5 font-mono">
                <span>aws_s3_bucket.patient_records</span>
              </div>
              <div class="text-[10px] text-emerald-400/80 font-mono">Independent &bull; 0 dependencies</div>
            </div>
            <span class="text-[10px] font-bold text-emerald-400 bg-emerald-500/15 border border-emerald-500/40 px-2 py-0.5 rounded whitespace-nowrap">SAFE LEAF</span>
          </div>
        </div>

        <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
          <div class="flex justify-between text-[10px] font-mono text-slate-400">
            <span>Safety check</span>
            <span class="text-emerald-400 font-bold">Safe to fix automatically</span>
          </div>
          <div class="w-full h-2 rounded-full bg-slate-800 overflow-hidden flex">
            <div class="h-full bg-emerald-500" style="width: 50%;"></div>
            <div class="h-full bg-slate-700" style="width: 50%;"></div>
          </div>
        </div>
      </div>
    `
  },
  {
    step: 3,
    title: "3. Draft Fix",
    badge: "DRAFT FIX",
    badgeClass: "badge-leaf",
    description: "Generates a separate resource block for encryption instead of modifying the existing bucket in place.",
    filename: "fix_encryption.tf",
    codeTitle: "Additive Configuration Block",
    codeContent: `resource "aws_s3_bucket_server_side_encryption_configuration" "patient_records_crypto" {
  bucket = aws_s3_bucket.patient_records.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.patient_data_key.arn
    }
  }
}`,
    statusLabel: "Fix Generated",
    statusDetail: "Added encryption block. Original bucket block remains unchanged.",
    statusClass: "text-cyan-400",
    visualHtml: `
      <div class="space-y-4 stage-fade-enter">
        <div class="flex items-center justify-between pb-2 border-b border-slate-800/80">
          <div class="flex items-center space-x-2">
            <span class="text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono">Fix Generation</span>
          </div>
          <span class="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">Additive Mode</span>
        </div>

        <div class="grid grid-cols-4 gap-1.5 text-center">
          <div class="p-2 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
            <div class="text-[10px] font-mono text-slate-400">01</div>
            <div class="text-[10px] font-bold text-slate-300">Scan</div>
            <div class="text-[9px] text-slate-500">Check</div>
          </div>
          <div class="p-2 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
            <div class="text-[10px] font-mono text-slate-400">02</div>
            <div class="text-[10px] font-bold text-slate-300">Plan</div>
            <div class="text-[9px] text-slate-500">Approach</div>
          </div>
          <div class="p-2 rounded-lg bg-slate-900 border border-amber-500/40 bg-amber-500/10 space-y-1 shadow-sm">
            <div class="text-[10px] font-mono text-amber-400">03</div>
            <div class="text-[10px] font-bold text-amber-300">Draft</div>
            <div class="text-[9px] text-amber-400 font-bold">Write HCL</div>
          </div>
          <div class="p-2 rounded-lg bg-slate-900 border border-emerald-500/40 bg-emerald-500/10 space-y-1">
            <div class="text-[10px] font-mono text-emerald-400">04</div>
            <div class="text-[10px] font-bold text-emerald-300">Check</div>
            <div class="text-[9px] text-emerald-400">Validate</div>
          </div>
        </div>

        <div class="p-3.5 rounded-xl bg-slate-900 border border-cyan-500/30 text-xs space-y-1.5 shadow-md shadow-cyan-500/5">
          <div class="flex items-center space-x-1.5 font-bold text-cyan-300 text-xs">
            <svg class="w-3.5 h-3.5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            <span>Additive Change</span>
          </div>
          <p class="text-[11px] text-slate-300 leading-relaxed">
            Adds a separate <code class="font-mono text-amber-300 bg-slate-950 px-1 py-0.5 rounded text-[10px]">aws_s3_bucket_server_side_encryption_configuration</code> block so the main bucket is not modified in place.
          </p>
        </div>
      </div>
    `
  },
  {
    step: 4,
    title: "4. Dry-Run Plan",
    badge: "DRY RUN",
    badgeClass: "badge-leaf",
    description: "Runs tofu plan in a test sandbox to confirm 0 deletions and 0 replacements before applying any change.",
    filename: "tofu_plan.txt",
    codeTitle: "Plan Output",
    codeContent: `Plan: 1 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + aws_s3_bucket_server_side_encryption_configuration.patient_records_crypto

Checks:
  - Additions:    1
  - Changes:      0
  - Deletions:    0
  - Replacements: 0
  - Result:       PASSED (No destructive changes)`,
    statusLabel: "Plan Passed",
    statusDetail: "Clean plan: 1 addition, 0 deletions, 0 replacements.",
    statusClass: "text-emerald-400",
    visualHtml: `
      <div class="space-y-4 stage-fade-enter">
        <div class="flex items-center justify-between pb-2 border-b border-slate-800/80">
          <div class="flex items-center space-x-2">
            <span class="text-xs font-bold uppercase tracking-wider text-emerald-400 font-mono">Plan Dry Run</span>
          </div>
          <span class="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono font-bold">PASSED</span>
        </div>

        <div class="grid grid-cols-2 gap-2 text-xs">
          <div class="p-2.5 rounded-xl bg-slate-900 border border-emerald-500/30">
            <div class="text-[10px] text-slate-400 uppercase font-mono">Added</div>
            <div class="text-lg font-bold font-mono text-emerald-400 mt-0.5">+1</div>
          </div>
          <div class="p-2.5 rounded-xl bg-slate-900 border border-emerald-500/30">
            <div class="text-[10px] text-slate-400 uppercase font-mono">Modified</div>
            <div class="text-lg font-bold font-mono text-slate-300 mt-0.5">~0</div>
          </div>
          <div class="p-2.5 rounded-xl bg-slate-900 border border-emerald-500/30">
            <div class="text-[10px] text-slate-400 uppercase font-mono">Deleted</div>
            <div class="text-lg font-bold font-mono text-emerald-400 mt-0.5">0</div>
          </div>
          <div class="p-2.5 rounded-xl bg-slate-900 border border-emerald-500/30">
            <div class="text-[10px] text-slate-400 uppercase font-mono">Replaced</div>
            <div class="text-lg font-bold font-mono text-emerald-400 mt-0.5">0</div>
          </div>
        </div>

        <div class="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center space-x-2 text-xs text-emerald-300 font-medium">
          <svg class="w-4 h-4 text-emerald-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
          <span>All checks passed without deleting or replacing resources.</span>
        </div>
      </div>
    `
  },
  {
    step: 5,
    title: "5. Pull Request",
    badge: "PULL REQUEST",
    badgeClass: "badge-leaf",
    description: "Opens a pull request with the tested fix, the plan diff, and the referenced security rule.",
    filename: "pull_request.md",
    codeTitle: "Pull Request Summary",
    codeContent: `PR #142: Enable default encryption for patient S3 bucket
Branch: regradar/fix-s3-encryption -> main
Rule:   HIPAA §164.312 / NIST SP 800-53
Diff:   1 to add, 0 to change, 0 to destroy
Status: Passed all checks`,
    statusLabel: "Ready to Merge",
    statusDetail: "Fix verified and ready for operator review and merge.",
    statusClass: "text-emerald-400",
    visualHtml: `
      <div class="space-y-4 stage-fade-enter">
        <div class="flex items-center justify-between pb-2 border-b border-slate-800/80">
          <div class="flex items-center space-x-2">
            <span class="text-xs font-bold uppercase tracking-wider text-emerald-400 font-mono">Pull Request</span>
          </div>
          <span class="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono font-bold">OPEN</span>
        </div>

        <div class="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5 text-xs shadow-md">
          <div class="flex items-center space-x-2">
            <svg class="w-4 h-4 text-emerald-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M18 6v6a6 6 0 0 1-6 6H6"/><circle cx="18" cy="6" r="3"/></svg>
            <span class="font-bold text-white">PR #142: Enable default SSE encryption</span>
          </div>
          <div class="flex items-center space-x-2 text-[10px] font-mono text-slate-400">
            <span class="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">regradar/fix-s3-encryption</span>
            <span>&rarr;</span>
            <span class="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">main</span>
          </div>
          <div class="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
            <span class="text-emerald-400 font-bold font-mono">+13 / -0 lines</span>
            <span class="text-slate-400">Plan diffs verified</span>
          </div>
        </div>

        <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between text-[10px] font-mono text-slate-400">
          <span>Signed with HMAC-SHA256</span>
          <span class="text-amber-400 font-bold">Verified</span>
        </div>
      </div>
    `
  }
];

let activeDemoStep = 1;
let demoAutoPlayInterval = null;

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
  const progressLine = document.getElementById("demoProgressLine");
  const stageIndexBadge = document.getElementById("demoStageIndexBadge");
  const visualEl = document.getElementById("demoVisualGraphic");

  if (titleEl) titleEl.textContent = data.title;
  if (badgeEl) {
    badgeEl.textContent = data.badge;
    badgeEl.className = `px-2.5 py-1 rounded-lg text-[10px] font-bold tracking-wider ${data.badgeClass}`;
  }
  if (descEl) descEl.textContent = data.description;
  if (codeTitleEl) codeTitleEl.textContent = data.filename || data.codeTitle;
  if (codeEl) codeEl.textContent = data.codeContent;
  if (statusLabelEl) {
    statusLabelEl.textContent = data.statusLabel;
    statusLabelEl.className = `font-bold ${data.statusClass} ml-1.5`;
  }
  if (statusDetailEl) statusDetailEl.textContent = data.statusDetail;
  if (stageIndexBadge) stageIndexBadge.textContent = `STAGE 0${stepNumber} / 05`;

  // Update animated progress fill line
  if (progressLine) {
    const pct = ((stepNumber - 1) / 4) * 100;
    progressLine.style.width = `calc(${pct}% * 0.88 + 12px)`;
  }

  // Update dynamic interactive visual graphic
  if (visualEl && data.visualHtml) {
    visualEl.innerHTML = data.visualHtml;
  }

  // Update step buttons
  document.querySelectorAll("[data-demo-step]").forEach(btn => {
    const s = parseInt(btn.getAttribute("data-demo-step"), 10);
    const numSpan = btn.querySelector(".step-num");
    if (s === stepNumber) {
      btn.className = "lifecycle-step-btn p-3.5 rounded-xl border border-amber-500 bg-amber-500/10 text-amber-400 active-step text-left transition group";
      if (numSpan) {
        numSpan.className = "step-num w-6 h-6 rounded-full bg-amber-500 text-white font-mono text-[11px] font-bold flex items-center justify-center shadow-md shadow-amber-500/30";
      }
    } else if (s < stepNumber) {
      btn.className = "lifecycle-step-btn p-3.5 rounded-xl border border-emerald-500/40 bg-slate-900 text-slate-300 text-left transition hover:border-emerald-500/70 group";
      if (numSpan) {
        numSpan.className = "step-num w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-mono text-[11px] font-bold flex items-center justify-center";
      }
    } else {
      btn.className = "lifecycle-step-btn p-3.5 rounded-xl border border-slate-800 bg-slate-900 text-slate-400 text-left transition hover:border-slate-700 group";
      if (numSpan) {
        numSpan.className = "step-num w-6 h-6 rounded-full bg-slate-800 text-slate-400 font-mono text-[11px] font-bold flex items-center justify-center";
      }
    }
  });
}
window.renderDemoStep = renderDemoStep;

function toggleDemoAutoPlay() {
  const btn = document.getElementById("demoAutoPlayBtn");
  const icon = document.getElementById("demoAutoPlayIcon");
  const label = document.getElementById("demoAutoPlayLabel");

  if (demoAutoPlayInterval) {
    clearInterval(demoAutoPlayInterval);
    demoAutoPlayInterval = null;
    if (icon) icon.innerHTML = "&#9654;";
    if (label) label.textContent = "Auto-Play";
    if (btn) btn.classList.remove("border-amber-500", "text-amber-400");
  } else {
    if (icon) icon.innerHTML = "&#9208;";
    if (label) label.textContent = "Pause";
    if (btn) btn.classList.add("border-amber-500", "text-amber-400");
    demoAutoPlayInterval = setInterval(() => {
      const nextStep = (activeDemoStep % 5) + 1;
      renderDemoStep(nextStep);
    }, 4000);
  }
}
window.toggleDemoAutoPlay = toggleDemoAutoPlay;

// Mermaid Flowchart Source
const MERMAID_DIAGRAM_SRC = `flowchart TD
    TF["Terraform and OpenTofu Source<br/>Infrastructure Configuration"] --> CHK["Checkov Policy Linter<br/>Detect Compliance Violations"]
    TF --> AST["HCL AST Parser<br/>Abstract Syntax Tree"]
    AST --> DAG["NetworkX Dependency DAG<br/>Betweenness and Eigenvector"]
    CHK --> G1{"Gate 1: Centrality Risk Gate<br/>Blast Radius Assessment"}
    DAG --> G1
    G1 -->|High Centrality Root| ESC["Human Review Escalation<br/>Mandatory Operator Sign-Off"]
    G1 -->|Leaf Safe Component| SWARM["Multi-Agent Swarm<br/>Auditor, Planner, Synthesizer"]
    SWARM --> G2{"Gate 2: Ephemeral Sandbox<br/>Dry-Run Plan Diff Verification"}
    G2 -->|Destructive Diffs Detected| RETRY["Patch Rejection<br/>Compiler Feedback Loop"]
    RETRY --> SWARM
    G2 -->|Zero Destructive Diffs| PR["Verified Safe Pull Request<br/>State Invariants Preserved"]`;

let mermaidRenderCounter = 0;

async function toggleArchView(view) {
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
    if (el && window.mermaid) {
      try {
        const isLight = document.documentElement.getAttribute("data-theme") === "light";
        mermaid.initialize({
          startOnLoad: false,
          theme: isLight ? "neutral" : "dark",
          securityLevel: "loose",
          fontFamily: "inherit"
        });
        const renderId = `regradarMermaidSvg_${++mermaidRenderCounter}`;
        const { svg } = await mermaid.render(renderId, MERMAID_DIAGRAM_SRC);
        el.innerHTML = svg;
      } catch (err) {
        console.warn("Mermaid render error:", err);
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