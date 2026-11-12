// RegRadar Web Studio - Compliance & GraphRAG Module

window.ComplianceModule = (function () {
  let violations = [];
  let policyEngines = null;

  async function load() {
    const tbody = document.getElementById("complianceTableBody");
    if (!tbody) return;

    if (!AppState.currentWorkspace) {
      await loadPolicyEngines();
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center py-12 text-slate-400">
            <div class="max-w-md mx-auto space-y-3">
              <div class="text-sm font-semibold text-slate-200">No Remote Repository Connected</div>
              <p class="text-xs text-slate-400">Connect a GitHub or GitLab repository under CI/CD & Git Webhooks to run static compliance and GraphRAG policy audits.</p>
              <button onclick="switchTab('github')" class="px-3.5 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold cursor-pointer">Connect Remote Repository</button>
            </div>
          </td>
        </tr>
      `;
      updateStats([]);
      return;
    }

    try {
      showLoading(true);
      const targetPath = AppState.currentWorkspace;
      await loadPolicyEngines();
      violations = await apiCall("/api/audit", "POST", { target_path: targetPath });
      renderTable(violations);
      updateStats(violations);
    } catch (err) {
      console.error("Compliance load error:", err);
      showToast(`Compliance audit failed: ${err.message}`, "error");
    } finally {
      showLoading(false);
    }
  }

  async function loadPolicyEngines() {
    const container = document.getElementById("policyEnginesPills");
    if (!container) return;
    try {
      const res = await apiCall("/api/policy/engines", "GET");
      policyEngines = res;
      if (res && res.engines) {
        container.innerHTML = res.engines.map(eng => {
          const isActive = eng.available;
          const badgeClass = isActive
            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
            : "bg-slate-800 text-slate-400 border-slate-700";
          const shortName = eng.engine_id === "checkov"
            ? "Checkov Linter"
            : eng.engine_id === "opa"
            ? "OPA / Rego"
            : "RegRadar AST";
          return `
            <span class="px-2.5 py-1 rounded-md text-[11px] font-mono border flex items-center gap-1.5 ${badgeClass}" title="${eng.name}: ${eng.status}">
              <span>${shortName}</span>
              <span class="text-[10px] opacity-75">(${eng.status})</span>
            </span>
          `;
        }).join('');
      }
    } catch (e) {
      console.warn("Could not load policy engines metadata", e);
    }
  }

  function showLoading(show) {
    const loader = document.getElementById("complianceLoader");
    if (loader) loader.classList.toggle("hidden", !show);
  }

  function updateStats(items) {
    document.getElementById("statTotalViolations").textContent = items.length;
    let hipaaCount = 0;
    let gdprCount = 0;
    let nistCount = 0;
    let pciCount = 0;

    items.forEach(v => {
      const fws = (v.frameworks || []).join(" ").toUpperCase();
      if (fws.includes("HIPAA")) hipaaCount++;
      if (fws.includes("GDPR")) gdprCount++;
      if (fws.includes("NIST")) nistCount++;
      if (fws.includes("PCI")) pciCount++;
    });

    document.getElementById("statHipaaCount").textContent = hipaaCount;
    document.getElementById("statGdprCount").textContent = gdprCount;
    document.getElementById("statNistCount").textContent = nistCount;
    document.getElementById("statPciCount").textContent = pciCount;
  }

  function renderTable(items) {
    const tbody = document.getElementById("complianceTableBody");
    if (!tbody) return;

    if (!items || items.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center py-8 text-slate-400 font-medium">
            <span class="inline-flex items-center gap-1.5 text-emerald-400 font-semibold">${window.RegIcons.svg('check', 'w-4 h-4')} No compliance smells detected in this architecture.</span>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = items.map((item, idx) => `
      <tr class="hover:bg-slate-800/50 cursor-pointer border-b border-slate-800 transition" onclick="window.ComplianceModule.openGroundingDrawer(${idx})">
        <td class="py-3 px-4">
          <div class="font-mono text-xs font-semibold text-cyan-400">${item.check_id}</div>
          <div class="text-xs text-slate-400 mt-0.5 line-clamp-1">${item.check_name}</div>
        </td>
        <td class="py-3 px-4 font-mono text-xs text-slate-200">
          ${item.resource_id}
        </td>
        <td class="py-3 px-4">
          <div class="flex flex-wrap gap-1">
            ${(item.frameworks || ["NIST SP 800-53"]).map(fw => `
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/30">
                ${fw}
              </span>
            `).join('')}
          </div>
        </td>
        <td class="py-3 px-4 text-xs text-slate-400">
          ${item.file_path ? item.file_path.split('/').pop() : 'main.tf'}
        </td>
        <td class="py-3 px-4 text-right">
          <button class="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">
            View Statute →
          </button>
        </td>
      </tr>
    `).join('');
  }

  function filterTable() {
    const query = document.getElementById("complianceSearchInput")?.value.toLowerCase() || "";
    const fwFilter = document.getElementById("complianceFrameworkFilter")?.value || "all";

    const filtered = violations.filter(v => {
      const matchText = (v.check_id + " " + v.check_name + " " + v.resource_id).toLowerCase().includes(query);
      const fws = (v.frameworks || []).join(" ").toLowerCase();
      const matchFw = fwFilter === "all" || fws.includes(fwFilter.toLowerCase());
      return matchText && matchFw;
    });

    renderTable(filtered);
  }

  async function openGroundingDrawer(index) {
    const item = violations[index];
    if (!item) return;

    const drawer = document.getElementById("groundingDrawer");
    if (!drawer) return;

    drawer.classList.remove("hidden");

    document.getElementById("groundingCheckId").textContent = item.check_id;
    document.getElementById("groundingCheckName").textContent = item.check_name;
    document.getElementById("groundingResource").textContent = item.resource_id;

    // Query GraphRAG for deep statutory grounding
    try {
      const rag = await apiCall("/api/knowledge/query", "POST", {
        query: `${item.check_id} ${item.check_name}`,
        resource_type: item.resource_type,
        top_k: 2
      });

      const ctxContainer = document.getElementById("groundingPathContent");
      if (rag.contexts && rag.contexts.length > 0) {
        const top = rag.contexts[0];
        ctxContainer.innerHTML = `
          <div class="space-y-4">
            <div class="p-3.5 rounded-lg bg-slate-800/80 border border-slate-700/80">
              <div class="text-[11px] font-bold uppercase text-slate-400 tracking-wider">Statutory Mandate</div>
              <div class="text-sm font-semibold text-emerald-400 mt-1">${top.statute_reference || 'NIST SP 800-53 Control'}</div>
              <div class="text-xs text-slate-300 mt-1.5 leading-relaxed">${top.statute_text || item.check_name}</div>
            </div>

            <div class="p-3.5 rounded-lg bg-slate-800/80 border border-slate-700/80">
              <div class="text-[11px] font-bold uppercase text-slate-400 tracking-wider">Non-Destructive Strategy</div>
              <div class="inline-block mt-1 px-2 py-0.5 rounded text-xs font-semibold ${
                top.strategy === 'ADDITIVE_ATTACHMENT' ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30' : 'bg-purple-500/10 text-purple-300 border border-purple-500/30'
              }">
                ${top.strategy || 'ADDITIVE_ATTACHMENT'}
              </div>
              <div class="text-xs text-slate-400 mt-2">
                ${top.strategy === 'ADDITIVE_ATTACHMENT' 
                  ? 'Injects a standalone compliance block without modifying parent state or triggering recreation.'
                  : 'Applies in-place attribute configuration preserving existing schema boundaries.'}
              </div>
            </div>

            <div class="p-3.5 rounded-lg bg-slate-800/80 border border-slate-700/80">
              <div class="text-[11px] font-bold uppercase text-slate-400 tracking-wider">Ontological Traversal Graph</div>
              <div class="flex items-center space-x-2 text-xs font-mono text-slate-300 mt-2 overflow-x-auto pb-1">
                <span class="px-2 py-1 rounded bg-slate-700 text-slate-200">${top.framework}</span>
                <span class="text-slate-500">→</span>
                <span class="px-2 py-1 rounded bg-slate-700 text-slate-200">${item.check_id}</span>
                <span class="text-slate-500">→</span>
                <span class="px-2 py-1 rounded bg-slate-700 text-slate-200">${item.resource_type || 'Resource'}</span>
              </div>
            </div>
          </div>
        `;
      } else {
        ctxContainer.innerHTML = `<div class="text-xs text-slate-400 p-4">Standard statutory control applies for ${item.check_id}.</div>`;
      }
    } catch (err) {
      console.error("Grounding query failed:", err);
    }
  }

  function closeGroundingDrawer() {
    const drawer = document.getElementById("groundingDrawer");
    if (drawer) drawer.classList.add("hidden");
  }

  async function executeGraphRagSearch() {
    const input = document.getElementById("ragSearchInput");
    const resultsContainer = document.getElementById("ragSearchResults");
    if (!input || !resultsContainer) return;

    const query = input.value.trim();
    if (!query) return;

    try {
      resultsContainer.innerHTML = `<div class="text-xs text-slate-400 py-2">Querying Regulatory Knowledge Graph...</div>`;
      const res = await apiCall("/api/knowledge/query", "POST", { query, top_k: 3 });

      if (!res.contexts || res.contexts.length === 0) {
        resultsContainer.innerHTML = `<div class="text-xs text-slate-400 py-2">No matching statutory controls found.</div>`;
        return;
      }

      resultsContainer.innerHTML = res.contexts.map(c => `
        <div class="p-3 rounded-lg bg-slate-800/60 border border-slate-700 mb-2">
          <div class="flex justify-between items-start">
            <span class="text-xs font-bold text-cyan-400 font-mono">${c.check_id}</span>
            <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-300">${c.framework}</span>
          </div>
          <div class="text-xs font-semibold text-slate-200 mt-1">${c.statute_reference}</div>
          <div class="text-xs text-slate-400 mt-1 line-clamp-2">${c.statute_text}</div>
        </div>
      `).join('');
    } catch (err) {
      resultsContainer.innerHTML = `<div class="text-xs text-rose-400 py-2">Query failed: ${err.message}</div>`;
    }
  }

  return {
    load,
    filterTable,
    openGroundingDrawer,
    closeGroundingDrawer,
    executeGraphRagSearch
  };
})();
