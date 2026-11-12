// RegRadar Web Studio - Ephemeral Pre-Flight Sandbox Module

window.SandboxModule = (function () {
  async function load() {
    if (!AppState.currentWorkspace) {
      renderEmptyState();
    }
  }

  function renderEmptyState() {
    const banner = document.getElementById("sandboxVerdictBanner");
    if (banner) {
      banner.className = "p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center justify-between mb-6";
      banner.innerHTML = `
        <div class="flex items-center space-x-3">
          <span class="text-amber-400 shrink-0">${window.RegIcons.svg('shield', 'w-6 h-6')}</span>
          <div>
            <div class="font-bold text-sm text-slate-100">No Remote Repository Connected</div>
            <div class="text-xs text-slate-400 mt-0.5">Connect a GitHub or GitLab repository to run isolated dry-run simulations and evaluate plan diff invariants.</div>
          </div>
        </div>
        <button onclick="switchTab('github')" class="px-3.5 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold cursor-pointer shrink-0">Connect Repository</button>
      `;
    }
    const cEl = document.getElementById("sandboxCreatedCount");
    const uEl = document.getElementById("sandboxUpdatedCount");
    const dEl = document.getElementById("sandboxDeletedCount");
    const rEl = document.getElementById("sandboxReplacedCount");
    if (cEl) cEl.textContent = "0";
    if (uEl) uEl.textContent = "0";
    if (dEl) dEl.textContent = "0";
    if (rEl) rEl.textContent = "0";
    const changesList = document.getElementById("sandboxChangesList");
    if (changesList) {
      changesList.innerHTML = `<div class="text-xs text-slate-500 py-4 text-center">No repository connected. Connect a remote repository in CI/CD &amp; Git Webhooks to inspect planned diffs.</div>`;
    }
  }

  async function runSimulation() {
    if (!AppState.currentWorkspace) {
      showToast("Connect a remote repository first in CI/CD & Git Webhooks.", "info");
      renderEmptyState();
      return;
    }

    const btn = document.getElementById("runSandboxBtn");
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('spinner', 'w-3.5 h-3.5')} Simulating in Isolated Workspace...</span>`;
    }

    try {
      const targetPath = AppState.currentWorkspace;
      const report = await apiCall("/api/sandbox/verify", "POST", { target_path: targetPath });
      renderReport(report);
      showToast("Dry-run execution sandbox simulation complete!", "success");
    } catch (err) {
      showToast(`Simulation failed: ${err.message}`, "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('shield', 'w-3.5 h-3.5')} Run Pre-Flight Sandbox Simulation</span>`;
      }
    }
  }

  function renderReport(report) {
    document.getElementById("sandboxCreatedCount").textContent = report.count_created || 0;
    document.getElementById("sandboxUpdatedCount").textContent = report.count_updated || 0;
    document.getElementById("sandboxDeletedCount").textContent = report.count_deleted || 0;
    document.getElementById("sandboxReplacedCount").textContent = report.count_replaced || 0;

    const banner = document.getElementById("sandboxVerdictBanner");
    if (banner) {
      if (report.zero_destruction_guarantee_met && report.is_safe) {
        banner.className = "p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center space-x-3 mb-6";
        banner.innerHTML = `
          <span class="text-emerald-400 shrink-0">${window.RegIcons.svg('shieldCheck', 'w-6 h-6')}</span>
          <div>
            <div class="font-bold text-sm text-emerald-200">Zero-Destruction Invariant Guaranteed</div>
            <div class="text-xs text-emerald-400 mt-0.5">All planned changes preserve state continuity. Zero unintended deletions and zero forced replacements detected across ${report.total_resources_evaluated} evaluated resources.</div>
          </div>
        `;
      } else {
        banner.className = "p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 mb-6";
        banner.innerHTML = `
          <span class="text-rose-400 shrink-0">${window.RegIcons.svg('shieldAlert', 'w-6 h-6')}</span>
          <div>
            <div class="font-bold text-sm text-rose-200">State Invariant Violation Detected!</div>
            <div class="text-xs text-rose-400 mt-0.5">${report.violations.length} critical violation(s) scheduled in plan diffs. Automated deployment is blocked.</div>
          </div>
        `;
      }
    }

    // Render detailed changes list
    const changesList = document.getElementById("sandboxChangesList");
    if (!changesList) return;

    if (!report.changes || report.changes.length === 0) {
      changesList.innerHTML = `<div class="text-xs text-slate-500 py-4 text-center">No resource state transitions planned.</div>`;
      return;
    }

    changesList.innerHTML = report.changes.map(c => {
      const isCreate = c.actions.includes("create") && !c.actions.includes("delete");
      const isUpdate = c.actions.includes("update");
      const isReplace = c.actions.includes("delete") && c.actions.includes("create");
      const isDelete = c.actions.includes("delete") && !c.actions.includes("create");

      const badge = isReplace
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white">REPLACE (Forces Recreation)</span>`
        : isDelete
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400">DELETE</span>`
        : isCreate
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400">CREATE (Additive)</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400">UPDATE</span>`;

      return `
        <div class="p-3.5 rounded-lg bg-slate-800/80 border border-slate-700 mb-2.5">
          <div class="flex justify-between items-center">
            <span class="font-mono text-xs font-bold text-slate-200">${c.address}</span>
            ${badge}
          </div>
          <div class="text-xs text-slate-400 mt-1 font-mono">${c.resource_type} • ${c.name}</div>
          ${c.action_reason ? `<div class="text-[11px] text-rose-400 mt-1">Reason: ${c.action_reason}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  return {
    load,
    runSimulation
  };
})();
