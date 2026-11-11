// RegRadar Web Studio - Operator Review Console Module

window.ReviewModule = (function () {
  let stagedData = null;
  let activeIndex = 0;
  let decisionsHistory = [];

  async function load() {
    try {
      showLoading(true);
      const targetPath = AppState.currentWorkspace;
      stagedData = await apiCall("/api/review/staged", "POST", { target_path: targetPath });
      updateCounters(stagedData);
      renderQueue(stagedData);
      if (stagedData.items && stagedData.items.length > 0) {
        selectItem(0);
      } else {
        renderEmptyState();
      }
    } catch (err) {
      console.error("Review load error:", err);
      showToast(`Failed to load staged items: ${err.message}`, "error");
    } finally {
      showLoading(false);
    }
  }

  function showLoading(show) {
    const loader = document.getElementById("reviewLoader");
    if (loader) loader.classList.toggle("hidden", !show);
  }

  function updateCounters(data) {
    document.getElementById("reviewAutoCount").textContent = data.auto_staged_count || 0;
    document.getElementById("reviewPendingCount").textContent = data.pending_human_count || 0;
    document.getElementById("reviewTotalCount").textContent = data.total_violations || 0;
  }

  function renderQueue(data) {
    const container = document.getElementById("reviewQueueList");
    if (!container) return;

    if (!data.items || data.items.length === 0) {
      container.innerHTML = `<div class="p-4 text-xs text-slate-500">No items staged for review.</div>`;
      return;
    }

    container.innerHTML = data.items.map((item, idx) => {
      const isCritical = item.risk_tier === "CRITICAL_ROOT";
      const isIntermediate = item.risk_tier === "INTERMEDIATE";
      const badgeClass = isCritical ? "badge-critical" : isIntermediate ? "badge-intermediate" : "badge-leaf";

      return `
        <div class="p-3 rounded-lg border cursor-pointer transition mb-2 ${
          idx === activeIndex ? 'bg-slate-800 border-cyan-500/60 shadow-lg' : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
        }" onclick="window.ReviewModule.selectItem(${idx})">
          <div class="flex items-center justify-between">
            <span class="text-xs font-mono font-bold text-slate-200 line-clamp-1">${item.resource_id}</span>
            <span class="text-[10px] px-1.5 py-0.5 rounded font-bold ${badgeClass}">
              ${item.risk_tier}
            </span>
          </div>
          <div class="flex items-center justify-between mt-2 text-[11px] text-slate-400">
            <span class="font-mono text-cyan-400">${item.check_id}</span>
            <span>Blast: ${Number(item.blast_radius_score || 0).toFixed(4)}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  function selectItem(idx) {
    activeIndex = idx;
    renderQueue(stagedData);

    const item = stagedData.items[idx];
    if (!item) return;

    // Render Review Detail Panel
    document.getElementById("reviewActiveResourceId").textContent = item.resource_id;
    document.getElementById("reviewActiveCheck").textContent = `${item.check_id}: ${item.check_name}`;
    document.getElementById("reviewActiveStatute").textContent = item.statute || "NIST SP 800-53";
    document.getElementById("reviewActiveStrategy").textContent = item.strategy || "ADDITIVE_ATTACHMENT";

    const modelTag = document.getElementById("reviewActiveModelTag");
    if (modelTag) {
      const s = window.AppState && window.AppState.settings;
      const m = (s && s.current_model) || "Deterministic Mock";
      const modelDisplayName = (window.getModelDisplayName && s) ? window.getModelDisplayName(s.current_provider, m) : m;
      modelTag.textContent = `Synthesized by: ${modelDisplayName}`;
    }

    // Risk Banner
    const banner = document.getElementById("reviewRiskBanner");
    if (banner) {
      if (item.requires_human) {
        banner.className = "p-4 rounded-xl mb-4 bg-rose-500/10 border border-rose-500/30 text-rose-300";
        banner.innerHTML = `
          <div class="flex items-start space-x-3">
            <span class="text-rose-400 mt-0.5">${window.RegIcons.svg('alert', 'w-5 h-5')}</span>
            <div>
              <div class="font-bold text-sm text-rose-300">High-Risk Infrastructure Node — Security Sign-Off Required</div>
              <div class="text-xs text-rose-400 mt-1">
                Resource '${item.resource_id}' is rated <span class="font-mono font-bold">${item.risk_tier}</span> with a composite risk score of 
                <span class="font-bold">${Number(item.blast_radius_score || 0).toFixed(4)}</span> and ${item.descendant_count} cascading downstream dependents.
                Automated unattended commits are restricted by safety policy.
              </div>
            </div>
          </div>
        `;
      } else {
        banner.className = "p-4 rounded-xl mb-4 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300";
        banner.innerHTML = `
          <div class="flex items-start space-x-3">
            <span class="text-emerald-400 mt-0.5">${window.RegIcons.svg('check', 'w-5 h-5')}</span>
            <div>
              <div class="font-bold text-sm text-emerald-300">Low-Blast Radius Component — Approved for Autonomous Repair</div>
              <div class="text-xs text-emerald-400 mt-1">
                Resource '${item.resource_id}' is a <span class="font-mono font-bold">${item.risk_tier}</span> with zero downstream dependents.
                Pre-flight execution plan diff verified zero resource recreations.
              </div>
            </div>
          </div>
        `;
      }
    }

    // Render Side-by-Side Diff
    renderCodeDiff(item.original_snippet, item.patch_snippet);
  }

  function renderCodeDiff(original, modified) {
    const origContainer = document.getElementById("diffOriginalCode");
    const modContainer = document.getElementById("diffModifiedCode");
    if (!origContainer || !modContainer) return;

    origContainer.textContent = original || "// No file content found";
    modContainer.textContent = modified || "// No modified patch available";
  }

  async function submitDecision(decision) {
    const item = stagedData.items[activeIndex];
    if (!item) return;

    const apply = document.getElementById("reviewApplyToggle")?.checked || false;

    try {
      const res = await apiCall("/api/review/decision", "POST", {
        target_path: AppState.currentWorkspace,
        resource_id: item.resource_id,
        check_id: item.check_id,
        decision: decision,
        apply: apply,
        edited_hcl: item.patch_snippet
      });

      decisionsHistory.unshift({
        time: new Date().toLocaleTimeString(),
        resource_id: item.resource_id,
        check_id: item.check_id,
        decision: decision,
        applied: res.applied
      });

      renderHistory();
      showToast(`Decision [${decision}] recorded for ${item.resource_id}`, "success");

      // Advance to next item
      if (activeIndex < stagedData.items.length - 1) {
        selectItem(activeIndex + 1);
      }
    } catch (err) {
      showToast(`Failed to record decision: ${err.message}`, "error");
    }
  }

  function renderHistory() {
    const container = document.getElementById("reviewHistoryList");
    if (!container) return;

    if (decisionsHistory.length === 0) {
      container.innerHTML = `<div class="text-xs text-slate-500 py-2">No decisions recorded in this session.</div>`;
      return;
    }

    container.innerHTML = decisionsHistory.map(h => `
      <div class="p-2 rounded bg-slate-800/80 border border-slate-700 mb-1.5 flex justify-between items-center text-xs">
        <div>
          <span class="font-mono text-cyan-400 font-bold">${h.resource_id}</span>
          <span class="text-slate-400 text-[10px] ml-2">${h.time}</span>
        </div>
        <div class="flex items-center space-x-2">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
            h.decision === 'APPROVE' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
          }">${h.decision}</span>
          ${h.applied ? '<span class="text-[10px] text-amber-400">APPLIED</span>' : ''}
        </div>
      </div>
    `).join('');
  }

  function renderEmptyState() {
    const detail = document.getElementById("reviewDetailContainer");
    if (detail) {
      detail.innerHTML = `
        <div class="flex flex-col items-center justify-center h-full text-slate-400 py-16">
          <div class="mb-3 text-cyan-400">${window.RegIcons.svg('shieldCheck', 'w-10 h-10')}</div>
          <div class="text-base font-bold text-white">No Review Items Pending</div>
          <p class="text-xs text-slate-400 mt-1">All compliance checks are resolved or gated in this workspace.</p>
        </div>
      `;
    }
  }

  return {
    load,
    selectItem,
    submitDecision
  };
})();
