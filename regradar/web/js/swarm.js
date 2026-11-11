// RegRadar Web Studio - Multi-Agent Swarm Orchestrator Module

window.SwarmModule = (function () {
  let executionResult = null;

  async function load() {
    // Initial empty state or last run result
    if (!executionResult) {
      resetPipeline();
    }
    updateSwarmHeaderModel();
  }

  function updateSwarmHeaderModel() {
    const s = window.AppState && window.AppState.settings;
    if (!s) return;
    const badge = document.getElementById("swarmActiveModelBadge");
    const ctxBadge = document.getElementById("swarmModelContextBadge");

    const p = s.current_provider || "mock";
    const m = s.current_model || "mock-deterministic";
    const models = (s.available_models && s.available_models[p]) || [];
    const found = models.find(x => x.id === m);

    if (badge) {
      const displayName = found ? found.name : m;
      badge.textContent = `${displayName} (${p.toUpperCase()})`;
    }
    if (ctxBadge && found) {
      ctxBadge.textContent = found.context;
    }
  }

  function resetPipeline() {
    const steps = ["step-audit", "step-retrieve", "step-plan", "step-synthesize", "step-sandbox", "step-verify"];
    steps.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.className = "p-3 rounded-xl border border-slate-700 bg-slate-800/60 text-slate-400 text-center text-xs font-semibold";
      }
    });
  }

  function setStepActive(id) {
    const el = document.getElementById(id);
    if (el) {
      el.className = "p-3 rounded-xl border border-cyan-500 bg-cyan-500/10 text-cyan-300 text-center text-xs font-bold animate-pulse-subtle";
    }
  }

  function setStepComplete(id) {
    const el = document.getElementById(id);
    if (el) {
      el.className = "p-3 rounded-xl border border-emerald-500 bg-emerald-500/10 text-emerald-300 text-center text-xs font-bold";
    }
  }

  async function runSwarm() {
    const btn = document.getElementById("runSwarmBtn");
    const applyToggle = document.getElementById("swarmApplyToggle");
    const apply = applyToggle ? applyToggle.checked : false;

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('spinner', 'w-3.5 h-3.5')} Orchestrating Swarm...</span>`;
    }

    const logContainer = document.getElementById("swarmEventFeed");
    if (logContainer) logContainer.innerHTML = "";
    resetPipeline();

    try {
      const s = window.AppState && window.AppState.settings;
      const activeProvider = (s && s.current_provider) ? s.current_provider.toUpperCase() : "MOCK";
      const activeModel = (s && s.current_model) || "Deterministic Solver";
      const modelDisplayName = (window.getModelDisplayName) ? window.getModelDisplayName(s.current_provider, activeModel) : activeModel;
      const targetPath = AppState.currentWorkspace;

      appendLog("SYSTEM", `Initializing multi-agent neuro-symbolic remediation swarm [AI Engine: ${modelDisplayName} (${activeProvider})] on target workspace: ${targetPath}...`);
      setStepActive("step-audit");

      // Execute live backend multi-agent orchestration
      const result = await apiCall("/api/remediate", "POST", {
        target_path: targetPath,
        apply: apply
      });
      executionResult = result;

      setStepComplete("step-audit");

      if (result.total_violations_found === 0) {
        appendLog("AUDITOR", "Static analysis & AST audit complete: 0 policy violations detected. Target workspace is fully compliant.");
        appendLog("SUPERVISOR", "No remediation actions required. Zero regressions found against regulatory invariants.");
      } else {
        appendLog("AUDITOR", `AST dependency DAG analyzed: detected ${result.total_violations_found} violations (${result.autonomous_remediations_eligible} eligible for autonomous synthesis, ${result.human_escalations_required} gated for human sign-off).`);

        // Render genuine multi-agent state-machine event stream from result.contexts
        if (result.contexts && Array.isArray(result.contexts) && result.contexts.length > 0) {
          let sawRetrieve = false;
          let sawPlan = false;
          let sawSynthesize = false;
          let sawSandbox = false;
          let sawVerify = false;

          for (const ctx of result.contexts) {
            const t = ctx.task || {};
            const v = t.violation || {};
            const resId = v.resource_id || t.rule_id || "resource";

            if (ctx.history && Array.isArray(ctx.history)) {
              for (const tr of ctx.history) {
                const state = tr.to_state;
                let agent = "SYSTEM";
                if (state === "GRAPH_RAG_RETRIEVE") {
                  agent = "PLANNER";
                  sawRetrieve = true;
                } else if (state === "PLAN") {
                  agent = "PLANNER";
                  sawPlan = true;
                } else if (state === "SYNTHESIZE") {
                  agent = "SYNTHESIZER";
                  sawSynthesize = true;
                } else if (state === "DRY_RUN_SANDBOX") {
                  agent = "SUPERVISOR";
                  sawSandbox = true;
                } else if (state === "SEMANTIC_VERIFY") {
                  agent = "SUPERVISOR";
                  sawVerify = true;
                } else if (state === "ACCEPT") {
                  agent = "SUPERVISOR";
                  sawVerify = true;
                } else if (state === "ESCALATE") {
                  agent = "SUPERVISOR";
                } else if (state === "RETRY_WITH_FEEDBACK") {
                  agent = "SUPERVISOR";
                }

                const msg = tr.message ? `[${resId}] ${tr.message}` : `[${resId}] Transitioned to ${state}`;
                appendLog(agent, msg);
              }
            }
          }

          if (sawRetrieve) setStepComplete("step-retrieve");
          if (sawPlan) setStepComplete("step-plan");
          if (sawSynthesize) setStepComplete("step-synthesize");
          if (sawSandbox) setStepComplete("step-sandbox");
          if (sawVerify) setStepComplete("step-verify");
        }

        appendLog("SUPERVISOR", `Swarm cycle completed. Verified & Accepted: ${result.patches_verified_and_accepted}, Escalated / Gated: ${result.patches_rejected_and_escalated + result.human_escalations_required}.`);
      }

      renderSwarmResults(result);
      showToast(`Swarm finished: ${result.patches_verified_and_accepted} patches verified safe!`, "success");
    } catch (err) {
      appendLog("ERROR", `Swarm execution halted: ${err.message}`);
      showToast(`Swarm halted: ${err.message}`, "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('play', 'w-3.5 h-3.5')} Launch Multi-Agent Swarm</span>`;
      }
    }
  }

  function appendLog(agent, message) {
    const container = document.getElementById("swarmEventFeed");
    if (!container) return;

    const colors = {
      AUDITOR: "text-amber-400 bg-amber-500/10 border-amber-500/30",
      PLANNER: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
      SYNTHESIZER: "text-purple-400 bg-purple-500/10 border-purple-500/30",
      SUPERVISOR: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
      SYSTEM: "text-blue-400 bg-blue-500/10 border-blue-500/30",
      ERROR: "text-rose-400 bg-rose-500/10 border-rose-500/30"
    };

    const color = colors[agent] || colors.SYSTEM;

    const div = document.createElement("div");
    div.className = "flex items-start space-x-2 text-xs py-1.5 font-mono";
    div.innerHTML = `
      <span class="px-1.5 py-0.5 rounded font-bold uppercase text-[10px] border ${color}">${agent}</span>
      <span class="text-slate-300 mt-0.5">${message}</span>
    `;

    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
  }

  function renderSwarmResults(res) {
    document.getElementById("swarmAcceptedCount").textContent = res.patches_verified_and_accepted || 0;
    document.getElementById("swarmEscalatedCount").textContent = res.human_escalations_required || 0;
    document.getElementById("swarmTotalCount").textContent = res.total_violations_found || 0;

    const patchesList = document.getElementById("swarmPatchesList");
    if (!patchesList) return;

    if (!res.accepted_patches || res.accepted_patches.length === 0) {
      patchesList.innerHTML = `<div class="text-xs text-slate-500 py-4">No automated patches generated.</div>`;
      return;
    }

    patchesList.innerHTML = res.accepted_patches.map((p, idx) => `
      <div class="p-3 rounded-lg bg-slate-800/80 border border-slate-700 mb-3">
        <div class="flex justify-between items-center mb-2">
          <span class="text-xs font-mono font-bold text-emerald-400 inline-flex items-center gap-1">${window.RegIcons.svg('check', 'w-3 h-3')} ${p.resource_id}</span>
          <span class="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 font-bold border border-emerald-500/30">VERIFIED SAFE</span>
        </div>
        <pre class="bg-slate-950 p-2.5 rounded text-[11px] font-mono text-slate-200 overflow-x-auto border border-slate-800">${p.remediated_snippet || '// In-place patch'}</pre>
      </div>
    `).join('');
  }

  return {
    load,
    runSwarm
  };
})();
