// RegRadar Web Studio - Multi-Agent Swarm Orchestrator Module

window.SwarmModule = (function () {
  let executionResult = null;

  async function load() {
    // Initial empty state or last run result
    if (!executionResult) {
      resetPipeline();
      const logContainer = document.getElementById("swarmEventFeed");
      if (logContainer && !AppState.currentWorkspace && logContainer.children.length === 0) {
        appendLog("SYSTEM", "Multi-agent remediation orchestrator ready. Connect a GitHub or GitLab repository in CI/CD & Git Webhooks to begin.");
      }
    }
    updateSwarmHeaderModel();
  }

  function updateSwarmHeaderModel() {
    const s = window.AppState && window.AppState.settings;
    if (!s) return;
    const badge = document.getElementById("swarmActiveModelBadge");
    const ctxBadge = document.getElementById("swarmModelContextBadge");

    const p = s.current_provider || "gemini";
    const m = s.current_model || "gemini-4-argon";
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
    resetAllAgents();
  }

  function setAgentState(agent, label, status) {
    const card = document.getElementById(`card-agent-${agent}`);
    const badge = document.getElementById(`badge-agent-${agent}`);
    if (!card || !badge) return;

    badge.textContent = label;

    if (status === "active") {
      card.className = "p-3 rounded-xl bg-cyan-950/40 border border-cyan-400 shadow-lg shadow-cyan-500/10 flex flex-col justify-between transition-all duration-300 relative group";
      badge.className = "text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-bold animate-pulse";
    } else if (status === "complete") {
      card.className = "p-3 rounded-xl bg-slate-950 border border-emerald-500/40 flex flex-col justify-between transition-all duration-300 relative group";
      badge.className = "text-[9px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold";
    } else if (status === "escalated") {
      card.className = "p-3 rounded-xl bg-slate-950 border border-amber-500/40 flex flex-col justify-between transition-all duration-300 relative group";
      badge.className = "text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold";
    } else {
      card.className = "p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between transition-all duration-300 relative group";
      badge.className = "text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700";
    }
  }

  function resetAllAgents() {
    ["auditor", "planner", "synthesizer", "supervisor"].forEach(a => setAgentState(a, "IDLE", "idle"));
  }

  async function runSwarm() {
    const btn = document.getElementById("runSwarmBtn");
    const applyToggle = document.getElementById("swarmApplyToggle");
    const apply = applyToggle ? applyToggle.checked : false;

    const targetPath = AppState.currentWorkspace;
    if (!targetPath) {
      appendLog("SYSTEM", "Execution halted: No remote repository connected. Please connect a GitHub or GitLab repository under CI/CD & Git Webhooks.");
      showToast("Please connect a remote repository in CI/CD & Git Webhooks first.", "error");
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('spinner', 'w-3.5 h-3.5')} Orchestrating Swarm...</span>`;
    }

    const logContainer = document.getElementById("swarmEventFeed");
    if (logContainer) logContainer.innerHTML = "";
    resetAllAgents();

    try {
      const s = window.AppState && window.AppState.settings;
      const activeProvider = (s && s.current_provider) ? s.current_provider.toUpperCase() : "GEMINI";
      const activeModel = (s && s.current_model) || "gemini-4-argon";
      const modelDisplayName = (window.getModelDisplayName) ? window.getModelDisplayName(s.current_provider, activeModel) : activeModel;

      appendLog("SYSTEM", `Initializing multi-agent neuro-symbolic remediation swarm [AI Engine: ${modelDisplayName} (${activeProvider})] on target workspace: ${targetPath}...`);
      setAgentState("auditor", "ANALYZING", "active");

      // Execute live backend multi-agent orchestration
      const result = await apiCall("/api/remediate", "POST", {
        target_path: targetPath,
        apply: apply
      });
      executionResult = result;

      setAgentState("auditor", "AUDITED", "complete");

      if (result.total_violations_found === 0) {
        appendLog("AUDITOR", "Static analysis & AST audit complete: 0 policy violations detected. Target workspace is fully compliant.");
        appendLog("SUPERVISOR", "No remediation actions required. Zero regressions found against regulatory invariants.");
        setAgentState("planner", "SKIPPED", "idle");
        setAgentState("synthesizer", "SKIPPED", "idle");
        setAgentState("supervisor", "INVARIANT PASS", "complete");
      } else {
        appendLog("AUDITOR", `AST dependency DAG analyzed: detected ${result.total_violations_found} violations (${result.autonomous_remediations_eligible} eligible for autonomous synthesis, ${result.human_escalations_required} gated for human sign-off).`);

        setAgentState("planner", "PLANNING", "active");

        // Render genuine multi-agent state-machine event stream from result.contexts
        if (result.contexts && Array.isArray(result.contexts) && result.contexts.length > 0) {
          let sawPlan = false;
          let sawSynthesize = false;
          let sawSupervisor = false;

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
                  sawPlan = true;
                } else if (state === "PLAN") {
                  agent = "PLANNER";
                  sawPlan = true;
                } else if (state === "SYNTHESIZE") {
                  agent = "SYNTHESIZER";
                  sawSynthesize = true;
                } else if (state === "DRY_RUN_SANDBOX" || state === "SEMANTIC_VERIFY" || state === "ACCEPT") {
                  agent = "SUPERVISOR";
                  sawSupervisor = true;
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

          if (sawPlan) setAgentState("planner", "PLANNED", "complete");
          if (sawSynthesize) setAgentState("synthesizer", "SYNTHESIZED", "complete");
          if (sawSupervisor) setAgentState("supervisor", "VERIFIED (0 DESTRUCTIVE)", "complete");
        } else {
          setAgentState("planner", "PLANNED", "complete");
          setAgentState("synthesizer", "SYNTHESIZED", "complete");
          setAgentState("supervisor", "VERIFIED (0 DESTRUCTIVE)", "complete");
        }

        appendLog("SUPERVISOR", `Swarm cycle completed. Verified & Accepted: ${result.patches_verified_and_accepted}, Escalated / Gated: ${result.patches_rejected_and_escalated + result.human_escalations_required}.`);
      }

      renderSwarmResults(result);
      showToast(`Swarm finished: ${result.patches_verified_and_accepted} patches verified safe!`, "success");
    } catch (err) {
      appendLog("ERROR", `Swarm execution halted: ${err.message}`);
      setAgentState("auditor", "ERROR", "escalated");
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
    const acceptedEl = document.getElementById("swarmAcceptedCount");
    const escalatedEl = document.getElementById("swarmEscalatedCount");
    const totalEl = document.getElementById("swarmTotalCount");
    if (acceptedEl) acceptedEl.textContent = res.patches_verified_and_accepted || 0;
    if (escalatedEl) escalatedEl.textContent = res.human_escalations_required || 0;
    if (totalEl) totalEl.textContent = res.total_violations_found || 0;

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
