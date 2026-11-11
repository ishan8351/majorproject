/**
 * RegRadar GitHub Hooks & Human-in-the-Loop PR Staging Controller
 * Zero emojis - Pure SVG iconography and Enterprise Design Tokens.
 */

window.GitHubModule = (function () {
  let stagedPRs = [];
  let config = {};
  let selectedPR = null;

  async function init() {
    await loadConfig();
    await loadPRs();
  }

  async function loadConfig() {
    try {
      const res = await fetch("/api/webhooks/github/config");
      if (res.ok) {
        config = await res.json();
        renderConfig();
      }
    } catch (e) {
      console.error("Failed to load GitHub webhook config", e);
    }
  }

  async function loadPRs() {
    try {
      const res = await fetch("/api/webhooks/github/prs");
      if (res.ok) {
        stagedPRs = await res.json();
        renderPRQueue();
        updateNavBadge();
      }
    } catch (e) {
      console.error("Failed to fetch staged PRs", e);
    }
  }

  function updateNavBadge() {
    const badge = document.getElementById("githubNavBadge");
    if (!badge) return;
    const awaiting = stagedPRs.filter(p => p.status === "AWAITING_HUMAN_APPROVAL").length;
    if (awaiting > 0) {
      badge.textContent = awaiting;
      badge.classList.remove("hidden");
    } else {
      badge.classList.add("hidden");
    }
  }

  function renderConfig() {
    const endpointEl = document.getElementById("ghWebhookEndpoint");
    const secretStatusEl = document.getElementById("ghSecretStatus");
    const signoffPolicyEl = document.getElementById("ghSignoffPolicy");

    const host = window.location.origin || "http://127.0.0.1:8000";
    if (endpointEl) {
      endpointEl.value = `${host}${config.webhook_endpoint || "/api/webhooks/github"}`;
    }
    if (secretStatusEl) {
      secretStatusEl.innerHTML = config.secret_configured
        ? `<span class="inline-flex items-center gap-1 text-emerald-400 font-medium">${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Configured</span>`
        : `<span class="inline-flex items-center gap-1 text-amber-400 font-medium">${window.RegIcons.svg('alert', 'w-3.5 h-3.5')} Not Set (Dev Mode)</span>`;
    }
    if (signoffPolicyEl) {
      signoffPolicyEl.innerHTML = config.require_human_signoff
        ? `<span class="inline-flex items-center gap-1 text-cyan-400 font-semibold">${window.RegIcons.svg('lock', 'w-3.5 h-3.5')} Mandatory Human Sign-Off</span>`
        : `<span class="text-slate-400 font-medium">Automated Merging Allowed</span>`;
    }
  }

  function renderPRQueue() {
    const listEl = document.getElementById("ghStagedPRList");
    const emptyEl = document.getElementById("ghEmptyPRList");
    if (!listEl) return;

    if (!stagedPRs || stagedPRs.length === 0) {
      listEl.innerHTML = "";
      if (emptyEl) emptyEl.classList.remove("hidden");
      return;
    }

    if (emptyEl) emptyEl.classList.add("hidden");

    listEl.innerHTML = stagedPRs.map(pr => {
      const isAwaiting = pr.status === "AWAITING_HUMAN_APPROVAL";
      const isApproved = pr.status === "APPROVED";
      const isRejected = pr.status === "REJECTED";
      const isRevise = pr.status === "REVISION_REQUESTED";

      let statusBadge = "";
      if (isAwaiting) {
        statusBadge = `<span class="theme-badge theme-badge-intermediate">${window.RegIcons.svg('userCheck', 'w-3 h-3')} Awaiting Human Sign-Off</span>`;
      } else if (isApproved) {
        statusBadge = `<span class="theme-badge theme-badge-leaf">${window.RegIcons.svg('check', 'w-3 h-3')} Operator Approved</span>`;
      } else if (isRejected) {
        statusBadge = `<span class="theme-badge theme-badge-critical">${window.RegIcons.svg('close', 'w-3 h-3')} Rejected</span>`;
      } else {
        statusBadge = `<span class="theme-badge theme-badge-intermediate">${window.RegIcons.svg('edit', 'w-3 h-3')} Revision Requested</span>`;
      }

      let riskBadge = "";
      if (pr.risk_tier === "CRITICAL_ROOT") {
        riskBadge = `<span class="theme-badge theme-badge-critical">${window.RegIcons.svg('shieldAlert', 'w-3 h-3')} CRITICAL_ROOT</span>`;
      } else if (pr.risk_tier === "INTERMEDIATE") {
        riskBadge = `<span class="theme-badge theme-badge-intermediate">${window.RegIcons.svg('shield', 'w-3 h-3')} INTERMEDIATE</span>`;
      } else {
        riskBadge = `<span class="theme-badge theme-badge-leaf">${window.RegIcons.svg('shieldCheck', 'w-3 h-3')} LEAF_SAFE</span>`;
      }

      const actorBadge = pr.is_agent_pr
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-purple-500/10 text-purple-400 border border-purple-500/30 flex items-center gap-1">${window.RegIcons.svg('cpu', 'w-3 h-3')} Agent PR</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-500/10 text-slate-300 border border-slate-600/30">Human PR</span>`;

      return `
        <div class="p-4 rounded-xl border border-slate-800 bg-slate-900/60 hover:border-slate-700 transition flex flex-col gap-3">
          <div class="flex items-start justify-between gap-4">
            <div class="space-y-1">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="text-xs font-mono font-bold text-slate-400">${pr.repo}#${pr.pr_number}</span>
                ${actorBadge}
                ${riskBadge}
                ${statusBadge}
              </div>
              <h4 class="text-sm font-semibold text-slate-100 hover:text-cyan-400 cursor-pointer" onclick="window.GitHubModule.inspectPR('${pr.id}')">
                ${pr.title}
              </h4>
              <div class="text-xs text-slate-400 flex items-center gap-3 font-mono">
                <span>Branch: <span class="text-cyan-400">${pr.head_branch}</span> &rarr; <span class="text-slate-300">${pr.base_branch}</span></span>
                <span>Author: <span class="text-slate-200">${pr.author}</span></span>
              </div>
            </div>

            <!-- Invariant Quick Indicator -->
            <div class="text-right shrink-0">
              <div class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Zero-Destruction</div>
              <div class="text-xs font-bold text-emerald-400 flex items-center justify-end gap-1 mt-0.5">
                ${window.RegIcons.svg('check', 'w-3.5 h-3.5')} ${pr.invariant_verdict} (0 Drops)
              </div>
            </div>
          </div>

          <!-- Operator Sign-Off Actions -->
          <div class="pt-2 border-t border-slate-800/80 flex items-center justify-between flex-wrap gap-2">
            <button onclick="window.GitHubModule.inspectPR('${pr.id}')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition">
              ${window.RegIcons.svg('file', 'w-3.5 h-3.5')} View Plan & Centrality Summary
            </button>

            <div class="flex items-center gap-2">
              ${isAwaiting ? `
                <button onclick="window.GitHubModule.reviewPR('${pr.id}', 'APPROVE')" class="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-md shadow-emerald-600/20 flex items-center gap-1.5 transition">
                  ${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Approve & Sign Off
                </button>
                <button onclick="window.GitHubModule.promptRevision('${pr.id}')" class="px-3 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-xs font-medium flex items-center gap-1.5 transition">
                  ${window.RegIcons.svg('edit', 'w-3.5 h-3.5')} Request Revision
                </button>
                <button onclick="window.GitHubModule.reviewPR('${pr.id}', 'REJECT')" class="px-3 py-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 text-xs font-medium flex items-center gap-1.5 transition">
                  ${window.RegIcons.svg('close', 'w-3.5 h-3.5')} Reject PR
                </button>
              ` : `
                <div class="text-xs text-slate-400 italic">
                  Reviewed by <strong class="text-slate-200">${pr.reviewed_by || 'operator'}</strong>
                  ${pr.review_comment ? `: "${pr.review_comment}"` : ''}
                </div>
              `}
            </div>
          </div>
        </div>
      `;
    }).join("");
  }

  async function reviewPR(prId, decision, comment = "") {
    try {
      const operatorId = localStorage.getItem("regradar_operator_id") || "secops_admin";
      const res = await fetch(`/api/webhooks/github/prs/${prId}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision: decision,
          reviewer: operatorId,
          comment: comment || (decision === "APPROVE" ? "Approved zero-destruction patch." : "Operator decision recorded.")
        })
      });
      if (res.ok) {
        await loadPRs();
        closeDrawer();
      }
    } catch (e) {
      console.error("Failed to review PR", e);
    }
  }

  function promptRevision(prId) {
    const notes = prompt("Enter revision instructions for the AI remediation agent:", "Please constrain the blast radius and preserve existing security group tags.");
    if (notes !== null) {
      reviewPR(prId, "REVISE", notes);
    }
  }

  function inspectPR(prId) {
    selectedPR = stagedPRs.find(p => p.id === prId);
    if (!selectedPR) return;

    const drawer = document.getElementById("ghPRDrawer");
    const titleEl = document.getElementById("ghDrawerTitle");
    const metaEl = document.getElementById("ghDrawerMeta");
    const contentEl = document.getElementById("ghDrawerContent");

    if (titleEl) titleEl.textContent = `${selectedPR.repo}#${selectedPR.pr_number}: ${selectedPR.title}`;
    if (metaEl) {
      metaEl.innerHTML = `
        <div class="flex items-center gap-2 text-xs text-slate-400">
          <span>Author: <strong class="text-slate-200">${selectedPR.author}</strong></span>
          <span>&bull;</span>
          <span>Risk: <strong class="text-slate-200">${selectedPR.risk_tier}</strong></span>
          <span>&bull;</span>
          <span>Verdict: <strong class="text-emerald-400">${selectedPR.invariant_verdict}</strong></span>
        </div>
      `;
    }
    if (contentEl) {
      contentEl.innerHTML = `
        <div class="space-y-4">
          <div class="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
${selectedPR.summary_markdown || "No extended markdown report provided."}
          </div>
        </div>
      `;
    }

    if (drawer) drawer.classList.remove("hidden");
  }

  function closeDrawer() {
    const drawer = document.getElementById("ghPRDrawer");
    if (drawer) drawer.classList.add("hidden");
  }

  async function triggerSimulation(riskTier = "LEAF_SAFE") {
    try {
      const btn = document.getElementById("simulateAgentPRBtn");
      if (btn) btn.innerHTML = `${window.RegIcons.svg('spinner', 'w-3.5 h-3.5')} Simulating PR Webhook...`;

      const res = await fetch(`/api/webhooks/github/simulate?risk=${riskTier}&is_agent=true`, {
        method: "POST"
      });
      if (res.ok) {
        await loadPRs();
      }
    } catch (e) {
      console.error("Simulation failed", e);
    } finally {
      const btn = document.getElementById("simulateAgentPRBtn");
      if (btn) btn.innerHTML = `${window.RegIcons.svg('cpu', 'w-3.5 h-3.5')} Simulate Agent PR Event`;
    }
  }

  function copyWebhookUrl() {
    const input = document.getElementById("ghWebhookEndpoint");
    if (!input) return;
    navigator.clipboard.writeText(input.value);
    const copyBtn = document.getElementById("copyWebhookBtn");
    if (copyBtn) {
      const original = copyBtn.innerHTML;
      copyBtn.innerHTML = `${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Copied`;
      setTimeout(() => { copyBtn.innerHTML = original; }, 2000);
    }
  }

  return {
    init,
    loadConfig,
    loadPRs,
    inspectPR,
    closeDrawer,
    reviewPR,
    promptRevision,
    triggerSimulation,
    copyWebhookUrl
  };
})();
