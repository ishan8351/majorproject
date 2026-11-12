/**
 * RegRadar CI/CD & Remote Git Webhooks Controller
 * Supports GitHub Actions & GitLab CI/CD Webhooks with SQLite persistence.
 * Zero emojis - Pure SVG iconography and Enterprise Design Tokens.
 */

window.GitHubModule = (function () {
  let stagedPRs = [];
  let githubConfig = {};
  let gitlabConfig = {};
  let connectedRepos = [];
  let selectedPR = null;

  async function init() {
    await loadConfig();
    await loadPRs();
    await loadConnectedRepos();
    await loadDbStats();
  }

  async function loadDbStats() {
    try {
      const res = await fetch("/api/database/status");
      if (res.ok) {
        const stats = await res.json();
        const pill = document.getElementById("ghDbPill");
        if (pill) {
          const prCount = (stats.tables && stats.tables.staged_prs && stats.tables.staged_prs.total) || 0;
          pill.textContent = `SQLite 3 Persistent: ${prCount} PRs/MRs`;
        }
      }
    } catch (e) {
      console.warn("Failed to load DB stats", e);
    }
  }

  async function loadConfig() {
    const host = window.location.origin || "http://127.0.0.1:8000";

    // 1. GitHub Config
    try {
      const res = await fetch("/api/webhooks/github/config");
      if (res.ok) {
        githubConfig = await res.json();
      }
    } catch (e) {
      console.error("Failed to load GitHub webhook config", e);
    }

    // 2. GitLab Config
    try {
      const res = await fetch("/api/webhooks/gitlab/config");
      if (res.ok) {
        gitlabConfig = await res.json();
      }
    } catch (e) {
      console.error("Failed to load GitLab webhook config", e);
    }

    renderEndpoints(host);
  }

  function renderEndpoints(host) {
    const ghEndpointEl = document.getElementById("ghWebhookEndpoint");
    const glEndpointEl = document.getElementById("glWebhookEndpoint");
    const secretStatusEl = document.getElementById("ghSecretStatus");
    const signoffPolicyEl = document.getElementById("ghSignoffPolicy");

    if (ghEndpointEl) {
      ghEndpointEl.value = `${host}${githubConfig.webhook_endpoint || "/api/webhooks/github"}`;
    }
    if (glEndpointEl) {
      glEndpointEl.value = `${host}${gitlabConfig.webhook_endpoint || "/api/webhooks/gitlab"}`;
    }
    if (secretStatusEl) {
      secretStatusEl.innerHTML = githubConfig.secret_configured
        ? `<span class="inline-flex items-center gap-1 text-emerald-400 font-medium">${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Configured</span>`
        : `<span class="inline-flex items-center gap-1 text-amber-400 font-medium">${window.RegIcons.svg('alert', 'w-3.5 h-3.5')} Not Set (Dev Mode)</span>`;
    }
    if (signoffPolicyEl) {
      signoffPolicyEl.innerHTML = githubConfig.require_human_signoff
        ? `<span class="inline-flex items-center gap-1 text-cyan-400 font-semibold">${window.RegIcons.svg('lock', 'w-3.5 h-3.5')} Mandatory Human Sign-Off</span>`
        : `<span class="text-slate-400 font-medium">Automated Merging Allowed</span>`;
    }
  }

  async function loadConnectedRepos() {
    try {
      const res = await fetch("/api/workspaces");
      if (res.ok) {
        connectedRepos = await res.json();
        renderConnectedRepos();
      }
    } catch (e) {
      console.error("Failed to load connected repositories", e);
    }
  }

  function renderConnectedRepos() {
    const listEl = document.getElementById("connectedReposList");
    if (!listEl) return;

    if (!connectedRepos || connectedRepos.length === 0) {
      listEl.innerHTML = `
        <div class="p-3.5 text-center rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
          No remote repositories connected. Use the form above to connect a GitHub or GitLab repository.
        </div>
      `;
      return;
    }

    listEl.innerHTML = connectedRepos.map(r => {
      const isGitLab = (r.name && r.name.toLowerCase().includes("gitlab")) || (r.description && r.description.toLowerCase().includes("gitlab"));
      const providerBadge = isGitLab
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-orange-500/10 text-orange-400 border border-orange-500/30">GitLab</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-500/10 text-slate-300 border border-slate-600/30">GitHub</span>`;

      const resBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">${r.resource_count || 0} resources</span>`;

      return `
        <div class="flex items-center justify-between p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs flex-wrap gap-2">
          <div class="flex items-center space-x-2.5 flex-wrap gap-1">
            ${providerBadge}
            <span class="font-mono font-bold text-slate-200">${r.path}</span>
            ${resBadge}
            <span class="text-slate-500 font-mono text-[11px]">&bull; ${r.description || 'Remote Git Repository'}</span>
          </div>
          <div class="flex items-center space-x-2">
            <button onclick="window.GitHubModule.syncRepo('${r.id}')" title="Pull latest changes from remote branch" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-medium transition cursor-pointer flex items-center gap-1">
              <svg class="w-3 h-3 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
              <span>Sync</span>
            </button>
            <button onclick="window.GitHubModule.disconnectRepo('${r.id}')" class="px-2.5 py-1 rounded bg-rose-600/10 hover:bg-rose-600/20 text-rose-400 border border-rose-500/30 text-[11px] font-medium transition cursor-pointer">
              Disconnect
            </button>
          </div>
        </div>
      `;
    }).join("");
  }

  function toggleConnectForm() {
    const card = document.getElementById("connectRepoCard");
    if (card) {
      card.classList.toggle("hidden");
    }
  }

  async function submitConnectRepo() {
    const providerEl = document.getElementById("connectProvider");
    const nameEl = document.getElementById("connectRepoName");
    const branchEl = document.getElementById("connectBranch");
    const tokenEl = document.getElementById("connectToken");
    const submitBtn = document.getElementById("submitConnectBtn");

    const provider = (providerEl && providerEl.value) || "github";
    const repoName = (nameEl && nameEl.value.trim()) || "";
    const branch = (branchEl && branchEl.value.trim()) || "main";
    const token = (tokenEl && tokenEl.value.trim()) || "";

    if (!repoName) {
      alert("Please enter a valid remote repository name or clone URL (e.g. 'owner/repo' or 'https://github.com/owner/repo').");
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = `<span class="inline-flex items-center gap-1.5">${window.RegIcons.svg('spinner', 'w-3.5 h-3.5')} <span>Verifying & Cloning...</span></span>`;
    }

    try {
      const res = await fetch("/api/workspaces/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: provider,
          repo_name: repoName,
          default_branch: branch,
          framework: "Terraform / OpenTofu",
          auth_token: token || undefined
        })
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const connected = await res.json();
      if (nameEl) nameEl.value = "";
      if (tokenEl) tokenEl.value = "";

      // Refresh workspaces selector and repos list
      if (window.loadWorkspaces) await window.loadWorkspaces();
      await loadConnectedRepos();

      // Auto-select in workspace selector
      const selector = document.getElementById("workspaceSelector");
      if (selector && connected.path) {
        selector.value = connected.path;
        if (window.AppState) window.AppState.currentWorkspace = connected.path;
      }

      if (window.showToast) {
        window.showToast(`Connected ${connected.name}: ${connected.resource_count || 0} declarative resources verified`, "success");
      }
    } catch (e) {
      alert(`Failed to connect repository: ${e.message}`);
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = `<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg><span>Verify & Connect Repository</span>`;
      }
    }
  }

  async function syncRepo(repoId) {
    try {
      if (window.showToast) window.showToast("Pulling latest commits from remote...", "info");
      const res = await fetch(`/api/workspaces/${encodeURIComponent(repoId)}/sync`, {
        method: "POST"
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const updated = await res.json();
      if (window.loadWorkspaces) await window.loadWorkspaces();
      await loadConnectedRepos();
      if (window.showToast) {
        window.showToast(`Synced ${updated.name}: ${updated.resource_count || 0} resources verified`, "success");
      }
    } catch (e) {
      alert(`Failed to sync repository: ${e.message}`);
    }
  }

  async function disconnectRepo(repoId) {
    if (!confirm(`Are you sure you want to disconnect repository '${repoId}'?`)) return;

    try {
      const res = await fetch(`/api/workspaces/${encodeURIComponent(repoId)}`, {
        method: "DELETE"
      });
      if (res.ok) {
        if (window.loadWorkspaces) await window.loadWorkspaces();
        await loadConnectedRepos();
        if (window.showToast) window.showToast("Repository disconnected successfully", "info");
      } else {
        alert("Failed to disconnect repository.");
      }
    } catch (e) {
      alert(`Error disconnecting repository: ${e.message}`);
    }
  }

  function switchGuideTab(tab) {
    const btnGitHub = document.getElementById("tabBtnGitHub");
    const btnGitLab = document.getElementById("tabBtnGitLab");
    const panelGitHub = document.getElementById("panelGuideGitHub");
    const panelGitLab = document.getElementById("panelGuideGitLab");

    if (tab === "github") {
      if (btnGitHub) {
        btnGitHub.className = "px-3 py-1 rounded text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30 transition cursor-pointer";
      }
      if (btnGitLab) {
        btnGitLab.className = "px-3 py-1 rounded text-xs font-semibold text-slate-400 hover:text-slate-200 transition cursor-pointer";
      }
      if (panelGitHub) panelGitHub.classList.remove("hidden");
      if (panelGitLab) panelGitLab.classList.add("hidden");
    } else {
      if (btnGitLab) {
        btnGitLab.className = "px-3 py-1 rounded text-xs font-semibold bg-orange-500/20 text-orange-300 border border-orange-500/30 transition cursor-pointer";
      }
      if (btnGitHub) {
        btnGitHub.className = "px-3 py-1 rounded text-xs font-semibold text-slate-400 hover:text-slate-200 transition cursor-pointer";
      }
      if (panelGitLab) panelGitLab.classList.remove("hidden");
      if (panelGitHub) panelGitHub.classList.add("hidden");
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
      const isGitLab = pr.provider === "gitlab" || (pr.repo && pr.repo.includes("gitlab"));
      const isAwaiting = pr.status === "AWAITING_HUMAN_APPROVAL";
      const isApproved = pr.status === "APPROVED";
      const isRejected = pr.status === "REJECTED";

      const providerBadge = isGitLab
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-orange-500/10 text-orange-400 border border-orange-500/30 flex items-center gap-1">GitLab MR</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-500/10 text-slate-300 border border-slate-600/30 flex items-center gap-1">GitHub PR</span>`;

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

      const idDisplay = isGitLab ? `${pr.repo}!${pr.pr_number}` : `${pr.repo}#${pr.pr_number}`;

      return `
        <div class="p-4 rounded-xl border border-slate-800 bg-slate-900/60 hover:border-slate-700 transition flex flex-col gap-3">
          <div class="flex items-start justify-between gap-4">
            <div class="space-y-1">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="text-xs font-mono font-bold text-slate-400">${idDisplay}</span>
                ${providerBadge}
                ${actorBadge}
                ${riskBadge}
                ${statusBadge}
              </div>
              <h4 class="text-sm font-semibold text-slate-100 hover:text-amber-400 cursor-pointer" onclick="window.GitHubModule.inspectPR('${pr.id}')">
                ${pr.title}
              </h4>
              <div class="text-xs text-slate-400 flex items-center gap-3 font-mono">
                <span>Branch: <span class="text-amber-400">${pr.head_branch}</span> &rarr; <span class="text-slate-300">${pr.base_branch}</span></span>
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
            <button onclick="window.GitHubModule.inspectPR('${pr.id}')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition cursor-pointer">
              ${window.RegIcons.svg('file', 'w-3.5 h-3.5')} View Plan & Centrality Summary
            </button>

            <div class="flex items-center gap-2">
              ${isAwaiting ? `
                <button onclick="window.GitHubModule.reviewPR('${pr.id}', 'APPROVE')" class="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-md shadow-emerald-600/20 flex items-center gap-1.5 transition cursor-pointer">
                  ${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Approve & Sign Off
                </button>
                <button onclick="window.GitHubModule.promptRevision('${pr.id}')" class="px-3 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-xs font-medium flex items-center gap-1.5 transition cursor-pointer">
                  ${window.RegIcons.svg('edit', 'w-3.5 h-3.5')} Request Revision
                </button>
                <button onclick="window.GitHubModule.reviewPR('${pr.id}', 'REJECT')" class="px-3 py-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 text-xs font-medium flex items-center gap-1.5 transition cursor-pointer">
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
    const notes = prompt("Enter revision instructions for the AI remediation agent:", "Please constrain blast radius and preserve existing security group tags.");
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

  function copyGitLabWebhookUrl() {
    const input = document.getElementById("glWebhookEndpoint");
    if (!input) return;
    navigator.clipboard.writeText(input.value);
    const copyBtn = document.getElementById("copyGlWebhookBtn");
    if (copyBtn) {
      const original = copyBtn.innerHTML;
      copyBtn.innerHTML = `${window.RegIcons.svg('check', 'w-3.5 h-3.5')} Copied`;
      setTimeout(() => { copyBtn.innerHTML = original; }, 2000);
    }
  }

  function copyWorkflowCode(type) {
    let yaml = "";
    if (type === "gitlab") {
      yaml = `stages:
  - governance

regradar-zero-destruction-gate:
  stage: governance
  image: ghcr.io/opentofu/opentofu:latest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - tofu init
    - tofu plan -out=plan.tfplan
    - tofu show -json plan.tfplan > plan.json
    - |
      curl -s -X POST "\${REGRADAR_URL}/api/webhooks/gitlab" \\
        -H "Content-Type: application/json" \\
        -H "X-Gitlab-Event: Merge Request Hook" \\
        -H "X-Gitlab-Token: \${REGRADAR_GITLAB_WEBHOOK_SECRET}" \\
        -d @plan.json`;
    } else {
      yaml = `name: RegRadar Zero-Destruction Gate
on:
  pull_request:
    branches: [ main, master ]

jobs:
  regradar-invariant-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup OpenTofu
        uses: opentofu/setup-opentofu@v1

      - name: Generate Plan Diff
        run: |
          tofu init
          tofu plan -out=plan.tfplan
          tofu show -json plan.tfplan > plan.json

      - name: Dispatch Plan to RegRadar Gate
        env:
          REGRADAR_URL: \${{ secrets.REGRADAR_URL }}
        run: |
          curl -s -X POST "\${REGRADAR_URL}/api/webhooks/github" \\
            -H "Content-Type: application/json" \\
            -H "X-GitHub-Event: pull_request" \\
            -d @plan.json`;
    }
    navigator.clipboard.writeText(yaml);
    if (window.showToast) window.showToast(`Copied ${type === 'gitlab' ? '.gitlab-ci.yml' : 'GitHub Action'} workflow to clipboard`, "info");
  }

  async function toggleWebhookLogs() {
    const drawer = document.getElementById("ghLogsDrawer");
    if (!drawer) return;
    const isHidden = drawer.classList.contains("hidden");
    if (isHidden) {
      drawer.classList.remove("hidden");
      await loadWebhookLogs();
    } else {
      drawer.classList.add("hidden");
    }
  }

  function closeLogsDrawer() {
    const drawer = document.getElementById("ghLogsDrawer");
    if (drawer) drawer.classList.add("hidden");
  }

  async function loadWebhookLogs() {
    const listEl = document.getElementById("ghWebhookLogsList");
    if (!listEl) return;
    try {
      listEl.innerHTML = `<div class="p-4 text-xs text-slate-400 text-center">Loading webhook dispatch audit trail...</div>`;
      const res = await fetch("/api/webhooks/logs?limit=30");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const logs = await res.json();
      if (!logs || logs.length === 0) {
        listEl.innerHTML = `
          <div class="p-6 text-center border border-slate-800 rounded-lg bg-slate-900/60 text-slate-400 text-xs">
            No outgoing webhook events recorded in SQLite yet.
          </div>
        `;
        return;
      }
      listEl.innerHTML = logs.map(l => {
        const isSuccess = l.success;
        const codeBadge = isSuccess
          ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">HTTP ${l.status_code || 200}</span>`
          : `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">HTTP ${l.status_code || 'ERR'}</span>`;
        return `
          <div class="p-3 rounded-lg border border-slate-800 bg-slate-900/80 space-y-1 text-xs">
            <div class="flex items-center justify-between">
              <span class="font-mono font-bold text-amber-400">${l.event_type}</span>
              ${codeBadge}
            </div>
            <div class="text-[11px] text-slate-300 font-mono truncate" title="${l.target_url}">
              ${l.target_url}
            </div>
            <div class="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800/60">
              <span>${l.dispatched_at ? new Date(l.dispatched_at).toLocaleTimeString() : ''}</span>
              ${l.error_message ? `<span class="text-rose-400 truncate max-w-xs">${l.error_message}</span>` : '<span class="text-emerald-400">Delivered</span>'}
            </div>
          </div>
        `;
      }).join('');
    } catch (e) {
      listEl.innerHTML = `<div class="p-4 text-xs text-rose-400 text-center">Failed to load logs: ${e.message}</div>`;
    }
  }

  async function dispatchTestNotification() {
    const input = document.getElementById("ghTestWebhookUrl");
    if (!input || !input.value) {
      alert("Please provide a valid webhook URL.");
      return;
    }
    const targetUrl = input.value.trim();
    try {
      const res = await fetch(`/api/webhooks/dispatch-test?url=${encodeURIComponent(targetUrl)}`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.success) {
        alert("Webhook test payload sent successfully (HTTP " + data.status_code + ")!");
      } else {
        alert("Webhook test failed: " + data.message);
      }
      await loadWebhookLogs();
    } catch (e) {
      alert("Failed to send webhook test: " + e.message);
    }
  }

  return {
    init,
    loadConfig,
    loadPRs,
    loadConnectedRepos,
    toggleConnectForm,
    submitConnectRepo,
    syncRepo,
    disconnectRepo,
    switchGuideTab,
    inspectPR,
    closeDrawer,
    reviewPR,
    promptRevision,
    copyWebhookUrl,
    copyGitLabWebhookUrl,
    copyWorkflowCode,
    toggleWebhookLogs,
    closeLogsDrawer,
    loadWebhookLogs,
    dispatchTestNotification
  };
})();
