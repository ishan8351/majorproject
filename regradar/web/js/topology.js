// RegRadar Web Studio - Interactive Topology & Centrality DAG Module

window.TopologyModule = (function () {
  let cy = null;
  let rawData = null;
  let currentOrientation = "TB";
  let activeFilter = "ALL";
  let activeNodeId = null;

  function getGraphStylesheet(isLight) {
    const textColor = isLight ? "#111827" : "#f8fafc";
    const textOutline = isLight ? "#ffffff" : "#181b22";
    const defaultBg = isLight ? "#f1ede2" : "#292e3b";
    const defaultBorder = isLight ? "#ded7c4" : "#3d4455";
    const edgeColor = isLight ? "#94a3b8" : "#525b71";
    const edgeArrowColor = isLight ? "#64748b" : "#94a3b8";

    return [
      {
        selector: "node",
        style: {
          "label": "data(card_label)",
          "text-wrap": "wrap",
          "text-max-width": "160px",
          "font-size": "9.5px",
          "font-family": "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
          "font-weight": 600,
          "line-height": 1.35,
          "text-justification": "center",
          "color": textColor,
          "text-valign": "bottom",
          "text-margin-y": 8,
          "text-outline-color": textOutline,
          "text-outline-width": 3,
          "text-outline-opacity": 0.95,
          "shape": "round-rectangle",
          "width": 46,
          "height": 46,
          "border-width": 2.5,
          "background-color": defaultBg,
          "border-color": defaultBorder,
          "transition-property": "background-color, border-color, width, height, shadow-blur",
          "transition-duration": "0.2s"
        }
      },
      {
        selector: 'node[risk_tier = "CRITICAL_ROOT"]',
        style: {
          "shape": "diamond",
          "width": 56,
          "height": 56,
          "background-color": isLight ? "#dc2626" : "#e11d48",
          "border-color": isLight ? "#991b1b" : "#f43f5e",
          "border-width": 3.5,
          "shadow-blur": 18,
          "shadow-color": "#e11d48",
          "shadow-opacity": 0.65
        }
      },
      {
        selector: 'node[risk_tier = "INTERMEDIATE"]',
        style: {
          "shape": "round-rectangle",
          "width": 48,
          "height": 48,
          "background-color": isLight ? "#d97706" : "#f59e0b",
          "border-color": isLight ? "#b45309" : "#fbbf24",
          "border-width": 2.5
        }
      },
      {
        selector: 'node[risk_tier = "LEAF_SAFE"]',
        style: {
          "shape": "round-rectangle",
          "width": 42,
          "height": 42,
          "background-color": isLight ? "#059669" : "#10b981",
          "border-color": isLight ? "#047857" : "#34d399",
          "border-width": 2
        }
      },
      {
        selector: "edge",
        style: {
          "width": 2.2,
          "line-color": edgeColor,
          "target-arrow-color": edgeArrowColor,
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "arrow-scale": 1.15
        }
      },
      {
        selector: ".highlighted-node",
        style: {
          "border-width": 4.5,
          "border-color": isLight ? "#0284c7" : "#38bdf8",
          "shadow-blur": 24,
          "shadow-color": isLight ? "#0284c7" : "#38bdf8",
          "shadow-opacity": 0.95
        }
      },
      {
        selector: ".highlighted-descendant",
        style: {
          "background-color": isLight ? "#e11d48" : "#f43f5e",
          "border-color": isLight ? "#be123c" : "#fb7185",
          "shadow-blur": 16,
          "shadow-color": "#f43f5e",
          "shadow-opacity": 0.75
        }
      },
      {
        selector: ".highlighted-edge",
        style: {
          "line-color": isLight ? "#0284c7" : "#38bdf8",
          "target-arrow-color": isLight ? "#0284c7" : "#38bdf8",
          "width": 3.4
        }
      },
      {
        selector: ".search-match",
        style: {
          "border-width": 4.5,
          "border-color": "#f59e0b",
          "shadow-blur": 26,
          "shadow-color": "#f59e0b",
          "shadow-opacity": 0.95
        }
      },
      {
        selector: ".dimmed",
        style: {
          "opacity": 0.16
        }
      }
    ];
  }

  async function load() {
    const container = document.getElementById("cyContainer");
    if (!container) return;

    if (!AppState.currentWorkspace) {
      showEmptyRepoState();
      return;
    }

    try {
      showLoading(true);
      const targetPath = AppState.currentWorkspace;
      const data = await apiCall(`/api/graph/export?target_path=${encodeURIComponent(targetPath)}&format=cytoscape`);
      rawData = data;
      renderGraph(data);
      updateSummaryMetrics(data);
    } catch (err) {
      console.error("Topology load error:", err);
      showToast(`Topology load failed: ${err.message}`, "error");
    } finally {
      showLoading(false);
    }
  }

  function showEmptyRepoState() {
    const cyElement = document.getElementById("cy");
    if (!cyElement) return;
    if (cy) {
      cy.destroy();
      cy = null;
    }
    cyElement.innerHTML = `
      <div class="h-full flex flex-col items-center justify-center p-8 text-center select-none">
        <div class="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 mb-4 shadow-xl">
          <svg class="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        </div>
        <h3 class="text-base font-bold text-slate-100 mb-1">No Remote Repository Connected</h3>
        <p class="text-xs text-slate-400 max-w-md mb-6 leading-relaxed">
          RegRadar operates exclusively on remote GitHub and GitLab repositories. Local repositories are disabled. Connect your remote repository via CI/CD Webhooks to visualize blast-radius topology.
        </p>
        <button onclick="switchTab('github')" class="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs shadow-lg shadow-amber-600/20 flex items-center gap-2 cursor-pointer transition">
          <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>
          <span>Connect Remote Repository in CI/CD</span>
        </button>
      </div>
    `;
    updateSummaryMetrics({ metrics: {} });
  }

  let graphLoadStartTime = 0;

  function showLoading(show) {
    const loader = document.getElementById("topologyLoader");
    const cyElement = document.getElementById("cy");
    if (!loader) return;
    if (show) {
      graphLoadStartTime = Date.now();
      loader.style.opacity = "1";
      loader.classList.remove("hidden");
      if (cyElement) {
        cyElement.classList.add("graph-stabilizing");
        cyElement.classList.remove("graph-revealed");
      }
    } else {
      const elapsed = Date.now() - graphLoadStartTime;
      const minDuration = 1000; // 1-second beautiful blurred loading screen before revealing graph
      const remaining = Math.max(0, minDuration - elapsed);
      setTimeout(() => {
        if (cy) {
          cy.resize();
          cy.fit(undefined, 50);
        }
        if (cyElement) {
          cyElement.classList.remove("graph-stabilizing");
          cyElement.classList.add("graph-revealed");
        }
        loader.style.opacity = "0";
        setTimeout(() => {
          loader.classList.add("hidden");
        }, 400);
      }, remaining);
    }
  }

  function renderGraph(graphData) {
    const cyElement = document.getElementById("cy");
    if (!cyElement) return;

    if (cyElement) {
      cyElement.classList.add("graph-stabilizing");
      cyElement.classList.remove("graph-revealed");
    }

    if (typeof cytoscape === "undefined") {
      renderSvgFallback(cyElement, graphData);
      return;
    }

    // Destroy existing instance
    if (cy) {
      cy.destroy();
      cy = null;
    }

    const elements = graphData.elements;
    const isLight = document.documentElement.getAttribute("data-theme") === "light";

    // Enrich node data for detailed visual cards
    if (elements && elements.nodes) {
      elements.nodes.forEach(node => {
        const d = node.data;
        const idParts = (d.id || "").split(".");
        const shortName = idParts.length > 1 ? idParts.slice(1).join(".") : d.id;
        const resType = d.resource_type || (idParts.length > 1 ? idParts[0] : "resource");
        const riskTier = d.risk_tier || "LEAF_SAFE";
        const scoreVal = Number(d.score || d.betweenness || 0).toFixed(3);
        const descCount = d.descendants || 0;

        let tierBadge = "LEAF";
        if (riskTier === "CRITICAL_ROOT") tierBadge = "ROOT";
        else if (riskTier === "INTERMEDIATE") tierBadge = "MID";

        d.short_name = shortName;
        d.res_type = resType;
        d.tier_badge = tierBadge;
        d.card_label = `${shortName}\n${resType}\n[${tierBadge} • blast ${scoreVal} • ${descCount} child]`;
      });
    }

    cy = cytoscape({
      container: cyElement,
      elements: elements,
      boxSelectionEnabled: false,
      autounselectify: false,
      wheelSensitivity: 0.14,
      minZoom: 0.2,
      maxZoom: 3.5,
      style: getGraphStylesheet(isLight),
      layout: {
        name: typeof cytoscape("layout", "dagre") !== "undefined" ? "dagre" : "breadthfirst",
        directed: true,
        padding: 60,
        nodeSep: 95,
        rankSep: 115,
        edgeSep: 35,
        rankDir: currentOrientation,
        spacingFactor: 1.6,
        animate: false // Eliminates the flying-in animation completely
      }
    });

    // Update zoom display indicator
    cy.on("zoom", updateZoomDisplay);
    updateZoomDisplay();

    // Node click interactions
    cy.on("tap", "node", function (evt) {
      const node = evt.target;
      inspectNode(node.data());
      highlightBlastRadius(node);
    });

    // Background tap clears highlight
    cy.on("tap", function (evt) {
      if (evt.target === cy) {
        clearHighlights();
        hideNodeInspector();
      }
    });
  }

  function updateZoomDisplay() {
    const el = document.getElementById("topoZoomDisplay");
    if (!el || !cy) return;
    const pct = Math.round(cy.zoom() * 100);
    el.textContent = `${pct}%`;
  }

  function updateTheme() {
    if (!cy) return;
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    cy.style(getGraphStylesheet(isLight)).update();
  }

  function zoomIn() {
    if (!cy) return;
    const newZoom = Math.min(cy.zoom() * 1.18, 3.5);
    cy.animate({
      zoom: newZoom,
      duration: 180,
      easing: "ease-out-cubic"
    });
  }

  function zoomOut() {
    if (!cy) return;
    const newZoom = Math.max(cy.zoom() * 0.85, 0.2);
    cy.animate({
      zoom: newZoom,
      duration: 180,
      easing: "ease-out-cubic"
    });
  }

  function centerGraph() {
    if (!cy) return;
    cy.animate({
      center: cy.elements(),
      duration: 350,
      easing: "ease-out-cubic"
    });
  }

  function fit() {
    if (!cy) return;
    cy.animate({
      fit: { padding: 50 },
      duration: 350,
      easing: "ease-out-cubic"
    });
  }

  function setOrientation(direction) {
    if (!cy || currentOrientation === direction) return;
    currentOrientation = direction;

    const btnTB = document.getElementById("topoOrientTB");
    const btnLR = document.getElementById("topoOrientLR");
    if (direction === "TB") {
      if (btnTB) {
        btnTB.className = "px-2.5 py-1 text-xs bg-slate-800 text-amber-400 border-r border-slate-700/80 font-semibold cursor-pointer";
      }
      if (btnLR) {
        btnLR.className = "px-2.5 py-1 text-xs bg-slate-900 hover:bg-slate-800 text-slate-300 font-medium cursor-pointer";
      }
    } else {
      if (btnTB) {
        btnTB.className = "px-2.5 py-1 text-xs bg-slate-900 hover:bg-slate-800 text-slate-300 border-r border-slate-700/80 font-medium cursor-pointer";
      }
      if (btnLR) {
        btnLR.className = "px-2.5 py-1 text-xs bg-slate-800 text-amber-400 font-semibold cursor-pointer";
      }
    }

    const layout = cy.layout({
      name: typeof cytoscape("layout", "dagre") !== "undefined" ? "dagre" : "breadthfirst",
      directed: true,
      padding: 60,
      nodeSep: 95,
      rankSep: 115,
      edgeSep: 35,
      rankDir: direction,
      spacingFactor: 1.6,
      animate: true,
      animationDuration: 400
    });
    layout.run();
  }

  function filterTier(tier) {
    activeFilter = tier;
    document.querySelectorAll(".topo-filter-btn").forEach(btn => {
      btn.classList.remove("active");
    });
    const map = {
      ALL: "topoFilterAll",
      CRITICAL_ROOT: "topoFilterCritical",
      INTERMEDIATE: "topoFilterIntermediate",
      LEAF_SAFE: "topoFilterLeaf"
    };
    const activeEl = document.getElementById(map[tier]);
    if (activeEl) activeEl.classList.add("active");

    if (!cy) return;
    clearHighlights();

    if (tier === "ALL") {
      cy.elements().removeClass("dimmed");
      fit();
      return;
    }

    const matches = cy.nodes(`[risk_tier = "${tier}"]`);
    cy.elements().addClass("dimmed");
    matches.removeClass("dimmed").addClass("highlighted-node");
    matches.connectedEdges().removeClass("dimmed");

    if (matches.length > 0) {
      cy.animate({
        center: { eles: matches },
        duration: 350,
        easing: "ease-out-cubic"
      });
    }
  }

  function searchNode(query) {
    if (!cy) return;
    const cleanQuery = (query || "").trim().toLowerCase();
    const countEl = document.getElementById("topoSearchMatchCount");

    if (!cleanQuery) {
      clearSearch();
      return;
    }

    clearHighlights();

    const matches = cy.nodes().filter(node => {
      const d = node.data();
      const idMatch = (d.id || "").toLowerCase().includes(cleanQuery);
      const typeMatch = (d.resource_type || "").toLowerCase().includes(cleanQuery);
      const shortMatch = (d.short_name || "").toLowerCase().includes(cleanQuery);
      const tierMatch = (d.risk_tier || "").toLowerCase().includes(cleanQuery);
      return idMatch || typeMatch || shortMatch || tierMatch;
    });

    if (countEl) {
      countEl.classList.remove("hidden");
      countEl.textContent = `${matches.length} match${matches.length === 1 ? '' : 'es'}`;
    }

    if (matches.length > 0) {
      cy.elements().addClass("dimmed");
      matches.removeClass("dimmed").addClass("search-match");
      matches.connectedEdges().removeClass("dimmed");

      const first = matches[0];
      inspectNode(first.data());
      cy.animate({
        center: { eles: first },
        zoom: 1.35,
        duration: 350,
        easing: "ease-out-cubic"
      });
    } else {
      cy.elements().addClass("dimmed");
    }
  }

  function clearSearch() {
    const input = document.getElementById("topoNodeSearch");
    if (input) input.value = "";
    const countEl = document.getElementById("topoSearchMatchCount");
    if (countEl) countEl.classList.add("hidden");

    if (!cy) return;
    clearHighlights();
    cy.elements().removeClass("dimmed search-match");
  }

  function focusNode(nodeId) {
    if (!cy || !nodeId) return;
    const node = cy.getElementById(nodeId);
    if (!node || node.length === 0) return;

    inspectNode(node.data());
    highlightBlastRadius(node);

    cy.animate({
      center: { eles: node },
      zoom: 1.45,
      duration: 380,
      easing: "ease-out-cubic"
    });
  }

  function focusActiveNode() {
    if (activeNodeId) {
      focusNode(activeNodeId);
    }
  }

  function highlightBlastRadius(node) {
    if (!cy) return;
    clearHighlights();

    const successors = node.successors();
    cy.elements().addClass("dimmed");

    node.removeClass("dimmed").addClass("highlighted-node");
    successors.nodes().removeClass("dimmed").addClass("highlighted-descendant");
    successors.edges().removeClass("dimmed").addClass("highlighted-edge");
    node.connectedEdges().removeClass("dimmed").addClass("highlighted-edge");
  }

  function clearHighlights() {
    if (!cy) return;
    cy.elements().removeClass("dimmed highlighted-node highlighted-descendant highlighted-edge search-match");
  }

  function inspectNode(data) {
    const inspector = document.getElementById("nodeInspector");
    if (!inspector) return;

    activeNodeId = data.id;
    inspector.classList.remove("hidden");

    document.getElementById("inspectNodeId").textContent = data.id;
    document.getElementById("inspectNodeType").textContent = data.resource_type;

    const riskBadge = document.getElementById("inspectNodeRisk");
    riskBadge.textContent = data.risk_tier;
    if (data.risk_tier === "CRITICAL_ROOT") {
      riskBadge.className = "px-2 py-0.5 rounded text-xs font-bold badge-critical";
    } else if (data.risk_tier === "INTERMEDIATE") {
      riskBadge.className = "px-2 py-0.5 rounded text-xs font-bold badge-intermediate";
    } else {
      riskBadge.className = "px-2 py-0.5 rounded text-xs font-bold badge-leaf";
    }

    document.getElementById("inspectDescendants").textContent = `${data.descendants || 0} child nodes`;
    document.getElementById("inspectAncestors").textContent = `${data.ancestors || 0} upstream nodes`;
    document.getElementById("inspectBetweenness").textContent = Number(data.betweenness || 0).toFixed(4);
    document.getElementById("inspectEigenvector").textContent = Number(data.eigenvector || 0).toFixed(4);
    document.getElementById("inspectPageRank").textContent = Number(data.pagerank || 0).toFixed(4);
    document.getElementById("inspectBlastScore").textContent = Number(data.score || 0).toFixed(4);

    const autoRemBadge = document.getElementById("inspectAutoRemediate");
    if (data.auto_remediate) {
      autoRemBadge.textContent = "Autonomous remediation permitted (low blast radius)";
      autoRemBadge.className = "text-xs font-semibold text-emerald-400";
    } else {
      autoRemBadge.textContent = "Engineer sign-off required (high centrality root)";
      autoRemBadge.className = "text-xs font-semibold text-rose-400";
    }

    // Populate dependent children and parents in inspector
    renderInspectorDependencies(data.id);
  }

  function renderInspectorDependencies(nodeId) {
    const container = document.getElementById("inspectDependenciesList");
    if (!container || !cy) return;

    const node = cy.getElementById(nodeId);
    if (!node || node.length === 0) {
      container.innerHTML = "";
      return;
    }

    const outNeighbors = node.outgoers("node");
    const inNeighbors = node.incomers("node");

    let html = "";
    if (outNeighbors.length > 0) {
      html += `
        <div class="mt-2.5 pt-2 border-t border-slate-800">
          <div class="text-[10px] font-bold uppercase text-slate-400 tracking-wider mb-1">Downstream Dependents (${outNeighbors.length})</div>
          <div class="space-y-1 max-h-24 overflow-y-auto">
            ${outNeighbors.map(n => `
              <button onclick="window.TopologyModule.focusNode('${n.id()}')" class="w-full text-left font-mono text-[10.5px] px-2 py-1 rounded bg-slate-950/60 hover:bg-slate-800 text-slate-300 hover:text-amber-400 border border-slate-800 truncate transition cursor-pointer">
                → ${n.id()}
              </button>
            `).join('')}
          </div>
        </div>
      `;
    }

    if (inNeighbors.length > 0) {
      html += `
        <div class="mt-2 pt-2 border-t border-slate-800">
          <div class="text-[10px] font-bold uppercase text-slate-400 tracking-wider mb-1">Upstream Prerequisites (${inNeighbors.length})</div>
          <div class="space-y-1 max-h-24 overflow-y-auto">
            ${inNeighbors.map(n => `
              <button onclick="window.TopologyModule.focusNode('${n.id()}')" class="w-full text-left font-mono text-[10.5px] px-2 py-1 rounded bg-slate-950/60 hover:bg-slate-800 text-slate-300 hover:text-cyan-400 border border-slate-800 truncate transition cursor-pointer">
                ← ${n.id()}
              </button>
            `).join('')}
          </div>
        </div>
      `;
    }

    container.innerHTML = html;
  }

  function hideNodeInspector() {
    activeNodeId = null;
    const inspector = document.getElementById("nodeInspector");
    if (inspector) inspector.classList.add("hidden");
  }

  function updateSummaryMetrics(data) {
    const resCount = document.getElementById("summaryResourceCount");
    const depCount = document.getElementById("summaryDependencyCount");
    if (resCount) resCount.textContent = data.total_resources || 0;
    if (depCount) depCount.textContent = data.total_dependencies || 0;
  }

  function renderSvgFallback(container, graphData) {
    container.innerHTML = `
      <div class="flex flex-col items-center justify-center h-full text-slate-400 p-8 text-center">
        <div class="mb-2 text-cyan-400">${window.RegIcons.svg('network', 'w-8 h-8')}</div>
        <h3 class="text-lg font-semibold text-white">Dependency Graph Overview</h3>
        <p class="text-sm max-w-md mt-1">Found ${graphData.total_resources} managed resources and ${graphData.total_dependencies} dependency bindings.</p>
        <div class="mt-4 flex flex-wrap gap-2 max-w-lg justify-center">
          ${graphData.elements.nodes.map(n => `
            <span class="px-2.5 py-1 rounded text-xs font-mono font-medium ${
              n.data.risk_tier === 'CRITICAL_ROOT' ? 'badge-critical' : n.data.risk_tier === 'INTERMEDIATE' ? 'badge-intermediate' : 'badge-leaf'
            }">${n.data.id}</span>
          `).join('')}
        </div>
      </div>
    `;
  }

  async function exportGraph(format) {
    if (!AppState.currentWorkspace) {
      showToast("Connect a remote repository first in CI/CD & Git Webhooks.", "info");
      return;
    }
    try {
      const targetPath = AppState.currentWorkspace;
      const res = await apiCall(`/api/graph/export?target_path=${encodeURIComponent(targetPath)}&format=${format}`);
      const content = res.content || JSON.stringify(res, null, 2);

      const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `regradar_topology.${format === 'mermaid' ? 'mmd' : format === 'dot' ? 'dot' : 'json'}`;
      a.click();
      URL.revokeObjectURL(url);
      showToast(`Exported ${format.toUpperCase()} graph`, "success");
    } catch (err) {
      showToast(`Export failed: ${err.message}`, "error");
    }
  }

  return {
    load,
    updateTheme,
    zoomIn,
    zoomOut,
    centerGraph,
    fit,
    setOrientation,
    filterTier,
    searchNode,
    clearSearch,
    focusNode,
    focusActiveNode,
    exportGraph,
    hideNodeInspector
  };
})();
