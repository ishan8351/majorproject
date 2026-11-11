// RegRadar Web Studio - Interactive Topology & Centrality DAG Module

window.TopologyModule = (function () {
  let cy = null;
  let rawData = null;

  async function load() {
    const container = document.getElementById("cyContainer");
    if (!container) return;

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

  function showLoading(show) {
    const loader = document.getElementById("topologyLoader");
    if (loader) {
      loader.classList.toggle("hidden", !show);
    }
  }

  function renderGraph(graphData) {
    const cyElement = document.getElementById("cy");
    if (!cyElement) return;

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

    cy = cytoscape({
      container: cyElement,
      elements: elements,
      boxSelectionEnabled: false,
      autounselectify: false,
      style: [
        {
          selector: "node",
          style: {
            "label": "data(id)",
            "font-size": "11px",
            "font-family": "monospace",
            "color": "#f8fafc",
            "text-valign": "bottom",
            "text-margin-y": 6,
            "width": 36,
            "height": 36,
            "border-width": 2,
            "background-color": "#334155",
            "border-color": "#64748b"
          }
        },
        {
          selector: 'node[risk_tier = "CRITICAL_ROOT"]',
          style: {
            "background-color": "#dc2626",
            "border-color": "#ef4444",
            "border-width": 3,
            "shadow-blur": 12,
            "shadow-color": "#ef4444",
            "shadow-opacity": 0.6
          }
        },
        {
          selector: 'node[risk_tier = "INTERMEDIATE"]',
          style: {
            "background-color": "#d97706",
            "border-color": "#f59e0b",
            "border-width": 2
          }
        },
        {
          selector: 'node[risk_tier = "LEAF_SAFE"]',
          style: {
            "background-color": "#059669",
            "border-color": "#10b981",
            "border-width": 2
          }
        },
        {
          selector: "edge",
          style: {
            "width": 2,
            "line-color": "#475569",
            "target-arrow-color": "#64748b",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "arrow-scale": 1.1
          }
        },
        {
          selector: ".highlighted-node",
          style: {
            "border-width": 4,
            "border-color": "#38bdf8",
            "shadow-blur": 20,
            "shadow-color": "#38bdf8",
            "shadow-opacity": 0.9
          }
        },
        {
          selector: ".highlighted-descendant",
          style: {
            "background-color": "#f43f5e",
            "border-color": "#fb7185",
            "shadow-blur": 15,
            "shadow-color": "#f43f5e",
            "shadow-opacity": 0.7
          }
        },
        {
          selector: ".highlighted-edge",
          style: {
            "line-color": "#38bdf8",
            "target-arrow-color": "#38bdf8",
            "width": 3
          }
        },
        {
          selector: ".dimmed",
          style: {
            "opacity": 0.25
          }
        }
      ],
      layout: {
        name: typeof cytoscape("layout", "dagre") !== "undefined" ? "dagre" : "breadthfirst",
        directed: true,
        padding: 40,
        spacingFactor: 1.25
      }
    });

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
    cy.elements().removeClass("dimmed highlighted-node highlighted-descendant highlighted-edge");
  }

  function inspectNode(data) {
    const inspector = document.getElementById("nodeInspector");
    if (!inspector) return;

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

    document.getElementById("inspectDescendants").textContent = `${data.descendants} nodes`;
    document.getElementById("inspectAncestors").textContent = `${data.ancestors} nodes`;
    document.getElementById("inspectBetweenness").textContent = Number(data.betweenness || 0).toFixed(4);
    document.getElementById("inspectEigenvector").textContent = Number(data.eigenvector || 0).toFixed(4);
    document.getElementById("inspectPageRank").textContent = Number(data.pagerank || 0).toFixed(4);
    document.getElementById("inspectBlastScore").textContent = Number(data.score || 0).toFixed(4);

    const autoRemBadge = document.getElementById("inspectAutoRemediate");
    if (data.auto_remediate) {
      autoRemBadge.textContent = "Permitted (Autonomous)";
      autoRemBadge.className = "text-xs font-semibold text-emerald-400";
    } else {
      autoRemBadge.textContent = "Locked Out (Human Gate Enforced)";
      autoRemBadge.className = "text-xs font-semibold text-rose-400";
    }
  }

  function hideNodeInspector() {
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
    exportGraph,
    hideNodeInspector
  };
})();
