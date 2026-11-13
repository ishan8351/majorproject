# RegRadar

Autonomous compliance remediation engine for Infrastructure as Code (IaC) that enforces a zero-destruction invariant.

Static security scanners such as Checkov detect misconfigurations, but leave engineers with manual remediation backlogs. Unconstrained language models can draft patches, but frequently modify immutable attributes or introduce schema changes that trigger resource replacement and state loss.

RegRadar uses a neuro-symbolic pipeline: it computes resource dependency graphs and network centrality metrics to bound risk, generates targeted HCL fixes, and verifies those patches against ephemeral OpenTofu execution plan diffs before allowing any change into version control.

---

## Technical Overview

```
                 Terraform / OpenTofu Configuration
                                |
             +------------------+------------------+
             |                                     |
             v                                     v
       Checkov Linter                      HCL AST Parser
     (Detect Violations)                 (python-hcl2 AST)
             |                                     |
             | Discovered Smells                   v
             |                           Dependency DAG Builder
             |                             (NetworkX DiGraph)
             |                                     |
             +------------------+------------------+
                                |
                                v
                    Centrality Risk Gatekeeper
                 (Betweenness + Descendant Ratio)
                                |
               [ Is Blast Radius <= 0.40 Threshold? ]
                     /                      \
                  (No)                      (Yes)
                   /                          \
        Human Escalation               Multi-Agent Swarm
        (Manual Review)              (Synthesizes HCL Patch)
                                              |
                                              v
                                   Ephemeral Execution Sandbox
                                  (tofu plan -json Simulation)
                                              |
                                   [ Destructive Diffs Detected? ]
                                         /               \
                                      (Yes)              (No)
                                       /                   \
                                 Retry Patch         Verified Safe PR
```

RegRadar enforces safety through two boundaries:
1. **Pre-Synthesis (Topological Blast-Radius Gate):** Calculates graph centrality across the resource dependency DAG. High-centrality infrastructure nodes (VPCs, route tables, IAM root roles) are locked out from automated mutation and escalated to human operators. Low-centrality leaves (bucket encryption, access blocks, audit logging) are approved for autonomous repair.
2. **Post-Synthesis (State Invariant Sandbox Gate):** Proposed patches run inside an isolated OpenTofu environment with mocked AWS providers. The engine parses the resulting `tofu plan -json` execution graph. If any existing resource is marked for deletion or replacement (`actions` contains `delete` or `delete, create`), the patch is rejected immediately.

---

## Installation

### Prerequisites
* Linux (Fedora, Debian, Ubuntu, or POSIX-compliant environment)
* Python 3.11+ (tested on Python 3.14)
* OpenTofu or Terraform CLI installed in PATH (`tofu` or `terraform`)

### Setup
Clone the repository and set up a virtual environment:

```bash
git clone git@github.com:ishan8351/majorproject.git
cd majorproject

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Verify your OpenTofu installation:
```bash
tofu --version
```

---

## Usage

RegRadar provides a single command-line interface for scanning, verification, interactive review, benchmarking, and starting the web studio.

### 1. Topological Blast-Radius Scan
Parses all `.tf` files in a directory, constructs the resource dependency DAG, calculates betweenness centrality, and prints a risk assessment table:

```bash
python -m regradar.cli scan tests/fixtures/multi_tier
```

Export graph visualizations for reports or presentations:
```bash
# Export Mermaid diagram for Markdown documentation
python -m regradar.cli scan tests/fixtures/multi_tier --mermaid graph.mmd

# Export Graphviz DOT format
python -m regradar.cli scan tests/fixtures/multi_tier --dot graph.dot

# Export structured JSON summary
python -m regradar.cli scan tests/fixtures/multi_tier --json report.json
```

### 2. Verify Execution Plans Against Invariants
Evaluates a saved OpenTofu or Terraform plan JSON file to detect destructive replacements or schema drops:

```bash
python -m regradar.cli verify-plan tests/fixtures/sample_destructive_plan.json
```

### 3. Dry-Run Sandbox Simulation
Simulates configuration execution inside an isolated temporary directory using mock AWS credentials:

```bash
python -m regradar.cli verify-sandbox tests/fixtures/simple_vpc
```

### 4. Autonomous Compliance Remediation
Runs Checkov across the codebase, passes violations through the blast-radius gate, synthesizes non-destructive patches, and verifies each patch in the sandbox:

```bash
# Dry-run mode: prints synthesized patches without modifying disk
python -m regradar.cli remediate tests/fixtures/multi_tier

# Apply mode: writes verified patches to disk
python -m regradar.cli remediate tests/fixtures/multi_tier --apply
```

### 5. Interactive Operator Review
Starts an interactive human-in-the-loop review session in the terminal. Automatically verifies safe leaf patches and prompts operators before touching high-centrality foundational components:

```bash
# Interactive terminal review
python -m regradar.cli review tests/fixtures/multi_tier

# Non-interactive mode for CI/CD pipelines
python -m regradar.cli review tests/fixtures/multi_tier -y --json review_audit.json
```

### 6. Empirical Benchmarking and Ablation Study
Runs a comparative evaluation against an unconstrained generative AI baseline, measuring remediation rates, invariant preservation, and avoided outages:

```bash
python -m regradar.cli benchmark tests/fixtures/multi_tier \
  --markdown benchmark_multi_tier.md \
  --latex benchmark_multi_tier.tex
```

### 7. Launch Web Studio and Operations Console
Launches the FastAPI backend and browser-based operations studio:

```bash
# Start server on default port (http://127.0.0.1:8000)
python -m regradar.cli serve

# Bind to all interfaces with a specific workspace
python -m regradar.cli serve --host 0.0.0.0 --port 8000 --workspace tests/fixtures/multi_tier
```

Open `http://127.0.0.1:8000` for the project landing page or `http://127.0.0.1:8000/dashboard` for the interactive Cytoscape graph console.

---

## Web Studio and Operations Console

The RegRadar Web Studio includes:
* **Interactive Graph Visualization:** Cytoscape-powered topological viewer color-coded by blast radius tier (`CRITICAL_ROOT`, `INTERMEDIATE`, `LEAF_SAFE`). Clicking any node displays upstream dependencies, downstream impact, and active compliance findings.
* **Pre-Flight Sandbox Runner:** Browser-based simulation interface that executes `tofu plan -json` against proposed fixes and renders live resource diffs.
* **GitHub Operations Console:** Tracks incoming pull requests, displays automated blast radius assessments, and allows operators to approve or reject staged PRs.
* **Regulatory Catalog Browser:** Inspects mapped controls across HIPAA, GDPR, NIST SP 800-53, and PCI-DSS.

---

## Documentation

Full technical documentation is located in the `docs/` directory:
* [Architecture and Engineering Specification](file:///home/chocoT/majorproject/docs/ARCHITECTURE.md): Mathematical formulations, invariant rules, and swarm agent lifecycle.
* [CLI Reference](file:///home/chocoT/majorproject/docs/CLI_REFERENCE.md): Detailed subcommands, arguments, exit codes, and usage examples.
* [REST API Reference](file:///home/chocoT/majorproject/docs/API_REFERENCE.md): Endpoints, request schemas, response models, and curl commands.
* [GitHub Integration Guide](file:///home/chocoT/majorproject/docs/GITHUB_INTEGRATION.md): Webhook setup, HMAC-SHA256 verification, and branch protection policies.
* [Regulatory Rules Catalog](file:///home/chocoT/majorproject/rules/README.md): Structure and schema for defining custom regulatory checks.

---

## Project Structure

```
regradar/
├── api/                       # FastAPI REST backend and webhook handlers
│   ├── models.py              # Pydantic schemas for API requests and responses
│   ├── routes.py              # Endpoint routers for scan, audit, sandbox, and webhooks
│   └── server.py              # Application factory and lifespan configuration
├── benchmark/                 # Empirical evaluation and baseline comparisons
│   ├── baselines.py           # Unconstrained LLM baseline implementation
│   ├── evaluator.py           # Benchmark runner measuring fix rates and safety
│   ├── models.py              # Benchmark data structures
│   └── report_generator.py    # Exporters for Markdown and LaTeX tables
├── cli.py                     # Command-line interface definitions and commands
├── graph/                     # Graph modeling and centrality calculations
│   ├── builder.py             # Constructs NetworkX directed dependency graphs
│   └── centrality.py          # Betweenness centrality and blast radius formulas
├── invariant/                 # Sandboxed execution and invariant checking
│   ├── invariant_engine.py    # Deterministic zero-destruction rules
│   ├── models.py              # Invariant violation and diff schemas
│   ├── plan_parser.py         # Parses OpenTofu execution plan JSON outputs
│   └── sandbox.py             # Isolated execution runner with mock cloud providers
├── models.py                  # Core data definitions and risk tier enums
├── parser/                    # HCL parsing and reference resolution
│   ├── hcl_parser.py          # Converts .tf files into normalized AST structures
│   └── reference_extractor.py # Resolves variable interpolations and dependencies
├── remediation/               # Multi-agent autonomous remediation swarm
│   ├── agents.py              # Swarm agents (Auditor, Planner, Synthesizer, Supervisor)
│   ├── knowledge_base.py      # Grounding layer mapping HIPAA, GDPR, NIST to HCL fixes
│   ├── models.py              # Violation and patch data models
│   ├── scanner.py             # Checkov static analysis wrapper
│   └── swarm_coordinator.py   # Closed-loop remediation coordinator
└── web/                       # Web Studio assets
    ├── css/                   # Stylesheets and theme variables
    ├── dashboard.html         # Interactive graph and operations console
    ├── index.html             # Product landing page and architecture overview
    └── js/                    # Client modules (topology, github, sandbox, swarm)
```

---

## Empirical Evaluation Summary

Evaluation performed on an enterprise multi-tier AWS topology (10 resources, 11 dependency bindings):

| Dimension | Unconstrained LLM Baseline | RegRadar (Neuro-Symbolic) | Advantage |
| :--- | :---: | :---: | :--- |
| Topological Risk Gating | None (Blind Mutation) | Betweenness Centrality | High-centrality roots protected |
| Pre-Flight Invariant Sandbox | None (Merges Blindly) | Ephemeral `tofu plan -json` | Destructive plan diffs rejected |
| Invariant Preservation Rate | 66.7% | 100.0% | +33.3% State Continuity |
| Destructive Replacements | 5 | 0 | 5 Outages Prevented |
| Gated Foundational Nodes | 0 | 11 | Human sign-off enforced on roots |

---

## Running Tests

The test suite covers parser extraction, DAG construction, invariant enforcement, agent gating, web API routes, and benchmarking logic. Run all tests with pytest:

```bash
.venv/bin/pytest -v
```

To run unit tests quickly while skipping the long live execution plan test:
```bash
.venv/bin/pytest -v -k "not test_sandbox_live_plan_simulation"
```

---

## Authors

Department of Computer Science and Engineering  
(Artificial Intelligence & Machine Learning / Cyber Security)  
M.S. Ramaiah Institute of Technology, Bangalore

* Amanpreet Singh Lohia (1MS23CI010)
* Chinmai Naik (1MS23CI026)
* Davan H S (1MS23CI028)
* Ishan Gupta (1MS23CI043)

**Project Guide:** Dr. Mohana Kumar S
