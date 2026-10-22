# RegRadar

Autonomous compliance remediation engine for Infrastructure as Code (IaC) that enforces a zero-destruction invariant.

RegRadar bridges static security scanners and automated code repair. Traditional tools like Checkov flag misconfigurations, but leave developers with manual backlogs. Unconstrained large language models can draft patches, but often hallucinate invalid arguments or edit immutable attributes that trigger cloud resource recreations and state loss. 

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

RegRadar provides a single command-line interface for scanning, verification, and autonomous repair.

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

### 5. Empirical Benchmarking & Ablation Study
Runs a comparative evaluation against an unconstrained generative AI baseline, measuring remediation rates, invariant preservation, and avoided outages:

```bash
python -m regradar.cli benchmark tests/fixtures/multi_tier \
  --markdown benchmark_multi_tier.md \
  --latex benchmark_multi_tier.tex
```

---

## Project Structure

```
regradar/
├── models.py                  # Core data definitions and risk tier enums
├── cli.py                     # Command-line interface and terminal reports
├── parser/
│   ├── hcl_parser.py          # Reads .tf files into normalized AST structures
│   └── reference_extractor.py # Resolves variable interpolations and depends_on lists
├── graph/
│   ├── builder.py             # Constructs NetworkX directed dependency graphs
│   └── centrality.py          # Calculates betweenness centrality and blast radius
├── invariant/
│   ├── models.py              # Invariant violation types and change diff models
│   ├── plan_parser.py         # Parses tofu show -json plan outputs
│   ├── invariant_engine.py    # Enforces zero-deletion and zero-replacement rules
│   └── sandbox.py             # Isolated execution runner with mock provider caching
├── remediation/
│   ├── models.py              # Compliance violation and patch proposal schemas
│   ├── scanner.py             # Checkov static analysis wrapper
│   ├── knowledge_base.py      # Grounding layer mapping HIPAA, GDPR, NIST to HCL fixes
│   ├── agents.py              # Swarm agents (Auditor, Planner, Synthesizer, Supervisor)
│   └── swarm_coordinator.py   # Closed-loop remediation lifecycle coordinator
└── benchmark/
    ├── models.py              # Benchmark metrics and comparative result models
    ├── baselines.py           # Unconstrained LLM empirical error baseline
    ├── evaluator.py           # Evaluation runner measuring fix rates and safety
    └── report_generator.py    # Exporters for Rich, Markdown, and LaTeX tables
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

The test suite covers parser extraction, DAG construction, invariant enforcement, agent gating, and benchmarking logic. Run all tests with pytest:

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
