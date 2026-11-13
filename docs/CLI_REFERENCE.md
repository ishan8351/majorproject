# RegRadar CLI Reference

RegRadar runs through the Python module interface: `python -m regradar.cli <subcommand> [options]`.

---

## 1. scan

Parses Terraform files in a directory, builds the dependency DAG, calculates betweenness centrality and blast radius scores, and displays an assessment table.

### Syntax
```bash
python -m regradar.cli scan [path] [options]
```

### Arguments
* `path` (optional): Path to a directory containing `.tf` files or a single `.tf` file. Defaults to the current directory (`.`).

### Options
* `--json <file>`: Export the graph topology and centrality metrics to a JSON file.
* `--mermaid <file>`: Export a Mermaid flowchart (`.mmd`) for Markdown documentation.
* `--dot <file>`: Export Graphviz DOT format (`.dot`) for rendering with `dot`.

### Examples
```bash
# Scan a directory and print the risk table
python -m regradar.cli scan tests/fixtures/multi_tier

# Export graph artifacts
python -m regradar.cli scan tests/fixtures/multi_tier \
  --json topology.json \
  --mermaid graph.mmd \
  --dot topology.dot
```

---

## 2. verify-plan

Evaluates an OpenTofu or Terraform plan JSON file against zero-destruction invariant rules.

### Syntax
```bash
python -m regradar.cli verify-plan <plan_file>
```

### Arguments
* `plan_file` (required): Path to an execution plan JSON file generated with `tofu show -json <plan.tfplan>`.

### Exit Codes
* `0`: All planned resource changes preserve state continuity (no deletions or replacements).
* `1`: Invariant violation detected (resource deletion, forced replacement, or schema drop).

### Examples
```bash
# Verify a plan file
python -m regradar.cli verify-plan tests/fixtures/sample_destructive_plan.json
```

---

## 3. verify-sandbox

Copies the target codebase into an ephemeral temporary directory, injects mock cloud provider settings, runs `tofu init` and `tofu plan`, and verifies the resulting plan diff.

### Syntax
```bash
python -m regradar.cli verify-sandbox [path]
```

### Arguments
* `path` (optional): Target Terraform directory to simulate. Defaults to `.`.

### Examples
```bash
python -m regradar.cli verify-sandbox tests/fixtures/simple_vpc
```

---

## 4. remediate

Runs static compliance auditing with Checkov, filters candidate violations through the blast radius gate, synthesizes non-destructive patches, and validates each patch inside the pre-flight execution sandbox.

### Syntax
```bash
python -m regradar.cli remediate [path] [options]
```

### Arguments
* `path` (optional): Path to target Terraform codebase. Defaults to `.`.

### Options
* `--apply`: Writes verified patches to disk. When omitted, runs in dry-run mode and prints patch snippets to standard output.

### Examples
```bash
# Run in dry-run mode
python -m regradar.cli remediate tests/fixtures/multi_tier

# Apply verified patches to disk
python -m regradar.cli remediate tests/fixtures/multi_tier --apply
```

---

## 5. benchmark

Runs empirical evaluations measuring compliance fix rates, invariant preservation, execution latency, and comparative ablation metrics against an unconstrained LLM baseline.

### Syntax
```bash
python -m regradar.cli benchmark [path] [options]
```

### Arguments
* `path` (optional): Path to benchmark target directory. Defaults to `.`.

### Options
* `--no-ablation`: Skip the comparative ablation study and output only RegRadar metrics.
* `--markdown <file>`: Export a Markdown evaluation report.
* `--latex <file>`: Export a LaTeX table snippet for academic project reports.

### Examples
```bash
# Run benchmark with full ablation and exports
python -m regradar.cli benchmark tests/fixtures/multi_tier \
  --markdown benchmark_multi_tier.md \
  --latex benchmark_multi_tier.tex
```

---

## 6. review

Starts an interactive terminal review workflow. Automatically approves safe leaf patches, and prompts an operator to inspect, approve, request revisions, or reject changes on foundational infrastructure components.

### Syntax
```bash
python -m regradar.cli review [path] [options]
```

### Arguments
* `path` (optional): Path to target Terraform codebase. Defaults to `.`.

### Options
* `--apply`: Automatically writes approved patches to disk.
* `--non-interactive`, `-y`: Runs without terminal prompts. Automatically approves `LEAF_SAFE` changes and flags higher-risk items in the output. Useful for CI/CD pipelines.
* `--json <file>`: Exports operator review decisions and violation records to a JSON file.

### Exit Codes
* `0`: All reviewed items were processed and resolved.
* `1`: High-risk violations remain unresolved or were rejected during review.

### Examples
```bash
# Start interactive terminal review
python -m regradar.cli review tests/fixtures/multi_tier

# Run unattended in CI pipeline and export audit record
python -m regradar.cli review tests/fixtures/multi_tier -y --json review_audit.json
```

---

## 7. serve

Launches the RegRadar Web Studio, REST API server, and interactive topology console.

### Syntax
```bash
python -m regradar.cli serve [options]
```

### Options
* `--host <ip>`: Network interface to bind. Defaults to `127.0.0.1` (or value in config).
* `--port <number>`: TCP port to listen on. Defaults to `8000`.
* `--reload`: Enable auto-reload for local development.
* `--workspace <path>`: Path to a Terraform directory to load into the workspace on startup.
* `--provider <name>`: Active LLM synthesis provider (`gemini`, `openai`, `anthropic`, `deepseek`, `ollama`, `mock`).

### Examples
```bash
# Start server on default port (http://127.0.0.1:8000)
python -m regradar.cli serve

# Bind to all interfaces with a specific workspace
python -m regradar.cli serve --host 0.0.0.0 --port 8080 --workspace ./infra
```
