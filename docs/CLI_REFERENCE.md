# RegRadar CLI Reference

RegRadar is executed as a Python module: `python -m regradar.cli <subcommand> [options]`.

---

## 1. scan

Parses Terraform HCL files in a directory, builds the dependency DAG, calculates betweenness centrality and blast radius scores, and displays an assessment table.

### Syntax
```bash
python -m regradar.cli scan [path] [options]
```

### Arguments
* `path` *(optional)*: Path to a directory containing `.tf` files or a specific `.tf` file. Defaults to current directory (`.`).

### Options
* `--json <file>`: Export complete graph topology and centrality metrics to a JSON file.
* `--mermaid <file>`: Export a Mermaid flowchart diagram (`.mmd`) for Markdown documentation.
* `--dot <file>`: Export Graphviz DOT format (`.dot`) for rendering with `dot`.

### Examples
```bash
# Scan a directory and print risk analysis table
python -m regradar.cli scan tests/fixtures/multi_tier

# Export graph artifacts
python -m regradar.cli scan tests/fixtures/multi_tier \
  --json topology.json \
  --mermaid graph.mmd \
  --dot topology.dot
```

---

## 2. verify-plan

Evaluates a pre-computed OpenTofu or Terraform plan JSON file against the zero-destruction invariant rules.

### Syntax
```bash
python -m regradar.cli verify-plan <plan_file>
```

### Arguments
* `plan_file` *(required)*: Path to an execution plan JSON file (generated via `tofu show -json <plan.tfplan>`).

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

Clones the target codebase into an ephemeral temporary directory, injects mock cloud provider configurations, executes `tofu init` and `tofu plan`, and verifies the resulting plan diff.

### Syntax
```bash
python -m regradar.cli verify-sandbox [path]
```

### Arguments
* `path` *(optional)*: Target Terraform directory to simulate. Defaults to `.`.

### Examples
```bash
python -m regradar.cli verify-sandbox tests/fixtures/simple_vpc
```

---

## 4. remediate

Runs static compliance auditing via Checkov, gates candidate violations through the Phase 1 blast-radius score, synthesizes non-destructive patches, and validates each patch inside the pre-flight execution sandbox.

### Syntax
```bash
python -m regradar.cli remediate [path] [options]
```

### Arguments
* `path` *(optional)*: Path to target Terraform codebase. Defaults to `.`.

### Options
* `--apply`: Writes verified patches to disk in place. When omitted, runs in dry-run mode and prints the verified patch snippets to stdout.

### Examples
```bash
# Run in dry-run mode
python -m regradar.cli remediate tests/fixtures/multi_tier

# Apply verified patches to disk
python -m regradar.cli remediate tests/fixtures/multi_tier --apply
```

---

## 5. benchmark

Executes empirical governance evaluations measuring compliance fix rates, invariant preservation fidelity, execution latency, and comparative ablation metrics against an unconstrained LLM baseline.

### Syntax
```bash
python -m regradar.cli benchmark [path] [options]
```

### Arguments
* `path` *(optional)*: Path to benchmark target directory. Defaults to `.`.

### Options
* `--no-ablation`: Omit the comparative ablation study and output only RegRadar metrics.
* `--markdown <file>`: Export a Markdown evaluation report.
* `--latex <file>`: Export a LaTeX table snippet for academic project reports.

### Examples
```bash
# Run benchmark with full ablation and exports
python -m regradar.cli benchmark tests/fixtures/multi_tier \
  --markdown benchmark_multi_tier.md \
  --latex benchmark_multi_tier.tex
```
