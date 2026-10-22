# RegRadar Architecture and Engineering Specification

This document provides a technical walkthrough of RegRadar's core modules, mathematical risk formulations, and invariant enforcement pipeline.

---

## 1. Abstract Syntax Tree (AST) Ingestion

Traditional linters rely on regex patterns or line-by-line checks. Declarative Infrastructure as Code (IaC) requires semantic structure: resources reference other resources through attribute interpolations, data blocks, modules, and explicit ordering parameters.

### Parsing Pipeline (`regradar/parser/`)
1. **File Discovery:** The parser discovers all `.tf` files in the target directory while ignoring hidden folders, `.terraform/` cache directories, and lock files.
2. **Lexical and Syntactic Ingestion:** Files are parsed using `python-hcl2`, producing normalized Python dictionary representations of HCL blocks: `resource`, `data`, `variable`, `module`, and `locals`.
3. **Reference Extraction (`ReferenceExtractor`):**
   * Inspects all attributes recursively across dictionaries, lists, and string interpolations.
   * Matches potential resource address patterns: `<resource_type>.<resource_name>.<attribute>`.
   * Filters out Terraform built-in keywords (`var.`, `local.`, `count.`, `each.`, `path.`).
   * Matches candidate references against the set of defined resource IDs in the project to eliminate false positives from random string matches.
   * Extracts explicit dependencies defined in `depends_on` attributes.

---

## 2. Resource Dependency DAG and Centrality Formulation

RegRadar models cloud topologies as a directed acyclic graph (DAG) using NetworkX.

### Edge Direction Convention
Edges are directed from dependency to dependent:
```
aws_vpc.main  -->  aws_subnet.public  -->  aws_instance.app
 (Dependency)       (Intermediate)           (Dependent)
```

Under this convention:
* **Predecessors (`nx.ancestors`):** The upstream resources required for this resource to exist.
* **Successors (`nx.descendants`):** The exact cascading downstream blast radius. If node $v$ changes, every resource in its descendant set is directly or indirectly exposed to disruption.

### Centrality and Risk Calculations
To determine whether an automated agent is allowed to edit a resource, RegRadar evaluates three graph-theoretic properties:

1. **Betweenness Centrality ($C_B$):**
   Measures how often a resource sits on the shortest dependency path between pairs of other cloud resources:
   $$C_B(v) = \sum_{s \ne v \ne t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$
   Foundational networking resources (VPCs, route tables, core gateways) have high betweenness because many services connect through them.

2. **Cascading Descendant Ratio ($R_{\text{desc}}$):**
   Measures the fraction of total infrastructure that depends on this resource:
   $$R_{\text{desc}}(v) = \frac{|\text{Descendants}(v)|}{N - 1}$$
   where $N$ is the total count of managed resources.

3. **Direct Out-Degree Ratio ($C_{\text{out}}$):**
   Measures direct fanout to immediate consumers:
   $$C_{\text{out}}(v) = \frac{\text{out\_degree}(v)}{N - 1}$$

### Composite Blast-Radius Risk Score
The composite risk score $S(v) \in [0.0, 1.0]$ combines these factors:
$$S(v) = 0.50 \cdot R_{\text{desc}}(v) + 0.30 \cdot C_B(v) + 0.20 \cdot C_{\text{out}}(v)$$

### Safety Tiers and Gating Policy
* **`CRITICAL_ROOT`** ($S(v) \ge 0.40$ or $R_{\text{desc}}(v) \ge 0.35$):
  Foundational resources whose modification carries significant risk of cascading disruption. Automated agent mutation is strictly blocked. Any compliance violations on these nodes are routed to human review.
* **`INTERMEDIATE`** ($0.15 \le S(v) < 0.40$):
  Mid-tier resources with bounded dependents. Autonomous patches are permitted under strict pre-flight plan diff validation.
* **`LEAF_SAFE`** ($S(v) < 0.15$ and $|\text{Descendants}(v)| = 0$):
  Leaf configurations with zero downstream dependents (e.g. S3 server-side encryption blocks, access logging, egress rules). Autonomous remediation is enabled.

---

## 3. Sandboxed Dry-Run Invariant Enforcement

Software repair tools typically test patches by running compilers and unit test suites. Declarative IaC configurations behave differently: syntactically valid code can pass linting and compilation, yet cause severe production incidents by triggering a cloud resource replacement during deployment.

### The Problem with Immutable Attributes
In cloud providers, certain attributes are immutable. Changing them cannot be done in place. When OpenTofu or Terraform encounters an immutable attribute edit, it marks the resource for destruction and recreation:
```
# OpenTofu plan action:
~ resource "aws_db_instance" "primary" {
    ~ identifier = "db-old" -> "db-new" # forces replacement
  }
Plan: 1 to add, 0 to change, 1 to destroy.
```
If applied automatically, stateful databases, storage volumes, or network gateways are destroyed.

### The Invariant Inspection Pipeline (`regradar/invariant/`)
1. **Isolated Workspace:** RegRadar clones the configuration into an ephemeral sandbox directory.
2. **Provider Mocking:** A mock provider override file (`_regradar_mock_override.tf`) is injected, configuring the AWS provider with dummy credentials and skipping live AWS API calls.
3. **Execution Plan Generation:** The sandbox runs:
   ```bash
   tofu init -backend=false -no-color
   tofu validate -no-color
   tofu plan -out=tfplan.binary -no-color
   tofu show -json tfplan.binary
   ```
4. **Plan Diff Parser (`PlanParser`):** Inspects the JSON structure, specifically the `resource_changes` array:
   ```json
   {
     "address": "aws_s3_bucket.logs",
     "change": {
       "actions": ["update"],
       "before": { ... },
       "after": { ... }
     }
   }
   ```
5. **Deterministic Invariant Rules (`InvariantEngine`):**
   * **Rule 1 (`NO_UNINTENDED_DELETION`):** No resource can have `actions` containing `"delete"`.
   * **Rule 2 (`NO_FORCES_REPLACEMENT`):** No existing resource can have actions `["delete", "create"]` or `["create", "delete"]`. Any plan diff triggering recreation is rejected.
   * **Rule 3 (`NO_SCHEMA_DROP`):** If an attribute had a non-empty value in `before`, it cannot be silently omitted or nullified in `after`.
   * **Rule 4 (`ADDITIVE_ATTACHMENTS_ALLOWED`):** New compliance attachments (e.g., adding a standalone `aws_s3_bucket_server_side_encryption_configuration` alongside an existing bucket) have `actions == ["create"]` and `before == null`. These are safe and accepted.

---

## 4. Multi-Agent Remediation Swarm

RegRadar organizes automated remediation into role-separated agents:

### 1. Auditor Agent
* Ingests compliance violations from Checkov.
* Cross-references the target resource against the Phase 1 dependency graph.
* Evaluates the risk tier: leaves are approved for autonomous repair, while root resources are escalated to human review.

### 2. Policy Planner Agent
* Grounds remediation tasks against the statutory regulatory knowledge base.
* Maps standards (HIPAA §164.312, GDPR Art. 32, NIST SP 800-53) to verified non-destructive remediation patterns.
* Selects between in-place attribute injection and additive attachments.

### 3. Synthesizer Agent
* Produces minimal, syntactically valid HCL code.
* For S3 compliance, synthesizes standalone attachment resources rather than editing the base bucket block. In modern AWS providers, standalone resources avoid attribute drift and eliminate replacement triggers on the parent bucket.

### 4. Supervisor Agent
* Pipes the synthesized patch into the pre-flight execution sandbox.
* If the patch satisfies the zero-destruction invariant, the patch is marked verified and staged.
* If an invariant violation occurs, the supervisor captures the exact diagnostic reason (e.g., offending attribute forcing replacement) and feeds it back to the synthesizer to refine the patch.

---

## 5. Empirical Benchmarking Framework

RegRadar measures performance across four primary metrics:

1. **Remediation Rate:**
   $$\text{Remediation Rate} = \frac{\text{Fixed Violations}}{\text{Total Identified Violations}} \times 100\%$$
2. **Invariant Preservation Rate:**
   $$\text{Invariant Preservation} = \frac{\text{Patches Without Destructive Actions}}{\text{Total Evaluated Patches}} \times 100\%$$
   RegRadar enforces a 100.0% invariant preservation rate through its plan diff gate.
3. **Safety Differential:**
   The count of state-destructive mutations and production outages prevented compared to unconstrained generative models.
4. **Pipeline Latency:**
   Total elapsed wall-clock time to run AST parsing, security linting, centrality evaluation, code synthesis, and plan diff validation.
