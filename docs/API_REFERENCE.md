# RegRadar REST API Reference

The RegRadar API server provides programmatic endpoints for workspace management, dependency graph extraction, compliance auditing, ephemeral sandbox verification, and GitHub webhook automation.

The API runs on `http://127.0.0.1:8000` by default when launched via `python -m regradar.cli serve`.

---

## 1. System Health and Diagnostics

### Check Service Health
```http
GET /api/health
```

Returns current service status, active configuration directory, and uptime details.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "active_workspace": "/home/user/infra",
  "providers": {
    "llm": "gemini",
    "cloud": ["aws", "azure", "gcp"]
  }
}
```

### Inspect Database and Storage Status
```http
GET /api/database/status
```

Returns connectivity status, managed repository count, and storage usage in `.regradar_repos/`.

---

## 2. Workspace and Version Control Management

### List Active Workspaces
```http
GET /api/workspaces
```

Returns all discovered or connected Terraform project workspaces.

**Response (200 OK):**
```json
[
  {
    "id": "github:ishan8351-majorprojtgt1",
    "name": "Production Multi-Tier VPC",
    "path": "/home/user/majorproject/.regradar_repos/github:ishan8351-majorprojtgt1",
    "provider": "aws",
    "resource_count": 10,
    "last_scanned": "2026-11-13T16:45:00Z"
  }
]
```

### Connect a Remote Repository
```http
POST /api/workspaces/connect
```

Clones a remote Git repository into the managed workspace pool under `.regradar_repos/`.

**Request Body:**
```json
{
  "remote_url": "https://github.com/org/terraform-infra.git",
  "branch": "main",
  "auth_token": "ghp_optionalTokenHere"
}
```

**Response (200 OK):**
```json
{
  "status": "connected",
  "workspace_id": "github:org-terraform-infra",
  "path": "/home/user/majorproject/.regradar_repos/github:org-terraform-infra",
  "branch": "main"
}
```

### Query Remote Branches
```http
POST /api/workspaces/branches
```

Queries available branches on a remote Git repository before cloning.

**Request Body:**
```json
{
  "remote_url": "https://github.com/org/terraform-infra.git",
  "auth_token": "ghp_optionalTokenHere"
}
```

**Response (200 OK):**
```json
{
  "branches": ["main", "staging", "feature/db-upgrade"],
  "default_branch": "main"
}
```

### Sync Workspace
```http
POST /api/workspaces/{repo_id}/sync
```

Pulls latest commits from origin for the currently active branch.

---

## 3. Scanning and Graph Topology

### Scan Terraform Workspace
```http
POST /api/scan
```

Parses HCL files, builds the dependency DAG, and calculates betweenness centrality, cascading descendant ratios, and composite risk scores.

**Request Body:**
```json
{
  "path": "tests/fixtures/multi_tier",
  "include_graph": true
}
```

**Response (200 OK):**
```json
{
  "total_resources": 10,
  "edges": 11,
  "nodes": [
    {
      "id": "aws_vpc.main",
      "type": "aws_vpc",
      "betweenness": 0.4444,
      "descendant_count": 9,
      "descendant_ratio": 1.0,
      "blast_radius_score": 0.81,
      "risk_tier": "CRITICAL_ROOT"
    },
    {
      "id": "aws_s3_bucket.patient_records",
      "type": "aws_s3_bucket",
      "betweenness": 0.0,
      "descendant_count": 0,
      "descendant_ratio": 0.0,
      "blast_radius_score": 0.0,
      "risk_tier": "LEAF_SAFE"
    }
  ],
  "summary": {
    "critical_root_count": 1,
    "intermediate_count": 3,
    "leaf_safe_count": 6
  }
}
```

### Export Graph Topology
```http
GET /api/graph/export?format=cytoscape&workspace_id=default
```

Query parameters:
* `format`: Export format (`cytoscape`, `mermaid`, `dot`, `json`).
* `workspace_id`: Target workspace ID.

---

## 4. Compliance Auditing and Knowledge Base

### Run Compliance Audit
```http
POST /api/audit
```

Runs Checkov static analysis across the workspace and joins each violation with its graph centrality risk tier.

**Request Body:**
```json
{
  "workspace_path": "tests/fixtures/multi_tier"
}
```

**Response (200 OK):**
```json
{
  "violations_count": 4,
  "violations": [
    {
      "check_id": "CKV_AWS_145",
      "rule_name": "Ensure S3 buckets have default encryption enabled",
      "resource_id": "aws_s3_bucket.patient_records",
      "risk_tier": "LEAF_SAFE",
      "statute_reference": "HIPAA §164.312(a)(2)(iv)",
      "auto_remediable": true
    }
  ]
}
```

### Query Regulatory Knowledge Base
```http
POST /api/knowledge/query
```

Searches externalized compliance catalogs for standards, section citations, and verified HCL patterns.

**Request Body:**
```json
{
  "framework": "HIPAA",
  "requirement": "Encryption at Rest"
}
```

---

## 5. Remediation and Sandbox Verification

### Autonomous Remediation
```http
POST /api/remediate
```

Executes the multi-agent remediation swarm: Auditor gates risk, Planner selects the rule strategy, Synthesizer writes HCL, and Supervisor validates the patch in the OpenTofu sandbox.

**Request Body:**
```json
{
  "workspace_path": "tests/fixtures/multi_tier",
  "apply": false
}
```

**Response (200 OK):**
```json
{
  "total_violations": 4,
  "fixed_count": 3,
  "gated_count": 1,
  "patches": [
    {
      "resource_id": "aws_s3_bucket.patient_records",
      "strategy": "ADDITIVE_ATTACHMENT",
      "filename": "fix_s3_encryption.tf",
      "patch_content": "resource \"aws_s3_bucket_server_side_encryption_configuration\" \"patient_records_encryption\" {\n  bucket = aws_s3_bucket.patient_records.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = \"AES256\"\n    }\n  }\n}",
      "sandbox_status": "PASSED",
      "invariant_preserved": true
    }
  ]
}
```

### Dry-Run Sandbox Plan Verification
```http
POST /api/sandbox/verify
```

Simulates an isolated `tofu plan` run on the specified folder or with a set of proposed code patches.

---

## 6. Human-in-the-Loop Review

### List Staged Review Items
```http
POST /api/review/staged
```

Returns all proposed compliance patches currently awaiting operator review.

### Submit Review Decision
```http
POST /api/review/decision
```

Submits an operator decision on a staged remediation item.

**Request Body:**
```json
{
  "item_id": "item_aws_route_table_01",
  "decision": "approve",
  "comment": "Verified secondary route table update does not impact primary gateway.",
  "apply": true
}
```

Decisions accepted: `approve`, `reject`, `revision_requested`.

---

## 7. Webhook Integrations (GitHub and GitLab)

### GitHub Webhook Receiver
```http
POST /api/webhooks/github
```

Receives GitHub event payloads (`pull_request`, `push`). Validates the request using the `X-Hub-Signature-256` header and the configured webhook secret.

**Headers Required:**
* `X-GitHub-Event`: Event name (`pull_request`, `push`, `ping`).
* `X-Hub-Signature-256`: `sha256=<hex_hmac_signature>`
* `Content-Type`: `application/json`

**Response (200 OK):**
```json
{
  "status": "processed",
  "event": "pull_request",
  "action": "opened",
  "pr_number": 42,
  "verdict": "AWAITING_OPERATOR_SIGN_OFF",
  "gated_nodes": ["aws_vpc.main"]
}
```

### Query Tracked Pull Requests
```http
GET /api/webhooks/github/prs
```

Returns all pull requests tracked by the webhook system, along with their current status check and blast radius tier.

### Review GitHub Pull Request
```http
POST /api/webhooks/github/prs/{pr_id}/review
```

Operators approve, reject, or request changes on a tracked pull request. When approved, RegRadar updates the GitHub commit status check to `success`.

---

## 8. Empirical Benchmarking

### Run Comparative Ablation Benchmark
```http
POST /api/benchmark/run
```

Runs a comparative evaluation against an unconstrained generative baseline.

**Request Body:**
```json
{
  "target_path": "tests/fixtures/multi_tier",
  "iterations": 1,
  "include_ablation": true
}
```

**Response (200 OK):**
```json
{
  "regradar": {
    "total_violations": 4,
    "fixed_violations": 3,
    "remediation_rate": 75.0,
    "invariant_preservation_rate": 100.0,
    "destructive_actions_prevented": 3,
    "gated_root_nodes": 1
  },
  "unconstrained_baseline": {
    "remediation_rate": 80.0,
    "invariant_preservation_rate": 60.0,
    "destructive_actions_triggered": 3,
    "gated_root_nodes": 0
  }
}
```
