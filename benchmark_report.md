# RegRadar Empirical Governance Benchmark Report

**Benchmark Suite:** `Enterprise Multi-Tier Cloud Benchmark`  
**Target Architecture:** `/home/ishan/maj-proj/tests/fixtures/simple_vpc`  

## 1. Quantitative Evaluation Metrics

| Metric | Value | Architectural Interpretation |
| :--- | :---: | :--- |
| **Initial Violations** | `3` | Baseline static smell count |
| **Autonomous Patches Accepted** | `0` | Verified non-destructive leaf fixes |
| **Human Review Escalations** | `3` | High blast-radius foundations gated |
| **Compliance Remediation Rate** | **`0.0%`** | Coverage of addressed violations |
| **Invariant Preservation Rate** | **`100.0%`** | Zero-destruction mathematical guarantee |
| **Destructive Mutations Blocked** | `0` | Caught before state mutation |
| **Pipeline Latency** | `10.07s` | Closed-loop execution time |

## 2. Comparative Ablation Study

Evaluation against an unconstrained generative AI baseline (e.g. Copilot / raw LLM script generator) reflecting empirical fault rates from literature (Alshammari et al. 2024, Majeed et al. 2025):

| Evaluation Dimension | Unconstrained LLM Baseline | RegRadar (Neuro-Symbolic) | Safety Advantage |
| :--- | :---: | :---: | :--- |
| **Blast-Radius Gating** | ❌ None (Mutates Roots) |  Betweenness Centrality | High-centrality roots protected |
| **Pre-Flight Invariant Sandbox** | ❌ None |  Ephemeral `tofu plan -json` | Destructive diffs rejected |
| **Invariant Preservation Rate** | `66.7%` | **`100.0%`** | **+33.3% State Integrity** |
| **Destructive Replacements** | `1` | **`0`** | `1` Outages Prevented |
| **Autonomous Leaf Repairs** | `1` | `0` | Strictly bounded leaf mutations |
