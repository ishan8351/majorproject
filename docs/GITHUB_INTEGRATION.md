# GitHub Integration and Pull Request Gating

RegRadar integrates into GitHub repositories as a pre-merge compliance gatekeeper. When developers submit pull requests that modify Terraform files, RegRadar intercepts the webhook, evaluates the blast radius of the modified resources, validates execution plans in an ephemeral sandbox, and reports status checks back to GitHub.

---

## How It Works

```
 Developer PR Submission
         |
         v
 GitHub Webhook Ingress ----> HMAC-SHA256 Signature Validation
                                         |
                                         v
                            Check out Head Commit Branch
                                         |
                                         v
                            Parse AST & Compute Centrality
                                         |
                       [ Does PR touch CRITICAL_ROOT? ]
                               /              \
                            (Yes)             (No)
                             /                  \
              Post "pending" Status        Run Sandbox Invariant Check
             (Awaiting Operator Sign-Off)       |
                             |            [ Any Destructive Diffs? ]
                             |                  /        \
                             |               (Yes)       (No)
                             |                /            \
                             |         Post "failure"   Post "success"
                             |
                     Operator Review
             (Web Studio or Terminal CLI)
                             |
                   [ Approved by Human? ]
                          /          \
                       (Yes)         (No)
                        /              \
                 Post "success"   Post "failure"
```

1. **Webhook Ingress:** GitHub sends a `pull_request` event payload to `/api/webhooks/github`.
2. **Signature Verification:** RegRadar computes an HMAC-SHA256 digest over the raw request payload using the configured webhook secret. Requests with missing or mismatching signatures are rejected with HTTP 401.
3. **Branch Synchronization:** The repository is checked out to an isolated directory under `.regradar_repos/`.
4. **Blast-Radius Assessment:** The parser evaluates the diff. If any modified resource has a blast radius score $S(v) \ge 0.40$ or cascading descendant ratio $R_{\text{desc}}(v) \ge 0.35$, the commit status check is marked `pending` with description `Awaiting Operator Sign-Off`.
5. **Sandbox Invariant Verification:** Low-risk changes (`LEAF_SAFE`) are simulated through `tofu plan -json`. If the plan introduces zero deletions and zero replacements, the check passes automatically.
6. **Branch Protection:** When configured with branch protection rules, GitHub blocks merging until RegRadar posts a passing status check.

---

## Environment Configuration

Configure the following environment variables before starting the server:

```bash
# Secret shared with GitHub for webhook payload verification
export REGRADAR_GITHUB_WEBHOOK_SECRET="your_shared_webhook_secret_here"

# Personal access token with repo:status permission for posting commit checks
export REGRADAR_GITHUB_TOKEN="ghp_yourPersonalAccessTokenHere"

# Optional: default workspace path
export REGRADAR_WORKSPACE="/home/user/infra"
```

Start the server:
```bash
python -m regradar.cli serve --port 8000
```

---

## Setting Up the Webhook in GitHub

1. Open your repository on GitHub.
2. Go to **Settings** > **Webhooks** > **Add webhook**.
3. Fill in the fields:
   * **Payload URL:** `https://regradar.example.com/api/webhooks/github` (or your public endpoint).
   * **Content type:** `application/json`
   * **Secret:** The same secret string configured in `REGRADAR_GITHUB_WEBHOOK_SECRET`.
   * **SSL verification:** Enable SSL verification.
4. Under **Which events would you like to trigger this webhook?**, select **Let me select individual events**:
   * Check **Pull requests**
   * Check **Pushes**
5. Click **Add webhook**.

---

## Configuring Branch Protection Rules

To prevent merging unverified pull requests:

1. In GitHub, go to **Settings** > **Branches** > **Add branch protection rule**.
2. Set **Branch name pattern** to `main` (or your release branch).
3. Check **Require status checks to pass before merging**.
4. In the search box, search for and select:
   * `regradar/compliance`
5. Check **Require branches to be up to date before merging**.
6. Save the protection rule.

---

## Operator Review Workflow

When a pull request touches high-centrality foundational infrastructure (such as VPCs, internet gateways, or root route tables), RegRadar holds the pull request in an `Awaiting Operator Sign-Off` state.

Operators can sign off through two channels:

### 1. Web Studio Console
1. Open `http://127.0.0.1:8000/dashboard` in a browser.
2. Select the **GitHub** navigation tab.
3. Review the staged pull request details, dependency graph location, and plan diff.
4. Click **Approve & Sign Off** (or **Reject** / **Request Revision**).
5. RegRadar immediately updates the GitHub commit status check to `success`.

### 2. Terminal CLI
Run the review command directly in the terminal:
```bash
python -m regradar.cli review /path/to/repo
```
The terminal prompt displays each violation, its centrality tier, and asks for operator input:
```text
Foundational node 'aws_vpc.main' modified (Blast Radius: 0.81, CRITICAL_ROOT)
Options: [a]pprove, [r]eject, [s]kip:
```

---

## Testing Webhook Connectivity

To verify your webhook configuration without creating an actual pull request, dispatch a synthetic test event:

```bash
curl -X POST http://127.0.0.1:8000/api/webhooks/dispatch-test \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "org/terraform-infra",
    "event_type": "pull_request",
    "pr_number": 1
  }'
```

Inspect webhook delivery logs at any time:
```bash
curl http://127.0.0.1:8000/api/webhooks/logs
```
