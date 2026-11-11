"""
Unit test suite for LLM Client abstractions, Role Prompts, Agents, and State Machine.
"""

from io import BytesIO
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from regradar.invariant.models import InvariantReport, InvariantViolation, ViolationType
from regradar.invariant.semantic_verifier import SemanticViolation, SemanticViolationType
from regradar.knowledge.models import ControlNode, RegulatoryContext, RemediationRule, RequirementNode
from regradar.models import CentralityMetrics, GraphSummary, RiskTier
from regradar.remediation.agents import AuditorAgent, PolicyPlannerAgent, SupervisorAgent, SynthesizerAgent
from regradar.remediation.llm.client import (
    AnthropicClient,
    BaseLLMClient,
    DeepSeekClient,
    GeminiClient,
    MockLLMClient,
    OllamaClient,
    OpenAIClient,
    extract_json_payload,
    get_llm_client,
)
from regradar.remediation.llm.prompts import (
    AuditorDecision,
    AuditorPrompt,
    PolicyPlan,
    PolicyPlannerPrompt,
    SupervisorDiagnosis,
    SupervisorPrompt,
    SynthesizerOutput,
    SynthesizerPrompt,
)
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    PatchProposal,
    RemediationAction,
    RemediationStrategy,
    RemediationTask,
)
from regradar.remediation.state_machine import (
    InvalidStateTransitionError,
    RemediationContext,
    RemediationState,
    StateTransition,
    SwarmStateMachine,
)


# ==============================================================================
# 1. JSON Extraction & MockLLMClient Tests
# ==============================================================================

def test_extract_json_payload():
    # Pure JSON
    assert extract_json_payload('{"key": "value"}') == '{"key": "value"}'

    # Markdown fenced json
    fenced = '```json\n{"status": "ok"}\n```'
    assert extract_json_payload(fenced) == '{"status": "ok"}'

    # Conversational text before and after
    chatter = 'Here is the requested output:\n```\n{"score": 42}\n```\nHope this helps!'
    assert extract_json_payload(chatter) == '{"score": 42}'

    # Array JSON
    array_fenced = '```json\n[{"id": 1}, {"id": 2}]\n```'
    assert extract_json_payload(array_fenced) == '[{"id": 1}, {"id": 2}]'

    # Plain text without JSON braces
    plain = 'No JSON here'
    assert extract_json_payload(plain) == 'No JSON here'


def test_mock_llm_client_scripted_responses():
    client = MockLLMClient()
    client.add_response("first response")
    client.add_response("second response")

    assert client.generate("prompt 1") == "first response"
    assert client.generate("prompt 2") == "second response"
    assert len(client.call_history) == 2

    # Reset
    client.reset()
    assert len(client.call_history) == 0


def test_mock_llm_client_pattern_matching():
    client = MockLLMClient(
        pattern_responses={
            r"classify.*risk": "CRITICAL_RISK",
            r"hcl.*encryption": "resource aws_s3_bucket_server_side_encryption_configuration test {}",
        }
    )

    resp1 = client.generate("Please classify the risk of this node")
    assert resp1 == "CRITICAL_RISK"

    resp2 = client.generate("Generate hcl for encryption")
    assert "aws_s3_bucket_server_side_encryption_configuration" in resp2


def test_mock_llm_client_structured_generation():
    client = MockLLMClient()

    # Dynamic generation of AuditorDecision
    dec_leaf = client.generate_structured(
        prompt="Auditor evaluate resource_id: aws_s3_bucket.logs with risk_tier: LEAF_SAFE score: 0.0",
        response_model=AuditorDecision,
    )
    assert dec_leaf.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE
    assert dec_leaf.risk_tier == "LEAF_SAFE"

    dec_crit = client.generate_structured(
        prompt="Auditor evaluate resource_id: aws_vpc.main with CRITICAL_ROOT score: 0.9",
        response_model=AuditorDecision,
    )
    assert dec_crit.gating_status == GatingStatus.HUMAN_ESCALATION_REQUIRED
    assert dec_crit.risk_tier == "CRITICAL_ROOT"

    # Dynamic generation of PolicyPlan
    plan = client.generate_structured(
        prompt="Plan remediation for CKV_AWS_19 on aws_s3_bucket.data",
        response_model=PolicyPlan,
    )
    assert plan.check_id == "CKV_AWS_19"
    assert plan.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT
    action = plan.to_action()
    assert action.check_id == "CKV_AWS_19"

    # Dynamic generation of SynthesizerOutput
    synth = client.generate_structured(
        prompt="Synthesize patch for resource_id: aws_s3_bucket.audit_logs",
        response_model=SynthesizerOutput,
    )
    assert synth.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT
    assert "aws_s3_bucket_server_side_encryption_configuration" in synth.modified_content

    # Dynamic generation of SupervisorDiagnosis
    diag_rep = client.generate_structured(
        prompt="Verify plan diff: forces replacement on aws_s3_bucket",
        response_model=SupervisorDiagnosis,
    )
    assert diag_rep.is_acceptable is False
    assert diag_rep.failure_type == "FORCES_REPLACEMENT"
    assert diag_rep.recommended_strategy == RemediationStrategy.ADDITIVE_ATTACHMENT

    diag_ok = client.generate_structured(
        prompt="Plan dry-run succeeded with zero mutations",
        response_model=SupervisorDiagnosis,
    )
    assert diag_ok.is_acceptable is True


# ==============================================================================
# 2. Remote Client Dispatch Tests (OpenAI, Anthropic, Ollama, Factory)
# ==============================================================================

def test_openai_client_dispatch():
    client = OpenAIClient(api_key="sk-test-key", model="gpt-6-sol")

    mock_resp_data = {
        "choices": [{"message": {"content": "Synthesized OpenTofu Configuration"}}]
    }
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(
            prompt="Remediate S3 encryption",
            system_prompt="You are an expert",
            max_tokens=4096,
        )

        assert result == "Synthesized OpenTofu Configuration"
        assert mock_urlopen.called
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://api.openai.com/v1/chat/completions"
        assert req.headers["Authorization"] == "Bearer sk-test-key"
        sent_body = json.loads(req.data.decode("utf-8"))
        assert sent_body["model"] == "gpt-6-sol"
        assert sent_body["messages"][0]["role"] == "developer"
        assert "max_completion_tokens" in sent_body


def test_openai_client_error_handling():
    client = OpenAIClient(api_key="sk-test-key")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.openai.com/v1/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=BytesIO(b'{"error": "Invalid API Key"}'),
        )

        with pytest.raises(RuntimeError, match="OpenAI API HTTP 401"):
            client.generate("Test prompt")


def test_anthropic_client_dispatch():
    client = AnthropicClient(api_key="anthropic-test-key", model="claude-sonnet-5-5")

    mock_resp_data = {"content": [{"text": "Anthropic Verified Patch"}]}
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(prompt="Synthesize patch", system_prompt="Sys")
        assert result == "Anthropic Verified Patch"
        req = mock_urlopen.call_args[0][0]
        assert req.headers["X-api-key"] == "anthropic-test-key"
        assert req.headers["Anthropic-version"] == "2023-06-01"


def test_openai_reasoning_model_dispatch():
    client = OpenAIClient(api_key="sk-test-key", model="gpt-6-astra")

    mock_resp_data = {
        "choices": [{"message": {"content": "Reasoned remediation plan"}}]
    }
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(
            prompt="Optimize graph",
            system_prompt="Developer instructions",
            max_tokens=2048,
            reasoning_effort="high",
        )

        assert result == "Reasoned remediation plan"
        req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req.data.decode("utf-8"))
        assert sent_body["model"] == "gpt-6-astra"
        assert sent_body["messages"][0]["role"] == "developer"
        assert sent_body["messages"][0]["content"] == "Developer instructions"
        assert sent_body["max_completion_tokens"] == 2048
        assert sent_body["reasoning_effort"] == "high"
        assert "temperature" not in sent_body


def test_gemini_client_dispatch():
    client = GeminiClient(api_key="gemini-test-key", model="gemini-4-argon")

    mock_resp_data = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Gemini 4 Argon generated IaC patch"}]
                }
            }
        ]
    }
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(
            prompt="Generate AWS KMS policy",
            system_prompt="You are a cloud architect",
            temperature=0.1,
            max_tokens=1000,
            thinking_level="high",
        )

        assert result == "Gemini 4 Argon generated IaC patch"
        req = mock_urlopen.call_args[0][0]
        assert "models/gemini-4-argon:generateContent" in req.full_url
        assert req.headers["X-goog-api-key"] == "gemini-test-key"
        sent_body = json.loads(req.data.decode("utf-8"))
        assert sent_body["systemInstruction"]["parts"][0]["text"] == "You are a cloud architect"
        assert sent_body["contents"][0]["parts"][0]["text"] == "Generate AWS KMS policy"
        assert sent_body["generationConfig"]["temperature"] == 0.1
        assert sent_body["generationConfig"]["maxOutputTokens"] == 1000
        assert sent_body["generationConfig"]["thinkingConfig"]["thinkingLevel"] == "high"


def test_gemini_client_dispatch_38_flash():
    client = GeminiClient(api_key="gemini-test-key", model="gemini-3.8-flash")

    mock_resp_data = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Gemini 3.8 Flash rapid fix"}]
                }
            }
        ]
    }
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(
            prompt="Fast vulnerability patch",
            max_tokens=512,
        )

        assert result == "Gemini 3.8 Flash rapid fix"
        req = mock_urlopen.call_args[0][0]
        assert "models/gemini-3.8-flash:generateContent" in req.full_url


def test_gemini_client_error_handling():
    client = GeminiClient(api_key="gemini-test-key")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://generativelanguage.googleapis.com/v1beta/models/gemini-4-argon:generateContent",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=BytesIO(b'{"error": "Invalid argument"}'),
        )

        with pytest.raises(RuntimeError, match="Gemini API HTTP 400"):
            client.generate("Test prompt")


def test_deepseek_client_dispatch_v4_pro():
    client = DeepSeekClient(api_key="deepseek-test-key", model="deepseek-v4-pro")

    mock_resp_data = {
        "choices": [
            {
                "message": {
                    "content": "DeepSeek-V4 Pro Synthesized Config",
                    "reasoning_content": "Deep reasoning trace on cloud security invariants",
                }
            }
        ]
    }
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(
            prompt="Fix Azure Storage network rule",
            system_prompt="Security expert",
            thinking_effort="high",
        )

        assert result == "DeepSeek-V4 Pro Synthesized Config"
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://api.deepseek.com/chat/completions"
        assert req.headers["Authorization"] == "Bearer deepseek-test-key"
        sent_body = json.loads(req.data.decode("utf-8"))
        assert sent_body["thinking_effort"] == "high"


def test_deepseek_client_dispatch_flash():
    client = DeepSeekClient(api_key="deepseek-test-key", model="deepseek-flash")

    mock_resp_data = {
        "choices": [
            {
                "message": {
                    "content": "DeepSeek-Flash Fast Synthesized Config",
                }
            }
        ]
    }
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(
            prompt="Generate fast patch",
            temperature=0.3,
        )

        assert result == "DeepSeek-Flash Fast Synthesized Config"
        req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req.data.decode("utf-8"))
        assert sent_body["temperature"] == 0.3


def test_anthropic_client_thinking_mode():
    client = AnthropicClient(api_key="anthropic-test-key", model="claude-opus-5-5")

    mock_resp_data = {
        "content": [
            {"type": "thinking", "thinking": "Internal reasoning step..."},
            {"type": "text", "text": "Claude Opus 5.5 synthesized patch"},
        ]
    }
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(
            prompt="Plan patch",
            thinking={"type": "enabled", "budget_tokens": 2048},
        )
        assert result == "Claude Opus 5.5 synthesized patch"
        req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req.data.decode("utf-8"))
        assert sent_body["thinking"]["type"] == "enabled"
        assert sent_body["thinking"]["budget_tokens"] == 2048


def test_ollama_client_dispatch():
    client = OllamaClient(base_url="http://localhost:11434", model="llama3")

    mock_resp_data = {"message": {"content": "Ollama Local Output"}}
    mock_bytes = json.dumps(mock_resp_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = mock_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_cm

        result = client.generate(prompt="Generate patch")
        assert result == "Ollama Local Output"
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "http://localhost:11434/api/chat"


def test_get_llm_client_factory(monkeypatch):
    # Explicit provider
    assert isinstance(get_llm_client(provider="mock"), MockLLMClient)
    assert isinstance(get_llm_client(provider="openai", api_key="test"), OpenAIClient)
    assert isinstance(get_llm_client(provider="anthropic", api_key="test"), AnthropicClient)
    assert isinstance(get_llm_client(provider="gemini", api_key="test"), GeminiClient)
    assert isinstance(get_llm_client(provider="deepseek", api_key="test"), DeepSeekClient)
    assert isinstance(get_llm_client(provider="ollama"), OllamaClient)

    # REGRADAR_LLM_PROVIDER env
    monkeypatch.setenv("REGRADAR_LLM_PROVIDER", "mock")
    assert isinstance(get_llm_client(), MockLLMClient)

    # OPENAI_API_KEY env
    monkeypatch.delenv("REGRADAR_LLM_PROVIDER")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-live-key")
    assert isinstance(get_llm_client(), OpenAIClient)

    # GEMINI_API_KEY env
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-live-key")
    assert isinstance(get_llm_client(), GeminiClient)

    # DEEPSEEK_API_KEY env
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "deepseek-live-key")
    assert isinstance(get_llm_client(), DeepSeekClient)

    # Fallback to MockLLMClient when unconfigured
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    monkeypatch.delenv("REGRADAR_LLM_PROVIDER", raising=False)
    from regradar.config import reset_config
    reset_config()
    assert isinstance(get_llm_client(), MockLLMClient)


# ==============================================================================
# 3. Prompt Builder & Context Formatter Tests
# ==============================================================================

def test_auditor_prompt_formatter():
    violation = ComplianceViolation(
        check_id="CKV_AWS_19",
        check_name="S3 Encryption at Rest",
        resource_id="aws_s3_bucket.finance_vault",
        resource_type="aws_s3_bucket",
        file_path="storage.tf",
    )
    metrics = CentralityMetrics(
        node_id="aws_s3_bucket.finance_vault",
        resource_type="aws_s3_bucket",
        in_degree=1,
        out_degree=3,
        descendant_count=5,
        ancestor_count=2,
        betweenness=0.45,
        blast_radius_score=0.62,
        risk_tier=RiskTier.INTERMEDIATE,
        auto_remediate=True,
        eigenvector=0.31,
        pagerank=0.28,
    )
    summary = GraphSummary(
        total_resources=10,
        total_dependencies=12,
        root_resources=["aws_vpc.main"],
        leaf_resources=["aws_s3_bucket.finance_vault"],
    )

    formatted = AuditorPrompt.format(violation=violation, metrics=metrics, graph_summary=summary)
    assert "aws_s3_bucket.finance_vault" in formatted
    assert "CKV_AWS_19" in formatted
    assert "Betweenness Centrality: 0.4500" in formatted
    assert "Eigenvector Centrality: 0.3100" in formatted
    assert "PageRank Centrality: 0.2800" in formatted
    assert "Total Cascading Descendants: 5" in formatted
    assert "Total Resources in DAG: 10" in formatted


def test_policy_planner_prompt_formatter():
    violation = ComplianceViolation(
        check_id="CKV_AWS_19",
        check_name="S3 Encryption at Rest",
        resource_id="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        file_path="main.tf",
    )
    rule = RemediationRule(
        check_id="CKV_AWS_19",
        name="S3 Encryption",
        description="Enforce default encryption",
        resource_type="aws_s3_bucket",
        framework="HIPAA",
        statute_reference="HIPAA §164.312(a)(2)(iv)",
        strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
        additive_resource_template='resource "aws_s3_bucket_server_side_encryption_configuration" "{name}" {}',
    )
    contexts = [
        RegulatoryContext(
            check_id="CKV_AWS_19",
            rule=rule,
            resource_type="aws_s3_bucket",
            standards=["HIPAA", "NIST SP 800-53"],
            controls=[ControlNode(id="HIPAA_164", control_id="§164.312", standard_id="HIPAA", title="Encryption", description="Encrypt data")],
            requirements=[RequirementNode(id="REQ_ENC", name="Encryption at Rest", description="AES256")],
            score=4.5,
            rationale="Direct lexical and graph match",
        )
    ]

    formatted = PolicyPlannerPrompt.format(violation=violation, contexts=contexts)
    assert "HIPAA §164.312(a)(2)(iv)" in formatted
    assert "ADDITIVE_ATTACHMENT" in formatted
    assert "Encryption at Rest" in formatted
    assert "Score: 4.50" in formatted


def test_synthesizer_prompt_formatter():
    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption",
            resource_id="aws_s3_bucket.data",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier=RiskTier.LEAF_SAFE.value,
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        action=RemediationAction(
            check_id="CKV_AWS_19",
            framework="HIPAA",
            statute_reference="HIPAA §164.312(a)(2)(iv)",
            strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
            description="Enforce bucket encryption",
        ),
        reason="Autonomous leaf",
    )

    formatted = SynthesizerPrompt.format(
        task=task,
        file_content='resource "aws_s3_bucket" "data" {}',
        feedback="Attempt 1 rejected: Plan triggers recreation",
    )
    assert "CRITICAL SUPERVISOR FEEDBACK" in formatted
    assert "Plan triggers recreation" in formatted
    assert 'resource "aws_s3_bucket" "data"' in formatted


def test_supervisor_prompt_formatter():
    proposal = PatchProposal(
        resource_id="aws_s3_bucket.data",
        target_file="main.tf",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        remediated_snippet="server_side_encryption_configuration {}",
        attempts=1,
    )
    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption",
            resource_id="aws_s3_bucket.data",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        reason="Leaf safe",
    )
    invariants = [
        InvariantViolation(
            resource_address="aws_s3_bucket.data",
            violation_type=ViolationType.FORCES_REPLACEMENT,
            actions=["delete", "create"],
            message="Resource replacement forbidden",
            action_reason="forces replacement",
        )
    ]
    semantics = [
        SemanticViolation(
            resource_address="aws_s3_bucket.data",
            violation_type=SemanticViolationType.UNMET_REQUIREMENT,
            attribute_path="server_side_encryption_configuration",
            message="Encryption not enabled in planned state",
        )
    ]

    formatted = SupervisorPrompt.format(
        proposal=proposal,
        task=task,
        invariant_violations=invariants,
        semantic_violations=semantics,
    )
    assert "FORCES_REPLACEMENT" in formatted
    assert "Resource replacement forbidden" in formatted
    assert "UNMET_REQUIREMENT" in formatted
    assert "Encryption not enabled in planned state" in formatted


# ==============================================================================
# 4. Agent Execution with LLM Tests
# ==============================================================================

def test_auditor_agent_with_mock_llm():
    summary = GraphSummary(
        total_resources=2,
        total_dependencies=1,
        root_resources=["aws_vpc.main"],
        leaf_resources=["aws_s3_bucket.data"],
        metrics={
            "aws_vpc.main": CentralityMetrics(
                node_id="aws_vpc.main",
                resource_type="aws_vpc",
                in_degree=0,
                out_degree=2,
                descendant_count=3,
                ancestor_count=0,
                betweenness=0.8,
                blast_radius_score=0.85,
                risk_tier=RiskTier.CRITICAL_ROOT,
                auto_remediate=False,
            ),
            "aws_s3_bucket.data": CentralityMetrics(
                node_id="aws_s3_bucket.data",
                resource_type="aws_s3_bucket",
                in_degree=0,
                out_degree=0,
                descendant_count=0,
                ancestor_count=0,
                betweenness=0.0,
                blast_radius_score=0.0,
                risk_tier=RiskTier.LEAF_SAFE,
                auto_remediate=True,
            ),
        },
    )

    mock_llm = MockLLMClient()
    auditor = AuditorAgent(graph_summary=summary, llm_client=mock_llm)

    v_leaf = ComplianceViolation(
        check_id="CKV_AWS_19",
        check_name="S3 Encryption",
        resource_id="aws_s3_bucket.data",
        resource_type="aws_s3_bucket",
        file_path="main.tf",
    )
    v_root = ComplianceViolation(
        check_id="CKV_AWS_19",
        check_name="VPC Config",
        resource_id="aws_vpc.main",
        resource_type="aws_vpc",
        file_path="main.tf",
    )

    tasks = auditor.audit_and_gate([v_leaf, v_root])
    assert len(tasks) == 2

    # Leaf safe should be autonomous
    task_leaf = next(t for t in tasks if t.violation.resource_id == "aws_s3_bucket.data")
    assert task_leaf.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE

    # Critical root MUST be escalated to human even if LLM tried to hallucinate
    task_root = next(t for t in tasks if t.violation.resource_id == "aws_vpc.main")
    assert task_root.gating_status == GatingStatus.HUMAN_ESCALATION_REQUIRED


def test_policy_planner_with_mock_llm():
    mock_llm = MockLLMClient()
    planner = PolicyPlannerAgent(llm_client=mock_llm)

    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption",
            resource_id="aws_s3_bucket.phi",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        reason="Leaf safe",
    )

    enriched_task = planner.plan_remediation(task)
    assert enriched_task.action is not None
    assert enriched_task.action.check_id == "CKV_AWS_19"
    assert enriched_task.action.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT


def test_synthesizer_with_mock_llm():
    mock_llm = MockLLMClient()
    synthesizer = SynthesizerAgent(llm_client=mock_llm)

    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption",
            resource_id="aws_s3_bucket.audit",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        action=RemediationAction(
            check_id="CKV_AWS_19",
            framework="HIPAA",
            statute_reference="HIPAA §164.312(a)(2)(iv)",
            strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
            additive_resource_template='resource "aws_s3_bucket_server_side_encryption_configuration" "{name}_enc" {{\n  bucket = {resource_id}.id\n}}',
            description="Enforce encryption",
        ),
        reason="Safe leaf",
    )

    base_hcl = 'resource "aws_s3_bucket" "audit" {\n  bucket = "my-audit"\n}\n'
    proposal = synthesizer.synthesize_patch(task, base_hcl)

    assert proposal.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT
    assert "aws_s3_bucket_server_side_encryption_configuration" in proposal.modified_content
    assert 'resource "aws_s3_bucket" "audit"' in proposal.modified_content


# ==============================================================================
# 5. Governance State Machine Tests
# ==============================================================================

def test_governance_state_machine_valid_lifecycle():
    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption",
            resource_id="aws_s3_bucket.test",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        reason="Leaf safe",
    )

    ctx = RemediationContext(task=task, current_state=RemediationState.AUDIT)

    # 1. AUDIT -> GRAPH_RAG_RETRIEVE
    SwarmStateMachine.transition(ctx, RemediationState.GRAPH_RAG_RETRIEVE, "Querying GraphRAG")
    assert ctx.current_state == RemediationState.GRAPH_RAG_RETRIEVE

    # 2. GRAPH_RAG_RETRIEVE -> PLAN
    SwarmStateMachine.transition(ctx, RemediationState.PLAN, "Grounding regulatory controls")
    assert ctx.current_state == RemediationState.PLAN

    # 3. PLAN -> SYNTHESIZE
    SwarmStateMachine.transition(ctx, RemediationState.SYNTHESIZE, "Synthesizing patch")
    assert ctx.current_state == RemediationState.SYNTHESIZE
    assert ctx.attempt_count == 1

    # 4. SYNTHESIZE -> SANDBOX_SIMULATE
    SwarmStateMachine.transition(ctx, RemediationState.SANDBOX_SIMULATE, "Simulating dry-run")
    assert ctx.current_state == RemediationState.SANDBOX_SIMULATE

    # 5. SANDBOX_SIMULATE -> SEMANTIC_VERIFY
    SwarmStateMachine.transition(ctx, RemediationState.SEMANTIC_VERIFY, "Verifying semantics")
    assert ctx.current_state == RemediationState.SEMANTIC_VERIFY

    # 6. SEMANTIC_VERIFY -> ACCEPT
    SwarmStateMachine.transition(ctx, RemediationState.ACCEPT, "Remediation verified safe")
    assert ctx.current_state == RemediationState.ACCEPT
    assert ctx.is_terminal is True
    assert ctx.is_accepted is True
    assert len(ctx.history) == 6


def test_governance_state_machine_invalid_transition():
    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption",
            resource_id="aws_s3_bucket.test",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        reason="Leaf safe",
    )

    ctx = RemediationContext(task=task, current_state=RemediationState.AUDIT)

    # Cannot skip straight from AUDIT to ACCEPT
    with pytest.raises(InvalidStateTransitionError, match="Cannot transition from 'AUDIT' to 'ACCEPT'"):
        SwarmStateMachine.transition(ctx, RemediationState.ACCEPT)
