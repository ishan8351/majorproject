"""
LLM Client Abstraction Layer for RegRadar.

Provides standardized access to real frontier LLMs (OpenAI, Anthropic), local LLMs (Ollama),
and deterministic Mock clients for offline testing and continuous integration.
"""

from abc import ABC, abstractmethod
import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def extract_json_payload(text: str) -> str:
    """
    Extracts a JSON object or array substring from LLM response text,
    stripping markdown fences (```json ... ```) or conversational commentary.
    """
    clean = text.strip()

    # Strip triple backtick markdown fences
    if "```" in clean:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean)
        if match:
            clean = match.group(1).strip()

    # Find the outermost JSON object {...} or array [...]
    start_brace = clean.find("{")
    start_bracket = clean.find("[")

    if start_brace != -1 and (start_bracket == -1 or start_brace < start_bracket):
        end_brace = clean.rfind("}")
        if end_brace > start_brace:
            return clean[start_brace : end_brace + 1]
    elif start_bracket != -1:
        end_bracket = clean.rfind("]")
        if end_bracket > start_bracket:
            return clean[start_bracket : end_bracket + 1]

    return clean


class BaseLLMClient(ABC):
    """Abstract base interface for LLM completions."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        """Generates a text completion given a prompt and optional system prompt."""
        pass

    def generate_structured(
        self,
        prompt: str,
        response_model: Type[T],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> T:
        """
        Generates a completion constrained to a Pydantic response schema.
        Extracts and parses JSON into an instance of response_model.
        """
        schema_json = json.dumps(response_model.model_json_schema(), indent=2)
        guidance = (
            f"\n\nYou MUST format your entire response as a single, valid JSON object "
            f"conforming strictly to this JSON schema:\n{schema_json}\n"
            f"Do not include any conversational preamble or wrap with explanations outside the JSON."
        )

        effective_system = (system_prompt or "") + guidance
        raw_response = self.generate(
            prompt=prompt,
            system_prompt=effective_system.strip(),
            temperature=temperature,
            **kwargs,
        )

        extracted_json = extract_json_payload(raw_response)
        return response_model.model_validate_json(extracted_json)


class MockLLMClient(BaseLLMClient):
    """
    Deterministic mock client supporting pattern matching, custom scripted responses,
    and realistic synthesized HCL patches for unit tests and offline environments.
    """

    def __init__(
        self,
        responses: Optional[List[str]] = None,
        pattern_responses: Optional[Dict[str, str]] = None,
        structured_responses: Optional[List[Any]] = None,
    ):
        self.responses: List[str] = list(responses) if responses else []
        self.pattern_responses: Dict[str, str] = dict(pattern_responses) if pattern_responses else {}
        self.structured_responses: List[Any] = list(structured_responses) if structured_responses else []
        self.call_history: List[Dict[str, Any]] = []

    def add_response(self, response: str) -> None:
        """Enqueues a canned text response."""
        self.responses.append(response)

    def add_pattern(self, pattern: str, response: str) -> None:
        """Maps a regex pattern to a canned response."""
        self.pattern_responses[pattern] = response

    def add_structured_response(self, response: Any) -> None:
        """Enqueues a canned Pydantic or dict structured response."""
        self.structured_responses.append(response)

    def reset(self) -> None:
        """Clears response queues and call history."""
        self.responses.clear()
        self.pattern_responses.clear()
        self.structured_responses.clear()
        self.call_history.clear()

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        self.call_history.append(
            {
                "prompt": prompt,
                "system_prompt": system_prompt,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "kwargs": kwargs,
            }
        )

        # 1. Check scripted FIFO queue
        if self.responses:
            return self.responses.pop(0)

        # 2. Check pattern matching
        combined = f"{system_prompt or ''}\n{prompt}"
        for pattern, canned in self.pattern_responses.items():
            if re.search(pattern, combined, re.IGNORECASE):
                return canned

        # 3. Dynamic realistic fallback generation based on role/context
        return self._dynamic_fallback_generate(prompt, system_prompt)

    def generate_structured(
        self,
        prompt: str,
        response_model: Type[T],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> T:
        # Check if structured response queue has an entry
        if self.structured_responses:
            item = self.structured_responses.pop(0)
            if isinstance(item, response_model):
                self.call_history.append(
                    {
                        "prompt": prompt,
                        "system_prompt": system_prompt,
                        "response_model": response_model.__name__,
                        "structured_response": item,
                    }
                )
                return item
            if isinstance(item, dict):
                return response_model.model_validate(item)
            if isinstance(item, str):
                return response_model.model_validate_json(extract_json_payload(item))

        # Check if standard text response is available
        if self.responses:
            text = self.responses.pop(0)
            self.call_history.append(
                {
                    "prompt": prompt,
                    "system_prompt": system_prompt,
                    "response_model": response_model.__name__,
                    "raw_text": text,
                }
            )
            return response_model.model_validate_json(extract_json_payload(text))

        # Check pattern responses
        combined = f"{system_prompt or ''}\n{prompt}"
        for pattern, canned in self.pattern_responses.items():
            if re.search(pattern, combined, re.IGNORECASE):
                return response_model.model_validate_json(extract_json_payload(canned))

        # Otherwise synthesize a valid response model dynamically
        return self._dynamic_fallback_structured(prompt, system_prompt, response_model)

    def _dynamic_fallback_generate(self, prompt: str, system_prompt: Optional[str]) -> str:
        """Produces realistic synthesized HCL or diagnostic text for offline runs."""
        combined = f"{system_prompt or ''}\n{prompt}".lower()

        # Unconstrained LLM Baseline Simulation (Empirical literature fault patterns)
        if "unconstrained" in combined or "blind" in combined:
            if "patient_db" in combined or "rds" in combined or "database" in combined:
                return (
                    '# Unconstrained LLM fix: Directly modifies RDS attributes (forces replacement)\n'
                    'resource "aws_db_instance" "patient_db" {\n'
                    '  allocated_storage = 10\n'
                    '  name              = "recreated_patient_db"\n'
                    '  engine            = "postgres"\n'
                    '  storage_encrypted = true\n'
                    '}\n'
                )
            if "patient_records" in combined or "s3" in combined or "bucket" in combined:
                return (
                    '# Unconstrained LLM fix: Recreates bucket and hallucinates parameters\n'
                    'resource "aws_s3_bucket" "patient_records" {\n'
                    '  bucket                  = "healthcare-corp-patient-records-prod-v2"\n'
                    '  enable_hipaa_compliance = true\n'
                    '  auto_encrypt            = true\n'
                    '}\n'
                )
            if "vpc" in combined or "network" in combined:
                return (
                    '# Unconstrained LLM fix: Mutates root VPC CIDR block (forces replacement)\n'
                    'resource "aws_vpc" "hipaa_vpc" {\n'
                    '  cidr_block = "172.16.0.0/16"\n'
                    '}\n'
                )
            if "cardholder_volume" in combined or "ebs" in combined or "volume" in combined:
                return (
                    '# Unconstrained LLM fix: Modifies AZ and hallucinates PCI flags\n'
                    'resource "aws_ebs_volume" "cardholder_volume" {\n'
                    '  availability_zone  = "us-east-1b"\n'
                    '  pci_dss_compliance = "active"\n'
                    '}\n'
                )
            if "sa_customer_data" in combined or "storage_account" in combined:
                return (
                    '# Unconstrained LLM fix: Mutates immutable storage name and adds hallucinated flags\n'
                    'resource "azurerm_storage_account" "sa_customer_data" {\n'
                    '  name         = "mutatedcustomerdata2026"\n'
                    '  enforce_gdpr = true\n'
                    '}\n'
                )
            return (
                '# Unconstrained LLM fix: Blind mutation with forces replacement and hallucinated parameter\n'
                'resource "mutated_resource" "blind_patch" {\n'
                '  forces_replacement = true\n'
                '  hallucinated_param = "invalid"\n'
                '}\n'
            )

        if "synthesizer" in combined or "hcl" in combined:
            # Check if this is an additive attachment or S3 encryption
            if "aws_s3_bucket" in combined or "s3" in combined:
                match_id = re.search(r'aws_s3_bucket\.([a-zA-Z0-9_\-]+)', prompt)
                res_name = match_id.group(1) if match_id else "audit_logs"
                return (
                    f'resource "aws_s3_bucket_server_side_encryption_configuration" "{res_name}_encryption" {{\n'
                    f'  bucket = aws_s3_bucket.{res_name}.id\n\n'
                    f'  rule {{\n'
                    f'    apply_server_side_encryption_by_default {{\n'
                    f'      sse_algorithm = "AES256"\n'
                    f'    }}\n'
                    f'  }}\n'
                    f'}}\n'
                )
            return '# RegRadar Synthesized Remediation\nresource "null_resource" "safe_remediation" {}\n'

        if "supervisor" in combined:
            return "Invariant analysis: Plan is verified safe with zero destructive mutations."

        if "auditor" in combined:
            return "Auditor evaluation: Resource assessed within acceptable blast-radius thresholds."

        return "OK"

    def _dynamic_fallback_structured(
        self, prompt: str, system_prompt: Optional[str], response_model: Type[T]
    ) -> T:
        """Constructs a valid Pydantic model dynamically matching the requested schema."""
        model_name = response_model.__name__
        combined = f"{system_prompt or ''}\n{prompt}".lower()

        # Auditor Decision
        if model_name == "AuditorDecision":
            prompt_lower = prompt.lower()
            is_critical = (
                "risk tier: critical_root" in prompt_lower
                or "risk_tier: critical_root" in prompt_lower
                or "resource id: aws_vpc" in prompt_lower
                or "resource_id: aws_vpc" in prompt_lower
                or "blast_radius_score: 0.7" in prompt_lower
                or "blast_radius_score: 0.8" in prompt_lower
                or "blast_radius_score: 0.9" in prompt_lower
                or "blast_radius_score: 1.0" in prompt_lower
            )
            # Extract resource_id if possible
            res_match = re.search(r'(?:target\s+)?resource[_\s]+id[:\s=]+([a-zA-Z0-9_\-\.]+)', prompt, re.IGNORECASE)
            res_id = res_match.group(1) if res_match else "aws_s3_bucket.audit_logs"

            gating = "HUMAN_ESCALATION_REQUIRED" if is_critical else "AUTONOMOUS_ELIGIBLE"
            risk_tier = "CRITICAL_ROOT" if is_critical else "LEAF_SAFE"
            blast_score = 0.85 if is_critical else 0.0
            reason = (
                f"Resource '{res_id}' is rated {risk_tier}. Locked out for human review."
                if is_critical
                else f"Resource '{res_id}' is rated {risk_tier}. Eligible for autonomous repair."
            )
            return response_model.model_validate(
                {
                    "resource_id": res_id,
                    "gating_status": gating,
                    "risk_tier": risk_tier,
                    "blast_radius_score": blast_score,
                    "reason": reason,
                }
            )

        # Policy Plan
        if model_name == "PolicyPlan":
            check_match = re.search(r'ckv_[a-zA-Z0-9_]+', combined)
            check_id = check_match.group(0).upper() if check_match else "CKV_AWS_19"
            use_additive = "aws_s3_bucket" in combined or "additive" in combined
            strategy = "ADDITIVE_ATTACHMENT" if use_additive else "IN_PLACE_ATTRIBUTE"

            return response_model.model_validate(
                {
                    "check_id": check_id,
                    "framework": "HIPAA",
                    "statute_reference": "HIPAA §164.312(a)(2)(iv)",
                    "strategy": strategy,
                    "target_attribute": "server_side_encryption_configuration",
                    "attribute_value": (
                        'server_side_encryption_configuration {\n  rule {\n    '
                        'apply_server_side_encryption_by_default {{\n      sse_algorithm = "AES256"\n    }}\n  }}\n}}'
                    ),
                    "additive_resource_template": (
                        'resource "aws_s3_bucket_server_side_encryption_configuration" "{name}_encryption" {{\n'
                        '  bucket = {resource_id}.id\n\n'
                        '  rule {{\n'
                        '    apply_server_side_encryption_by_default {{\n'
                        '      sse_algorithm = "AES256"\n'
                        '    }}\n'
                        '  }}\n'
                        '}}\n'
                    ),
                    "description": "Enforce server-side encryption at rest",
                    "rationale": "Retrieved via GraphRAG regulatory ontology mapping.",
                }
            )

        # Synthesizer Output
        if model_name == "SynthesizerOutput":
            res_match = re.search(r'(?:target\s+)?resource[_\s]+id[:\s=]+([a-zA-Z0-9_\-\.]+)', prompt, re.IGNORECASE)
            res_id = res_match.group(1) if res_match else "aws_s3_bucket.audit_logs"
            res_name = res_id.split(".")[-1]

            additive_snippet = (
                f'resource "aws_s3_bucket_server_side_encryption_configuration" "{res_name}_encryption" {{\n'
                f'  bucket = {res_id}.id\n\n'
                f'  rule {{\n'
                f'    apply_server_side_encryption_by_default {{\n'
                f'      sse_algorithm = "AES256"\n'
                f'    }}\n'
                f'  }}\n'
                f'}}'
            )
            # Find base content from prompt if included
            base_content = ""
            if "## Current File Content:" in prompt:
                part = prompt.split("## Current File Content:")[1]
                if "```hcl" in part:
                    base_content = part.split("```hcl")[1].split("```")[0].strip()
                elif "```" in part:
                    base_content = part.split("```")[1].split("```")[0].strip()
            elif "File Content:" in prompt:
                base_content = prompt.split("File Content:")[1].split("Remediation Action:")[0].strip()

            if not base_content:
                base_content = f'resource "aws_s3_bucket" "{res_name}" {{\n  bucket = "{res_name}"\n}}\n'

            modified = base_content.rstrip() + f"\n\n# --- RegRadar Autonomous Compliance Remediation ---\n{additive_snippet}\n"

            return response_model.model_validate(
                {
                    "resource_id": res_id,
                    "strategy": "ADDITIVE_ATTACHMENT",
                    "remediated_snippet": additive_snippet,
                    "modified_content": modified,
                    "explanation": "Synthesized additive attachment preventing recreation of bucket state.",
                }
            )

        # Supervisor Diagnosis
        if model_name == "SupervisorDiagnosis":
            prompt_lower = prompt.lower()
            has_replacement = (
                "forces_replacement" in prompt_lower
                or "forces replacement" in prompt_lower
                or "replace" in prompt_lower
            )
            has_deletion = "unintended_deletion" in prompt_lower or "unintended deletion" in prompt_lower
            has_semantic = (
                "unmet_requirement" in prompt_lower
                or "semantic" in prompt_lower
                or "security_regression" in prompt_lower
                or "regression" in prompt_lower
            )

            # Check semantic first if semantic violations section is present in prompt
            if "semantic" in prompt_lower and not ("forces_replacement" in prompt_lower or "forces replacement" in prompt_lower):
                has_replacement = False

            if has_replacement:
                return response_model.model_validate(
                    {
                        "is_acceptable": False,
                        "failure_type": "FORCES_REPLACEMENT",
                        "root_cause": "Modification of in-place resource attributes triggers state recreation.",
                        "actionable_feedback": (
                            "Do not modify the primary resource block directly. "
                            "Switch strategy to ADDITIVE_ATTACHMENT using an external configuration resource."
                        ),
                        "recommended_strategy": "ADDITIVE_ATTACHMENT",
                        "retry_permitted": True,
                    }
                )
            if has_semantic:
                return response_model.model_validate(
                    {
                        "is_acceptable": False,
                        "failure_type": "UNMET_REQUIREMENT",
                        "root_cause": "The synthesized patch failed to enforce the required security attribute.",
                        "actionable_feedback": "Ensure the encryption configuration block is explicitly defined.",
                        "recommended_strategy": "ADDITIVE_ATTACHMENT",
                        "retry_permitted": True,
                    }
                )
            if has_deletion:
                return response_model.model_validate(
                    {
                        "is_acceptable": False,
                        "failure_type": "UNINTENDED_DELETION",
                        "root_cause": "An existing resource was dropped or truncated from configuration.",
                        "actionable_feedback": "Preserve all existing resource blocks and attributes.",
                        "recommended_strategy": "ADDITIVE_ATTACHMENT",
                        "retry_permitted": True,
                    }
                )

            # Acceptable
            return response_model.model_validate(
                {
                    "is_acceptable": True,
                    "failure_type": None,
                    "root_cause": "Zero destruction guarantee met. Semantic invariants satisfied.",
                    "actionable_feedback": "Patch approved for deployment.",
                    "recommended_strategy": None,
                    "retry_permitted": False,
                }
            )

        # Generic fallback: attempt default instantiation
        try:
            return response_model.model_validate({})
        except Exception:
            raise NotImplementedError(
                f"MockLLMClient has no scripted or dynamic handler for schema: {model_name}. "
                f"Use add_structured_response() or add_response() to script it."
            )


class OpenAIClient(BaseLLMClient):
    """
    OpenAI API client using standard urllib/HTTP requests.
    Supports gpt-6-sol, gpt-6-astra, gpt-6.1-terra, gpt-6-luna, o3-mini, o1, gpt-4o.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        from regradar.config import get_config
        cfg = get_config().llm.openai
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "") or (cfg.api_key or "")
        self.model = model or os.environ.get("OPENAI_MODEL", cfg.model)
        raw_url = base_url or os.environ.get("OPENAI_BASE_URL", cfg.base_url)
        self.base_url = raw_url.rstrip("/")
        self.timeout = timeout if timeout is not None else cfg.timeout

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        if not self.api_key:
            raise ValueError("OpenAI API key not configured. Set OPENAI_API_KEY environment variable.")

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        # Handle OpenAI reasoning and GPT-6 models (gpt-6-sol, gpt-6-astra, o1, o3-mini)
        is_reasoning_model = (
            any(self.model.startswith(prefix) for prefix in ("o1", "o3", "gpt-6"))
            or "reasoning" in self.model.lower()
            or "astra" in self.model.lower()
            or "sol" in self.model.lower()
        )

        messages: List[Dict[str, str]] = []
        if system_prompt:
            # Reasoning / GPT-6 models use developer role instead of system
            role = "developer" if is_reasoning_model else "system"
            messages.append({"role": role, "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }
        # Reasoning models do not support arbitrary temperature customization
        if not is_reasoning_model:
            payload["temperature"] = temperature

        if max_tokens:
            if is_reasoning_model:
                payload["max_completion_tokens"] = max_tokens
            else:
                payload["max_tokens"] = max_tokens

        if "reasoning_effort" in kwargs:
            payload["reasoning_effort"] = kwargs.pop("reasoning_effort")

        payload.update(kwargs)

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                return resp_json["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.error("OpenAI API error %d: %s", e.code, err_body)
            raise RuntimeError(f"OpenAI API HTTP {e.code}: {err_body}") from e
        except Exception as e:
            logger.error("OpenAI request error: %s", e)
            raise RuntimeError(f"OpenAI request failed: {e}") from e


class AnthropicClient(BaseLLMClient):
    """
    Anthropic Messages API integration.
    Supports claude-sonnet-5-5, claude-opus-5-5, claude-fable-5-2, claude-haiku-5-5, claude-3-7-sonnet.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        version: Optional[str] = None,
    ):
        from regradar.config import get_config
        cfg = get_config().llm.anthropic
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "") or (cfg.api_key or "")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", cfg.model)
        raw_url = base_url or os.environ.get("ANTHROPIC_BASE_URL", cfg.base_url)
        self.base_url = raw_url.rstrip("/")
        self.timeout = timeout if timeout is not None else cfg.timeout
        self.version = version or cfg.version

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        if not self.api_key:
            raise ValueError("Anthropic API key not configured. Set ANTHROPIC_API_KEY environment variable.")

        url = f"{self.base_url}/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": self.version,
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens or 4096,
        }
        # Support Claude 5.5 / 3.7 adaptive/hybrid extended thinking mode
        if "thinking" in kwargs:
            payload["thinking"] = kwargs.pop("thinking")
        else:
            payload["temperature"] = temperature

        if system_prompt:
            payload["system"] = system_prompt
        payload.update(kwargs)

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                contents = resp_json.get("content", [])
                if contents and isinstance(contents, list):
                    # Concatenate or find text block (skipping thinking blocks if present)
                    text_parts = [c.get("text", "") for c in contents if c.get("type") == "text"]
                    if text_parts:
                        return "".join(text_parts)
                    return contents[0].get("text", "")
                return ""
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.error("Anthropic API error %d: %s", e.code, err_body)
            raise RuntimeError(f"Anthropic API HTTP {e.code}: {err_body}") from e
        except Exception as e:
            logger.error("Anthropic request error: %s", e)
            raise RuntimeError(f"Anthropic request failed: {e}") from e


class GeminiClient(BaseLLMClient):
    """
    Google Gemini API client using standard urllib/HTTP requests.
    Supports gemini-4-argon, gemini-3.8-flash, gemini-4-carbon, gemini-2.0-flash.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        from regradar.config import get_config
        cfg = get_config().llm.gemini
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "") or (cfg.api_key or "")
        self.model = model or os.environ.get("GEMINI_MODEL", cfg.model)
        raw_url = base_url or os.environ.get("GEMINI_BASE_URL", cfg.base_url)
        self.base_url = raw_url.rstrip("/")
        self.timeout = timeout if timeout is not None else cfg.timeout

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        if not self.api_key:
            raise ValueError("Gemini API key not configured. Set GEMINI_API_KEY environment variable.")

        url = f"{self.base_url}/models/{self.model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }

        generation_config: Dict[str, Any] = {
            "temperature": temperature,
        }
        if max_tokens:
            generation_config["maxOutputTokens"] = max_tokens

        # Support Gemini 4 thinking levels (low, medium, high) or budget
        if "thinking_level" in kwargs:
            generation_config["thinkingConfig"] = {"thinkingLevel": kwargs.pop("thinking_level")}
        elif "thinking_budget" in kwargs:
            generation_config["thinkingConfig"] = {"thinkingBudget": kwargs.pop("thinking_budget")}

        payload: Dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": generation_config,
        }
        if system_prompt:
            payload["systemInstruction"] = {
                "parts": [{"text": system_prompt}]
            }
        payload.update(kwargs)

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                candidates = resp_json.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
                return ""
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.error("Gemini API error %d: %s", e.code, err_body)
            raise RuntimeError(f"Gemini API HTTP {e.code}: {err_body}") from e
        except Exception as e:
            logger.error("Gemini request error: %s", e)
            raise RuntimeError(f"Gemini request failed: {e}") from e


class DeepSeekClient(BaseLLMClient):
    """
    DeepSeek API client (OpenAI compatible, api.deepseek.com).
    Supports deepseek-v4-pro, deepseek-flash, deepseek-chat, deepseek-reasoner.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        from regradar.config import get_config
        cfg = get_config().llm.deepseek
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "") or (cfg.api_key or "")
        self.model = model or os.environ.get("DEEPSEEK_MODEL", cfg.model)
        raw_url = base_url or os.environ.get("DEEPSEEK_BASE_URL", cfg.base_url)
        self.base_url = raw_url.rstrip("/")
        self.timeout = timeout if timeout is not None else cfg.timeout

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        if not self.api_key:
            raise ValueError("DeepSeek API key not configured. Set DEEPSEEK_API_KEY environment variable.")

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        is_reasoner = "reasoner" in self.model.lower() or "v4-pro" in self.model.lower()

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }
        # Pure reasoner models do not support arbitrary temperature tuning
        if not is_reasoner:
            payload["temperature"] = temperature

        if max_tokens:
            payload["max_tokens"] = max_tokens

        # Support DeepSeek-V4 thinking effort control
        if "thinking_effort" in kwargs:
            payload["thinking_effort"] = kwargs.pop("thinking_effort")

        payload.update(kwargs)

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                choice = resp_json["choices"][0]
                content = choice.get("message", {}).get("content", "")
                reasoning = choice.get("message", {}).get("reasoning_content")
                if reasoning:
                    logger.debug("DeepSeek reasoning trace (%d chars): %s...", len(reasoning), reasoning[:100])
                return content
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.error("DeepSeek API error %d: %s", e.code, err_body)
            raise RuntimeError(f"DeepSeek API HTTP {e.code}: {err_body}") from e
        except Exception as e:
            logger.error("DeepSeek request error: %s", e)
            raise RuntimeError(f"DeepSeek request failed: {e}") from e


class OllamaClient(BaseLLMClient):
    """
    Local LLM integration via Ollama (/api/chat endpoint or OpenAI-compatible endpoint).
    Supports llama3.3, qwen2.5-coder:32b, deepseek-r1:8b, mistral, etc.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        from regradar.config import get_config
        cfg = get_config().llm.ollama
        raw_url = base_url or os.environ.get("OLLAMA_BASE_URL", cfg.base_url)
        self.base_url = raw_url.rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", cfg.model)
        self.timeout = timeout if timeout is not None else cfg.timeout

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        url = f"{self.base_url}/api/chat"
        headers = {"Content-Type": "application/json"}

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        options: Dict[str, Any] = {"temperature": temperature}
        if max_tokens:
            options["num_predict"] = max_tokens

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": options,
        }

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                return resp_json.get("message", {}).get("content", "")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.error("Ollama API error %d: %s", e.code, err_body)
            raise RuntimeError(f"Ollama API HTTP {e.code}: {err_body}") from e
        except Exception as e:
            logger.error("Ollama request error: %s", e)
            raise RuntimeError(f"Ollama request failed: {e}") from e


def get_llm_client(provider: Optional[str] = None, **kwargs: Any) -> BaseLLMClient:
    """
    Factory function for resolving the active LLM client.

    Resolution precedence:
      1. Explicit provider parameter ("mock", "openai", "anthropic", "gemini", "deepseek", "ollama")
      2. REGRADAR_LLM_PROVIDER environment variable
      3. Automatic detection from available API credentials:
         - OPENAI_API_KEY -> OpenAIClient
         - ANTHROPIC_API_KEY -> AnthropicClient
         - GEMINI_API_KEY -> GeminiClient
         - DEEPSEEK_API_KEY -> DeepSeekClient
         - OLLAMA_BASE_URL -> OllamaClient
      4. Configured provider in RegRadarConfig (if explicitly non-mock)
      5. Graceful fallback to MockLLMClient (offline / test safe default)
    """
    from regradar.config import get_config

    target = provider or os.environ.get("REGRADAR_LLM_PROVIDER")
    if target:
        target = target.strip().lower()

    if target == "openai":
        return OpenAIClient(**kwargs)
    if target == "anthropic":
        return AnthropicClient(**kwargs)
    if target == "gemini":
        return GeminiClient(**kwargs)
    if target == "deepseek":
        return DeepSeekClient(**kwargs)
    if target == "ollama":
        return OllamaClient(**kwargs)
    if target == "mock":
        return MockLLMClient(**kwargs)

    # Automatic detection from available API credentials
    if os.environ.get("OPENAI_API_KEY"):
        return OpenAIClient(**kwargs)
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicClient(**kwargs)
    if os.environ.get("GEMINI_API_KEY"):
        return GeminiClient(**kwargs)
    if os.environ.get("DEEPSEEK_API_KEY"):
        return DeepSeekClient(**kwargs)
    if os.environ.get("OLLAMA_BASE_URL"):
        return OllamaClient(**kwargs)

    # Configured provider if non-default
    cfg_target = get_config().llm.provider.lower()
    if cfg_target == "openai":
        return OpenAIClient(**kwargs)
    if cfg_target == "anthropic":
        return AnthropicClient(**kwargs)
    if cfg_target == "gemini":
        return GeminiClient(**kwargs)
    if cfg_target == "deepseek":
        return DeepSeekClient(**kwargs)
    if cfg_target == "ollama":
        return OllamaClient(**kwargs)

    # Safe default for test and offline environments
    return MockLLMClient(**kwargs)
