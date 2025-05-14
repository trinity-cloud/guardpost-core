# LLM Integration in GuardPost Core

GuardPost Core leverages Large Language Models (LLMs) to enhance the remediation guidance provided for security findings. This document outlines how this integration works.

## Overview

The primary goal of LLM integration is to transform rule-based remediation guidance into more comprehensive, contextually aware, and user-friendly advice. By combining the structured output of GuardPost's analyzers with the generative capabilities of LLMs, we aim to provide richer explanations and more detailed remediation steps.

## LLM Provider: Anthropic Claude

*   GuardPost Core is currently configured to use **Anthropic's Claude** models (specifically, defaulting to `claude-3-sonnet-20240229` but configurable via `CLAUDE_MODEL` environment variable).
*   Interaction with Claude is performed via its official Python client SDK.

## How LLM Enhancement Works

1.  **Baseline Guidance:** When remediation is requested for a finding, GuardPost Core first generates baseline guidance using its rule-based engine. This engine produces a `RemediationOutputV2` object which may include basic steps and IaC snippets.

2.  **Contextual Information:** In addition to the baseline guidance, the system gathers other relevant information:
    *   Details about the security finding itself (title, description, severity, resource involved).
    *   Specific configuration details of the affected resource (`finding.details`).
    *   *(Future Phase 2 Work):* Richer context from the Neo4j graph database, such as resource relationships, impact analysis (blast radius), and detailed resource properties.

3.  **Prompt Engineering:** This collected information (baseline guidance + contextual details) is formatted into a detailed prompt for the LLM. The prompt instructs the LLM to:
    *   Act as an expert AWS cloud security advisor.
    *   Provide a concise summary of the issue.
    *   Explain the technical details and security concerns.
    *   Generate actionable, step-by-step manual remediation instructions.
    *   Provide an Infrastructure as Code (IaC) snippet (primarily Terraform) if applicable, tailored to the resource and finding.
    *   Suggest relevant reference links.
    *   **Crucially, respond in a valid JSON format** matching a predefined structure, which mirrors many fields of the `RemediationOutputV2` schema.

4.  **LLM Interaction (`llm_guidance.py`):**
    *   The `generate_llm_remediation` function orchestrates the call to the Claude API.
    *   It sends the system prompt (defining the LLM's role and desired JSON output structure) and the user message (containing all the contextual data).

5.  **Response Parsing & Integration:**
    *   The LLM's JSON response is parsed.
    *   The structured data (summary, technical details, steps, IaC, links) from the LLM is used to populate a `RemediationOutputV2` object.
    *   This object includes the `is_llm_enhanced=True` flag.

6.  **Caching:**
    *   Successfully generated LLM-enhanced `RemediationOutputV2` guidance is serialized (as JSON) and stored in the `llm_remediation_output` column of the `Finding` table in the PostgreSQL database.
    *   Subsequent requests for remediation for the same finding will first attempt to retrieve and return this cached version, improving performance and reducing LLM API costs.

## Fallback Mechanism

If the LLM enhancement process fails for any reason (e.g., API error, LLM disabled, API key missing, response parsing failure), GuardPost Core gracefully falls back to providing the rule-based `RemediationOutputV2` guidance. This ensures that users always receive actionable advice.

The `is_llm_enhanced` flag in the `RemediationOutputV2` object will be `False` in such cases.

## Configuration

LLM integration is controlled by the following environment variables:

*   `ENABLE_LLM_REMEDIATION`:
    *   Set to `true` (default) to enable LLM-enhanced remediation.
    *   Set to `false` to disable LLM calls; the system will only use rule-based guidance.
*   `ANTHROPIC_API_KEY`:
    *   Your API key for Anthropic Claude. This must be set if `ENABLE_LLM_REMEDIATION` is true for LLM calls to succeed.
*   `CLAUDE_MODEL`:
    *   (Optional) Specifies the Claude model to use (e.g., `claude-3-sonnet-20240229`). Defaults to a recent Sonnet model.
*   `CLAUDE_MAX_TOKENS`:
    *   (Optional) The maximum number of tokens to generate in the LLM response. Defaults to `2000`.

This integration of LLMs aims to significantly improve the quality, depth, and actionability of the security remediation guidance provided by GuardPost Core. 