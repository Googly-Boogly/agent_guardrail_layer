# Architecture

## Overview

The guardrail layer is security middleware that wraps the tool execution loop of an autonomous AI agent. It does not modify the LLM; it sits between the model's decisions and the tools those decisions would invoke.

The three components are deliberately independent:

```
┌─────────────────────────────────────────────────────┐
│                   GuardrailPipeline                 │
│                                                     │
│  ┌──────────────────┐   ┌───────────────────────┐  │
│  │  ToolValidator   │   │   OutputSanitizer     │  │
│  │                  │   │                       │  │
│  │ • allowlist      │   │ • injection detection │  │
│  │ • rate limit     │   │ • exfiltration scan   │  │
│  │ • schema check   │   │ • shell char strip    │  │
│  │ • injection scan │   │ • JSON validation     │  │
│  └──────────────────┘   └───────────────────────┘  │
│           │                        │               │
│           └──────────┬─────────────┘               │
│                      │                             │
│             ┌─────────────────┐                    │
│             │  AnomalyLogger  │                    │
│             │                 │                    │
│             │ • JSONL to file │                    │
│             │ • echo stderr   │                    │
│             └─────────────────┘                    │
└─────────────────────────────────────────────────────┘
```

## Data flow

This is the complete path for a single agent turn that results in a tool call:

```
1.  Agent sends messages to LLM API
         │
         ▼
2.  LLM returns response (text + optional tool_use blocks)
         │
         ├─► [text content]
         │       │
         │       ▼
         │   OutputSanitizer.sanitize(llm_text)
         │       │ blocked=True  →  return guardrail error; do not continue
         │       │ blocked=False →  text is safe to use
         │
         └─► [tool_use block: name + input dict]
                 │
                 ▼
3.  ToolValidator.validate(tool_name, parameters, agent_id)
         │ allowed=False  →  inject error tool_result; skip to step 7
         │ allowed=True   ↓
         │
         ▼
4.  Execute tool implementation (mock or real)
         │
         ▼
5.  OutputSanitizer.sanitize(tool_output)
         │ blocked=True  →  inject error tool_result
         │ blocked=False →  tool_result with sanitized content
         │
         ▼
6.  AnomalyLogger writes event for every check result
         │
         ▼
7.  Append assistant content + tool_results to messages
         │
         ▼
8.  Next turn (back to step 1)
```

## Module dependency graph

Dependencies flow strictly downward. There are no cycles.

```
src/config.py
     │
     ▼
src/guardrails/schemas.py          (no internal deps)
     │
     ▼
src/guardrails/anomaly_logger.py   (imports: config, schemas)
     │
     ├──────────────────────────────┐
     ▼                              ▼
src/guardrails/tool_validator.py   src/guardrails/output_sanitizer.py
     │                              │
     └──────────────┬───────────────┘
                    ▼
         src/guardrails/pipeline.py
                    │
                    ▼
         src/guardrails/__init__.py
```

`src/utils/call_llm.py` is a parallel utility — it imports `config` but has no relationship to the guardrail modules.

## Component responsibilities

### `schemas.py` — shared data contracts

All Pydantic models used across the system live here. Keeping them in one file prevents circular imports and gives a single place to look up the shape of any object.

Key models:

| Model | Used by | Purpose |
|---|---|---|
| `ToolSchema` | `ToolValidator`, agent code | Declares what a tool accepts and which params need security checks |
| `ParameterSchema` | `ToolSchema` | Type, length, enum constraints for a single parameter |
| `ValidationResult` | `ToolValidator` → pipeline → agent | Outcome of a tool validation check |
| `SanitizationResult` | `OutputSanitizer` → pipeline → agent | Outcome of an output sanitization check |
| `AnomalyEvent` | `AnomalyLogger` | A single structured log entry |

### `anomaly_logger.py` — audit trail

`AnomalyLogger` is instantiated once by `GuardrailPipeline` and injected into both `ToolValidator` and `OutputSanitizer`. This ensures all events share a single file handle and log file.

The logger is intentionally the simplest module and has no dependencies on the other guardrail components, so it can be used by all of them without risk of circular imports.

File writes use `buffering=1` (line-buffered). Each `AnomalyEvent` is flushed to disk before the function returns, so the log is reliable even if the process crashes mid-run.

### `tool_validator.py` — pre-execution gate

`ToolValidator.validate()` runs seven sequential checks. The checks are ordered from cheapest to most expensive:

1. **Allowlist** — O(1) dict lookup; fails fast if the tool is unknown
2. **Rate limit** — O(k) where k = calls in window; uses monotonic timestamps
3. **Required params** — O(p) where p = parameter count
4. **Type / constraint** — O(p); also checks max_length and allowed_values
5. **Prompt injection** — O(p × patterns); scans all string params
6. **Shell injection** — O(shell_params × patterns); only targeted params
7. **Path traversal** — O(path_params × patterns); only targeted params

All violations are collected before returning so the LLM receives a complete list of what was wrong. This is preferable to returning on the first violation, which forces the model to retry the same call multiple times.

### `output_sanitizer.py` — post-generation filter

`OutputSanitizer.sanitize()` runs four checks in this order:

1. **Prompt injection in output** — always blocking; replaces matched text with `[REDACTED BY GUARDRAIL]`
2. **Exfiltration signals** — always blocking; same redaction
3. **Shell metacharacter stripping** — non-blocking; strips characters as defence-in-depth
4. **JSON validation** — blocking only when `expect_json=True`

The distinction between blocking and non-blocking is intentional. Shell character stripping alone does not indicate a security threat (many legitimate strings contain these characters); the tool validator handles actual injection at the parameter level. The output sanitizer's shell pass is a last-resort cleanup.

### `pipeline.py` — composition layer

`GuardrailPipeline` has no logic of its own. It instantiates the three components with shared configuration and exposes two methods:

- `validate_tool_call(tool_name, parameters, agent_id)` → `ValidationResult`
- `sanitize_output(content, agent_id, tool_name, expect_json)` → `SanitizationResult`

Agent loops should only import and use `GuardrailPipeline`. The component classes are internal implementation details.

## Configuration

All tuneable values come from `src/config.py` via `pydantic-settings`. Values can be overridden with environment variables or a `.env` file. See [configuration.md](configuration.md) for the full reference.

## Threat model

See [threat-model.md](threat-model.md) for the full threat model, attack vectors covered, and known limitations.
