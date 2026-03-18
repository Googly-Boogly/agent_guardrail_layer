# Agent Guardrail Layer

Security middleware for autonomous AI agent systems. Intercepts every tool call an LLM requests and every output it produces before either can cause harm — without modifying the LLM itself.

```
User task
    │
    ▼
LLM (Anthropic / OpenAI / Google)
    │
    ├─ text response ──► OutputSanitizer  ──► blocked? halt
    │
    └─ tool_use request
            │
            ▼
        ToolValidator          ← allowlist · rate limit · schema · injection checks
            │ blocked? ──► return error to LLM; skip execution
            │ approved ↓
        Tool execution
            │
            ▼
        OutputSanitizer        ← injection · exfiltration · shell char scan
            │ blocked? ──► return error to LLM
            │ clean ↓
        Tool result fed back into context
            │
            ▼
        AnomalyLogger          ← structured JSONL audit trail for every event
```

## Why this exists

Autonomous agents loop without human approval. A single malicious payload — in a web page, a file, or a cleverly crafted user prompt — can hijack the loop and make the agent call destructive tools, exfiltrate data, or escalate privileges. Standard LLM safety training does not prevent these *agentic* attack vectors because the threat arrives at runtime, not training time.

This library adds a deterministic, auditable enforcement layer that sits between the model and your tools.

## Features

| Layer | What it catches |
|---|---|
| **Tool Call Validation** | Unknown tools, rate-limit abuse, type/schema violations, prompt injection in parameters, shell injection, path traversal |
| **Output Sanitization** | Indirect prompt injection in LLM/tool responses, data exfiltration signals, shell metacharacter cleanup, malformed structured output |
| **Anomaly Logging** | Every event logged as structured JSON — severity, agent ID, tool name, raw input excerpt, full violation list |

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set your API key
export LLM_API_KEY=sk-ant-...     # or add to .env

# 3. Run the demo (no API key required for the direct tests)
LLM_API_KEY=dummy python examples/agent_with_tools.py

# 4. Run with live LLM scenarios
ANTHROPIC_API_KEY=sk-ant-... python examples/agent_with_tools.py
```

## Usage

```python
from src.guardrails import GuardrailPipeline, ToolSchema, ParameterSchema

pipeline = GuardrailPipeline(
    tool_schemas=[
        ToolSchema(
            name="read_file",
            parameters={"path": ParameterSchema(type="string", max_length=512)},
            path_params=["path"],   # enables path traversal checks
        ),
    ],
    log_file="guardrail_events.jsonl",
    rate_limit_max_calls=10,
)

# Before executing any tool call:
result = pipeline.validate_tool_call(tool_name, parameters, agent_id="my-agent")
if not result.allowed:
    # Return result.violations to the model instead of executing
    ...

# Before feeding any LLM or tool output back into context:
san = pipeline.sanitize_output(text, agent_id="my-agent")
if san.blocked:
    # Do not proceed — check san.flags for what was detected
    ...

pipeline.close()   # on shutdown
```

## Project layout

```
src/
  config.py                   Settings (pydantic-settings, reads .env)
  utils/
    call_llm.py               Multi-provider LLM caller (Anthropic / OpenAI / Google)
  guardrails/
    schemas.py                Shared Pydantic models
    anomaly_logger.py         Structured JSONL anomaly logger
    tool_validator.py         Tool call validation (allowlist, schema, injection, rate limit)
    output_sanitizer.py       Output sanitization (injection, exfiltration, shell chars)
    pipeline.py               GuardrailPipeline — single entry point
examples/
  agent_with_tools.py         Runnable demo with 12 direct tests + live LLM scenarios
docs/
  architecture.md             System design and data-flow details
  getting-started.md          Setup, configuration, first run
  tool-validator.md           ToolValidator API reference
  output-sanitizer.md         OutputSanitizer API reference
  anomaly-logger.md           AnomalyLogger API reference
  configuration.md            All environment variables and settings
  threat-model.md             Attack surface, mitigations, known limitations
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `LLM_API_KEY` | *(required)* | API key for the LLM provider |
| `LLM_PROVIDER` | `anthropic` | `anthropic` · `openai` · `google` |
| `LLM_MODEL` | `claude-sonnet-4-6` | Model ID passed to the provider |
| `GUARDRAIL_LOG_FILE` | `guardrail_events.jsonl` | JSONL log path (`""` to disable) |
| `GUARDRAIL_LOG_STDOUT` | `true` | Echo events to stderr |
| `GUARDRAIL_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rolling window for rate limiting |
| `GUARDRAIL_MAX_INPUT_LOG_CHARS` | `500` | Max chars stored in `raw_input_excerpt` |

See [docs/configuration.md](docs/configuration.md) for details.

## Documentation

- [Architecture](docs/architecture.md) — how the components fit together
- [Getting Started](docs/getting-started.md) — installation and first integration
- [Tool Validator](docs/tool-validator.md) — allowlist, schema, injection checks
- [Output Sanitizer](docs/output-sanitizer.md) — what it detects and how
- [Anomaly Logger](docs/anomaly-logger.md) — log format and querying
- [Configuration](docs/configuration.md) — all settings
- [Threat Model](docs/threat-model.md) — attack surface coverage and limitations
