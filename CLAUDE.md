# CLAUDE.md

Developer notes for working on this repository with Claude Code.

## Project purpose

Security middleware for autonomous AI agents. The guardrail layer intercepts tool calls and LLM output before they can cause harm. The three components — `ToolValidator`, `OutputSanitizer`, `AnomalyLogger` — compose into `GuardrailPipeline`, the single entry point for agent loops.

## Running things

```bash
# Activate the virtualenv (always use .venv/bin/python, not system python)
source .venv/bin/activate

# Install/update deps
pip install -r requirements.txt

# Import smoke test
LLM_API_KEY=dummy python -c "from src.guardrails import GuardrailPipeline; print('ok')"

# Run demo (direct guardrail tests, no API key needed)
LLM_API_KEY=dummy python examples/agent_with_tools.py

# Run demo with live LLM
ANTHROPIC_API_KEY=sk-ant-... python examples/agent_with_tools.py
```

## Architecture — dependency order (no cycles)

```
schemas.py
    └── anomaly_logger.py  (+ config.py)
            ├── tool_validator.py
            └── output_sanitizer.py
                    └── pipeline.py
                            └── guardrails/__init__.py
```

Never import `tool_validator` or `output_sanitizer` from `anomaly_logger`. Never import `pipeline` from the component modules. `schemas.py` has zero internal imports.

## Module responsibilities

| File | Responsibility |
|---|---|
| `src/config.py` | `Settings` via pydantic-settings. Module-level `settings` singleton. Must exist for `call_llm.py` import to work. |
| `src/guardrails/schemas.py` | All shared Pydantic models. No internal deps. |
| `src/guardrails/anomaly_logger.py` | Writes `AnomalyEvent` as JSONL to file + stderr. Line-buffered. |
| `src/guardrails/tool_validator.py` | Allowlist, rate limit, schema, injection pattern checks. Returns `ValidationResult`. |
| `src/guardrails/output_sanitizer.py` | Injection/exfiltration detection + shell char stripping. Returns `SanitizationResult`. |
| `src/guardrails/pipeline.py` | Composes all three. This is the only import agents need. |
| `src/utils/call_llm.py` | Multi-provider async LLM caller. Separate from the guardrail layer. |

## Extending the tool validator

To add a new injection pattern, append a compiled regex to the appropriate module-level list in `tool_validator.py`:

```python
_PROMPT_INJECTION_PATTERNS.append(re.compile(r"your new pattern", re.IGNORECASE))
```

Patterns are compiled at module load time — do not compile inside a function.

To add a new tool to the allowlist, define a `ToolSchema` and pass it to `GuardrailPipeline`. Mark shell-bound parameters in `shell_params` and path parameters in `path_params`; these enable the targeted injection checks.

## Extending the output sanitizer

Add entries to `_INJECTION_IN_OUTPUT_PATTERNS` or `_EXFILTRATION_PATTERNS` in `output_sanitizer.py` as `(compiled_pattern, label_string)` tuples. Injection and exfiltration matches are always blocking (`blocked=True`). Shell char stripping is non-blocking.

## AnomalyEvent log format

Each line in `guardrail_events.jsonl` is a JSON object:

```json
{
  "event_id": "2781f348",
  "timestamp": "2026-03-18T23:06:24.569427+00:00",
  "severity": "CRITICAL",
  "event_type": "tool_validation_failure",
  "agent_id": "agent-003",
  "tool_name": "read_file",
  "message": "Tool call blocked: read_file",
  "raw_input_excerpt": "{'path': '../../etc/passwd'}",
  "metadata": {
    "violations": ["Path traversal pattern in 'path': matched '\\\\.\\\\.[/\\\\\\\\]'"]
  }
}
```

`event_type` values: `tool_validated`, `tool_not_in_allowlist`, `tool_validation_failure`, `output_sanitization_triggered`.

## Key design decisions to preserve

- **`schemas.py` has no internal imports** — keeps the dependency graph acyclic.
- **`anomaly_logger.py` has no dependency on `tool_validator` or `output_sanitizer`** — those modules depend on the logger, not the other way around.
- **Regex patterns are module-level compiled constants** — performance; do not move them into methods.
- **Rate limiter uses `time.monotonic()`** — immune to clock adjustments. Not thread-safe for concurrent coroutines; add `asyncio.Lock` if the agent dispatches parallel tool calls.
- **`AnomalyLogger` opens the file in line-buffered mode (`buffering=1`)** — events flush immediately and survive process crashes.
- **Tool output is sanitized *before* it re-enters context** — this is the indirect prompt injection defence. Do not skip this step.
- **`GuardrailPipeline.close()` must be called on shutdown** — flushes and closes the log file handle.

## What not to change without care

- The `ValidationResult.allowed` / `SanitizationResult.blocked` boolean contract — agent loops rely on checking exactly these fields.
- `raw_input_excerpt` truncation via `guardrail_max_input_log_chars` — this prevents sensitive data from appearing in full in logs.
- The `shell_params` / `path_params` lists on `ToolSchema` — removing them disables the targeted injection checks silently.

## Common pitfalls

- **`LLM_API_KEY` is required at import time** — `settings = Settings()` is module-level in `config.py`. Tests that import from `src.guardrails` must set `LLM_API_KEY` (even a dummy value works).
- **`call_llm.py` is separate from the guardrail pipeline** — the example agent uses the Anthropic SDK directly (not `call_llm`) because tool_use requires structured message handling that `call_llm` does not provide.
- **`examples/agent_with_tools.py` resets its own pipeline rate limiter** — the direct tests pre-fill 5 `execute_code` calls before running the rate-limit test scenario. Don't confuse this state with the live LLM pipeline.
