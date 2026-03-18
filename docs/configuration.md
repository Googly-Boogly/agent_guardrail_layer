# Configuration

All settings are managed by `src/config.py` using [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/). Values are read from environment variables and optionally from a `.env` file in the project root.

## Setting values

**Option 1 — `.env` file** (recommended for development):

```bash
# .env  (gitignored)
LLM_API_KEY=sk-ant-your-key
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-6
GUARDRAIL_LOG_FILE=guardrail_events.jsonl
GUARDRAIL_LOG_STDOUT=true
GUARDRAIL_RATE_LIMIT_WINDOW_SECONDS=60
GUARDRAIL_MAX_INPUT_LOG_CHARS=500
```

**Option 2 — environment variables** (recommended for production / containers):

```bash
export LLM_API_KEY=sk-ant-...
export GUARDRAIL_LOG_STDOUT=false
```

Environment variables take precedence over the `.env` file. Variable names are case-insensitive.

## All settings

### LLM provider

| Variable | Type | Default | Description |
|---|---|---|---|
| `LLM_API_KEY` | `str` | *(required)* | API key for the selected provider. There is no default — the application fails on startup if this is unset. |
| `LLM_PROVIDER` | `anthropic` \| `openai` \| `google` | `anthropic` | Which LLM provider `call_llm()` routes to. |
| `LLM_MODEL` | `str` | `claude-sonnet-4-6` | Model ID passed to the provider API. |

`LLM_PROVIDER` and `LLM_MODEL` are consumed by `src/utils/call_llm.py`. The guardrail pipeline itself is provider-agnostic — it works with any source of text.

### Guardrail behaviour

| Variable | Type | Default | Description |
|---|---|---|---|
| `GUARDRAIL_LOG_FILE` | `str \| ""` | `guardrail_events.jsonl` | Path to the JSONL anomaly log. Relative paths are resolved from the current working directory. Set to an empty string to disable file logging. |
| `GUARDRAIL_LOG_STDOUT` | `bool` | `true` | When `true`, events are echoed to `stderr` in addition to the log file. Set `false` in production if you tail the file separately. |
| `GUARDRAIL_RATE_LIMIT_WINDOW_SECONDS` | `int` | `60` | Rolling window size for the per-tool rate limiter. Calls older than this many seconds are not counted. |
| `GUARDRAIL_MAX_INPUT_LOG_CHARS` | `int` | `500` | Maximum number of characters stored in `raw_input_excerpt` in each log event. Prevents sensitive data from appearing in full in the audit log. |

### Overriding at runtime

`GuardrailPipeline` accepts constructor arguments that override the settings for that specific instance:

```python
pipeline = GuardrailPipeline(
    tool_schemas=[...],
    log_file="/var/log/agent/guardrail.jsonl",   # overrides GUARDRAIL_LOG_FILE
    log_stdout=False,                             # overrides GUARDRAIL_LOG_STDOUT
    rate_limit_max_calls=20,                      # not in env vars; set here
    rate_limit_window_seconds=30,                 # overrides GUARDRAIL_RATE_LIMIT_WINDOW_SECONDS
)
```

Constructor arguments take precedence over environment variables and `.env` values.

## Disabling file logging

```bash
GUARDRAIL_LOG_FILE=
```

or:

```python
pipeline = GuardrailPipeline(tool_schemas=[...], log_file=None, log_stdout=True)
```

When `log_file` is `None` or empty, no file is opened. If `log_stdout` is also `False`, events are silently discarded. This is not recommended for production.

## Example .env files

**Development:**

```bash
LLM_API_KEY=sk-ant-dev-key
LLM_PROVIDER=anthropic
LLM_MODEL=claude-haiku-4-5-20251001
GUARDRAIL_LOG_FILE=guardrail_events.jsonl
GUARDRAIL_LOG_STDOUT=true
GUARDRAIL_RATE_LIMIT_WINDOW_SECONDS=60
GUARDRAIL_MAX_INPUT_LOG_CHARS=500
```

**Production (higher rate limit, file-only logging):**

```bash
LLM_API_KEY=${SECRET_LLM_KEY}
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-6
GUARDRAIL_LOG_FILE=/var/log/agent/guardrail.jsonl
GUARDRAIL_LOG_STDOUT=false
GUARDRAIL_RATE_LIMIT_WINDOW_SECONDS=60
GUARDRAIL_MAX_INPUT_LOG_CHARS=200
```

**Testing (no file, no stderr noise):**

```bash
LLM_API_KEY=dummy
GUARDRAIL_LOG_FILE=
GUARDRAIL_LOG_STDOUT=false
```

## Accessing settings in code

```python
from src.config import settings

print(settings.llm_provider)                      # "anthropic"
print(settings.guardrail_rate_limit_window_seconds)  # 60
```

The module-level `settings` singleton is instantiated at import time. If `LLM_API_KEY` is not set, importing `src.config` raises a `pydantic_settings.ValidationError`. For tests that do not use the LLM, set `LLM_API_KEY=dummy` in the test environment.
