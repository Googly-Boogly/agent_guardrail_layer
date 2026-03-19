# Getting Started

## Prerequisites

- Python 3.11+
- An API key for at least one supported LLM provider (Anthropic, OpenAI, or Google)

## Installation

```bash
# Clone and enter the repo
git clone https://github.com/Googly-Boogly/agent_guardrail_layer
cd agent_guardrail_layer

# Create and activate a virtualenv
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root (it is gitignored):

```bash
# .env
LLM_API_KEY=sk-ant-your-key-here
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-6
```

Or set environment variables directly:

```bash
export LLM_API_KEY=sk-ant-...
export LLM_PROVIDER=anthropic
```

`LLM_API_KEY` is the only required value. All other settings have defaults.

## Verify the installation

```bash
# Should print "ok" with no errors
LLM_API_KEY=dummy python -c "from src.guardrails import GuardrailPipeline; print('ok')"
```

## Run the demo

The example agent has two modes:

**Direct tests** (no API key required) — feeds crafted inputs straight into the pipeline and runs 12 assertions:

```bash
LLM_API_KEY=dummy python examples/agent_with_tools.py
```

Expected output:

```
======================================================================
Agent Guardrail Layer — Securing Autonomous AI Systems
======================================================================

======================================================================
Direct Guardrail Tests (no LLM call)
======================================================================
  [PASS] Allowlist: unknown tool 'delete_database'
  [PASS] Path traversal: ../../etc/passwd
  [PASS] Path traversal: /etc/shadow
  [PASS] Shell injection in code param: os.system with curl
  [PASS] Prompt injection in search query
  [PASS] Rate limit: 6th call to execute_code within window
  [PASS] Benign: valid web search
  [PASS] Benign: valid read_file with safe path
  [PASS] Output injection: ignore previous instructions
  [PASS] Output exfiltration: curl command
  [PASS] Output exfiltration: URL with secret param
  [PASS] Benign output: normal text response

  Results: 12/12 passed

[SKIP] Live LLM scenarios require ANTHROPIC_API_KEY to be set.
```

**Live LLM scenarios** — runs the same agent against real LLM calls:

```bash
ANTHROPIC_API_KEY=sk-ant-... python examples/agent_with_tools.py
```

Anomaly events are echoed to stderr and written to `guardrail_events.jsonl` in the working directory.

## Integrating into your agent

### 1. Define your tool schemas

```python
from src.guardrails import GuardrailPipeline, ToolSchema, ParameterSchema

schemas = [
    ToolSchema(
        name="read_file",
        description="Read a file from disk",
        parameters={
            "path": ParameterSchema(
                type="string",
                required=True,
                max_length=512,
            ),
        },
        path_params=["path"],       # enables path traversal checks on this param
    ),
    ToolSchema(
        name="run_shell",
        parameters={
            "command": ParameterSchema(type="string", required=True),
        },
        shell_params=["command"],   # enables shell injection checks on this param
    ),
    ToolSchema(
        name="web_search",
        parameters={
            "query": ParameterSchema(type="string", required=True, max_length=300),
            "max_results": ParameterSchema(type="integer", required=False),
        },
    ),
]
```

### 2. Create the pipeline

```python
pipeline = GuardrailPipeline(
    tool_schemas=schemas,
    log_file="guardrail_events.jsonl",   # None to disable file logging
    log_stdout=True,                      # echo events to stderr
    rate_limit_max_calls=10,              # per tool, per window
    rate_limit_window_seconds=60,
)
```

### 3. Add guardrail calls to your agent loop

```python
async def agent_loop(task: str, agent_id: str) -> str:
    messages = [{"role": "user", "content": task}]

    for _ in range(max_turns):
        response = await llm_client.messages.create(...)

        # Sanitize LLM text output
        for text_block in get_text_blocks(response):
            san = pipeline.sanitize_output(text_block.text, agent_id=agent_id)
            if san.blocked:
                return f"Blocked: {san.flags}"

        if response.stop_reason == "end_turn":
            return extract_final_text(response)

        for tool_block in get_tool_blocks(response):
            # Validate before executing
            result = pipeline.validate_tool_call(
                tool_block.name, tool_block.input, agent_id
            )
            if not result.allowed:
                append_tool_error(messages, tool_block.id, result.violations)
                continue

            # Execute
            output = execute_tool(tool_block.name, tool_block.input)

            # Sanitize tool output before it re-enters context
            san = pipeline.sanitize_output(output, agent_id=agent_id,
                                           tool_name=tool_block.name)
            if san.blocked:
                append_tool_error(messages, tool_block.id, san.flags)
            else:
                append_tool_result(messages, tool_block.id, san.sanitized_content)

        append_turn(messages, response)

    return "max_turns reached"

# Always close on shutdown to flush the log file
pipeline.close()
```

A complete working example is in [`examples/agent_with_tools.py`](../examples/agent_with_tools.py).

## Reading the audit log

`guardrail_events.jsonl` is newline-delimited JSON. Each line is one event:

```bash
# View all events
cat guardrail_events.jsonl | python -m json.tool

# Filter to blocked events only
python -c "
import json, sys
for line in open('guardrail_events.jsonl'):
    e = json.loads(line)
    if e['severity'] in ('WARNING', 'CRITICAL'):
        print(json.dumps(e, indent=2))
"

# Count by event type
python -c "
import json
from collections import Counter
c = Counter(json.loads(l)['event_type'] for l in open('guardrail_events.jsonl'))
print(c)
"
```

## Next steps

- [Architecture](architecture.md) — understand how the components fit together
- [Tool Validator](tool-validator.md) — add custom injection patterns or tool schemas
- [Output Sanitizer](output-sanitizer.md) — extend exfiltration or injection detection
- [Configuration](configuration.md) — all tuneable settings
- [Threat Model](threat-model.md) — what is and isn't covered
