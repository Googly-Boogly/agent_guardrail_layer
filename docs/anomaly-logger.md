# Anomaly Logger

`AnomalyLogger` writes structured audit events for every decision the guardrail pipeline makes — approvals, rejections, and sanitization triggers. Events are written as newline-delimited JSON (JSONL) to a file and/or stderr.

## Event format

Each line in `guardrail_events.jsonl` is a self-contained JSON object:

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
    "violations": [
      "Path traversal pattern in 'path': matched '\\.\\.[/\\\\]'"
    ]
  }
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `event_id` | `str` | First 8 chars of a UUID4. Unique per event within a run. |
| `timestamp` | `str` | ISO 8601 with timezone offset (always UTC `+00:00`). |
| `severity` | `"INFO"` \| `"WARNING"` \| `"CRITICAL"` | See severity guide below. |
| `event_type` | `str` | Machine-readable event category. |
| `agent_id` | `str` | Identifier passed in by the caller; used for correlation. |
| `tool_name` | `str \| null` | Tool involved, if applicable. |
| `message` | `str` | Human-readable summary. |
| `raw_input_excerpt` | `str` | Truncated copy of the input that triggered the event. |
| `metadata` | `object` | Event-specific data (violations list, flags list, etc.). |

`raw_input_excerpt` is truncated to `guardrail_max_input_log_chars` (default 500) to prevent sensitive data from appearing in full in logs.

## Event types

| `event_type` | Severity | Emitted by | Meaning |
|---|---|---|---|
| `tool_validated` | INFO | `ToolValidator` | Tool call passed all checks; approved for execution. |
| `tool_not_in_allowlist` | WARNING | `ToolValidator` | Tool name not in the allowlist. |
| `tool_validation_failure` | WARNING / CRITICAL | `ToolValidator` | One or more checks failed. CRITICAL when injection or traversal was detected. |
| `output_sanitization_triggered` | WARNING / CRITICAL | `OutputSanitizer` | Sanitization flags raised. CRITICAL when `blocked=True`. |

## Severity guide

| Severity | Meaning | Example |
|---|---|---|
| `INFO` | Normal operation, no security concern | Tool call approved |
| `WARNING` | Anomalous but not necessarily a live attack | Unknown tool, rate limit hit, malformed params |
| `CRITICAL` | Active attack attempt or definite policy violation | Prompt injection, path traversal, exfiltration signal |

## API

`AnomalyLogger` is usually created by `GuardrailPipeline` and shared internally. You do not need to instantiate it directly unless you are building a custom pipeline.

```python
from src.guardrails.anomaly_logger import AnomalyLogger

logger = AnomalyLogger(
    log_file="guardrail_events.jsonl",   # None to disable file logging
    log_stdout=True,                      # echo to stderr
    max_input_chars=500,                  # truncation limit for raw_input_excerpt
)

logger.info(
    agent_id="agent-001",
    event_type="custom_event",
    message="Something happened",
    tool_name="my_tool",
    metadata={"detail": "value"},
)

logger.warning(agent_id="agent-001", event_type="...", message="...")
logger.critical(agent_id="agent-001", event_type="...", message="...")

logger.close()   # flush and close file handle on shutdown
```

### Logging raw input

Pass raw input via the `raw_input` keyword argument. It is automatically truncated:

```python
logger.warning(
    agent_id="agent-001",
    event_type="tool_validation_failure",
    message="Tool call blocked",
    raw_input=str(parameters),   # will be truncated to max_input_chars
    tool_name="read_file",
    metadata={"violations": [...]},
)
```

## File behaviour

- The log file is opened in **append mode** (`"a"`) — existing events are preserved between runs.
- **Line-buffered** (`buffering=1`) — each event is flushed to disk before the logger returns. Events survive process crashes.
- Events are also written to `sys.stderr` when `log_stdout=True`, keeping them separate from agent stdout that may be piped.

## Querying the log

`guardrail_events.jsonl` is plain text and can be queried with standard tools.

**View all events, pretty-printed:**

```bash
python -c "
import json
for line in open('guardrail_events.jsonl'):
    print(json.dumps(json.loads(line), indent=2))
    print()
"
```

**Filter by severity:**

```bash
python -c "
import json
for line in open('guardrail_events.jsonl'):
    e = json.loads(line)
    if e['severity'] == 'CRITICAL':
        print(e['timestamp'], e['agent_id'], e['message'])
"
```

**Group by event type:**

```bash
python -c "
import json
from collections import Counter
c = Counter(json.loads(l)['event_type'] for l in open('guardrail_events.jsonl'))
for k, v in c.most_common():
    print(f'{v:4d}  {k}')
"
```

**Filter by agent ID:**

```bash
python -c "
import json, sys
target = sys.argv[1]
for line in open('guardrail_events.jsonl'):
    e = json.loads(line)
    if e['agent_id'] == target:
        print(json.dumps(e, indent=2))
" agent-003
```

**Extract violations from a run:**

```bash
python -c "
import json
for line in open('guardrail_events.jsonl'):
    e = json.loads(line)
    if 'violations' in e.get('metadata', {}):
        for v in e['metadata']['violations']:
            print(f\"[{e['severity']}] {e['agent_id']} / {e['tool_name']}: {v}\")
"
```

## Integration with other logging systems

`AnomalyLogger` is intentionally minimal and writes only to file and stderr. To forward events to a centralised logging system (Datadog, Splunk, CloudWatch, etc.), tail the JSONL file or subclass `AnomalyLogger` and override `log()`:

```python
class ForwardingLogger(AnomalyLogger):
    def log(self, event: AnomalyEvent) -> None:
        super().log(event)                          # keep local file + stderr
        send_to_datadog(event.model_dump())         # forward to external system
```

Pass your subclass to `ToolValidator` and `OutputSanitizer` when constructing the pipeline manually.
