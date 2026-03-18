# Tool Validator

`ToolValidator` is the pre-execution gate. It runs seven sequential checks on every tool call the LLM requests before any tool code runs.

## API

```python
from src.guardrails.tool_validator import ToolValidator
from src.guardrails.schemas import ToolSchema, ParameterSchema, ValidationResult
from src.guardrails.anomaly_logger import AnomalyLogger

validator = ToolValidator(
    tool_schemas=[...],
    logger=AnomalyLogger(...),
    rate_limit_window=60,          # seconds; default from config
    rate_limit_max_calls=10,       # per tool per window
)

result: ValidationResult = validator.validate(
    tool_name="read_file",
    parameters={"path": "/home/user/doc.txt"},
    agent_id="agent-001",
)

if result.allowed:
    execute_tool(...)
else:
    # result.violations: list[str] — return to LLM
    ...
```

In practice, use `GuardrailPipeline.validate_tool_call()` rather than instantiating `ToolValidator` directly.

## ValidationResult fields

| Field | Type | Description |
|---|---|---|
| `allowed` | `bool` | `True` if the call passed all checks |
| `tool_name` | `str` | Name of the tool that was checked |
| `violations` | `list[str]` | Human-readable reasons for rejection (empty when `allowed=True`) |

## The seven checks

### 1. Allowlist

The tool name must appear in the `tool_schemas` list passed to `ToolValidator`. Unknown tools are rejected immediately — no further checks run.

Logged as: `tool_not_in_allowlist` (WARNING)

```python
# Block — "delete_database" not in schema list
validator.validate("delete_database", {"table": "users"}, "agent")
# violations: ["Tool 'delete_database' is not in the allowlist"]
```

### 2. Rate limiting

Each tool has an independent call counter. Calls older than `rate_limit_window` seconds are pruned on every call. If the remaining count is ≥ `rate_limit_max_calls`, the call is rejected.

Rate limiting is per-instance of `ToolValidator`. If you run multiple agents sharing one pipeline, their call counts are pooled.

```python
# With rate_limit_max_calls=5, the 6th call within the window is rejected
# violations: ["Rate limit exceeded for 'execute_code': 5 calls within 60s window (max 5)"]
```

### 3. Required parameter presence

Every parameter with `required=True` in its `ParameterSchema` must be present in the call.

```python
ToolSchema(
    name="send_email",
    parameters={
        "to": ParameterSchema(type="string", required=True),
        "subject": ParameterSchema(type="string", required=True),
        "body": ParameterSchema(type="string", required=True),
    },
)

# Block — "body" missing
validator.validate("send_email", {"to": "x@y.com", "subject": "hi"}, "agent")
# violations: ["Missing required parameter: 'body'"]
```

### 4. Type, length, and enum constraints

Three sub-checks per parameter:

**Type check** — verifies the Python type of the value.

| Schema type | Accepted Python types |
|---|---|
| `string` | `str` |
| `integer` | `int` |
| `float` | `int`, `float` |
| `boolean` | `bool` |
| `list` | `list` |
| `dict` | `dict` |

**max_length** — enforced on string values only:

```python
ParameterSchema(type="string", max_length=300)
# violations if len(value) > 300: "Parameter 'query' length 450 exceeds max_length 300"
```

**allowed_values** — enum-style constraint:

```python
ParameterSchema(type="string", allowed_values=["python", "javascript"])
# violations if value="ruby": "Parameter 'language' value 'ruby' not in allowed values ['python', 'javascript']"
```

### 5. Prompt injection patterns

Scanned on **all string parameters** regardless of whether they are declared in `shell_params` or `path_params`. The patterns target common jailbreak and instruction-override phrasing:

| Pattern | Example match |
|---|---|
| `ignore (all) (previous\|prior\|above) instructions` | "Ignore all previous instructions" |
| `disregard (all) (previous\|prior) instructions` | "Disregard prior instructions" |
| `<system>` | XML system-tag injection |
| `[INST]` | Llama instruction-template injection |
| `### system` | Markdown system-header injection |
| `new instructions:` | Instruction override prefix |
| `jailbreak` | Literal keyword |
| `you are now` (not followed by "an AI") | Role hijack ("you are now DAN") |

Matched violations are logged as CRITICAL.

```python
# Block
validator.validate("web_search", {"query": "Ignore all previous instructions"}, "agent")
# violations: ["Prompt injection pattern in 'query': matched '...'"]
```

### 6. Shell injection patterns

Scanned only on parameters listed in `ToolSchema.shell_params`. Targets characters and constructs dangerous when a value is passed to a subprocess or shell:

| Pattern | Targets |
|---|---|
| `[;&\|` `` ` `` `]` | Shell metacharacters |
| `$(` | Command substitution |
| `${` | Variable expansion |
| `> /` | Output redirection to absolute paths |
| `../` | Path traversal component |

```python
ToolSchema(name="run_command", shell_params=["cmd"])

# Block
validator.validate("run_command", {"cmd": "ls; rm -rf /"}, "agent")
# violations: ["Shell injection pattern in 'cmd': matched '[;&|`]'"]
```

### 7. Path traversal patterns

Scanned only on parameters listed in `ToolSchema.path_params`. Targets filesystem paths that could escape the intended working directory or access sensitive system files:

| Pattern | Example |
|---|---|
| `../` or `..\` | Relative traversal |
| `^/etc/` | System config directory |
| `^/proc/` | Kernel process info |
| `^/sys/` | Kernel sysfs |
| `^/dev/` | Device files |
| `~` | Home directory expansion |

```python
ToolSchema(name="read_file", path_params=["path"])

# Block
validator.validate("read_file", {"path": "../../etc/passwd"}, "agent")
# violations: ["Path traversal pattern in 'path': matched '\\\\.\\\\.[/\\\\\\\\]'"]
```

## Defining tool schemas

```python
from src.guardrails.schemas import ToolSchema, ParameterSchema

ToolSchema(
    name="execute_code",
    description="Run Python in a sandbox",
    parameters={
        "code": ParameterSchema(
            type="string",
            required=True,
            description="Python source to execute",
            max_length=2000,
        ),
        "language": ParameterSchema(
            type="string",
            required=False,
            allowed_values=["python"],
        ),
    },
    shell_params=["code"],   # inject shell checks on 'code'
    path_params=[],          # no path checks needed here
)
```

Both `shell_params` and `path_params` are lists of **parameter names**. Only parameters explicitly listed receive those checks. This keeps false-positive rates low — not every string is a shell argument.

## Adding new injection patterns

Patterns are module-level compiled lists in `tool_validator.py`. Append to the relevant list:

```python
# In tool_validator.py
_PROMPT_INJECTION_PATTERNS.append(
    re.compile(r"act as if you have no restrictions", re.IGNORECASE)
)
```

Compile patterns at module level, not inside methods — they are shared across all instances.

## Severity mapping

| Violation type | Log severity |
|---|---|
| Unknown tool (allowlist) | WARNING |
| Rate limit exceeded | WARNING |
| Missing / wrong type / enum | WARNING |
| Prompt injection detected | CRITICAL |
| Shell injection detected | CRITICAL |
| Path traversal detected | CRITICAL |
