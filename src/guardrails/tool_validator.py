"""
Tool call validator for agentic guardrail pipeline.

Checks every tool call the LLM requests before it is executed:
  1. Allowlist membership
  2. Rate limiting
  3. Required parameter presence
  4. Type / length / enum constraints
  5. Prompt injection patterns (all string params)
  6. Shell injection patterns (declared shell_params)
  7. Path traversal patterns (declared path_params)
"""
import re
import time
from collections import defaultdict
from typing import Any

from src.config import settings
from src.guardrails.anomaly_logger import AnomalyLogger
from src.guardrails.schemas import ToolSchema, ValidationResult

# ---------------------------------------------------------------------------
# Compiled patterns — paid once at module load time
# ---------------------------------------------------------------------------

_PROMPT_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"disregard\s+(all\s+)?(previous|prior)\s+instructions?",
        r"<\s*system\s*>",            # XML system-tag injection
        r"\[INST\]",                  # Llama template injection
        r"###\s*system",              # Markdown system header
        r"new\s+instructions?\s*:",   # instruction override
        r"jailbreak",
        r"you\s+are\s+now\s+(?!an?\s+AI)",  # "you are now DAN" etc.
    ]
]

_SHELL_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p)
    for p in [
        r"[;&|`]",        # shell metacharacters
        r"\$\(",          # command substitution $(...)
        r"\$\{",          # variable expansion ${...}
        r">\s*/",         # output redirection to absolute paths
        r"\.\.[/\\]",     # relative path traversal
    ]
]

_PATH_TRAVERSAL_PATTERNS: list[re.Pattern] = [
    re.compile(p)
    for p in [
        r"\.\.[/\\]",     # ../  or  ..\
        r"^/etc/",
        r"^/proc/",
        r"^/sys/",
        r"^/dev/",
        r"~[/\\]?",       # home-dir expansion
    ]
]


def _check_type(value: Any, expected: str) -> bool:
    mapping: dict[str, type | tuple] = {
        "string": str,
        "integer": int,
        "float": (int, float),
        "boolean": bool,
        "list": list,
        "dict": dict,
    }
    return isinstance(value, mapping[expected])


class ToolValidator:
    """
    Validates tool calls before execution.

    Args:
        tool_schemas: Allowlist of tools the agent may call.
        logger: Shared AnomalyLogger instance.
        rate_limit_window: Rolling window in seconds for rate limiting.
        rate_limit_max_calls: Max calls to a single tool within the window.
    """

    def __init__(
        self,
        tool_schemas: list[ToolSchema],
        logger: AnomalyLogger,
        rate_limit_window: int | None = None,
        rate_limit_max_calls: int = 10,
    ):
        self._schemas: dict[str, ToolSchema] = {s.name: s for s in tool_schemas}
        self._logger = logger
        self._rate_limit_window = (
            rate_limit_window if rate_limit_window is not None
            else settings.guardrail_rate_limit_window_seconds
        )
        self._rate_limit_max_calls = rate_limit_max_calls
        # Monotonic timestamps per tool name
        self._call_timestamps: dict[str, list[float]] = defaultdict(list)

    def validate(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        agent_id: str,
    ) -> ValidationResult:
        """
        Run all validation checks for a single tool call.

        Returns a ValidationResult. Callers should check `result.allowed` before
        executing the tool and surface `result.violations` to the model if blocked.
        """
        violations: list[str] = []

        # 1. Allowlist check — hard gate; no point running further checks if unknown
        if tool_name not in self._schemas:
            violations.append(f"Tool '{tool_name}' is not in the allowlist")
            self._logger.warning(
                agent_id=agent_id,
                event_type="tool_not_in_allowlist",
                message=f"Unknown tool blocked: {tool_name}",
                tool_name=tool_name,
                raw_input=str(parameters),
                metadata={"violations": violations},
            )
            return ValidationResult(allowed=False, tool_name=tool_name, violations=violations)

        schema = self._schemas[tool_name]

        # 2. Rate limiting
        now = time.monotonic()
        window_start = now - self._rate_limit_window
        timestamps = self._call_timestamps[tool_name]
        while timestamps and timestamps[0] < window_start:
            timestamps.pop(0)
        if len(timestamps) >= self._rate_limit_max_calls:
            violations.append(
                f"Rate limit exceeded for '{tool_name}': "
                f"{len(timestamps)} calls within {self._rate_limit_window}s window "
                f"(max {self._rate_limit_max_calls})"
            )

        # 3. Required parameter presence
        for param_name, param_schema in schema.parameters.items():
            if param_schema.required and param_name not in parameters:
                violations.append(f"Missing required parameter: '{param_name}'")

        # 4. Type / constraint checks
        for param_name, value in parameters.items():
            if param_name not in schema.parameters:
                violations.append(f"Unknown parameter: '{param_name}'")
                continue

            param_schema = schema.parameters[param_name]

            if not _check_type(value, param_schema.type):
                violations.append(
                    f"Parameter '{param_name}': expected {param_schema.type}, "
                    f"got {type(value).__name__}"
                )

            if param_schema.max_length is not None and isinstance(value, str):
                if len(value) > param_schema.max_length:
                    violations.append(
                        f"Parameter '{param_name}' length {len(value)} "
                        f"exceeds max_length {param_schema.max_length}"
                    )

            if param_schema.allowed_values is not None and value not in param_schema.allowed_values:
                violations.append(
                    f"Parameter '{param_name}' value {value!r} "
                    f"not in allowed values {param_schema.allowed_values}"
                )

        # 5–7. Injection / traversal pattern scanning
        for param_name, value in parameters.items():
            if not isinstance(value, str):
                continue

            # 5. Prompt injection — scan every string parameter
            for pattern in _PROMPT_INJECTION_PATTERNS:
                if pattern.search(value):
                    violations.append(
                        f"Prompt injection pattern in '{param_name}': "
                        f"matched {pattern.pattern!r}"
                    )
                    break

            # 6. Shell injection — only params flagged in shell_params
            if param_name in schema.shell_params:
                for pattern in _SHELL_INJECTION_PATTERNS:
                    if pattern.search(value):
                        violations.append(
                            f"Shell injection pattern in '{param_name}': "
                            f"matched {pattern.pattern!r}"
                        )
                        break

            # 7. Path traversal — only params flagged in path_params
            if param_name in schema.path_params:
                for pattern in _PATH_TRAVERSAL_PATTERNS:
                    if pattern.search(value):
                        violations.append(
                            f"Path traversal pattern in '{param_name}': "
                            f"matched {pattern.pattern!r}"
                        )
                        break

        if violations:
            is_injection = any(
                kw in v for v in violations
                for kw in ("injection", "traversal", "jailbreak")
            )
            severity = "CRITICAL" if is_injection else "WARNING"
            self._logger._emit(
                severity,
                agent_id=agent_id,
                event_type="tool_validation_failure",
                message=f"Tool call blocked: {tool_name}",
                tool_name=tool_name,
                raw_input=str(parameters),
                metadata={"violations": violations},
            )
            return ValidationResult(allowed=False, tool_name=tool_name, violations=violations)

        # All checks passed — record timestamp and approve
        timestamps.append(now)
        self._logger.info(
            agent_id=agent_id,
            event_type="tool_validated",
            message=f"Tool call approved: {tool_name}",
            tool_name=tool_name,
        )
        return ValidationResult(allowed=True, tool_name=tool_name)
