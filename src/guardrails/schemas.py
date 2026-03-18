"""
Shared Pydantic models used across all guardrail modules.
Keeping schemas in one file prevents circular imports.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class ParameterSchema(BaseModel):
    """Schema definition for a single tool parameter."""

    type: Literal["string", "integer", "float", "boolean", "list", "dict"]
    required: bool = True
    description: str = ""
    max_length: int | None = None        # enforced for string params
    allowed_values: list[Any] | None = None  # enum-style constraint


class ToolSchema(BaseModel):
    """Full schema for a registered (allowlisted) tool."""

    name: str
    description: str = ""
    parameters: dict[str, ParameterSchema] = {}
    # Parameter names whose values will be passed to OS/shell — triggers shell injection checks
    shell_params: list[str] = []
    # Parameter names that represent filesystem paths — triggers path traversal checks
    path_params: list[str] = []


class ValidationResult(BaseModel):
    """Returned by ToolValidator.validate()."""

    allowed: bool
    tool_name: str
    violations: list[str] = []


class SanitizationResult(BaseModel):
    """Returned by OutputSanitizer.sanitize()."""

    safe: bool
    sanitized_content: str   # cleaned version (may be redacted)
    flags: list[str] = []    # human-readable labels for what was detected
    blocked: bool = False    # True means do not proceed; False means proceed with sanitized_content


class AnomalyEvent(BaseModel):
    """A single structured audit log entry."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    severity: Literal["INFO", "WARNING", "CRITICAL"]
    event_type: str              # e.g. "tool_validation_failure", "output_sanitization_triggered"
    agent_id: str
    tool_name: str | None = None
    message: str
    raw_input_excerpt: str = "" # truncated to guardrail_max_input_log_chars
    metadata: dict[str, Any] = {}
