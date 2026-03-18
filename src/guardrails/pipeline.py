"""
GuardrailPipeline — single entry point for the agent loop.

Composes ToolValidator, OutputSanitizer, and AnomalyLogger so callers
only need to import and instantiate one object.

Typical agent loop usage:

    pipeline = GuardrailPipeline(tool_schemas=[...])

    # Before executing any tool call from the LLM:
    result = pipeline.validate_tool_call(tool_name, params, agent_id)
    if not result.allowed:
        # Return error back to LLM instead of executing
        ...

    # Before feeding LLM output or tool output back into context:
    san = pipeline.sanitize_output(text, agent_id)
    if san.blocked:
        # Do not proceed
        ...

    pipeline.close()  # on agent shutdown
"""
from src.guardrails.anomaly_logger import AnomalyLogger
from src.guardrails.output_sanitizer import OutputSanitizer
from src.guardrails.schemas import (
    SanitizationResult,
    ToolSchema,
    ValidationResult,
)
from src.guardrails.tool_validator import ToolValidator


class GuardrailPipeline:
    """
    Security middleware for autonomous AI agent tool loops.

    Args:
        tool_schemas: Allowlist of tools the agent may call.
        log_file: Path to write JSONL anomaly events. None disables file logging.
        log_stdout: Whether to echo events to stderr.
        rate_limit_max_calls: Max calls to any single tool within the time window.
        rate_limit_window_seconds: Rolling window size in seconds.
    """

    def __init__(
        self,
        tool_schemas: list[ToolSchema],
        log_file: str | None = None,
        log_stdout: bool = True,
        rate_limit_max_calls: int = 10,
        rate_limit_window_seconds: int | None = None,
    ):
        self.logger = AnomalyLogger(log_file=log_file, log_stdout=log_stdout)
        self.validator = ToolValidator(
            tool_schemas=tool_schemas,
            logger=self.logger,
            rate_limit_max_calls=rate_limit_max_calls,
            rate_limit_window=rate_limit_window_seconds,
        )
        self.sanitizer = OutputSanitizer(logger=self.logger)

    def validate_tool_call(
        self,
        tool_name: str,
        parameters: dict,
        agent_id: str,
    ) -> ValidationResult:
        """Validate a tool call before execution. Returns ValidationResult."""
        return self.validator.validate(tool_name, parameters, agent_id)

    def sanitize_output(
        self,
        content: str,
        agent_id: str,
        tool_name: str | None = None,
        expect_json: bool = False,
    ) -> SanitizationResult:
        """Sanitize LLM or tool output before re-use. Returns SanitizationResult."""
        return self.sanitizer.sanitize(
            content,
            agent_id=agent_id,
            tool_name=tool_name,
            expect_json=expect_json,
        )

    def close(self) -> None:
        """Flush and close the log file handle. Call on agent shutdown."""
        self.logger.close()
