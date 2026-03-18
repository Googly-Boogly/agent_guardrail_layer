"""
Structured anomaly logger for the guardrail pipeline.

Writes AnomalyEvent records as JSON lines to a file and/or stderr.
This module has no dependencies on other guardrail modules so it can
be safely imported by all of them without circular import issues.
"""
import sys
from typing import Any

from src.config import settings
from src.guardrails.schemas import AnomalyEvent


class AnomalyLogger:
    """
    Writes structured AnomalyEvent records as newline-delimited JSON.

    Simultaneously appends to a file (line-buffered, so events survive crashes)
    and writes to stderr (kept separate from agent stdout that may be piped).
    """

    def __init__(
        self,
        log_file: str | None = None,
        log_stdout: bool | None = None,
        max_input_chars: int | None = None,
    ):
        self.log_file = log_file if log_file is not None else settings.guardrail_log_file
        self.log_stdout = log_stdout if log_stdout is not None else settings.guardrail_log_stdout
        self.max_input_chars = (
            max_input_chars if max_input_chars is not None
            else settings.guardrail_max_input_log_chars
        )
        self._file_handle = None
        if self.log_file:
            # line-buffered (buffering=1) so each event is flushed immediately
            self._file_handle = open(self.log_file, "a", buffering=1)

    def log(self, event: AnomalyEvent) -> None:
        line = event.model_dump_json()
        if self._file_handle:
            self._file_handle.write(line + "\n")
        if self.log_stdout:
            print(line, file=sys.stderr)

    def info(self, agent_id: str, event_type: str, message: str, **kwargs: Any) -> None:
        self._emit("INFO", agent_id, event_type, message, **kwargs)

    def warning(self, agent_id: str, event_type: str, message: str, **kwargs: Any) -> None:
        self._emit("WARNING", agent_id, event_type, message, **kwargs)

    def critical(self, agent_id: str, event_type: str, message: str, **kwargs: Any) -> None:
        self._emit("CRITICAL", agent_id, event_type, message, **kwargs)

    def _emit(
        self,
        severity: str,
        agent_id: str,
        event_type: str,
        message: str,
        **kwargs: Any,
    ) -> None:
        raw = kwargs.pop("raw_input", "")
        tool_name = kwargs.pop("tool_name", None)
        metadata = kwargs.pop("metadata", {})
        event = AnomalyEvent(
            severity=severity,
            event_type=event_type,
            agent_id=agent_id,
            tool_name=tool_name,
            message=message,
            raw_input_excerpt=str(raw)[: self.max_input_chars],
            metadata=metadata,
        )
        self.log(event)

    def close(self) -> None:
        """Flush and close the log file. Call on agent shutdown."""
        if self._file_handle:
            self._file_handle.flush()
            self._file_handle.close()
            self._file_handle = None
