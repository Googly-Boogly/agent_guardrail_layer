"""
Output sanitizer for agentic guardrail pipeline.

Sanitizes LLM output and tool output before either is:
  - Fed back into the agent's context (indirect prompt injection vector)
  - Used to construct arguments for the next tool call

Detection categories:
  1. Prompt injection directives in the output text
  2. Data exfiltration signals (URLs with secret params, curl/wget, encoding tricks)
  3. Shell-dangerous characters (stripped as defence-in-depth; non-blocking alone)
  4. Invalid JSON when structured output is expected
"""
import json
import re

from src.guardrails.anomaly_logger import AnomalyLogger
from src.guardrails.schemas import SanitizationResult

_REDACTED = "[REDACTED BY GUARDRAIL]"

# ---------------------------------------------------------------------------
# Compiled patterns — paid once at module load time
# ---------------------------------------------------------------------------

# Injection directives embedded in LLM or tool output
_INJECTION_IN_OUTPUT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), label)
    for p, label in [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "prompt_injection_directive"),
        (r"disregard\s+(all\s+)?(previous|prior)\s+instructions?", "prompt_injection_directive"),
        (r"<\s*system\s*>.*?<\s*/\s*system\s*>", "xml_system_tag"),
        (r"\[INST\].*?\[/INST\]", "llama_instruction_tag"),
        (r"new\s+instructions?\s*:", "instruction_override"),
        (r"###\s*system", "markdown_system_header"),
        (r"you\s+are\s+now\s+(?!an?\s+AI)", "role_hijack"),
        (r"jailbreak", "jailbreak_keyword"),
    ]
]

# Signals that tool output is trying to exfiltrate data or run network commands
_EXFILTRATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.IGNORECASE), label)
    for p, label in [
        (
            r"https?://(?!localhost|127\.0\.0\.1)[^\s]+[?&](key|token|secret|password|auth|api_key)=",
            "url_with_secret_param",
        ),
        (r"curl\s+-[^\n]*", "curl_command"),
        (r"wget\s+", "wget_command"),
        (r"nc\s+-[^\n]*", "netcat_command"),
        (r"base64\s+(?:encode|decode|-[de])", "base64_encoding"),
        (r"xxd\s+|hexdump\s+", "hex_encoding"),
    ]
]

# Shell metacharacters — stripped defensively (non-blocking by itself)
_SHELL_DANGEROUS_CHARS: re.Pattern = re.compile(r"[;&|`<>\\]|\$\(|\$\{")


class OutputSanitizer:
    """
    Sanitizes LLM responses and tool outputs before they re-enter the agent loop.

    Args:
        logger: Shared AnomalyLogger instance.
    """

    def __init__(self, logger: AnomalyLogger):
        self._logger = logger

    def sanitize(
        self,
        content: str,
        agent_id: str,
        tool_name: str | None = None,
        expect_json: bool = False,
    ) -> SanitizationResult:
        """
        Scan and clean a string before it is used in the agent pipeline.

        Args:
            content: Raw string from the LLM or a tool's return value.
            agent_id: Identifier for the running agent (for log correlation).
            tool_name: Tool whose output is being sanitized, if applicable.
            expect_json: When True, validate that content is parseable JSON.
                         Malformed JSON is treated as a blocking violation.

        Returns:
            SanitizationResult with `blocked=True` if the content must not be used.
        """
        flags: list[str] = []
        blocked = False
        working = content

        # 1. Prompt injection in output — always blocking
        for pattern, label in _INJECTION_IN_OUTPUT_PATTERNS:
            if pattern.search(working):
                flags.append(label)
                working = pattern.sub(_REDACTED, working)
                blocked = True

        # 2. Exfiltration signals — always blocking
        for pattern, label in _EXFILTRATION_PATTERNS:
            if pattern.search(working):
                flags.append(label)
                working = pattern.sub(_REDACTED, working)
                blocked = True

        # 3. Shell character stripping — defence-in-depth, non-blocking alone
        shell_cleaned = _SHELL_DANGEROUS_CHARS.sub("", working)
        if shell_cleaned != working:
            flags.append("shell_chars_stripped")
            working = shell_cleaned
            # Not set blocked here — the tool validator handles injection at
            # the parameter level; this is just a cleanup pass

        # 4. JSON validation when structured output is required
        if expect_json:
            try:
                json.loads(working)
            except json.JSONDecodeError as exc:
                flags.append(f"invalid_json:{exc.msg}")
                blocked = True

        if flags:
            severity = "CRITICAL" if blocked else "WARNING"
            self._logger._emit(
                severity,
                agent_id=agent_id,
                event_type="output_sanitization_triggered",
                message=f"Sanitization flags raised: {flags}",
                tool_name=tool_name,
                raw_input=content,
                metadata={"flags": flags, "blocked": blocked},
            )

        return SanitizationResult(
            safe=not blocked,
            sanitized_content=working,
            flags=flags,
            blocked=blocked,
        )

    def sanitize_for_shell(
        self,
        value: str,
        agent_id: str,
        tool_name: str,
    ) -> str:
        """
        Convenience wrapper: sanitize a string destined for a shell parameter.

        Returns the cleaned string, or raises ValueError if blocked.
        """
        result = self.sanitize(value, agent_id=agent_id, tool_name=tool_name)
        if result.blocked:
            raise ValueError(
                f"Shell parameter failed sanitization for tool '{tool_name}': "
                f"{result.flags}"
            )
        return result.sanitized_content
