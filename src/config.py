from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # LLM provider config — consumed by src/utils/call_llm.py
    llm_provider: Literal["anthropic", "openai", "google"] = "anthropic"
    llm_api_key: str = Field(..., description="API key for the configured LLM provider")
    llm_model: str = "claude-sonnet-4-6"

    # Guardrail config
    guardrail_log_file: str | None = "guardrail_events.jsonl"
    guardrail_log_stdout: bool = True
    guardrail_rate_limit_window_seconds: int = 60
    guardrail_max_input_log_chars: int = 500


settings = Settings()
