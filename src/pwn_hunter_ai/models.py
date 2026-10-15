from __future__ import annotations

from dataclasses import dataclass
from pydantic import BaseModel, Field
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class ReferencedFile:
    repo_name: str
    path: str
    ref: str | None


@dataclass(frozen=True, slots=True)
class PromptFile:
    repo_name: str
    path: str
    ref: str
    content: str


@dataclass(frozen=True, slots=True)
class AnalysisPromptRequest:
    prompt: str
    metadata: dict[str, Any] | None = None


class AiAnalysis(BaseModel):
    vulnerable: bool = Field(description="Whether the workflow is vulnerable to a Pwn Request.")
    confidence: Literal["very low", "low", "medium", "high", "very high"] = Field(
        description="Confidence in the verdict."
    )
    explanation: str = Field(description="Short explanation for the verdict.")
    impact: str = Field(description="Impact of a successful exploit, or a short note if none applies.")
    poc: str = Field(description="PoC steps for confirmation, or an empty string if not vulnerable.")
