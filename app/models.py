from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Decision(str, Enum):
    APPROVED = "APPROVED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REJECTED = "REJECTED"


class Finding(BaseModel):
    file: str
    line: int
    finding: str
    severity: Severity
    evidence: str
    recommendation: str
    decision: Decision = Decision.REVIEW_REQUIRED


class AnalysisResult(BaseModel):
    file: str
    findings: list[Finding] = Field(default_factory=list)
    analysis_errors: list[str] = Field(default_factory=list)


class LLMFinding(BaseModel):
    file: str
    line: int
    finding: str
    severity: Severity
    evidence: str
    recommendation: str


class LLMReviewResult(BaseModel):
    summary: str
    findings: list[LLMFinding] = Field(default_factory=list)
    available: bool = True


class AgentState(str, Enum):
    INITIAL_REVIEW = "INITIAL_REVIEW"
    NEEDS_CONTEXT = "NEEDS_CONTEXT"
    REVISIT = "REVISIT"
    COMPLETE = "COMPLETE"


class ReviewResult(BaseModel):
    decision: Decision
    findings: list[Finding] = Field(default_factory=list)
    analysis_errors: list[str] = Field(default_factory=list)
    llm_summary: str = ""


class AgentReviewResult(BaseModel):
    state: AgentState
    iterations: int
    revisited: bool
    context_requested: bool
    review: ReviewResult