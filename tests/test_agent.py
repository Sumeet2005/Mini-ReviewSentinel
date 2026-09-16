from app.agent import ReviewAgent
from app.decision_engine import DecisionEngine
from app.llm_reviewer import FakeLLMProvider, LLMReviewer
from app.models import (
    AgentState,
    AnalysisResult,
    Decision,
    LLMFinding,
    LLMReviewResult,
    Severity,
)
from app.static_analyzer import StaticAnalyzer


def create_agent(
    llm_result: LLMReviewResult | None = None,
    max_iterations: int = 2,
    context_provider=None,
):
    provider = FakeLLMProvider(
        result=llm_result
        or LLMReviewResult(
            summary="No contextual issues identified.",
            findings=[],
        )
    )

    return ReviewAgent(
        static_analyzer=StaticAnalyzer(),
        llm_reviewer=LLMReviewer(provider),
        decision_engine=DecisionEngine(),
        max_iterations=max_iterations,
        context_provider=context_provider,
    )


def test_agent_completes_normal_review():
    agent = create_agent()

    result = agent.review(
        source="print('hello')",
        filename="app.py",
    )

    assert result.state == AgentState.COMPLETE
    assert result.iterations == 1
    assert result.revisited is False
    assert result.context_requested is False
    assert result.review.decision == Decision.APPROVED


def test_agent_revisits_when_llm_finds_contextual_issue():
    llm_result = LLMReviewResult(
        summary="A contextual issue was identified.",
        findings=[
            LLMFinding(
                file="app.py",
                line=1,
                finding="Potential reliability issue",
                severity=Severity.MEDIUM,
                evidence="The operation may fail for unexpected input.",
                recommendation="Validate the input before processing.",
            )
        ],
    )

    context_calls = []

    def context_provider(filename: str) -> str:
        context_calls.append(filename)
        return "Additional repository context."

    agent = create_agent(
        llm_result=llm_result,
        context_provider=context_provider,
    )

    result = agent.review(
        source="value = input('Enter value: ')",
        filename="app.py",
    )

    assert result.state == AgentState.COMPLETE
    assert result.iterations == 2
    assert result.revisited is True
    assert result.context_requested is True
    assert context_calls == ["app.py"]
    assert result.review.decision == Decision.REVIEW_REQUIRED


def test_agent_requests_context_on_static_analysis_error():
    agent = create_agent(
        context_provider=lambda filename: "Additional context."
    )

    result = agent.review(
        source="def broken(",
        filename="broken.py",
    )

    assert result.state == AgentState.COMPLETE
    assert result.revisited is True
    assert result.context_requested is True
    assert result.iterations == 2
    assert result.review.decision == Decision.REVIEW_REQUIRED


def test_agent_respects_max_iterations():
    llm_result = LLMReviewResult(
        summary="Contextual issue remains.",
        findings=[
            LLMFinding(
                file="app.py",
                line=1,
                finding="Potential issue",
                severity=Severity.MEDIUM,
                evidence="Potentially unsafe behavior.",
                recommendation="Review the implementation.",
            )
        ],
    )

    context_calls = []

    def context_provider(filename: str) -> str:
        context_calls.append(filename)
        return "More context."

    agent = create_agent(
        llm_result=llm_result,
        max_iterations=1,
        context_provider=context_provider,
    )

    result = agent.review(
        source="value = 1",
        filename="app.py",
    )

    assert result.state == AgentState.COMPLETE
    assert result.iterations == 1
    assert result.iterations <= 1
    assert result.revisited is False
    assert result.context_requested is False
    assert context_calls == []


def test_agent_never_exceeds_max_iterations():
    llm_result = LLMReviewResult(
        summary="Persistent contextual issue.",
        findings=[
            LLMFinding(
                file="app.py",
                line=1,
                finding="Persistent issue",
                severity=Severity.MEDIUM,
                evidence="The issue remains after review.",
                recommendation="Review the implementation manually.",
            )
        ],
    )

    context_calls = []

    def context_provider(filename: str) -> str:
        context_calls.append(filename)
        return "Additional context."

    agent = create_agent(
        llm_result=llm_result,
        max_iterations=2,
        context_provider=context_provider,
    )

    result = agent.review(
        source="value = 1",
        filename="app.py",
    )

    assert result.state == AgentState.COMPLETE
    assert result.iterations <= 2
    assert len(context_calls) <= 1


def test_agent_rejects_invalid_iteration_limit():
    provider = FakeLLMProvider()

    try:
        ReviewAgent(
            static_analyzer=StaticAnalyzer(),
            llm_reviewer=LLMReviewer(provider),
            decision_engine=DecisionEngine(),
            max_iterations=0,
        )
    except ValueError as exc:
        assert "max_iterations" in str(exc)
    else:
        raise AssertionError(
            "ReviewAgent should reject max_iterations=0."
        )