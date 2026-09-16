from app.decision_engine import DecisionEngine
from app.models import (
    AnalysisResult,
    Decision,
    Finding,
    LLMFinding,
    LLMReviewResult,
    Severity,
)


def test_static_high_overrides_llm_low():
    static_result = AnalysisResult(
        file="app.py",
        findings=[
            Finding(
                file="app.py",
                line=10,
                finding="SQL Injection",
                severity=Severity.HIGH,
                evidence="Dynamic SQL",
                recommendation="Use parameters",
            )
        ],
    )

    llm_result = LLMReviewResult(
        summary="No major issues.",
        findings=[],
    )

    result = DecisionEngine().decide(
        static_result=static_result,
        llm_result=llm_result,
    )

    assert result.decision == Decision.REJECTED


def test_static_clean_but_llm_high_requires_review():
    static_result = AnalysisResult(
        file="app.py",
        findings=[],
    )

    llm_result = LLMReviewResult(
        summary="Potential command injection.",
        findings=[
            LLMFinding(
                file="app.py",
                line=20,
                finding="Command injection",
                severity=Severity.HIGH,
                evidence="User input reaches shell execution.",
                recommendation="Avoid shell execution.",
            )
        ],
    )

    result = DecisionEngine().decide(
        static_result=static_result,
        llm_result=llm_result,
    )

    assert result.decision == Decision.REVIEW_REQUIRED


def test_no_findings_results_in_approved():
    static_result = AnalysisResult(
        file="app.py",
        findings=[],
    )

    llm_result = LLMReviewResult(
        summary="No contextual issues identified.",
        findings=[],
        available=True,
    )

    result = DecisionEngine().decide(
        static_result=static_result,
        llm_result=llm_result,
    )

    assert result.decision == Decision.APPROVED


def test_static_analysis_error_requires_review():
    static_result = AnalysisResult(
        file="app.py",
        findings=[],
        analysis_errors=[
            "Unable to parse Python source."
        ],
    )

    llm_result = LLMReviewResult(
        summary="No contextual issues identified.",
        findings=[],
    )

    result = DecisionEngine().decide(
        static_result=static_result,
        llm_result=llm_result,
    )

    assert result.decision == Decision.REVIEW_REQUIRED


def test_medium_static_finding_requires_review():
    static_result = AnalysisResult(
        file="app.py",
        findings=[
            Finding(
                file="app.py",
                line=5,
                finding="Potential security concern",
                severity=Severity.MEDIUM,
                evidence="Suspicious behavior",
                recommendation="Review implementation",
            )
        ],
    )

    llm_result = LLMReviewResult(
        summary="No contextual issues identified.",
        findings=[],
    )

    result = DecisionEngine().decide(
        static_result=static_result,
        llm_result=llm_result,
    )

    assert result.decision == Decision.REVIEW_REQUIRED


def test_llm_findings_are_converted_to_common_finding_model():
    static_result = AnalysisResult(
        file="app.py",
        findings=[],
    )

    llm_result = LLMReviewResult(
        summary="Potential issue.",
        findings=[
            LLMFinding(
                file="app.py",
                line=12,
                finding="Potential issue",
                severity=Severity.LOW,
                evidence="Suspicious input handling.",
                recommendation="Review input validation.",
            )
        ],
    )

    result = DecisionEngine().decide(
        static_result=static_result,
        llm_result=llm_result,
    )

    assert len(result.findings) == 1
    assert result.findings[0].finding == "Potential issue"
    assert result.findings[0].decision == Decision.REVIEW_REQUIRED
    assert result.decision == Decision.REVIEW_REQUIRED


def test_llm_unavailable_requires_review():
    static_result = AnalysisResult(
        file="app.py",
        findings=[],
    )

    llm_result = LLMReviewResult(
        summary="LLM review unavailable: API timeout.",
        findings=[],
        available=False,
    )

    result = DecisionEngine().decide(
        static_result=static_result,
        llm_result=llm_result,
    )

    assert result.decision == Decision.REVIEW_REQUIRED