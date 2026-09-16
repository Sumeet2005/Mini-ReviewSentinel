from app.models import (
    AnalysisResult,
    Decision,
    Finding,
    LLMFinding,
    LLMReviewResult,
    ReviewResult,
    Severity,
)


class DecisionEngine:
    """
    Deterministic final decision layer.

    The LLM is advisory only. It cannot directly make the final
    APPROVED, REVIEW_REQUIRED, or REJECTED decision.
    """

    def decide(
        self,
        static_result: AnalysisResult,
        llm_result: LLMReviewResult,
    ) -> ReviewResult:
        """
        Combine static and LLM findings and calculate the final decision.
        """

        llm_findings = self._convert_llm_findings(
            llm_result.findings
        )

        findings = list(static_result.findings)
        findings.extend(llm_findings)

        decision = self._calculate_decision(
            static_findings=static_result.findings,
            llm_findings=llm_result.findings,
            llm_available=llm_result.available,
            analysis_errors=static_result.analysis_errors,
        )

        return ReviewResult(
            decision=decision,
            findings=findings,
            analysis_errors=static_result.analysis_errors,
            llm_summary=llm_result.summary,
        )

    def _calculate_decision(
        self,
        static_findings: list[Finding],
        llm_findings: list[LLMFinding],
        llm_available: bool,
        analysis_errors: list[str],
    ) -> Decision:
        """
        Apply the deterministic conflict and reliability policy.

        Policy:

        1. Deterministic HIGH severity finding -> REJECTED.
        2. Static analysis failure -> REVIEW_REQUIRED.
        3. LLM unavailable or invalid -> REVIEW_REQUIRED.
        4. LLM HIGH severity finding -> REVIEW_REQUIRED.
        5. LLM MEDIUM severity finding -> REVIEW_REQUIRED.
        6. Static MEDIUM severity finding -> REVIEW_REQUIRED.
        7. Any remaining finding -> REVIEW_REQUIRED.
        8. No findings, no errors, and available LLM -> APPROVED.
        """

        if any(
            finding.severity == Severity.HIGH
            for finding in static_findings
        ):
            return Decision.REJECTED

        if analysis_errors:
            return Decision.REVIEW_REQUIRED

        if not llm_available:
            return Decision.REVIEW_REQUIRED

        if any(
            finding.severity == Severity.HIGH
            for finding in llm_findings
        ):
            return Decision.REVIEW_REQUIRED

        if any(
            finding.severity == Severity.MEDIUM
            for finding in llm_findings
        ):
            return Decision.REVIEW_REQUIRED

        if any(
            finding.severity == Severity.MEDIUM
            for finding in static_findings
        ):
            return Decision.REVIEW_REQUIRED

        if static_findings or llm_findings:
            return Decision.REVIEW_REQUIRED

        return Decision.APPROVED

    @staticmethod
    def _convert_llm_findings(
        llm_findings: list[LLMFinding],
    ) -> list[Finding]:
        """
        Convert LLM findings into the common Finding model.

        LLM findings are marked REVIEW_REQUIRED because the LLM
        does not have authority to make the final decision.
        """

        return [
            Finding(
                file=finding.file,
                line=finding.line,
                finding=finding.finding,
                severity=finding.severity,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
                decision=Decision.REVIEW_REQUIRED,
            )
            for finding in llm_findings
        ]