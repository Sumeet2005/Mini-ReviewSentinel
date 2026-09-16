from collections.abc import Callable

from app.decision_engine import DecisionEngine
from app.llm_reviewer import LLMReviewer
from app.models import (
    AgentReviewResult,
    AgentState,
    AnalysisResult,
    Decision,
    LLMReviewResult,
    ReviewResult,
)
from app.static_analyzer import StaticAnalyzer


class ReviewAgent:
    """
    Bounded agentic code-review workflow.

    The agent performs an initial review and can revisit the review
    when additional context is needed. A hard iteration limit prevents
    infinite loops.
    """

    def __init__(
        self,
        static_analyzer: StaticAnalyzer,
        llm_reviewer: LLMReviewer,
        decision_engine: DecisionEngine,
        max_iterations: int = 2,
        context_provider: Callable[[str], str] | None = None,
    ) -> None:
        if max_iterations < 1:
            raise ValueError(
                "max_iterations must be at least 1."
            )

        self.static_analyzer = static_analyzer
        self.llm_reviewer = llm_reviewer
        self.decision_engine = decision_engine
        self.max_iterations = max_iterations
        self.context_provider = context_provider

    def review(
        self,
        source: str,
        filename: str = "<input>",
    ) -> AgentReviewResult:
        state = AgentState.INITIAL_REVIEW
        iterations = 0
        revisited = False
        context_requested = False

        current_source = source

        static_result = AnalysisResult(file=filename)
        llm_result = LLMReviewResult(
            summary="LLM review has not been executed.",
            findings=[],
        )
        final_review = ReviewResult(
            decision=Decision.REVIEW_REQUIRED,
        )

        while iterations < self.max_iterations:
            iterations += 1

            if state in {
                AgentState.INITIAL_REVIEW,
                AgentState.REVISIT,
            }:
                static_result = self.static_analyzer.analyze(
                    source=current_source,
                    filename=filename,
                )

                llm_result = self.llm_reviewer.review(
                    source=current_source,
                    filename=filename,
                )

                final_review = self.decision_engine.decide(
                    static_result=static_result,
                    llm_result=llm_result,
                )

            if (
                state == AgentState.INITIAL_REVIEW
                and self._needs_context(
                    static_result=static_result,
                    llm_result=llm_result,
                )
                and iterations < self.max_iterations
            ):
                state = AgentState.NEEDS_CONTEXT
                context_requested = True

                additional_context = self._request_context(
                    filename=filename,
                )

                if additional_context:
                    current_source = self._append_context_safely(
                        source=source,
                        context=additional_context,
                    )

                state = AgentState.REVISIT
                revisited = True
                continue

            state = AgentState.COMPLETE
            break

        return AgentReviewResult(
            state=state,
            iterations=iterations,
            revisited=revisited,
            context_requested=context_requested,
            review=final_review,
        )

    @staticmethod
    def _needs_context(
        static_result: AnalysisResult,
        llm_result: LLMReviewResult,
    ) -> bool:
        if static_result.analysis_errors:
            return True

        if llm_result.findings:
            return True

        return False

    def _request_context(self, filename: str) -> str:
        if self.context_provider is None:
            return (
                f"No additional repository context was available "
                f"for {filename}."
            )

        return self.context_provider(filename)

    @staticmethod
    def _append_context_safely(
        source: str,
        context: str,
    ) -> str:
        """
        Append review context without changing the syntax of the
        original Python source.

        Context is deliberately represented as Python comments so
        arbitrary context cannot accidentally become executable code.
        """

        context_lines = context.splitlines()

        formatted_context = "\n".join(
            f"# {line}"
            for line in context_lines
        )

        return (
            f"{source}\n\n"
            f"# Additional review context\n"
            f"{formatted_context}\n"
        )