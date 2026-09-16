import argparse
import json
import sys
from pathlib import Path

from app.agent import ReviewAgent
from app.decision_engine import DecisionEngine
from app.llm_reviewer import GeminiProvider, LLMReviewer
from app.loader import SourceLoader
from app.static_analyzer import StaticAnalyzer


def build_review_agent() -> ReviewAgent:
    """
    Build the complete ReviewSentinel pipeline.
    """
    static_analyzer = StaticAnalyzer()

    llm_provider = GeminiProvider()
    llm_reviewer = LLMReviewer(
        provider=llm_provider
    )

    decision_engine = DecisionEngine()

    return ReviewAgent(
        static_analyzer=static_analyzer,
        llm_reviewer=llm_reviewer,
        decision_engine=decision_engine,
        max_iterations=2,
    )


def review_path(
    path: str,
) -> list[dict]:
    """
    Load and review a Python file or repository.
    """
    loader = SourceLoader()
    agent = build_review_agent()

    source_files = loader.load(path)

    results: list[dict] = []

    for filename, source in source_files:
        review_result = agent.review(
            source=source,
            filename=filename,
        )

        result = review_result.model_dump(
            mode="json"
        )

        results.append(result)

    return results


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Mini ReviewSentinel - "
            "AI-assisted Python security code reviewer."
        )
    )

    parser.add_argument(
        "path",
        help=(
            "Path to a Python file or a repository "
            "directory to review."
        ),
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    path = Path(args.path)

    try:
        results = review_path(str(path))
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": (
                        f"{type(exc).__name__}: {exc}"
                    )
                },
                indent=2,
            )
        )
        return 1

    output = {
        "path": str(path),
        "files_reviewed": len(results),
        "results": results,
    }

    print(
        json.dumps(
            output,
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())