import ast
import re
from typing import Optional

from app.models import AnalysisResult, Decision, Finding, Severity


class StaticAnalyzer:
    """
    Deterministic security analyzer for Python source code.

    The analyzer uses Python's AST rather than relying only on text
    matching. This allows it to reason about how expressions are
    constructed and reduces obvious false positives.
    """

    SQL_METHODS = {
        "execute",
        "executemany",
        "executescript",
    }

    SECRET_NAME_PATTERN = re.compile(
        r"(password|passwd|secret|api[_-]?key|access[_-]?key|"
        r"auth[_-]?token|private[_-]?key|client[_-]?secret)",
        re.IGNORECASE,
    )

    SECRET_VALUE_PATTERNS = [
        re.compile(r"^sk-[A-Za-z0-9_-]{16,}$"),
        re.compile(r"^AKIA[0-9A-Z]{16}$"),
        re.compile(r"^gh[pousr]_[A-Za-z0-9_]{20,}$"),
        re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),
    ]

    PLACEHOLDER_VALUES = {
        "",
        "password",
        "your_password",
        "your-password",
        "your_password_here",
        "your-password-here",
        "change_me",
        "change-me",
        "changeme",
        "example",
        "example_password",
        "example_password_here",
        "example_key",
        "example_secret",
        "dummy",
        "dummy_password",
        "dummy_secret",
        "test",
        "test_password",
        "test_secret",
        "replace_me",
        "replace-me",
        "none",
        "null",
    }

    SQL_KEYWORDS = re.compile(
        r"\b(select|insert|update|delete|replace|merge|drop|alter|create)\b",
        re.IGNORECASE,
    )

    def analyze(self, source: str, filename: str = "<input>") -> AnalysisResult:
        """
        Analyze Python source code and return deterministic findings.

        If parsing fails, the analyzer returns an AnalysisResult containing
        the analysis error instead of crashing the application.
        """
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as exc:
            return AnalysisResult(
                file=filename,
                findings=[],
                analysis_errors=[
                    f"Unable to parse Python source: {exc.msg} "
                    f"(line {exc.lineno or 'unknown'})"
                ],
            )

        visitor = _SecurityVisitor(
            filename=filename,
            sql_methods=self.SQL_METHODS,
            secret_name_pattern=self.SECRET_NAME_PATTERN,
            secret_value_patterns=self.SECRET_VALUE_PATTERNS,
            placeholder_values=self.PLACEHOLDER_VALUES,
            sql_keywords=self.SQL_KEYWORDS,
        )

        try:
            visitor.visit(tree)
        except Exception as exc:
            return AnalysisResult(
                file=filename,
                findings=visitor.findings,
                analysis_errors=[
                    f"Static analysis failed: {type(exc).__name__}: {exc}"
                ],
            )

        return AnalysisResult(
            file=filename,
            findings=visitor.findings,
            analysis_errors=visitor.errors,
        )


class _SecurityVisitor(ast.NodeVisitor):
    """
    AST visitor responsible for deterministic security checks.
    """

    def __init__(
        self,
        filename: str,
        sql_methods: set[str],
        secret_name_pattern: re.Pattern[str],
        secret_value_patterns: list[re.Pattern[str]],
        placeholder_values: set[str],
        sql_keywords: re.Pattern[str],
    ) -> None:
        self.filename = filename
        self.findings: list[Finding] = []
        self.errors: list[str] = []

        self.sql_methods = sql_methods
        self.secret_name_pattern = secret_name_pattern
        self.secret_value_patterns = secret_value_patterns
        self.placeholder_values = placeholder_values
        self.sql_keywords = sql_keywords

        # Tracks simple assignments so that code such as:
        #
        # query = f"SELECT ... {user_id}"
        # cursor.execute(query)
        #
        # can be analyzed using the original expression.
        self.assignments: dict[str, ast.AST] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments[target.id] = node.value

        self._check_hard_coded_secret(node)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.assignments[node.target.id] = node.value

        if node.value is not None:
            fake_assign = ast.Assign(
                targets=[node.target],
                value=node.value,
            )
            fake_assign.lineno = node.lineno
            fake_assign.col_offset = node.col_offset

            self._check_hard_coded_secret(fake_assign)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_eval_or_exec(node)
        self._check_sql_injection(node)

        self.generic_visit(node)

    def _check_eval_or_exec(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Name):
            return

        if node.func.id not in {"eval", "exec"}:
            return

        function_name = node.func.id

        self.findings.append(
            Finding(
                file=self.filename,
                line=node.lineno,
                finding=f"Dangerous use of {function_name}()",
                severity=Severity.HIGH,
                evidence=(
                    f"{function_name}() executes dynamically supplied "
                    "Python code and can allow arbitrary code execution."
                ),
                recommendation=(
                    f"Avoid {function_name}(). Use a safer, explicit "
                    f"implementation for the required behavior."
                ),
                decision=Decision.REJECTED,
            )
        )

    def _check_sql_injection(self, node: ast.Call) -> None:
        if not self._is_sql_execution_call(node):
            return

        if not node.args:
            return

        query_expression = self._resolve_expression(node.args[0])

        if self._is_safe_parameterized_query(node):
            return

        if self._is_dynamic_sql_expression(query_expression):
            self.findings.append(
                Finding(
                    file=self.filename,
                    line=node.lineno,
                    finding="SQL Injection",
                    severity=Severity.HIGH,
                    evidence=(
                        "A SQL execution call receives a query containing "
                        "dynamically constructed SQL. User-controlled or "
                        "runtime values may be inserted directly into the "
                        "query instead of being passed as parameters."
                    ),
                    recommendation=(
                        "Use parameterized queries and pass runtime values "
                        "through the database driver's parameter mechanism."
                    ),
                    decision=Decision.REJECTED,
                )
            )

    def _check_hard_coded_secret(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            variable_name = target.id

            if not self.secret_name_pattern.search(variable_name):
                continue

            value = self._extract_string_value(node.value)

            if value is None:
                continue

            if self._looks_like_placeholder(value):
                continue

            self.findings.append(
                Finding(
                    file=self.filename,
                    line=node.lineno,
                    finding="Hard-coded secret",
                    severity=Severity.HIGH,
                    evidence=(
                        f"Variable '{variable_name}' contains a "
                        "credential-like value directly in source code."
                    ),
                    recommendation=(
                        "Move secrets to a secure secret manager or "
                        "environment variable and do not commit credentials "
                        "to source control."
                    ),
                    decision=Decision.REJECTED,
                )
            )

    def _is_sql_execution_call(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute):
            return False

        return node.func.attr.lower() in self.sql_methods

    def _is_safe_parameterized_query(self, node: ast.Call) -> bool:
        """
        Recognize the common safe pattern:

            cursor.execute(
                "SELECT ... WHERE id = ?",
                (user_id,),
            )

        The query is static SQL and runtime values are passed separately.
        """
        if len(node.args) < 2:
            return False

        query_expression = self._resolve_expression(node.args[0])

        if not isinstance(query_expression, ast.Constant):
            return False

        if not isinstance(query_expression.value, str):
            return False

        query = query_expression.value

        if not self.sql_keywords.search(query):
            return False

        return True

    def _is_dynamic_sql_expression(self, expression: ast.AST) -> bool:
        if isinstance(expression, ast.JoinedStr):
            return True

        if isinstance(expression, ast.BinOp) and isinstance(
            expression.op,
            (ast.Add, ast.Mod),
        ):
            return self._contains_dynamic_value(expression)

        if isinstance(expression, ast.Call):
            return True

        if isinstance(expression, ast.Name):
            resolved = self.assignments.get(expression.id)

            if resolved is None:
                return False

            if resolved is expression:
                return False

            return self._is_dynamic_sql_expression(resolved)

        return False

    def _contains_dynamic_value(self, expression: ast.AST) -> bool:
        if isinstance(expression, ast.Constant):
            return False

        if isinstance(expression, ast.Name):
            return True

        if isinstance(expression, ast.JoinedStr):
            return True

        if isinstance(expression, ast.BinOp):
            return (
                self._contains_dynamic_value(expression.left)
                or self._contains_dynamic_value(expression.right)
            )

        return True

    def _resolve_expression(self, expression: ast.AST) -> ast.AST:
        """
        Resolve simple variable assignments while avoiding recursive loops.
        """
        visited: set[str] = set()
        current = expression

        while isinstance(current, ast.Name):
            name = current.id

            if name in visited:
                break

            visited.add(name)

            resolved = self.assignments.get(name)

            if resolved is None:
                break

            current = resolved

        return current

    @staticmethod
    def _extract_string_value(expression: ast.AST) -> Optional[str]:
        if isinstance(expression, ast.Constant) and isinstance(
            expression.value,
            str,
        ):
            return expression.value

        return None

    def _looks_like_placeholder(self, value: str) -> bool:
        normalized = value.strip().lower()

        if normalized in self.placeholder_values:
            return True

        placeholder_patterns = (
            "your-",
            "your_",
            "<your",
            "${",
            "{{",
            "replace-",
            "replace_",
        )

        return normalized.startswith(placeholder_patterns)

    def _looks_like_real_secret(self, value: str) -> bool:
        for pattern in self.secret_value_patterns:
            if pattern.match(value):
                return True

        # A long mixed-character credential-like value is suspicious.
        if len(value) >= 24:
            has_upper = any(char.isupper() for char in value)
            has_lower = any(char.islower() for char in value)
            has_digit = any(char.isdigit() for char in value)

            return has_upper and has_lower and has_digit

        return False