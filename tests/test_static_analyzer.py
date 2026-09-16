from app.models import Decision, Severity
from app.static_analyzer import StaticAnalyzer


def test_detects_genuine_sql_injection():
    source = """
user_id = input("User ID: ")
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="app.py",
    )

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.finding == "SQL Injection"
    assert finding.severity == Severity.HIGH
    assert finding.decision == Decision.REJECTED
    assert finding.line == 4


def test_safe_parameterized_sql_is_not_reported():
    source = """
user_id = input("User ID: ")
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="app.py",
    )

    assert result.findings == []


def test_detects_hard_coded_secret():
    source = """
DATABASE_PASSWORD = "SuperSecretPassword123!"
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="config.py",
    )

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.finding == "Hard-coded secret"
    assert finding.severity == Severity.HIGH
    assert finding.decision == Decision.REJECTED
    assert finding.line == 2


def test_placeholder_secret_is_not_reported():
    source = """
API_KEY = "your_api_key_here"
DATABASE_PASSWORD = "change_me"
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="config.py",
    )

    assert result.findings == []


def test_detects_eval():
    source = """
user_expression = input("Expression: ")
result = eval(user_expression)
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="app.py",
    )

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.finding == "Dangerous use of eval()"
    assert finding.severity == Severity.HIGH
    assert finding.decision == Decision.REJECTED


def test_detects_exec():
    source = """
code = input("Code: ")
exec(code)
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="app.py",
    )

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.finding == "Dangerous use of exec()"
    assert finding.severity == Severity.HIGH
    assert finding.decision == Decision.REJECTED


def test_dynamic_sql_concatenation_is_detected():
    source = """
user_id = input("User ID: ")
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="app.py",
    )

    assert len(result.findings) == 1
    assert result.findings[0].finding == "SQL Injection"


def test_static_analyzer_reports_syntax_errors():
    source = """
def broken(
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="broken.py",
    )

    assert result.findings == []
    assert len(result.analysis_errors) == 1
    assert "Unable to parse Python source" in result.analysis_errors[0]


# ---------------------------------------------------------------------------
# Hidden-style / additional robustness cases
# ---------------------------------------------------------------------------


def test_static_sql_keyword_alone_is_not_sql_injection():
    source = """
query = "SELECT * FROM users"
cursor.execute(query)
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="app.py",
    )

    assert result.findings == []


def test_placeholder_environment_variable_is_not_secret():
    source = """
SECRET_KEY = "${SECRET_KEY}"
API_KEY = "replace_me"
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="config.py",
    )

    assert result.findings == []


def test_dynamic_sql_through_variable_assignment_is_detected():
    source = """
table = input("Table: ")
query = f"SELECT * FROM {table}"
cursor.execute(query)
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="app.py",
    )

    assert len(result.findings) == 1
    assert result.findings[0].finding == "SQL Injection"


def test_multiple_security_findings_are_reported():
    source = """
API_KEY = "sk-test-real-looking-key-123456789"
user_input = input("Code: ")
result = eval(user_input)
"""

    result = StaticAnalyzer().analyze(
        source,
        filename="app.py",
    )

    assert len(result.findings) == 2

    finding_names = {
        finding.finding
        for finding in result.findings
    }

    assert "Hard-coded secret" in finding_names
    assert "Dangerous use of eval()" in finding_names


def test_repeated_analysis_does_not_duplicate_findings():
    source = """
user_id = input("User ID: ")
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"""

    analyzer = StaticAnalyzer()

    first_result = analyzer.analyze(
        source,
        filename="app.py",
    )

    second_result = analyzer.analyze(
        source,
        filename="app.py",
    )

    assert len(first_result.findings) == 1
    assert len(second_result.findings) == 1
    assert first_result.findings[0].finding == "SQL Injection"
    assert second_result.findings[0].finding == "SQL Injection"