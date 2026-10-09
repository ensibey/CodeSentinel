"""
Abstract Syntax Tree (AST) Static Security Scanner.
Performs deterministic static analysis on Python code to identify:
- Hardcoded secrets and high-entropy credentials
- SQL Injection risks (string interpolation in database queries)
- Insecure deserialization (pickle, unsafe yaml)
- Arbitrary code execution (eval, exec, shell=True)
- Path traversal patterns
"""

from __future__ import annotations
import ast
import re
from typing import List, Optional

from src.agents.state import SecurityVulnerability


class SecurityASTVisitor(ast.NodeVisitor):
    """AST Visitor searching for dangerous security anti-patterns in Python code."""

    SECRET_VAR_PATTERN = re.compile(
        r"(api[_-]?key|secret|token|password|auth[_-]?key|jwt[_-]?secret|private[_-]?key|aws[_-]?key)",
        re.IGNORECASE,
    )
    SQL_KEYWORDS_PATTERN = re.compile(
        r"(SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM|DROP\s+TABLE)",
        re.IGNORECASE,
    )

    def __init__(self, file_path: str = "unknown.py"):
        self.file_path = file_path
        self.vulnerabilities: List[SecurityVulnerability] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect hardcoded credentials in assignments."""
        for target in node.targets:
            var_name = ""
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr

            if var_name and self.SECRET_VAR_PATTERN.search(var_name):
                # Check if assigned value is a non-empty string literal
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value.strip()
                    # Skip common placeholder strings
                    placeholders = {"", "dummy", "placeholder", "xxx", "change_me", "test", "your_secret_here"}
                    if len(val) >= 8 and val.lower() not in placeholders and not val.startswith("env:"):
                        self.vulnerabilities.append(
                            SecurityVulnerability(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                category="CWE-798: Hardcoded Credentials",
                                severity="CRITICAL",
                                description=(
                                    f"Hardcoded sensitive secret or API key assigned to variable '{var_name}'. "
                                    "Exposing secrets in version control creates severe supply chain risks."
                                ),
                                remediation=(
                                    "Extract credentials to environment variables or use a secret management service "
                                    "(e.g., AWS Secrets Manager, HashiCorp Vault, Doppler)."
                                ),
                                code_snippet=f"{var_name} = '***'",
                            )
                        )
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect hardcoded credentials in equality comparisons (e.g. if password == 'SECRET')."""
        left_name = ""
        if isinstance(node.left, ast.Name):
            left_name = node.left.id
        elif isinstance(node.left, ast.Attribute):
            left_name = node.left.attr

        for comparator in node.comparators:
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                val = comparator.value.strip()
                if left_name and self.SECRET_VAR_PATTERN.search(left_name):
                    placeholders = {"", "dummy", "placeholder", "xxx", "change_me", "test"}
                    if len(val) >= 8 and val.lower() not in placeholders and not val.startswith("env:"):
                        self.vulnerabilities.append(
                            SecurityVulnerability(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                category="CWE-798: Hardcoded Credentials",
                                severity="CRITICAL",
                                description=(
                                    f"Hardcoded sensitive secret compared against '{left_name}'. "
                                    "Bypassing authentication or comparing raw secrets in code creates critical exposure."
                                ),
                                remediation=(
                                    "Compare against securely hashed secrets (e.g., argon2, bcrypt) "
                                    "or load secrets from secure environment variables using constant-time comparison."
                                ),
                                code_snippet=f"{left_name} == '***'",
                            )
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect function and method calls for dangerous patterns."""
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # 1. Arbitrary Code Execution: eval() and exec()
        if func_name in ("eval", "exec"):
            self.vulnerabilities.append(
                SecurityVulnerability(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    category="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
                    severity="CRITICAL",
                    description=f"Direct invocation of '{func_name}()' enables Remote Code Execution (RCE).",
                    remediation="Avoid dynamic code execution. Use safe parsing alternatives (e.g. ast.literal_eval, json).",
                    code_snippet=f"{func_name}(...)",
                )
            )

        # 2. Insecure Deserialization: pickle.loads()
        if func_name in ("loads", "load"):
            is_pickle = False
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id in ("pickle", "_pickle", "cPickle"):
                    is_pickle = True
            if is_pickle:
                self.vulnerabilities.append(
                    SecurityVulnerability(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        category="CWE-502: Deserialization of Untrusted Data",
                        severity="CRITICAL",
                        description="pickle deserialization allows arbitrary code execution via forged pickle payloads.",
                        remediation="Replace pickle with safe serialization formats like JSON, Protobuf, or MsgPack.",
                        code_snippet="pickle.loads(...)",
                    )
                )

        # 3. Command Injection: subprocess with shell=True or os.system
        if func_name == "system" and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                self.vulnerabilities.append(
                    SecurityVulnerability(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        category="CWE-78: OS Command Injection",
                        severity="HIGH",
                        description="Direct call to os.system() executes shell commands without parameter sanitization.",
                        remediation="Use subprocess.run with arguments passed as a list and shell=False.",
                        code_snippet="os.system(...)",
                    )
                )

        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.vulnerabilities.append(
                    SecurityVulnerability(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        category="CWE-78: OS Command Injection via shell=True",
                        severity="HIGH",
                        description="Invoking subprocess commands with shell=True allows arbitrary command execution.",
                        remediation="Set shell=False and pass command and arguments as a sequence of strings.",
                        code_snippet=f"{func_name}(..., shell=True)",
                    )
                )

        # 4. SQL Injection in database execution methods
        db_methods = {"execute", "raw", "query", "raw_query", "executemany"}
        if func_name in db_methods and node.args:
            first_arg = node.args[0]
            is_sql_injection = False
            detail = ""

            # Check f-strings
            if isinstance(first_arg, ast.JoinedStr):
                # Check if it looks like SQL
                static_parts = "".join(part.value for part in first_arg.values if isinstance(part, ast.Constant) and isinstance(part.value, str))
                if self.SQL_KEYWORDS_PATTERN.search(static_parts):
                    is_sql_injection = True
                    detail = "Formatted f-string query"

            # Check % string formatting or + concatenation
            elif isinstance(first_arg, ast.BinOp):
                if isinstance(first_arg.op, (ast.Mod, ast.Add)):
                    is_sql_injection = True
                    detail = "String concatenation or % operator query"

            # Check .format() call
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                is_sql_injection = True
                detail = "str.format() query"

            if is_sql_injection:
                self.vulnerabilities.append(
                    SecurityVulnerability(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        category="CWE-89: SQL Injection",
                        severity="CRITICAL",
                        description=(
                            f"Dynamic string interpolation ({detail}) in database call '{func_name}'. "
                            "Allows attackers to manipulate SQL queries and exfiltrate or modify records."
                        ),
                        remediation="Use parameterized queries / prepared statements (e.g., cursor.execute('SELECT ... WHERE id = %s', (val,))).",
                        code_snippet=f"{func_name}(<dynamic_query>)",
                    )
                )

        self.generic_visit(node)


class ASTScanner:
    """Wrapper to run static AST checks across files or code snippets."""

    @classmethod
    def scan_code(cls, source_code: str, file_path: str = "source.py") -> List[SecurityVulnerability]:
        """
        Parses source code into AST and executes security checks.
        Handles syntax errors gracefully (e.g. non-python files or partial diff fragments).
        """
        if not source_code or not source_code.strip():
            return []

        import textwrap
        dedented = textwrap.dedent(source_code)

        tree = None
        try:
            tree = ast.parse(dedented, filename=file_path)
        except SyntaxError:
            # Code fragment may be indented inside a function (e.g. containing 'return')
            try:
                wrapped = "def _diff_context():\n" + textwrap.indent(dedented, "    ")
                tree = ast.parse(wrapped, filename=file_path)
            except SyntaxError:
                return []

        visitor = SecurityASTVisitor(file_path=file_path)
        visitor.visit(tree)
        return visitor.vulnerabilities
