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
import math
import re
from typing import Dict, List, Optional, Set, Tuple

from src.agents.state import SecurityVulnerability
from src.rules_config import ScanConfig

INLINE_IGNORE_PATTERN = re.compile(
    r"#\s*codesentinel:\s*ignore(?:\[([^\]]+)\])?",
    re.IGNORECASE,
)


def _extract_suppressions(source_code: str) -> Dict[int, Optional[Set[str]]]:
    """
    Map 1-based line numbers to inline suppression targets.

    - None value means suppress all rules on that line (`# codesentinel: ignore`)
    - Set[str] means suppress only matching CWE/rule tokens (`# codesentinel: ignore[CWE-798]`)
    """
    suppressions: Dict[int, Optional[Set[str]]] = {}
    for lineno, line in enumerate(source_code.splitlines(), start=1):
        match = INLINE_IGNORE_PATTERN.search(line)
        if not match:
            continue
        raw_codes = match.group(1)
        if not raw_codes:
            suppressions[lineno] = None
        else:
            codes = {c.strip().upper() for c in raw_codes.split(",") if c.strip()}
            suppressions[lineno] = codes
    return suppressions


def _is_suppressed(vuln: SecurityVulnerability, suppressions: Dict[int, Optional[Set[str]]]) -> bool:
    if vuln.line_number not in suppressions:
        return False
    allowed = suppressions[vuln.line_number]
    if allowed is None:
        return True
    cat_upper = vuln.category.upper()
    return any(code in cat_upper for code in allowed)


class SecurityASTVisitor(ast.NodeVisitor):
    """AST Visitor searching for dangerous security anti-patterns in Python code."""

    SECRET_VAR_PATTERN = re.compile(
        r"(api[_-]?key|secret|token|password|auth[_-]?key|jwt[_-]?secret|private[_-]?key|aws[_-]?key)",
        re.IGNORECASE,
    )
    PROVIDER_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("GitHub Personal Access Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
        ("OpenAI API Key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
        ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b")),
        ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
        ("Private Key Material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ]
    SQL_KEYWORDS_PATTERN = re.compile(
        r"(SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM|DROP\s+TABLE)",
        re.IGNORECASE,
    )

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in text:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def _detect_provider_secret(self, value: str) -> Optional[str]:
        for label, pattern in self.PROVIDER_SECRET_PATTERNS:
            if pattern.search(value):
                return label
        return None

    def __init__(self, file_path: str = "unknown.py"):
        self.file_path = file_path
        self.vulnerabilities: List[SecurityVulnerability] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect hardcoded credentials via variable names, provider token patterns, and Shannon entropy."""
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value.strip()
            placeholders = {"", "dummy", "placeholder", "xxx", "change_me", "test", "your_secret_here"}
            provider_hit = self._detect_provider_secret(val)

            for target in node.targets:
                var_name = ""
                if isinstance(target, ast.Name):
                    var_name = target.id
                elif isinstance(target, ast.Attribute):
                    var_name = target.attr

                if provider_hit:
                    self.vulnerabilities.append(
                        SecurityVulnerability(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            category="CWE-798: Hardcoded Credentials",
                            severity="CRITICAL",
                            description=(
                                f"Detected hardcoded {provider_hit} assigned to '{var_name or 'literal'}'. "
                                "Committing live provider credentials exposes cloud and API accounts immediately."
                            ),
                            remediation=(
                                "Revoke the exposed credential immediately and load it from environment variables "
                                "or a dedicated secret manager (AWS Secrets Manager, HashiCorp Vault, Doppler)."
                            ),
                            code_snippet=f"{var_name or 'secret'} = '***'",
                        )
                    )
                    break

                if var_name and self.SECRET_VAR_PATTERN.search(var_name):
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
                elif (
                    len(val) >= 24
                    and " " not in val
                    and "/" not in val
                    and not val.startswith(("http://", "https://"))
                    and self._shannon_entropy(val) >= 4.4
                ):
                    self.vulnerabilities.append(
                        SecurityVulnerability(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            category="CWE-798: High-Entropy Hardcoded Secret",
                            severity="HIGH",
                            description=(
                                f"High-entropy string (Shannon H={self._shannon_entropy(val):.2f}) assigned to '{var_name}'. "
                                "This strongly resembles an API token, signing key, or credential."
                            ),
                            remediation="Move secrets out of source code into environment variables or a secret vault.",
                            code_snippet=f"{var_name} = '<high-entropy-secret>'",
                        )
                    )
        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
            if isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "random":
                for target in node.targets:
                    var_name = (
                        target.id
                        if isinstance(target, ast.Name)
                        else (target.attr if isinstance(target, ast.Attribute) else "")
                    )
                    if var_name and re.search(r"(token|secret|password|nonce|otp|session|key|salt)", var_name, re.IGNORECASE):
                        self.vulnerabilities.append(
                            SecurityVulnerability(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                category="CWE-330: Use of Insufficiently Random Values",
                                severity="HIGH",
                                description=(
                                    f"Non-cryptographic 'random.{node.value.func.attr}()' used to generate security value '{var_name}'. "
                                    "Mersenne Twister output is predictable."
                                ),
                                remediation="Use Python's 'secrets' module (e.g., secrets.token_urlsafe(), secrets.choice()).",
                                code_snippet=f"{var_name} = random.{node.value.func.attr}(...)",
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

        # 2. Insecure Deserialization: pickle.loads() and unsafe yaml.load()
        if func_name in ("loads", "load", "unsafe_load"):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                if module_name in ("pickle", "_pickle", "cPickle") and func_name in ("loads", "load"):
                    self.vulnerabilities.append(
                        SecurityVulnerability(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            category="CWE-502: Deserialization of Untrusted Data",
                            severity="CRITICAL",
                            description="pickle deserialization allows arbitrary code execution via forged pickle payloads.",
                            remediation="Replace pickle with safe serialization formats like JSON, Protobuf, or MsgPack.",
                            code_snippet=f"pickle.{func_name}(...)",
                        )
                    )
                elif module_name == "yaml":
                    safe_loaders = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
                    loader_is_safe = False
                    if func_name == "load":
                        for kw in node.keywords:
                            if kw.arg == "Loader":
                                loader_name = (
                                    kw.value.attr
                                    if isinstance(kw.value, ast.Attribute)
                                    else (kw.value.id if isinstance(kw.value, ast.Name) else "")
                                )
                                if loader_name in safe_loaders:
                                    loader_is_safe = True
                    if func_name == "unsafe_load" or (func_name == "load" and not loader_is_safe):
                        self.vulnerabilities.append(
                            SecurityVulnerability(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                category="CWE-502: Unsafe YAML Deserialization",
                                severity="CRITICAL",
                                description=(
                                    f"Calling yaml.{func_name}() without SafeLoader can instantiate arbitrary Python objects "
                                    "and lead to Remote Code Execution."
                                ),
                                remediation="Use yaml.safe_load(data) or pass Loader=yaml.SafeLoader explicitly.",
                                code_snippet=f"yaml.{func_name}(...)",
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

        # 5. Weak Cryptography: hashlib.md5 / hashlib.sha1
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib":
                weak_alg: Optional[str] = None
                if func_name in ("md5", "sha1"):
                    weak_alg = func_name
                elif (
                    func_name == "new"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and node.args[0].value.lower() in ("md5", "sha1")
                ):
                    weak_alg = node.args[0].value.lower()

                if weak_alg:
                    non_security = any(
                        kw.arg == "usedforsecurity"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is False
                        for kw in node.keywords
                    )
                    if not non_security:
                        self.vulnerabilities.append(
                            SecurityVulnerability(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                category="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                                severity="MEDIUM",
                                description=(
                                    f"Weak hash algorithm 'hashlib.{weak_alg}()' is vulnerable to collision attacks."
                                ),
                                remediation=(
                                    "Use SHA-256/SHA-3 (hashlib.sha256) for integrity checks, Argon2/bcrypt for passwords, "
                                    "or pass usedforsecurity=False for non-security checksums."
                                ),
                                code_snippet=f"hashlib.{weak_alg}(...)",
                            )
                        )

        # 6. Disabled TLS/SSL Certificate Verification (CWE-295)
        if func_name == "_create_unverified_context":
            self.vulnerabilities.append(
                SecurityVulnerability(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    category="CWE-295: Improper Certificate Validation",
                    severity="HIGH",
                    description="Using ssl._create_unverified_context() disables TLS certificate validation, exposing traffic to MITM attacks.",
                    remediation="Use ssl.create_default_context() with valid CA certificates.",
                    code_snippet="ssl._create_unverified_context()",
                )
            )

        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.vulnerabilities.append(
                    SecurityVulnerability(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        category="CWE-295: Improper Certificate Validation",
                        severity="HIGH",
                        description=(
                            f"TLS certificate verification disabled via verify=False in '{func_name}()'. "
                            "Allows Man-in-the-Middle (MITM) interception."
                        ),
                        remediation="Remove verify=False or point verify= to a trusted CA bundle.",
                        code_snippet=f"{func_name}(..., verify=False)",
                    )
                )

        self.generic_visit(node)


class ASTScanner:
    """Wrapper to run static AST checks across files or code snippets."""

    @classmethod
    def scan_code(
        cls,
        source_code: str,
        file_path: str = "source.py",
        config: Optional[ScanConfig] = None,
    ) -> List[SecurityVulnerability]:
        """
        Parses source code into AST and executes security checks.
        Applies inline `# codesentinel: ignore` suppressions and optional ScanConfig filters.
        Handles syntax errors gracefully (e.g. non-python files or partial diff fragments).
        """
        if not source_code or not source_code.strip():
            return []

        import textwrap
        dedented = textwrap.dedent(source_code)
        suppressions = _extract_suppressions(dedented)
        wrapped_offset = 0

        tree = None
        try:
            tree = ast.parse(dedented, filename=file_path)
        except SyntaxError:
            # Code fragment may be indented inside a function (e.g. containing 'return')
            try:
                wrapped = "def _diff_context():\n" + textwrap.indent(dedented, "    ")
                tree = ast.parse(wrapped, filename=file_path)
                wrapped_offset = 1
            except SyntaxError:
                return []

        visitor = SecurityASTVisitor(file_path=file_path)
        visitor.visit(tree)

        filtered: List[SecurityVulnerability] = []
        for vuln in visitor.vulnerabilities:
            if wrapped_offset:
                vuln.line_number = max(1, vuln.line_number - wrapped_offset)
            if _is_suppressed(vuln, suppressions):
                continue
            if config is not None:
                if not config.meets_severity(vuln.severity):
                    continue
                if not config.is_rule_enabled(category=vuln.category):
                    continue
            filtered.append(vuln)

        return filtered
