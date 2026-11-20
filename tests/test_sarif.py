"""Tests for SARIF 2.1.0 exporter."""

from src.agents.ast_scanner import ASTScanner
from src.reporting.sarif import SARIF_SCHEMA_URI, export_sarif


def test_export_sarif_schema_and_results():
    code = """
    import requests
    eval(payload)
    requests.get("https://internal", verify=False)
    """
    vulns = ASTScanner.scan_code(code, "app/service.py")
    sarif = export_sarif(vulns)

    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == SARIF_SCHEMA_URI
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "CodeSentinel"
    assert len(driver["rules"]) == 12

    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"CS003", "CS008"}
    for res in results:
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "app/service.py"
        assert loc["region"]["startLine"] >= 1
