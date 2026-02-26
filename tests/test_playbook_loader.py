import os
from core.playbooks import load_all_playbooks


def test_playbooks_load():
    root = os.path.join(os.path.dirname(__file__), "..", "playbooks")
    playbooks = load_all_playbooks(root)
    assert "xss" in playbooks
    assert "sqli" in playbooks


def test_validation_harness():
    from core.harness.validate import load_findings, score_false_positives

    path = os.path.join(os.path.dirname(__file__), "fixtures", "sample_report.json")
    findings = load_findings(path)
    score = score_false_positives(findings)
    assert score["total"] == 1
    assert score["missing_evidence"] == 0
