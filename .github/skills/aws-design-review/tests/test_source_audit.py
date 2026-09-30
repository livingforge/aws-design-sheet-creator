from pathlib import Path

from aws_design_sheet.source_audit import build_audit, documentation_url


ROOT = Path(__file__).resolve().parents[1]


def test_documentation_url_handles_aws_and_alexa():
    assert documentation_url("AWS::EC2::SubnetCidrBlock").endswith(
        "/aws-resource-ec2-subnetcidrblock.html")
    assert documentation_url("Alexa::ASK::Skill").endswith(
        "/alexa-resource-ask-skill.html")


def test_audit_keeps_source_discovery_separate_from_review(monkeypatch):
    from aws_design_sheet import source_audit

    monkeypatch.setattr(source_audit, "inspect_page", lambda name: {
        "url": documentation_url(name), "http_status": 200,
        "title_matches_type": True, "content_sha256": "0" * 64})
    report = build_audit(ROOT / "rules/ledger.json", ROOT / "schemas", namespace="ACMPCA")
    assert report["kind"] == "SOURCE_DISCOVERY_ONLY"
    assert report["counts"] == {"verified": 4, "unverified": 0}
    assert len(report["types"]) == 4
    assert "/properties/Principal" in report["types"]["AWS::ACMPCA::Permission"][
        "conditional_description_paths"]
