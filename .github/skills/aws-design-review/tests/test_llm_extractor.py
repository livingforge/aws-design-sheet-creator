"""LLM extractor: request shape and source verification, with a fake client (no network)."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aws_design_sheet.extractor import TextSource
from aws_design_sheet.llm_extractor import LlmExtractor, SCHEMA
from aws_design_sheet.runner import run_text


ROOT = Path(__file__).resolve().parents[1]
TEXT = ("本番環境の VPC main は 10.0.0.0/16 を使う。DNS サポートは無効にする。\n"
        "アプリ用サブネット app-a は main に置き、CIDR は 10.0.1.0/24。\n"
        "要件: 本番のサブネットではパブリック IP を自動割当しない。\n"
        "雑記: 来週レビュー予定。")
OUTPUT = {
    "resources": [
        {"type": "AWS::EC2::VPC", "name": "main", "document_id": "doc-1", "line": 1,
         "excerpt": "VPC main", "properties": [
             {"name": "CidrBlock", "value_json": "\"10.0.0.0/16\"", "document_id": "doc-1",
              "line": 1, "excerpt": "10.0.0.0/16"},
             {"name": "EnableDnsSupport", "value_json": "false", "document_id": "doc-1",
              "line": 1, "excerpt": "DNS サポートは無効"}]},
        {"type": "AWS::EC2::Subnet", "name": "app-a", "document_id": "doc-1", "line": 2,
         "excerpt": "サブネット app-a", "properties": [
             {"name": "VpcId", "value_json": "\"@AWS::EC2::VPC/main\"", "document_id": "doc-1",
              "line": 2, "excerpt": "main に置き"},
             {"name": "CidrBlock", "value_json": "\"10.0.1.0/24\"", "document_id": "doc-1",
              "line": 2, "excerpt": "10.0.1.0/24"},
             {"name": "MapPublicIpOnLaunch", "value_json": "false", "document_id": "doc-1",
              "line": 2, "excerpt": "パブリック IP"},
             {"name": "AvailabilityZone", "value_json": "ap-northeast-1a", "document_id": "doc-1",
              "line": 2, "excerpt": "app-a"}]}],
    "requirements": [{"id": "REQ-1", "description": "No automatic public IPs in prod subnets",
                      "document_id": "doc-1", "line": 3, "excerpt": "パブリック IP を自動割当しない"}]}


class FakeStream:
    def __init__(self, recorder, output):
        self.recorder, self.output = recorder, output

    def __call__(self, **kwargs):
        self.recorder.append(kwargs)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return SimpleNamespace(stop_reason="end_turn",
                               content=[SimpleNamespace(type="text", text=json.dumps(self.output))])


def fake_client(output=OUTPUT, calls=None):
    calls = [] if calls is None else calls
    return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(stream=FakeStream(calls, output))))


def extract(client):
    extractor = LlmExtractor(client)
    design = extractor.extract([TextSource(id="doc-1", name="notes.txt", version="1", text=TEXT)],
                               project="p", environment="prod", account="111111111111",
                               region="ap-northeast-1")
    return extractor, design


def test_request_uses_structured_output_and_numbered_lines():
    calls = []
    extract(fake_client(calls=calls))
    [call] = calls
    assert call["model"] == "claude-opus-5"
    assert call["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}
    assert "1: 本番環境の VPC main" in call["messages"][0]["content"]


def test_explicit_template_metadata_is_separate_from_properties():
    text = 'VPC main belongs to stack and explicitly has no DependsOn.'
    located = {'document_id': 'd', 'line': 1, 'excerpt': text}
    output = {'resources': [{'type': 'AWS::EC2::VPC', 'name': 'main', **located,
        'properties': [{'name': '@Template', 'value_json': '{"id":"stack","depends_on":[]}', **located}]}],
        'requirements': []}
    extractor = LlmExtractor()
    data = extractor.build(output, [TextSource('d', 'input', '1', text)], project='p', environment='prod',
                           account='111111111111', region='ap-northeast-1')
    assert data.resources[0].template.depends_on == []
    assert data.resources[0].fields == []
    assert data.extractor_version == 'llm-v2'
    assert not extractor.rejected


def test_only_items_quoted_from_their_line_are_kept():
    extractor, design = extract(fake_client())
    vpc, subnet = design.resources
    assert vpc.field("/properties/EnableDnsSupport").selected().value is False
    assert subnet.field("/properties/MapPublicIpOnLaunch") is None
    assert subnet.field("/properties/AvailabilityZone") is None
    reasons = sorted(item["reason"] for item in extractor.rejected)
    assert reasons == ["excerpt not on cited line", "value is not JSON"]
    [relation] = design.relations
    assert relation.target_resource_id == vpc.id
    assert design.requirements[0].id == "REQ-1"
    assert design.documents[0].extracted_ranges == [[1, 1], [2, 2], [3, 3]]
    assert all(e.excerpt in TEXT.splitlines()[e.start_line - 1] for e in design.evidence)


def test_refusal_is_an_error():
    client = fake_client()
    client.beta.messages.stream.get_final_message = lambda: SimpleNamespace(stop_reason="refusal", content=[])
    with pytest.raises(RuntimeError, match="refused"):
        extract(client)


def test_pipeline_checks_llm_output_and_reports_unprocessed_line():
    extractor = LlmExtractor(fake_client())
    design, result = run_text([TextSource(id="doc-1", name="notes.txt", version="1", text=TEXT)],
                              project="p", environment="prod", account="111111111111",
                              region="ap-northeast-1", schema_dir=ROOT / "schemas",
                              profile_path=ROOT / "profiles/vpc-subnet.json", extractor=extractor)
    assert result["versions"]["extractor"] == "llm-v1"
    assert any(r["rule_id"] == "CIDR_CONTAINMENT" and r["verdict"] == "PASS" for r in result["results"])
    assert any(c["kind"] == "UNPROCESSED_TEXT" and "line 4" in c["reason"] for c in result["coverage"])
