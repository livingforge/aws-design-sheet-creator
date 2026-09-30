import copy
import json
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]
PATHS = {
    "AWS::APS::AnomalyDetector": "/properties/Workspace",
    "AWS::APS::ResourcePolicy": "/properties/WorkspaceArn",
    "AWS::APS::RuleGroupsNamespace": "/properties/Workspace",
}


def result(source_type, *, target_id="workspace", external=False):
    data = json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    scope = copy.deepcopy(data["resources"][0]["scope"])
    data["resources"].append({"id": "workspace", "type": "AWS::APS::Workspace",
                              "name": "metrics", "scope": scope, "fields": []})
    field_path = PATHS[source_type]
    fields = []
    if external:
        fields.append({"path": field_path, "state": "KNOWN", "selected_candidate_id": "arn",
                       "candidates": [{"id": "arn", "raw": "arn", "value":
                                       "arn:aws:aps:ap-northeast-1:111111111111:workspace/ws-123",
                                       "evidence_ids": ["e-vpc"]}]})
    data["resources"].append({"id": "dependent", "type": source_type,
                              "name": "dependent", "scope": scope, "fields": fields})
    if not external:
        data["relations"].append({"id": "aps-ref", "source_resource_id": "dependent",
                                  "source_path": field_path, "target_resource_id": target_id})
    checked = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        Design.model_validate(data))
    return [row for row in checked["results"] if row["rule_id"] == "REFERENCE"
            and row["resource_id"] == "dependent"]


def test_aps_workspace_reference_type_and_external_id():
    for source_type in PATHS:
        assert result(source_type)[0]["verdict"] == "PASS"
        assert result(source_type, target_id="vpc-main")[0]["verdict"] == "FAIL"
        assert result(source_type, external=True)[0]["verdict"] == "NEEDS_REVIEW"
