import hashlib
import json
import zipfile
from pathlib import Path

from aws_design_sheet.models import Design
from aws_design_sheet.checks.sqs.queue_encryption import evaluate_sqs_queue_encryption_option


ROOT = Path(__file__).resolve().parents[1]


def design(fields=None, *, key_reference=False, resource_type="AWS::SQS::Queue"):
    fields = fields or {}
    text = "queue encryption"
    properties = []
    for index, (name, specification) in enumerate(fields.items()):
        state, value = specification if isinstance(specification, tuple) else ("KNOWN", specification)
        field = {"path": f"/properties/{name}", "state": state}
        if state == "KNOWN":
            field.update(selected_candidate_id=f"c-{index}", candidates=[{
                "id": f"c-{index}", "raw": str(value), "value": value,
                "evidence_ids": ["e-1"]}])
        elif state == "INFERRED":
            field["candidates"] = [{"id": f"c-{index}", "raw": str(value),
                                     "value": value, "evidence_ids": ["e-1"]}]
        properties.append(field)
    relations = [{"id": "r-1", "source_resource_id": "queue",
                  "source_path": "/properties/KmsMasterKeyId",
                  "expected_target_type": "AWS::KMS::Key", "unresolved_name": "key",
                  "evidence_ids": ["e-1"]}] if key_reference else []
    return Design.model_validate({
        "project": "test", "environment": "prod", "account": "111111111111",
        "documents": [{"id": "d-1", "name": "note", "version": "1", "sha256": hashlib.sha256(text.encode()).hexdigest(),
                       "text": text, "extracted_ranges": [[1, 1]]}],
        "evidence": [{"id": "e-1", "document_id": "d-1", "start_line": 1,
                      "end_line": 1, "excerpt": text}],
        "resources": [{"id": "queue", "type": resource_type, "name": "queue", "scope": {
            "environment": "prod", "account": "111111111111", "region": "ap-northeast-1"},
                       "fields": properties}], "relations": relations})


def evaluate(data):
    return evaluate_sqs_queue_encryption_option(data, data.resources[0])


def test_pinned_schema_does_not_encode_encryption_exclusion():
    manifest = json.loads((ROOT / "schemas/manifest.json").read_text(encoding="utf-8"))
    with zipfile.ZipFile(ROOT / "schemas/CloudformationSchema.zip") as archive:
        schema = json.loads(archive.read(manifest["types"]["AWS::SQS::Queue"]))
    assert "KmsMasterKeyId" in schema["properties"]
    assert "SqsManagedSseEnabled" in schema["properties"]
    assert not any(key in schema for key in ("allOf", "anyOf", "oneOf", "dependencies"))


def test_simultaneous_encryption_options_fail_with_evidence():
    result = evaluate(design({"KmsMasterKeyId": "alias/aws/sqs", "SqsManagedSseEnabled": True}))
    assert result["verdict"] == "FAIL"
    assert result["rule_id"] == "SQS_QUEUE_ENCRYPTION_OPTION_EXCLUSIVE"
    assert result["path"] == "/properties/SqsManagedSseEnabled"
    assert result["evidence_ids"] == ["e-1"]


def test_kms_with_false_or_omitted_sqs_option_passes():
    assert evaluate(design({"KmsMasterKeyId": "alias/aws/sqs", "SqsManagedSseEnabled": False}))["verdict"] == "PASS"
    assert evaluate(design({"KmsMasterKeyId": "alias/aws/sqs"}))["verdict"] == "PASS"
    assert evaluate(design({"SqsManagedSseEnabled": True}, key_reference=True))["verdict"] == "FAIL"


def test_without_kms_selection_is_not_applicable():
    assert evaluate(design({"SqsManagedSseEnabled": True}))["verdict"] == "NOT_APPLICABLE"
    assert evaluate(design({"KmsMasterKeyId": "", "SqsManagedSseEnabled": True}))["verdict"] == "NOT_APPLICABLE"
    assert evaluate(design(resource_type="AWS::SNS::Topic"))["verdict"] == "NOT_APPLICABLE"


def test_uncertain_or_invalid_values_need_review():
    result = evaluate(design({"KmsMasterKeyId": ("INFERRED", "alias/aws/sqs"),
                              "SqsManagedSseEnabled": True}))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/KmsMasterKeyId"]
    result = evaluate(design({"KmsMasterKeyId": "alias/aws/sqs",
                              "SqsManagedSseEnabled": ("UNRESOLVED", None)}))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/SqsManagedSseEnabled"]
    result = evaluate(design({"KmsMasterKeyId": "alias/aws/sqs", "SqsManagedSseEnabled": "true"}))
    assert result["verdict"] == "NEEDS_REVIEW"  # The schema owns the type error.
