import json
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.corrections import correct, main as correct_main
from aws_design_sheet.evaluate import evaluate
from aws_design_sheet.extractor import LineExtractor, TextSource
from aws_design_sheet.models import Design, ValueState
from aws_design_sheet.runner import run_text

ROOT = Path(__file__).resolve().parents[1]


def source(text, id="doc-1"):
    return TextSource(id=id, name=f"{id}.txt", version="1", text=text)


def check(design):
    return Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)


def test_text_to_result_with_provenance():
    text = (ROOT / "examples/network.txt").read_text(encoding="utf-8")
    design, result = run_text([source(text)], project="p", environment="prod",
                              account="111111111111", region="ap-northeast-1",
                              schema_dir=ROOT / "schemas", profile_path=ROOT / "profiles/vpc-subnet.json")
    assert result["status"] == "COMPLETE"
    assert result["summary"] == {"PASS": 10, "NOT_APPLICABLE": 1}
    assert {item["kind"] for item in result["coverage"]} == {"RULE_REVIEW_REQUIRED"}
    assert design.resources[0].field("/properties/EnableDnsSupport").selected().value is False
    assert design.documents[0].extracted_ranges == [[1, 1], [2, 2]]
    assert result["metrics"]["resources"] == 2
    assert result["metrics"]["process_peak_rss_bytes"] > result["metrics"]["peak_bytes"] > 0
    assert result["versions"]["extractor"] == "line-v4"
    assert result["versions"]["ledger"] == "1.0.0"
    assert len(result["versions"]["ledger_sha256"]) == 64


def test_generic_cloudformation_resource_types():
    design = LineExtractor().extract([source(
        "AWS::S3::Bucket assets: Tags=1\n"
        "AWS::Lambda::Function worker: Runtime=python3.12\n"
        "Alexa::ASK::Skill voice: VendorId=vendor")],
        project="p", environment="dev", account="1", region="ap-northeast-1")
    assert [resource.type for resource in design.resources] == [
        "AWS::S3::Bucket", "AWS::Lambda::Function", "Alexa::ASK::Skill"]
    result = check(design)
    assert result["status"] == "COMPLETE"
    assert not any(item["kind"] == "RESOURCE_TYPE" for item in result["coverage"])
    assert {item["kind"] for item in result["coverage"] if item["kind"].startswith("RULE_")} == {
        "RULE_REVIEW_REQUIRED"}
    assert not any(item["rule_id"].startswith("CFN_LINT.") for item in result["results"])


def test_next_wave_rules_are_in_normal_check_results():
    design = LineExtractor().extract([source(
        'AWS::IAM::User alice: UserName="alice"\n'
        'AWS::IAM::AccessKey key: UserName=@AWS::IAM::User/alice\n'
        'AWS::EC2::Route route: RouteTableId="rtb-external"; DestinationCidrBlock="0.0.0.0/0"; NatGatewayId="nat-a"; GatewayId="igw-a"\n'
        'AWS::RDS::DBInstance db: Engine="postgres"; KmsKeyId="key-a"; StorageEncrypted=false\n'
        'AWS::S3::Bucket bucket: ObjectLockConfiguration={"ObjectLockEnabled":"Enabled"}; ObjectLockEnabled=false'),
    ], project="p", environment="prod", account="111111111111", region="ap-northeast-1")
    results = check(design)["results"]
    verdicts = {item["rule_id"]: item["verdict"] for item in results}
    assert verdicts["IAM_ACCESS_KEY_USER_REFERENCE"] == "PASS"
    assert verdicts["EC2_ROUTE_DESTINATION_AND_TARGET"] == "FAIL"
    assert verdicts["RDS_DBINSTANCE_KMS_REQUIRES_ENCRYPTION"] == "FAIL"
    assert verdicts["S3_OBJECT_LOCK_CONFIGURATION_ENABLED"] == "FAIL"


def test_iam_access_key_reference_allows_same_account_user_in_another_region():
    design = LineExtractor().extract([source(
        'AWS::IAM::User alice: UserName="alice"\n'
        'AWS::IAM::AccessKey key: UserName=@AWS::IAM::User/alice'),
    ], project="p", environment="prod", account="111111111111", region="ap-northeast-1")
    design.resources[0].scope.region = "us-east-1"
    results = check(design)["results"]
    assert any(item["rule_id"] == "IAM_ACCESS_KEY_USER_REFERENCE" and item["verdict"] == "PASS"
               for item in results)
    assert any(item["rule_id"] == "REFERENCE" and item["verdict"] == "PASS"
               and item["path"] == "/properties/UserName" for item in results)


def test_third_wave_rules_are_in_normal_check_results():
    design = LineExtractor().extract([source(
        'AWS::Lambda::Function fn: PackageType=Image; Runtime=python3.12; Code={"ImageUri":"image"}\n'
        'AWS::SQS::Queue queue: KmsMasterKeyId="key"; SqsManagedSseEnabled=true\n'
        'AWS::SNS::Topic topic: FifoTopic=true; TopicName="events"\n'
        'AWS::DynamoDB::Table table: BillingMode=PAY_PER_REQUEST; '
        'ProvisionedThroughput={"ReadCapacityUnits":1,"WriteCapacityUnits":1}'),
    ], project="p", environment="prod", account="111111111111", region="ap-northeast-1")
    results = check(design)["results"]
    verdicts = {item["rule_id"]: item["verdict"] for item in results}
    assert verdicts["LAMBDA_PACKAGE_CONFIGURATION"] == "FAIL"
    assert verdicts["SQS_QUEUE_ENCRYPTION_OPTION_EXCLUSIVE"] == "FAIL"
    assert verdicts["SNS_FIFO_TOPIC_NAME_SUFFIX"] == "FAIL"
    assert verdicts["DYNAMODB_TABLE_BILLING_THROUGHPUT"] == "FAIL"


def test_typed_reference_for_generic_resource():
    design = LineExtractor().extract([source(
        'AWS::S3::Bucket assets: BucketName="sample-assets"\n'
        'AWS::S3::BucketPolicy policy: Bucket=@AWS::S3::Bucket/assets; PolicyDocument={}'),
    ], project="p", environment="dev", account="1", region="ap-northeast-1")
    assert len(design.relations) == 1
    assert design.relations[0].expected_target_type == "AWS::S3::Bucket"
    result = check(design)
    assert any(item["rule_id"] == "REFERENCE" and item["verdict"] == "PASS"
               for item in result["results"])
    assert not any(item["rule_id"] == "SCHEMA_REQUIRED" and item["path"] == "/properties/Bucket"
                   for item in result["results"])
    assert any(item["kind"] == "REFERENCE_VALUE" for item in result["coverage"])


def test_generic_reference_missing_and_type_mismatch():
    design = LineExtractor().extract([source(
        'AWS::S3::BucketPolicy policy: Bucket=@AWS::S3::Bucket/missing; PolicyDocument={}'),
    ], project="p", environment="dev", account="1", region="ap-northeast-1")
    assert any(item["rule_id"] == "REFERENCE" and item["verdict"] == "NEEDS_REVIEW"
               for item in check(design)["results"])
    data = design.model_dump(mode="json")
    data["resources"].append({"id": "res-2", "type": "AWS::SNS::Topic", "name": "other",
                              "scope": {"environment": "dev", "account": "1", "region": "ap-northeast-1"}})
    data["relations"][0]["target_resource_id"] = "res-2"
    assert any(item["rule_id"] == "REFERENCE" and item["verdict"] == "FAIL"
               for item in check(Design.model_validate(data))["results"])


def test_nested_typed_reference_keeps_schema_uncertainty_visible():
    design = LineExtractor().extract([source(
        'AWS::S3::Bucket assets: BucketName="sample-assets"\n'
        'AWS::S3::BucketPolicy policy: Bucket=@AWS::S3::Bucket/assets; '
        'PolicyDocument={"Statement":[{"Resource":"@AWS::S3::Bucket/assets"}]}'),
    ], project="p", environment="dev", account="1", region="ap-northeast-1")
    result = check(design)
    assert len(design.relations) == 2
    assert any(rel.source_path == "/properties/PolicyDocument/Statement/0/Resource"
               for rel in design.relations)
    assert len([item for item in result["results"] if item["rule_id"] == "REFERENCE"
                and item["verdict"] == "PASS"]) == 2


def test_pilot_rules_are_in_normal_check_results():
    design = LineExtractor().extract([source(
        'AWS::IAM::Policy inline: PolicyName="inline"; PolicyDocument={}; Roles=[]\n'
        'AWS::ElasticLoadBalancingV2::Listener secure: Protocol=HTTPS; Certificates=[]'),
    ], project="p", environment="dev", account="1", region="ap-northeast-1")
    result = check(design)
    assert result["status"] == "COMPLETE"
    assert {item["rule_id"] for item in result["results"] if item["verdict"] == "FAIL"} >= {
        "IAM_POLICY_ATTACHMENT", "ELBV2_SECURE_LISTENER_CERTIFICATE"}
    assert all(item["source_urls"] for item in result["results"]
               if item["rule_id"] in {"IAM_POLICY_ATTACHMENT", "ELBV2_SECURE_LISTENER_CERTIFICATE"})
    assert {item["kind"] for item in result["coverage"] if item["kind"].startswith("RULE_")} == {
        "RULE_REVIEW_REQUIRED"}


def test_lambda_vpc_rule_is_in_normal_check_results():
    design = LineExtractor().extract([source(
        'VPC main: CidrBlock=10.0.0.0/16\n'
        'VPC other: CidrBlock=10.1.0.0/16\n'
        'Subnet app: Vpc=main; CidrBlock=10.0.1.0/24\n'
        'SecurityGroup sg: Vpc=other; GroupDescription="sg"\n'
        'AWS::Lambda::Function worker: VpcConfig={"SubnetIds":["@AWS::EC2::Subnet/app"],'
        '"SecurityGroupIds":["@AWS::EC2::SecurityGroup/sg"]}'),
    ], project="p", environment="dev", account="1", region="ap-northeast-1")
    result = check(design)
    assert any(item["rule_id"] == "LAMBDA_VPC_MEMBERSHIP" and item["verdict"] == "FAIL"
               for item in result["results"])


def test_s3_replication_rule_and_cross_region_destination():
    design = LineExtractor().extract([source(
        'AWS::S3::Bucket source: VersioningConfiguration={"Status":"Enabled"}; '
        'ReplicationConfiguration={"Rules":[{"Destination":'
        '{"Bucket":"@AWS::S3::Bucket/target"}}]}\n'
        'AWS::S3::Bucket target: VersioningConfiguration={"Status":"Enabled"}'),
    ], project="p", environment="dev", account="1", region="ap-northeast-1")
    data = design.model_dump(mode="json")
    data["resources"][1]["scope"]["region"] = "us-east-1"
    result = check(Design.model_validate(data))
    assert any(item["rule_id"] == "S3_REPLICATION_VERSIONING" and item["verdict"] == "PASS"
               for item in result["results"])
    assert any(item["rule_id"] == "REFERENCE" and item["verdict"] == "PASS"
               for item in result["results"])
    assert not any(item["rule_id"] == "REFERENCE" and item["verdict"] == "FAIL"
                   for item in result["results"])


def test_generic_tags_and_profile_requirements(tmp_path):
    profile = {"version": "test", "types": {"AWS::S3::Bucket": [
        {"path": "/properties/BucketEncryption", "label": "encryption policy"}]}}
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    design = LineExtractor().extract([source(
        'AWS::S3::Bucket assets: Tags=[{"Key":"Owner","Value":"a"},{"Key":"Owner","Value":"b"}]'),
    ], project="p", environment="dev", account="1", region="ap-northeast-1")
    result = Checker(ROOT / "schemas", profile_path).check(design)
    assert any(item["rule_id"] == "TAG_KEY_UNIQUE" and item["verdict"] == "FAIL"
               for item in result["results"])
    assert any(item["rule_id"] == "PROFILE_REQUIRED" and item["verdict"] == "NEEDS_REVIEW"
               for item in result["results"])


def test_multidocument_conflict_and_unprocessed_line():
    first = source("VPC main: CidrBlock=10.0.0.0/16\nunknown requirement", "a")
    second = source("VPC main: CidrBlock=10.1.0.0/16", "b")
    design = LineExtractor().extract([first, second], project="p", environment="dev",
                                     account="1", region="ap-northeast-1")
    field = design.resources[0].field("/properties/CidrBlock")
    assert field.state == ValueState.CONFLICT
    assert field.selected_candidate_id is None
    assert len(field.candidates) == 2
    result = check(design)
    assert any(r["rule_id"] == "VALUE_CONFLICT" and r["verdict"] == "NEEDS_REVIEW"
               for r in result["results"])
    assert any(c["kind"] == "UNPROCESSED_TEXT" and "line 2" in c["reason"]
               for c in result["coverage"])


def test_default_intent_and_json_values():
    design = LineExtractor().extract([
        source('VPC main: CidrBlock=default; EnableDnsSupport=false; Ipv4NetmaskLength=0; Tags=[]; InstanceTenancy=""')],
        project="p", environment="dev", account="1", region="ap-northeast-1")
    vpc = design.resources[0]
    assert vpc.field("/properties/CidrBlock").default_intent
    assert vpc.field("/properties/CidrBlock").state == ValueState.UNRESOLVED
    assert vpc.field("/properties/CidrBlock").intent_evidence_ids
    assert vpc.field("/properties/EnableDnsSupport").selected().value is False
    assert vpc.field("/properties/Ipv4NetmaskLength").selected().value == 0
    assert vpc.field("/properties/Tags").selected().value == []
    assert vpc.field("/properties/InstanceTenancy").selected().value == ""


def test_correction_recheck_and_hash_guard():
    text = "VPC main: CidrBlock=10.0.0.0/16\nSubnet app: Vpc=main; CidrBlock=10.1.0.0/24"
    design = LineExtractor().extract([source(text)], project="p", environment="dev",
                                     account="1", region="ap-northeast-1")
    previous = check(design)
    assert any(r["rule_id"] == "CIDR_CONTAINMENT" and r["verdict"] == "FAIL"
               for r in previous["results"])
    subnet = next(r for r in design.resources if r.type == "AWS::EC2::Subnet")
    evidence_id = subnet.field("/properties/CidrBlock").selected().evidence_ids[0]
    updated = correct(design, previous, resource_id=subnet.id, path="/properties/CidrBlock",
                      value="10.0.1.0/24", evidence_id=evidence_id, author="reviewer",
                      reason="source line corrected after review")
    rerun = check(updated)
    assert any(r["rule_id"] == "CIDR_CONTAINMENT" and r["verdict"] == "PASS"
               for r in rerun["results"])
    assert updated.corrections[0].source_run_id == previous["run_id"]
    assert updated.corrections[0].before["state"] == "KNOWN"
    assert design.resources[1].field("/properties/CidrBlock").selected().value == "10.1.0.0/24"
    with pytest.raises(ValueError, match="does not match"):
        correct(updated, previous, resource_id=subnet.id, path="/properties/CidrBlock",
                value="10.0.2.0/24", evidence_id=evidence_id, author="r", reason="fix")


def test_saved_design_reproduces_verdicts():
    text = (ROOT / "examples/network.txt").read_text(encoding="utf-8")
    design = LineExtractor().extract([source(text)], project="p", environment="prod",
                                     account="1", region="ap-northeast-1")
    saved = Design.model_validate_json(design.model_dump_json())
    a, b = check(design), check(saved)
    assert a["input_sha256"] == b["input_sha256"]
    assert a["results"] == b["results"]
    assert a["coverage"] == b["coverage"]


def test_gold_evaluation():
    text = (ROOT / "examples/network.txt").read_text(encoding="utf-8")
    design = LineExtractor().extract([TextSource(id="doc-1", name="network.txt", version="1", text=text)],
                                     project="p", environment="prod", account="1", region="ap-northeast-1")
    gold = json.loads((ROOT / "examples/network-gold.json").read_text(encoding="utf-8"))
    report = evaluate(design, check(design), gold)
    assert report["extraction"]["precision"] == 1.0
    assert report["extraction"]["recall"] == 1.0
    assert report["extraction"]["provenance_accuracy"] == 1.0
    assert report["findings"]["precision"] == 1.0


def test_conflicting_vpc_references_are_not_assumed():
    text = ("VPC first: CidrBlock=10.0.0.0/16\nVPC second: CidrBlock=10.1.0.0/16\n"
            "Subnet app: Vpc=first; CidrBlock=10.0.1.0/24\nSubnet app: Vpc=second")
    design = LineExtractor().extract([source(text)], project="p", environment="dev",
                                     account="1", region="ap-northeast-1")
    result = check(design)
    references = [r for r in result["results"] if r["rule_id"] == "REFERENCE"]
    containment = [r for r in result["results"] if r["rule_id"] == "CIDR_CONTAINMENT"]
    assert len(references) == 1 and references[0]["verdict"] == "NEEDS_REVIEW"
    assert len(containment) == 1 and containment[0]["verdict"] == "NEEDS_REVIEW"


def test_requirement_and_japanese_aliases():
    text = "VPC main： CIDR=10.0.0.0/16; DNSサポート=false\nRequirement req-1： バックアップ方針を確認する"
    design = LineExtractor().extract([source(text)], project="p", environment="dev",
                                     account="1", region="ap-northeast-1")
    assert design.resources[0].field("/properties/EnableDnsSupport").selected().value is False
    assert design.requirements[0].id == "req-1"
    assert design.documents[0].extracted_ranges == [[1, 1], [2, 2]]
    assert any(c["kind"] == "REQUIREMENT" for c in check(design)["coverage"])


def test_correction_cli_roundtrip(tmp_path):
    text = "VPC main: CidrBlock=10.0.0.0/16\nSubnet app: Vpc=main; CidrBlock=10.1.0.0/24"
    design = LineExtractor().extract([source(text)], project="p", environment="dev",
                                     account="1", region="ap-northeast-1")
    source_design = tmp_path / "design.json"
    source_run = tmp_path / "run.json"
    corrected_design = tmp_path / "corrected.json"
    corrected_run = tmp_path / "corrected-run.json"
    source_design.write_text(design.model_dump_json(), encoding="utf-8")
    source_run.write_text(json.dumps(check(design)), encoding="utf-8")
    status = correct_main([str(source_design), str(source_run), "--resource", "res-2",
                           "--path", "/properties/CidrBlock", "--value", '"10.0.1.0/24"',
                           "--author", "reviewer", "--reason", "corrected CIDR",
                           "--intermediate", str(corrected_design), "--result", str(corrected_run)])
    assert status == 0
    updated = Design.model_validate_json(corrected_design.read_text(encoding="utf-8"))
    outcome = json.loads(corrected_run.read_text(encoding="utf-8"))
    assert len(updated.corrections) == 1
    assert updated.documents[-1].name == "review correction"
    assert outcome["status"] == "COMPLETE"
    assert any(r["rule_id"] == "CIDR_CONTAINMENT" and r["verdict"] == "PASS"
               for r in outcome["results"])
