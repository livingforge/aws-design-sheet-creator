import hashlib

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.pilot_iam_access_key import evaluate_iam_access_key_user_reference as evaluate


def case(*, user_type="AWS::IAM::User", account="111111111111", region="ap-northeast-1",
         target_id="user", name="alice", relation=True, literal=False):
    scope = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
    fields = ([FieldValue(path="/properties/UserName", state=ValueState.KNOWN,
                          candidates=[Candidate(id="c1", raw="external-user", value="external-user",
                                                evidence_ids=["e1"])], selected_candidate_id="c1")]
              if literal else [])
    key = Resource(id="key", type="AWS::IAM::AccessKey", name="key", scope=scope, fields=fields)
    user = Resource(id=target_id, type=user_type, name=name,
                    scope=Scope(environment="prod", account=account, region=region))
    text = "access key"
    design = Design(project="pilot", environment="prod", account=scope.account,
                    documents=[Document(id="d1", name="input", version="1", text=text,
                                        sha256=hashlib.sha256(text.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                       excerpt=text)], resources=[key, user],
                    relations=([Relation(id="rel", source_resource_id="key",
                                         source_path="/properties/UserName", target_resource_id=target_id,
                                         expected_target_type="AWS::IAM::User", evidence_ids=["e1"])]
                               if relation else []))
    return design, key


def test_same_account_user_reference_passes_even_when_region_differs():
    design, key = case(region="us-east-1")
    result = evaluate(design, key)
    assert result["verdict"] == "PASS"
    assert result["rule_id"] == "IAM_ACCESS_KEY_USER_REFERENCE"
    assert result["evidence_ids"] == ["e1"]


def test_wrong_type_or_account_fails():
    design, key = case(user_type="AWS::IAM::Group")
    assert evaluate(design, key)["verdict"] == "FAIL"
    design, key = case(account="222222222222")
    assert evaluate(design, key)["verdict"] == "FAIL"


def test_external_literal_and_ambiguous_name_need_review():
    design, key = case(relation=False, literal=True)
    assert evaluate(design, key)["verdict"] == "NEEDS_REVIEW"
    design, key = case()
    design.relations[0].target_resource_id = None
    design.relations[0].unresolved_name = "alice"
    design.resources.append(Resource(id="user2", type="AWS::IAM::User", name="alice",
                                     scope=design.resources[1].scope))
    assert evaluate(design, key)["verdict"] == "NEEDS_REVIEW"


def test_literal_and_logical_reference_together_need_review():
    design, key = case(literal=True)
    assert evaluate(design, key)["verdict"] == "NEEDS_REVIEW"


def test_unrelated_resource_is_not_applicable():
    design, _ = case()
    assert evaluate(design, design.resources[1])["verdict"] == "NOT_APPLICABLE"
