import hashlib
import json

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.pilot_iam_principal import evaluate_iam_identity_policy_no_principal


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
PATH = "/properties/PolicyDocument"


def make_design(value=None, *, state=ValueState.KNOWN, resource_type="AWS::IAM::Policy"):
    if state == ValueState.KNOWN:
        policy_field = FieldValue(path=PATH, state=state,
                                  candidates=[Candidate(id="policy", raw=str(value), value=value,
                                                        evidence_ids=["e1"])],
                                  selected_candidate_id="policy")
    else:
        policy_field = FieldValue(path=PATH, state=state)
    resource = Resource(id="policy", type=resource_type, name="policy", scope=SCOPE,
                        fields=[policy_field])
    source = "IAM policy evidence"
    design = Design(project="pilot", environment="prod", account=SCOPE.account,
                    documents=[Document(id="d1", name="input", version="1", text=source,
                                        sha256=hashlib.sha256(source.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                       excerpt=source)], resources=[resource])
    return design, resource


def evaluate(value=None, **kwargs):
    design, resource = make_design(value, **kwargs)
    return evaluate_iam_identity_policy_no_principal(design, resource)


def test_identity_policy_accepts_object_array_and_json_string():
    statement = {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}
    assert evaluate({"Statement": statement})["verdict"] == "PASS"
    result = evaluate(json.dumps({"Statement": [statement, {"Effect": "Deny"}]}))
    assert result["verdict"] == "PASS"
    assert result["evidence_ids"] == ["e1"]


def test_identity_policy_rejects_principal_and_notprincipal():
    for key in ("Principal", "NotPrincipal"):
        document = {"Statement": [{"Effect": "Allow"}, {"Effect": "Deny", key: "*"}]}
        result = evaluate(document)
        assert result["verdict"] == "FAIL"
        assert result["path"] == PATH + "/Statement/1/" + key


def test_known_violation_takes_precedence_over_other_malformed_statement():
    result = evaluate({"Statement": [None, {"Principal": "*"}]})
    assert result["verdict"] == "FAIL"


def test_identity_policy_unknown_and_unparseable_need_review():
    assert evaluate(state=ValueState.UNRESOLVED)["verdict"] == "NEEDS_REVIEW"
    for document in ("not JSON", [], {"Statement": []}, {"Statement": [42]}):
        result = evaluate(document)
        assert result["verdict"] == "NEEDS_REVIEW"
        assert result["dependencies"]


def test_role_trust_policy_is_outside_rule():
    result = evaluate({"Statement": {"Principal": "*"}}, resource_type="AWS::IAM::Role")
    assert result["verdict"] == "NOT_APPLICABLE"
