import hashlib

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.pilot_lambda import evaluate_lambda_vpc_membership


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def field(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def resource(type_name, id, *fields):
    return Resource(id=id, type=type_name, name=id, scope=SCOPE, fields=list(fields))


def design(resources, relations=()):
    text = "Lambda VPC design"
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="d1", name="input", version="1", text=text,
                                      sha256=hashlib.sha256(text.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                     excerpt=text)], resources=resources, relations=list(relations))


def relation(id, source, path, target):
    return Relation(id=id, source_resource_id=source, source_path=path,
                    target_resource_id=target, evidence_ids=["e1"])


def fixture(second_vpc="vpc-a", *, with_config=True):
    config = field("/properties/VpcConfig", {"SubnetIds": ["@AWS::EC2::Subnet/subnet"],
                                             "SecurityGroupIds": ["@AWS::EC2::SecurityGroup/sg"]})
    function = resource("AWS::Lambda::Function", "lambda", *((config,) if with_config else ()))
    subnet = resource("AWS::EC2::Subnet", "subnet")
    sg = resource("AWS::EC2::SecurityGroup", "sg")
    vpc_a = resource("AWS::EC2::VPC", "vpc-a")
    vpc_b = resource("AWS::EC2::VPC", "vpc-b")
    links = [relation("subnet", "lambda", "/properties/VpcConfig/SubnetIds/0", "subnet"),
             relation("sg", "lambda", "/properties/VpcConfig/SecurityGroupIds/0", "sg"),
             relation("subnet-vpc", "subnet", "/properties/VpcId", "vpc-a"),
             relation("sg-vpc", "sg", "/properties/VpcId", second_vpc)]
    return design([function, subnet, sg, vpc_a, vpc_b], links), function


def test_lambda_vpc_membership_passes_same_vpc_with_nested_relations():
    case, function = fixture()
    result = evaluate_lambda_vpc_membership(case, function)
    assert result["verdict"] == "PASS"
    assert result["rule_id"] == "LAMBDA_VPC_MEMBERSHIP"
    assert result["path"] == "/properties/VpcConfig"
    assert result["evidence_ids"] == ["e1"]


def test_lambda_vpc_membership_fails_known_difference():
    case, function = fixture("vpc-b")
    assert evaluate_lambda_vpc_membership(case, function)["verdict"] == "FAIL"


def test_lambda_vpc_membership_unknown_external_and_partial():
    case, function = fixture()
    case.relations = [r for r in case.relations if r.id != "sg-vpc"]
    result = evaluate_lambda_vpc_membership(case, function)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert any("sg/properties/VpcId" in item for item in result["dependencies"])
    case, function = fixture()
    case.relations = [r for r in case.relations if r.id != "sg"]
    assert evaluate_lambda_vpc_membership(case, function)["verdict"] == "NEEDS_REVIEW"
    case, function = fixture()
    case.resources[2].fields.append(field("/properties/VpcId", "vpc-external"))
    case.relations = [r for r in case.relations if r.id != "sg-vpc"]
    assert evaluate_lambda_vpc_membership(case, function)["verdict"] == "NEEDS_REVIEW"


def test_lambda_vpc_membership_relation_only_and_non_applicable():
    case, function = fixture(with_config=False)
    assert evaluate_lambda_vpc_membership(case, function)["verdict"] == "PASS"
    case.relations = []
    assert evaluate_lambda_vpc_membership(case, function)["verdict"] == "NOT_APPLICABLE"
    unrelated = resource("AWS::EC2::Subnet", "other")
    assert evaluate_lambda_vpc_membership(design([unrelated]), unrelated)["verdict"] == "NOT_APPLICABLE"


def test_lambda_vpc_membership_unresolved_config_and_known_mismatch_win():
    case, function = fixture()
    function.fields[0] = FieldValue(path="/properties/VpcConfig", state=ValueState.UNRESOLVED)
    assert evaluate_lambda_vpc_membership(case, function)["verdict"] == "NEEDS_REVIEW"
    case, function = fixture("vpc-b")
    case.relations[1].target_resource_id = "outside"
    assert evaluate_lambda_vpc_membership(case, function)["verdict"] == "NEEDS_REVIEW"
