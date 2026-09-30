import hashlib

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.pilot_lambda_package import evaluate_lambda_package_configuration as evaluate


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def field(name, value):
    path = "/properties/" + name
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=name, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=name)


def case(*fields):
    function = Resource(id="function", type="AWS::Lambda::Function", name="function",
                        scope=SCOPE, fields=list(fields))
    text = "Lambda package"
    design = Design(project="pilot", environment="prod", account=SCOPE.account,
                    documents=[Document(id="d1", name="input", version="1", text=text,
                                        sha256=hashlib.sha256(text.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                       excerpt=text)], resources=[function])
    return design, function


def verdict(*fields):
    design, function = case(*fields)
    return evaluate(design, function)["verdict"]


def test_zip_and_image_packages_pass():
    assert verdict(field("PackageType", "Zip"), field("Runtime", "python3.12"),
                   field("Handler", "index.handler"), field("Code", {"ZipFile": "print(1)"})) == "PASS"
    assert verdict(field("PackageType", "Image"),
                   field("Code", {"ImageUri": "123.dkr.ecr/image:tag"})) == "PASS"


def test_known_package_violations_fail():
    assert verdict(field("PackageType", "Image"), field("Runtime", "python3.12"),
                   field("Code", {"ImageUri": "123.dkr.ecr/image:tag"})) == "FAIL"
    assert verdict(field("PackageType", "Image"), field("Code", {"ZipFile": "code"})) == "FAIL"
    assert verdict(field("PackageType", "Zip"), field("Runtime", "python3.12"),
                   field("Code", {"ZipFile": "code"})) == "FAIL"
    assert verdict(field("PackageType", "Zip"), field("Runtime", "python3.12"),
                   field("Handler", "index.handler"), field("Code", {"ImageUri": "image"})) == "FAIL"


def test_missing_or_unresolved_package_information_needs_review():
    assert verdict(field("Runtime", "python3.12")) == "NEEDS_REVIEW"
    design, function = case(field("PackageType", "Zip"), field("Handler", "index.handler"),
                            field("Code", {"ZipFile": "code"}))
    function.fields.append(FieldValue(path="/properties/Runtime", state=ValueState.UNRESOLVED))
    result = evaluate(design, function)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/Runtime"]


def test_unrelated_type_not_applicable():
    design, function = case()
    function.type = "AWS::S3::Bucket"
    assert evaluate(design, function)["verdict"] == "NOT_APPLICABLE"
