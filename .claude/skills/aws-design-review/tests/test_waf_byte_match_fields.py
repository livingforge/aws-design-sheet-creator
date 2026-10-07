import pytest
from aws_design_sheet.checks.waf.byte_match_fields import evaluate_waf_byte_match_fields, FIELDS
from aws_design_sheet.checks.waf.size_constraints import TRANSFORMS
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('service',['WAF','WAFRegional'])
@pytest.mark.parametrize('raw,expected',[('a'*50,'PASS'),('a'*51,'FAIL'),('é'*25,'PASS'),('é'*26,'FAIL'),('あ'*16+'aa','PASS'),('あ'*17,'FAIL'),('', 'PASS'),(UNKNOWN,'NEEDS_REVIEW'),('${value}','NEEDS_REVIEW'),('\ud800','NEEDS_REVIEW')])
def test_utf8_byte_boundary(service,raw,expected):
    r=target('main','AWS::'+service+'::ByteMatchSet',ByteMatchTuples=[{'TargetString':raw}])
    f=next(f for f in evaluate_waf_byte_match_fields(linked_design(r),r) if f['path'].endswith('/TargetString'))
    assert f['verdict']==expected


@pytest.mark.parametrize('service',['WAF','WAFRegional'])
@pytest.mark.parametrize('key,raw,expected',[(key,raw,'PASS') for key,values in [('TextTransformation',TRANSFORMS),('FieldToMatch',FIELDS)] for raw in values]+[(key,raw,expected) for key in ['TextTransformation','FieldToMatch'] for raw,expected in [('future','FAIL'),('', 'FAIL'),(UNKNOWN,'NEEDS_REVIEW')]])
def test_enums(service,key,raw,expected):
    r=target('main','AWS::'+service+'::ByteMatchSet',ByteMatchTuples=[{key:{'Type':raw} if key=='FieldToMatch' else raw}])
    path='/properties/ByteMatchTuples/0/'+key+('/Type' if key=='FieldToMatch' else '')
    f=next(f for f in evaluate_waf_byte_match_fields(linked_design(r),r) if f['path']==path)
    assert f['verdict']==expected


@pytest.mark.parametrize('raw',[UNKNOWN,'malformed'])
def test_collection_ancestor_never_becomes_leaf(raw):
    r=target('main','AWS::WAF::ByteMatchSet',ByteMatchTuples=raw)
    found=evaluate_waf_byte_match_fields(linked_design(r),r)
    assert found and all(f['verdict']=='NEEDS_REVIEW' for f in found)


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::WAF::ByteMatchSet',ByteMatchTuples=[{'TargetString':'é'*26}])
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='WAF_BYTE_FIELD_LIMITS' and f['verdict']=='FAIL' for f in results)
