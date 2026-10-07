import pytest
from aws_design_sheet.checks.ses.rule_order import evaluate_ses_rule_order
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link,template


def fixture():
    r=target('new','AWS::SES::ReceiptRule',RuleSetName='set',Rule={'Name':'new'})
    old=target('old','AWS::SES::ReceiptRule',RuleSetName='set',Rule={'Name':'old'})
    template(r,[]);template(old,[])
    d=linked_design(r,[old]);link(d,r,'After',old)
    return d,r,old


def verdict(d,r):return evaluate_ses_rule_order(d,r)[0]['verdict']


def test_rule_order_and_set():
    d,r,*_=fixture();assert verdict(d,r)=='PASS'


@pytest.mark.parametrize('mode,want',[
    ('other_set','FAIL'),('self','FAIL'),('cycle','FAIL'),('conditional','NEEDS_REVIEW'),
    ('missing','NEEDS_REVIEW'),('duplicate','NEEDS_REVIEW'),('unknown_set','NEEDS_REVIEW'),
    ('scope','NEEDS_REVIEW'),('missing_template','NEEDS_REVIEW'),('other_template','NEEDS_REVIEW'),
    ('literal_match','PASS'),('literal_conflict','NEEDS_REVIEW')])
def test_scope_and_order_evidence(mode,want):
    d,r,old=fixture()
    if mode=='other_set':old.fields[0].candidates[0].value='different'
    if mode=='self':d.relations[0].target_resource_id=r.id
    if mode=='cycle':link(d,old,'After',r)
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='missing':d.resources.remove(old)
    if mode=='duplicate':link(d,r,'After',old)
    if mode=='unknown_set':old.fields[0].candidates[0].value=UNKNOWN
    if mode=='scope':old.scope.region='us-east-1'
    if mode=='missing_template':r.template=None
    if mode=='other_template':old.template.id='other'
    if mode.startswith('literal_'):r.fields+=target('dummy',r.type,After='old' if mode=='literal_match' else 'unrelated').fields
    assert verdict(d,r)==want


def test_logical_rule_set():
    d,r,old=fixture();s=target('set','AWS::SES::ReceiptRuleSet');template(s,[]);d.resources.append(s)
    for x in (r,old):x.fields.pop(0);link(d,x,'RuleSetName',s)
    assert verdict(d,r)=='PASS'


def test_no_after():
    d,r,*_=fixture();d.relations=[]
    assert verdict(d,r)=='NOT_APPLICABLE'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="SES_RECEIPT_RULE_AFTER_SCOPE" and f["verdict"]=="PASS" for f in results)
