import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.deadline.limit_names import evaluate_deadline_limit_names
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link

FARM='farm-'+'a'*32
QUEUE='queue-'+'b'*32


def setup():
    a=target('a','AWS::Deadline::QueueLimitAssociation',FarmId=FARM,QueueId=QUEUE)
    b=target('b','AWS::Deadline::QueueLimitAssociation',FarmId=FARM,QueueId=QUEUE)
    l1=target('l1','AWS::Deadline::Limit',FarmId=FARM,AmountRequirementName='amount.worker.license')
    l2=target('l2','AWS::Deadline::Limit',FarmId=FARM,AmountRequirementName='amount.worker.license')
    d=linked_design(a,[b,l1,l2],[('LimitId','l1')]);link(d,b,'LimitId',l2)
    return d,a,b,l1,l2


@pytest.mark.parametrize('case,expected',[
 ('duplicate','FAIL'),('different_name','NEEDS_REVIEW'),('different_queue','NEEDS_REVIEW'),
 ('different_farm','NEEDS_REVIEW'),('limit_farm','NEEDS_REVIEW'),('unknown','NEEDS_REVIEW'),
 ('conditional','NEEDS_REVIEW'),('scope','NEEDS_REVIEW'),('template','NEEDS_REVIEW'),
 ('same_limit','NEEDS_REVIEW'),('external','NEEDS_REVIEW'),('case','NEEDS_REVIEW')])
def test_duplicate_witness(case,expected):
    d,a,b,l1,l2=setup()
    def change(r,key,val):
        next(f for f in r.fields if f.path=='/properties/'+key).candidates[0].value=val
    if case=='different_name':change(l2,'AmountRequirementName','amount.worker.other')
    if case=='case':change(l2,'AmountRequirementName','AMOUNT.WORKER.LICENSE')
    if case=='different_queue':change(b,'QueueId','queue-'+'c'*32)
    if case=='different_farm':change(b,'FarmId','farm-'+'c'*32)
    if case=='limit_farm':change(l2,'FarmId','farm-'+'c'*32)
    if case=='unknown':change(l2,'AmountRequirementName',UNKNOWN)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':b.scope.region='us-east-1'
    if case=='template':l2.template=TemplateContext(state='UNRESOLVED')
    if case=='same_limit':d.relations[-1].target_resource_id=l1.id
    if case=='external':d.relations.pop()
    assert evaluate_deadline_limit_names(d,a)[0]['verdict']==expected


def test_no_external_uniqueness_claim():
    d,a,b,l1,l2=setup();d.resources.remove(b)
    assert evaluate_deadline_limit_names(d,a)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('context,expected',[('linked','FAIL'),('queue_farm','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),('unknown_farm','NEEDS_REVIEW')])
def test_linked_parent_identities(context,expected):
    d,a,b,l1,l2=setup()
    farm=target('farm','AWS::Deadline::Farm')
    queue=target('queue','AWS::Deadline::Queue',FarmId=FARM)
    d.resources.extend([farm,queue])
    for r in (a,b,l1,l2,queue):
        r.fields[:]=[f for f in r.fields if f.path!='/properties/FarmId']
        link(d,r,'FarmId',farm)
    for r in (a,b):
        r.fields[:]=[f for f in r.fields if f.path!='/properties/QueueId']
        link(d,r,'QueueId',queue)
    if context=='queue_farm':
        d.relations[:]=[ref for ref in d.relations if not (ref.source_resource_id=='queue' and ref.source_path=='/properties/FarmId')]
    if context=='conditional':d.relations[-1].condition='maybe'
    if context=='unknown_farm':farm.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_deadline_limit_names(d,a)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1];d,a,*_=setup()
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='DEADLINE_QUEUE_LIMIT_REQUIREMENT_DUPLICATE' and f['verdict']=='FAIL' for f in results)


@pytest.mark.parametrize('key', ['FarmId','QueueId','LimitId'])
def test_raw_identity_with_reference_is_not_assumed_equal(key):
    d,a,b,l1,l2=setup()
    if key=='LimitId':
        a.fields.append(target('temp','AWS::Deadline::QueueLimitAssociation',LimitId='limit-'+'c'*32).fields[0])
    else:
        other=target('other','AWS::Deadline::Farm' if key=='FarmId' else 'AWS::Deadline::Queue')
        d.resources.append(other);link(d,a,key,other)
    assert evaluate_deadline_limit_names(d,a)[0]['verdict']=='NEEDS_REVIEW'
