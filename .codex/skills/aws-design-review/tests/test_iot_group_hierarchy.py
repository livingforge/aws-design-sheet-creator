import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.iot.group_hierarchy import evaluate_iot_group_hierarchy
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture():
    r=target('action','AWS::IoT::MitigationAction',ActionParams={'AddThingsToThingGroupParams':{'ThingGroupNames':['one','two']}})
    a=target('one','AWS::IoT::ThingGroup',ThingGroupName='one');b=target('two','AWS::IoT::ThingGroup',ThingGroupName='two')
    root=target('root','AWS::IoT::ThingGroup',ThingGroupName='root')
    d=linked_design(r,[a,b,root],[('ActionParams/AddThingsToThingGroupParams/ThingGroupNames/0',a.id),('ActionParams/AddThingsToThingGroupParams/ThingGroupNames/1',b.id)])
    return d,r,a,b,root


def parent(d,child,other):
    child.fields.extend(target('extra','x',ParentGroupName=other.id).fields);link(d,child,'ParentGroupName',other)


@pytest.mark.parametrize('mode,expected',[
    ('distinct','PASS'),('siblings','FAIL'),('ancestor','FAIL'),('cousins','FAIL'),('same_identity','PASS'),
    ('common_then_external','FAIL'),('separate_unknown_parent','NEEDS_REVIEW'),('cycle','NEEDS_REVIEW'),
    ('conditional','NEEDS_REVIEW'),('scope','NEEDS_REVIEW'),('template','NEEDS_REVIEW'),
    ('dynamic','NEEDS_REVIEW'),('name_mismatch','NEEDS_REVIEW'),('unknown_names','NEEDS_REVIEW'),('external','NEEDS_REVIEW'),
])
def test_hierarchy(mode,expected):
    d,r,a,b,root=fixture()
    if mode in ('siblings','common_then_external','conditional','scope','template','name_mismatch'):
        parent(d,a,root);parent(d,b,root)
    if mode=='ancestor':parent(d,b,a)
    if mode=='cousins':
        middle=target('middle','AWS::IoT::ThingGroup',ThingGroupName='middle');d.resources.append(middle)
        parent(d,a,root);parent(d,b,middle);parent(d,middle,root)
    if mode=='same_identity':
        d.relations[1].target_resource_id=a.id
        next(f for f in r.fields if f.path=='/properties/ActionParams').candidates[0].value['AddThingsToThingGroupParams']['ThingGroupNames'][1]='one'
    if mode=='common_then_external':root.fields.extend(target('extra','x',ParentGroupName='outside').fields)
    if mode=='separate_unknown_parent':a.fields.extend(target('extra','x',ParentGroupName=UNKNOWN).fields)
    if mode=='cycle':parent(d,a,b);parent(d,b,a)
    if mode=='conditional':d.relations[-1].condition='maybe'
    if mode=='scope':root.scope.region='us-east-1'
    if mode=='template':root.template=TemplateContext(state='UNRESOLVED')
    if mode=='dynamic':a.fields.extend(target('extra','x',QueryString='attributes.x:true').fields)
    if mode=='name_mismatch':next(f for f in root.fields if f.path=='/properties/ThingGroupName').candidates[0].value='different'
    if mode=='unknown_names':next(f for f in r.fields if f.path=='/properties/ActionParams').candidates[0].value=UNKNOWN
    if mode=='external':d.relations.pop()
    assert evaluate_iot_group_hierarchy(d,r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    rootdir=Path(__file__).resolve().parents[1];d,r,a,b,root=fixture();parent(d,a,root);parent(d,b,root)
    assert any(f['rule_id']=='IOT_MITIGATION_GROUP_HIERARCHY' and f['verdict']=='FAIL' for f in Checker(rootdir/'schemas',rootdir/'profiles/vpc-subnet.json').check(d)['results'])
