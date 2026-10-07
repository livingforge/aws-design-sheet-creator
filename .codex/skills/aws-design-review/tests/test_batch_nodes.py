import pytest
from aws_design_sheet.checks.batch.nodes import evaluate_batch_nodes
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def run(ranges):
    r=target('job','AWS::Batch::JobDefinition',NodeProperties={'NumNodes':4,'NodeRangeProperties':ranges})
    return {f['rule_id']:f['verdict'] for f in evaluate_batch_nodes(linked_design(r),r)}


@pytest.mark.parametrize('container,expected',[
    ({'Memory':512,'Vcpus':1},'PASS'),({'Memory':512},'FAIL'),({},'FAIL'),
    ({'Memory':UNKNOWN,'Vcpus':1},'NEEDS_REVIEW'),
    ({'ResourceRequirements':[{'Type':'MEMORY','Value':'512'},{'Type':'VCPU','Value':'1'}]},'PASS'),
    ({'ResourceRequirements':UNKNOWN},'NEEDS_REVIEW'),
    ({'Memory':512,'ResourceRequirements':[{'Type':UNKNOWN,'Value':'1'}]},'NEEDS_REVIEW')])
def test_node_quantity(container,expected):
    assert run([{'TargetNodes':':','Container':container}])['BATCH_NODE_RESOURCE_PRESENCE']==expected


@pytest.mark.parametrize('spans',[['0:3','1:2'],['0:2','2:3'],['0:1'],[UNKNOWN]])
def test_inheritance_and_incomplete_ranges_held(spans):
    rows=run([{'TargetNodes':s,'Container':{'Memory':512,'Vcpus':1,'InstanceType':'m5.large'}} for s in spans])
    assert set(rows.values())=={'NEEDS_REVIEW'}


@pytest.mark.parametrize('types,expected',[(['m5.large','m5.large'],'PASS'),
    (['m5.large','c5.large'],'FAIL'),(['m5.large',UNKNOWN],'NEEDS_REVIEW')])
@pytest.mark.parametrize('legacy',[False,True])
def test_instance_types(types,expected,legacy):
    ranges=[]
    for span,kind in zip(['0:1','2:3'],types):
        r={'TargetNodes':span,'Container':{'Memory':512,'Vcpus':1}}
        if legacy:r['Container']['InstanceType']=kind
        else:r['InstanceTypes']=[kind]
        ranges.append(r)
    assert run(ranges)['BATCH_NODE_INSTANCE_UNIFORM']==expected
