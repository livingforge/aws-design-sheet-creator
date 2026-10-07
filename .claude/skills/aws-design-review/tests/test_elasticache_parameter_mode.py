import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.elasticache.parameter_mode import evaluate_elasticache_parameter_mode
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('mode',['enabled','disabled','compatible',None,UNKNOWN])
@pytest.mark.parametrize('parameter',['yes','no','future',UNKNOWN])
@pytest.mark.parametrize('context',['linked','conditional','scope','template'])
def test_independent_mode(mode,parameter,context):
    r=target('main','AWS::ElastiCache::ReplicationGroup',CacheParameterGroupName='group',**({} if mode is None else {'ClusterMode':mode}))
    p=target('group','AWS::ElastiCache::ParameterGroup',Properties={'cluster-enabled':parameter})
    d=linked_design(r,[p],[('CacheParameterGroupName','group')])
    if context=='conditional':d.relations[0].condition='maybe'
    if context=='scope':p.scope.region='us-east-1'
    if context=='template':p.template=TemplateContext(state='UNRESOLVED')
    expected='NEEDS_REVIEW'
    if context=='linked' and mode in ('enabled','disabled') and parameter in ('yes','no'):
        expected='PASS' if (mode=='enabled')==(parameter=='yes') else 'FAIL'
    assert evaluate_elasticache_parameter_mode(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('name,expected',[('default.redis3.2','FAIL'),('default.redis3.2.cluster.on','PASS'),('default.redis99.cluster.on','NEEDS_REVIEW')])
def test_independent_shard_count(name,expected):
    r=target('main','AWS::ElastiCache::ReplicationGroup',NumNodeGroups=2,CacheParameterGroupName=name)
    assert evaluate_elasticache_parameter_mode(linked_design(r),r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::ElastiCache::ReplicationGroup',ClusterMode='enabled',CacheParameterGroupName='default.redis3.2')
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='REPLICATIONGROUP_PARAMETER_MODE_MATCH' and f['verdict']=='FAIL' for f in results)
