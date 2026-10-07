import pytest
from aws_design_sheet.checks.elasticache.cluster_mode import evaluate_elasticache_cluster_mode
from aws_design_sheet.models import TemplateContext
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('raw,expected',[('yes','FAIL'),('no','PASS'),('YES','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(True,'NEEDS_REVIEW')])
@pytest.mark.parametrize('context',['local','external','conditional','ambiguous','scope','template'])
def test_parameter(raw,expected,context):
    r=target('main','AWS::ElastiCache::CacheCluster',CacheParameterGroupName='group')
    g=target('group','AWS::ElastiCache::ParameterGroup',Properties={'cluster-enabled':raw})
    d=linked_design(r,[g],[] if context=='external' else [('CacheParameterGroupName','group')]*(2 if context=='ambiguous' else 1))
    if context=='conditional':d.relations[0].condition='maybe'
    if context=='scope':g.scope.account='222222222222'
    if context=='template':g.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_elasticache_cluster_mode(d,r)[0]['verdict']==(expected if context=='local' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['parameter','shards','explicit','unknown','conflict','disabled','compatible','false_parameter'])
@pytest.mark.parametrize('failover',[True,False,UNKNOWN,'absent'])
def test_inferred_constraints(mode,failover):
    props={'CacheParameterGroupName':'group','SnapshottingClusterId':'snapshot-source'}
    if mode in ('shards','false_parameter'):props['NumNodeGroups']=2
    if mode in ('explicit','conflict','disabled','compatible'):props['ClusterMode']={'explicit':'enabled','conflict':'disabled','disabled':'disabled','compatible':'compatible'}[mode]
    if failover!='absent':props['AutomaticFailoverEnabled']=failover
    r=target('main','AWS::ElastiCache::ReplicationGroup',**props)
    g=target('group','AWS::ElastiCache::ParameterGroup',Properties={'cluster-enabled':'yes' if mode in ('parameter','conflict') else 'no' if mode=='false_parameter' else UNKNOWN})
    d=linked_design(r,[g],[('CacheParameterGroupName','group')])
    found={f['rule_id']:f['verdict'] for f in evaluate_elasticache_cluster_mode(d,r)}
    enabled=mode in ('parameter','shards','explicit')
    requires_failover=enabled or mode=='compatible'
    expected='PASS' if requires_failover and failover is True else 'FAIL' if requires_failover and (failover is False or failover=='absent') else 'NOT_APPLICABLE' if mode=='disabled' else 'NEEDS_REVIEW'
    assert found['REPLICATIONGROUP_INFERRED_FAILOVER']==expected
    assert found['REPLICATIONGROUP_INFERRED_SNAPSHOT']==('FAIL' if enabled else 'NOT_APPLICABLE' if mode=='disabled' else 'NEEDS_REVIEW')


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::ElastiCache::ReplicationGroup',NumNodeGroups=2)
    found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='REPLICATIONGROUP_INFERRED_FAILOVER' and f['verdict']=='FAIL' for f in found)
