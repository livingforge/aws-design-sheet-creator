import pytest
from aws_design_sheet.checks.elasticache.cluster_mode import evaluate_elasticache_cluster_mode
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('name,expected',[
 ('default.redis3.2.cluster.on','FAIL'),('default.redis3.2','NOT_APPLICABLE'),
 ('custom.cluster.on','NEEDS_REVIEW'),('default.redis99.cluster.on','NEEDS_REVIEW'),
 (UNKNOWN,'NEEDS_REVIEW')])
def test_only_documented_default_names(name,expected):
    r=target('main','AWS::ElastiCache::ReplicationGroup',CacheParameterGroupName=name)
    assert evaluate_elasticache_cluster_mode(linked_design(r),r)[0]['verdict']==expected


def test_conditional_reference_does_not_fall_back_to_literal_name():
    r=target('main','AWS::ElastiCache::ReplicationGroup',CacheParameterGroupName='default.redis3.2.cluster.on')
    g=target('group','AWS::ElastiCache::ParameterGroup',Properties={'cluster-enabled':'yes'})
    d=linked_design(r,[g],[('CacheParameterGroupName','group')]);d.relations[0].condition='maybe'
    assert evaluate_elasticache_cluster_mode(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_compatible_snapshot_applicability_is_not_assumed():
    r=target('main','AWS::ElastiCache::ReplicationGroup',ClusterMode='compatible',SnapshottingClusterId='source')
    found={f['rule_id']:f['verdict'] for f in evaluate_elasticache_cluster_mode(linked_design(r),r)}
    assert found=={'REPLICATIONGROUP_INFERRED_FAILOVER':'FAIL','REPLICATIONGROUP_INFERRED_SNAPSHOT':'NEEDS_REVIEW'}
