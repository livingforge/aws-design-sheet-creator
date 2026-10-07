import pytest
from aws_design_sheet.checks.dms.event_sources import evaluate_dms_event_sources
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('mode',['replication-instance','replication-task',None,'future',UNKNOWN])
@pytest.mark.parametrize('case',['instances','tasks','mixed','external','conditional','scope','duplicate','absent','empty','unknown'])
def test_event_sources(mode,case):
    props={} if case=='absent' else {'SourceIds':[] if case=='empty' else UNKNOWN if case=='unknown' else ['a','b']}
    if mode is not None:props['SourceType']=mode
    r=target('main','AWS::DMS::EventSubscription',**props)
    a=target('a','AWS::DMS::ReplicationTask' if case=='tasks' else 'AWS::DMS::ReplicationInstance')
    b=target('b','AWS::DMS::ReplicationTask' if case in ('tasks','mixed') else 'AWS::DMS::ReplicationInstance')
    d=linked_design(r,[a,b]);link(d,r,'SourceIds/0',a)
    if case!='external':link(d,r,'SourceIds/1',b)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':b.scope.account='222222222222'
    if case=='duplicate':link(d,r,'SourceIds/1',a)
    expected='NEEDS_REVIEW'
    if case=='absent':expected='NOT_APPLICABLE'
    elif case not in ('empty','unknown'):
        if case=='mixed' or mode=='replication-task' and case!='tasks' or mode=='replication-instance' and case=='tasks':expected='FAIL'
        elif case in ('instances','tasks') and (mode is None or mode in ('replication-instance','replication-task')):expected='PASS'
    assert evaluate_dms_event_sources(d,r)[0]['verdict']==expected
