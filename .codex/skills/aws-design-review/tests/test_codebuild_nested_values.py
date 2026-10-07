import pytest
from aws_design_sheet.checks.codebuild.options import evaluate_codebuild_options
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind,pattern,want', [
    ('EVENT','PUSH','PASS'), ('EVENT','PUSH, PULL_REQUEST_CREATED','PASS'),
    ('EVENT','WORKFLOW_JOB_QUEUED,RELEASED,PRERELEASED','PASS'),
    ('EVENT','PUSH,PULL_REQUEST_REOPENED,PULL_REQUEST_MERGED,PULL_REQUEST_CLOSED,PULL_REQUEST_UPDATED','PASS'),
    ('EVENT','INVALID','FAIL'), ('EVENT','PUSH,','FAIL'),
    ('EVENT','','NEEDS_REVIEW'), ('EVENT',UNKNOWN,'NEEDS_REVIEW'),
    ('HEAD_REF','^refs/heads/','NOT_APPLICABLE'), (UNKNOWN,'PUSH','NEEDS_REVIEW'),
])
def test_webhook_event_patterns(kind,pattern,want):
    r=target('build','AWS::CodeBuild::Project',Triggers={'FilterGroups':[[{'Type':kind,'Pattern':pattern}]]})
    findings=evaluate_codebuild_options(linked_design(r),r)
    assert next(f['verdict'] for f in findings if f['rule_id']=='CODEBUILD_WEBHOOK_EVENT_VALUES')==want


@pytest.mark.parametrize('raw', [UNKNOWN, [UNKNOWN], [[UNKNOWN]], 'invalid'])
def test_unresolved_filter_ancestors(raw):
    r=target('build','AWS::CodeBuild::Project',Triggers={'FilterGroups':raw})
    findings=evaluate_codebuild_options(linked_design(r),r)
    assert findings and all(f['verdict']=='NEEDS_REVIEW' for f in findings)


@pytest.mark.parametrize('kind', ['EVENT','ACTOR_ACCOUNT_ID','HEAD_REF','BASE_REF','FILE_PATH','COMMIT_MESSAGE','TAG_NAME','RELEASE_NAME','REPOSITORY_NAME','ORGANIZATION_NAME','WORKFLOW_NAME'])
def test_webhook_types(kind):
    r=target('build','AWS::CodeBuild::Project',Triggers={'FilterGroups':[[{'Type':kind}]]})
    assert evaluate_codebuild_options(linked_design(r),r)[0]['verdict']=='PASS'


@pytest.mark.parametrize('scope', ['GITHUB_ORGANIZATION','GITHUB_GLOBAL','GITLAB_GROUP','invalid'])
def test_webhook_scope(scope):
    r=target('build','AWS::CodeBuild::Project',Triggers={'ScopeConfiguration':{'Scope':scope}})
    assert evaluate_codebuild_options(linked_design(r),r)[0]['verdict']==('FAIL' if scope=='invalid' else 'PASS')


@pytest.mark.parametrize('approval', ['DISABLED','ALL_PULL_REQUESTS','FORK_PULL_REQUESTS','invalid'])
def test_comment_approval(approval):
    r=target('build','AWS::CodeBuild::Project',Triggers={'PullRequestBuildPolicy':{'RequiresCommentApproval':approval}})
    assert evaluate_codebuild_options(linked_design(r),r)[0]['verdict']==('FAIL' if approval=='invalid' else 'PASS')


@pytest.mark.parametrize('compute,want', [('CUSTOM_INSTANCE_TYPE','PASS'), ('BUILD_GENERAL1_SMALL','PASS'), ('invalid','FAIL'), (UNKNOWN,'NEEDS_REVIEW')])
def test_docker_compute(compute,want):
    r=target('build','AWS::CodeBuild::Project',Environment={'DockerServer':{'ComputeType':compute}})
    assert evaluate_codebuild_options(linked_design(r),r)[0]['verdict']==want


@pytest.mark.parametrize('count,want', [(0,'PASS'),(5,'PASS'),(6,'FAIL')])
def test_docker_security_group_bound(count,want):
    r=target('build','AWS::CodeBuild::Project',Environment={'DockerServer':{'SecurityGroupIds':[UNKNOWN]*count}})
    assert evaluate_codebuild_options(linked_design(r),r)[0]['verdict']==want
