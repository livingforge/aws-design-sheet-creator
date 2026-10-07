"""Checks for AWS::CodeDeploy::DeploymentGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEDEPLOY_ECS_PLATFORM': [CF+'aws-resource-codedeploy-deploymentgroup.html'],
    'CODEDEPLOY_BLUE_GREEN_PLATFORM': [CF+'aws-resource-codedeploy-deploymentgroup.html'],
    'CODEDEPLOY_REVISION_PLATFORM': [CF+'aws-properties-codedeploy-deploymentgroup-revisionlocation.html'],
    'CODEDEPLOY_TARGET_GROUP_NAME': [CF+'aws-properties-codedeploy-deploymentgroup-targetgroupinfo.html'],
}


@resource_check('AWS::CodeDeploy::DeploymentGroup')
def evaluate_codedeploy_deployment_group(design, resource):
    ctx = _Context(design, resource)
    results = []

    def get(path):
        return value(ctx, resource, path)

    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)

    def enum(rule, path, allowed):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL', 'checks documented literal values; external availability and applicability remain separate')

    if resource.type == 'AWS::CodeDeploy::DeploymentGroup':
        app = linked(ctx, resource, '/properties/ApplicationName', 'AWS::CodeDeploy::Application')
        platform = value(ctx, app, '/properties/ComputePlatform') if app else UNKNOWN

        def platform_check(rule, path, expected):
            verdict = 'NEEDS_REVIEW'
            if platform in ('Server', 'Lambda', 'ECS'):
                verdict = 'PASS' if platform == expected else 'FAIL'
            emit(rule, path, verdict, 'checks explicit compute platform of a unique same-scope linked application; omitted platform, unresolved and external references held')

        p = '/properties/ECSServices'
        services = get(p)
        if services is not ABSENT:
            if isinstance(services, list) and services:
                platform_check('CODEDEPLOY_ECS_PLATFORM', p, 'ECS')
            else:
                emit('CODEDEPLOY_ECS_PLATFORM', p, 'NEEDS_REVIEW', 'empty or unresolved service collection does not establish an applicable target')
        p = '/properties/DeploymentStyle/DeploymentType'
        if get(p) == 'BLUE_GREEN':
            platform_check('CODEDEPLOY_BLUE_GREEN_PLATFORM', p, 'Lambda')
        p = '/properties/Deployment/Revision/RevisionType'
        revision = get(p)
        if revision in ('GitHub', 'String'):
            platform_check('CODEDEPLOY_REVISION_PLATFORM', p, 'Server' if revision == 'GitHub' else 'Lambda')
        elif revision is not ABSENT and not literal(revision):
            emit('CODEDEPLOY_REVISION_PLATFORM', p, 'NEEDS_REVIEW', 'revision kind unresolved; revision payload requirements remain separate')
        for pattern in ('/properties/LoadBalancerInfo/TargetGroupInfoList/*/Name', '/properties/LoadBalancerInfo/TargetGroupPairInfoList/*/TargetGroups/*/Name'):
            for p in expand(ctx, resource, pattern):
                raw = get(p)
                if raw is ABSENT:
                    continue
                verdict = 'NEEDS_REVIEW' if not literal(raw) else 'FAIL' if raw.startswith(('arn:', 'targetgroup/')) else 'PASS'
                emit('CODEDEPLOY_TARGET_GROUP_NAME', p, verdict, 'rejects literal ARN and TargetGroupFullName representations; name syntax, existence and unresolved GetAtt attributes remain separate')
    return results
