"""Checks for AWS::CodeBuild::Project."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEBUILD_PROJECT_PUBLIC_BOUNDS': [CF+'aws-resource-codebuild-project.html', CF+'aws-properties-codebuild-project-vpcconfig.html'],
}


@resource_check('AWS::CodeBuild::Project')
def evaluate_codebuild_project_public_bounds(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::CodeBuild::Project':
        rule = 'CODEBUILD_PROJECT_PUBLIC_BOUNDS'
        for field, high in (('TimeoutInMinutes',2160),('QueuedTimeoutInMinutes',480)):
            p = '/properties/'+field
            raw = get(p)
            if raw is not ABSENT:
                emit(rule,p,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if 5<=raw<=high else 'FAIL','explicit documented minute range only; actual build execution and quotas remain separate')
        p = '/properties/Description'
        raw = get(p)
        if raw is not ABSENT:
            known = isinstance(raw,str) and '${' not in raw and '{{' not in raw
            emit(rule,p,'NEEDS_REVIEW' if not known else 'PASS' if len(raw)<=255 else 'FAIL','explicit description maximum 255 characters, including valid empty description')
        for field, maximum in (('SecurityGroupIds',5),('Subnets',16)):
            p = '/properties/VpcConfig/'+field
            raw = get(p)
            if raw is not ABSENT:
                emit(rule,p,'NEEDS_REVIEW' if not isinstance(raw,list) else 'PASS' if len(raw)<=maximum else 'FAIL','explicit VPC array upper bound only; minimum presence, network identity and connectivity remain separate')
    return results
