"""Explicit CodeBuild project names and documented primary/secondary enums."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEBUILD_PROJECT_NAME_FORMAT': [CF+'aws-resource-codebuild-project.html'],
    'CODEBUILD_PROJECT_ENUMS': [CF+'aws-resource-codebuild-project.html'] + [
        CF+'aws-properties-codebuild-project-'+name+'.html'
        for name in ('source','artifacts','environment','projectcache')
    ] + ['https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectEnvironment.html'],
}
SOURCE_TYPES = ('CODECOMMIT','CODEPIPELINE','GITHUB','GITLAB','GITLAB_SELF_MANAGED','S3','BITBUCKET','GITHUB_ENTERPRISE','NO_SOURCE')
ARTIFACT_TYPES = ('CODEPIPELINE','S3','NO_ARTIFACTS')
ENUMS = {
    'Source/Type': SOURCE_TYPES,
    'SecondarySources/*/Type': SOURCE_TYPES,
    'Artifacts/Type': ARTIFACT_TYPES,
    'SecondaryArtifacts/*/Type': ARTIFACT_TYPES,
    'Environment/Type': ('WINDOWS_CONTAINER','LINUX_CONTAINER','LINUX_GPU_CONTAINER','ARM_CONTAINER','WINDOWS_SERVER_2019_CONTAINER','WINDOWS_SERVER_2022_CONTAINER','LINUX_LAMBDA_CONTAINER','ARM_LAMBDA_CONTAINER','LINUX_EC2','ARM_EC2','WINDOWS_EC2','MAC_ARM'),
    'Environment/ComputeType': ('BUILD_GENERAL1_SMALL','BUILD_GENERAL1_MEDIUM','BUILD_GENERAL1_LARGE','BUILD_GENERAL1_XLARGE','BUILD_GENERAL1_2XLARGE','BUILD_LAMBDA_1GB','BUILD_LAMBDA_2GB','BUILD_LAMBDA_4GB','BUILD_LAMBDA_8GB','BUILD_LAMBDA_10GB','ATTRIBUTE_BASED_COMPUTE','CUSTOM_INSTANCE_TYPE'),
    'Cache/Type': ('NO_CACHE','S3','LOCAL'),
}


@resource_check('AWS::CodeBuild::Project')
def evaluate_codebuild_project_values(design, resource):
    if resource.type != 'AWS::CodeBuild::Project':
        return []
    ctx = _Context(design, resource)
    results = []
    seen = set()

    def emit(rule, path, verdict, reason):
        if (rule, path) in seen:
            return
        seen.add((rule, path))
        finding = ctx.finding(rule, path, verdict, reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)

    path = '/properties/Name'
    raw = value(ctx, resource, path)
    if raw is not ABSENT:
        verdict = 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{1,149}', raw) else 'FAIL'
        emit('CODEBUILD_PROJECT_NAME_FORMAT', path, verdict, 'Explicit nonempty project name pattern and length only; empty reset inputs, unresolved names and account-wide uniqueness remain reviewable.')
    for suffix, allowed in ENUMS.items():
        pattern = '/properties/'+suffix
        for path in expand(ctx, resource, pattern):
            raw = value(ctx, resource, path)
            exact = re.fullmatch(re.escape(pattern).replace(r'\*', r'\d+'), path)
            verdict = 'NEEDS_REVIEW'
            if exact and literal(raw):
                verdict = 'PASS' if raw in allowed else 'FAIL'
                if suffix == 'Environment/Type' and value(ctx, resource, '/properties/Environment/Fleet') is not ABSENT:
                    verdict = 'NEEDS_REVIEW'
            emit('CODEBUILD_PROJECT_ENUMS', path, verdict, 'Documented enum membership only. Fleet may override environment type during creation; operation context, empty reset inputs, dynamic/malformed ancestors, enum combinations and service availability remain separate.')
    return results
