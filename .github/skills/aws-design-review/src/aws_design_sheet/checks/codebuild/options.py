"""CodeBuild subsidiary enums with documented applicability guards."""
import re
from ..registry import resource_check
from .project_values import CF, ENUMS as PROJECT_ENUMS
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

SOURCES = {'CODEBUILD_PROJECT_OPTION_ENUMS': [CF+'aws-resource-codebuild-project.html'] + [
    CF+'aws-properties-codebuild-project-'+name+'.html' for name in (
        'sourceauth','environment','environmentvariable','registrycredential',
        'cloudwatchlogsconfig','s3logsconfig','projectfilesystemlocation',
        'artifacts','projectcache','projectbuildbatchconfig','projecttriggers',
        'dockerserver','scopeconfiguration','pullrequestbuildpolicy')
]}
SOURCES['CODEBUILD_PROJECT_COLLECTION_BOUNDS'] = [CF+'aws-resource-codebuild-project.html',CF+'aws-properties-codebuild-project-dockerserver.html']
SOURCES['CODEBUILD_WEBHOOK_EVENT_VALUES'] = ['https://docs.aws.amazon.com/codebuild/latest/APIReference/API_WebhookFilter.html',CF+'aws-properties-codebuild-project-projecttriggers.html']
SOURCES['CODEBUILD_PROJECT_OPTION_ENUMS'].append('https://docs.aws.amazon.com/codebuild/latest/APIReference/API_WebhookFilter.html')
EVENTS = ('PUSH','PULL_REQUEST_CREATED','PULL_REQUEST_UPDATED','PULL_REQUEST_CLOSED','PULL_REQUEST_REOPENED','PULL_REQUEST_MERGED','RELEASED','PRERELEASED','WORKFLOW_JOB_QUEUED')
ENUMS = {
    'Environment/DockerServer/ComputeType': PROJECT_ENUMS['Environment/ComputeType'],
    'Triggers/ScopeConfiguration/Scope': ('GITHUB_ORGANIZATION','GITHUB_GLOBAL','GITLAB_GROUP'),
    'Triggers/PullRequestBuildPolicy/RequiresCommentApproval': ('DISABLED','ALL_PULL_REQUESTS','FORK_PULL_REQUESTS'),
    'Triggers/FilterGroups/*/*/Type': ('EVENT','ACTOR_ACCOUNT_ID','HEAD_REF','BASE_REF','FILE_PATH','COMMIT_MESSAGE','TAG_NAME','RELEASE_NAME','REPOSITORY_NAME','ORGANIZATION_NAME','WORKFLOW_NAME'),
    'Visibility': ('PRIVATE','PUBLIC_READ'),
    'Source/Auth/Type': ('OAUTH','CODECONNECTIONS','SECRETS_MANAGER'),
    'SecondarySources/*/Auth/Type': ('OAUTH','CODECONNECTIONS','SECRETS_MANAGER'),
    'Environment/ImagePullCredentialsType': ('CODEBUILD','SERVICE_ROLE'),
    'Environment/EnvironmentVariables/*/Type': ('PLAINTEXT','PARAMETER_STORE','SECRETS_MANAGER'),
    'Environment/RegistryCredential/CredentialProvider': ('SECRETS_MANAGER',),
    'LogsConfig/CloudWatchLogs/Status': ('ENABLED','DISABLED'),
    'LogsConfig/S3Logs/Status': ('ENABLED','DISABLED'),
    'FileSystemLocations/*/Type': ('EFS',),
    'Triggers/BuildType': ('BUILD','BUILD_BATCH'),
    'Environment/HostKernel': ('LINUX_KERNEL_4','LINUX_KERNEL_6','LINUX_KERNEL_LATEST'),
    'Cache/Modes/*': ('LOCAL_SOURCE_CACHE','LOCAL_DOCKER_LAYER_CACHE','LOCAL_CUSTOM_CACHE'),
    'BuildBatchConfig/BatchReportMode': ('REPORT_INDIVIDUAL_BUILDS','REPORT_AGGREGATED_BATCH'),
}
for root in ('Artifacts','SecondaryArtifacts/*'):
    ENUMS[root+'/NamespaceType'] = ('NONE','BUILD_ID')
    ENUMS[root+'/Packaging'] = ('NONE','ZIP')


def applicability(ctx, resource, suffix, path):
    def get(p):
        return value(ctx, resource, '/properties/'+p)
    if suffix.endswith(('/NamespaceType','/Packaging')):
        kind = value(ctx, resource, path.rsplit('/',1)[0]+'/Type')
        return True if kind == 'S3' else False if kind in ('CODEPIPELINE','NO_ARTIFACTS') else None
    if suffix == 'Cache/Modes/*':
        kind = get('Cache/Type')
        return True if kind == 'LOCAL' else False if kind in ('S3','NO_CACHE') else None
    if suffix == 'Environment/HostKernel':
        if get('Environment/Fleet') is not ABSENT:
            return None
        kind = get('Environment/Type')
        if kind in ('LINUX_CONTAINER','ARM_CONTAINER','LINUX_EC2','ARM_EC2'):
            return True
        if kind in ('WINDOWS_CONTAINER','WINDOWS_SERVER_2019_CONTAINER','WINDOWS_SERVER_2022_CONTAINER','WINDOWS_EC2','LINUX_LAMBDA_CONTAINER','ARM_LAMBDA_CONTAINER','MAC_ARM'):
            return False
        return None
    if suffix == 'BuildBatchConfig/BatchReportMode':
        kind, report = get('Source/Type'), get('Source/ReportBuildStatus')
        if report is False:
            return False
        if kind in ('GITHUB','GITHUB_ENTERPRISE','BITBUCKET') and report is True:
            return True
        return None
    return True


@resource_check('AWS::CodeBuild::Project')
def evaluate_codebuild_options(design, resource):
    if resource.type != 'AWS::CodeBuild::Project':
        return []
    ctx = _Context(design, resource)
    results, seen = [], set()
    for field, maximum in (('SecondarySources',12),('SecondarySourceVersions',12),('SecondaryArtifacts',12),('Tags',50),('Environment/DockerServer/SecurityGroupIds',5)):
        path = '/properties/'+field
        raw = value(ctx, resource, path)
        if raw is ABSENT:
            continue
        verdict = 'NEEDS_REVIEW' if not isinstance(raw,list) else 'PASS' if len(raw)<=maximum else 'FAIL'
        f = ctx.finding('CODEBUILD_PROJECT_COLLECTION_BOUNDS',path,verdict,'Explicit documented project collection bounds only; element validity, reset operations and combinations are separate.')
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    for suffix, allowed in ENUMS.items():
        pattern = '/properties/'+suffix
        for path in expand(ctx, resource, pattern):
            if path in seen:
                continue
            seen.add(path)
            raw = value(ctx, resource, path)
            exact = re.fullmatch(re.escape(pattern).replace(r'\*',r'\d+'),path)
            active = applicability(ctx, resource, suffix, path) if exact else None
            verdict = 'NOT_APPLICABLE' if active is False else 'NEEDS_REVIEW'
            if active is True and literal(raw):
                verdict = 'PASS' if raw in allowed else 'FAIL'
            f = ctx.finding('CODEBUILD_PROJECT_OPTION_ENUMS',path,verdict,'Explicit documented subsidiary enum membership with applicability guards. Empty reset inputs, unknown ancestors or activation context remain reviewable. PASS does not certify credential permissions, enum combinations, build execution or webhook availability.')
            f['source_checked_at'] = '2026-10-04'
            results.append(f)
    pattern = '/properties/Triggers/FilterGroups/*/*/Pattern'
    for path in expand(ctx, resource, pattern):
        raw = value(ctx, resource, path)
        exact = re.fullmatch(re.escape(pattern).replace(r'\*',r'\d+'),path)
        kind = value(ctx, resource, path.rsplit('/',1)[0]+'/Type') if exact else None
        verdict = 'NEEDS_REVIEW'
        if exact and kind == 'EVENT' and literal(raw):
            tokens = [part.strip() for part in raw.split(',')]
            verdict = 'PASS' if all(token in EVENTS for token in tokens) else 'FAIL'
        elif exact and kind in ENUMS['Triggers/FilterGroups/*/*/Type'] and kind != 'EVENT':
            verdict = 'NOT_APPLICABLE'
        f = ctx.finding('CODEBUILD_WEBHOOK_EVENT_VALUES',path,verdict,'EVENT filters use the documented comma-separated event names. Other filter regex syntax, source/event compatibility, required EVENT grouping and webhook availability are separate. Empty resets and unknown types remain reviewable.')
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    return results
