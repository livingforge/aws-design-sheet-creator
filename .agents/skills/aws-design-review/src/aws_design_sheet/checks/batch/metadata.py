"""Nested Windows declarations and literal EKS annotation keys."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
    'BATCH_NESTED_WINDOWS_FIELDS':[CF+'aws-properties-batch-jobdefinition-runtimeplatform.html'],
    'BATCH_EKS_ANNOTATION_KEYS':[CF+'aws-properties-batch-jobdefinition-eksmetadata.html','https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/','https://raw.githubusercontent.com/kubernetes/apimachinery/master/pkg/util/validation/validation.go'],
}
WINDOWS={'WINDOWS_SERVER_2019_CORE','WINDOWS_SERVER_2019_FULL','WINDOWS_SERVER_2022_CORE','WINDOWS_SERVER_2022_FULL'}


def dns_subdomain(name):
    return len(name)<=253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?',p) for p in name.split('.'))


def annotation_key(key):
    parts=key.split('/')
    if len(parts)>2:return False
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?',parts[-1]):return False
    if len(parts)==2:
        prefix=parts[0]
        if not dns_subdomain(prefix):return False
    return True


@resource_check('AWS::Batch::JobDefinition')
def evaluate_batch_metadata(design,resource):
    if resource.type!='AWS::Batch::JobDefinition':return []
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    for pattern in ('/properties/ContainerProperties',
                    '/properties/NodeProperties/NodeRangeProperties/*/Container',
                    '/properties/EcsProperties/TaskProperties/*'):
        for owner in expand(ctx,resource,pattern):
            os=value(ctx,resource,owner+'/RuntimePlatform/OperatingSystemFamily')
            if os is ABSENT or os=='LINUX':continue
            windows=isinstance(os,str) and os in WINDOWS
            paths=[]
            if owner!='/properties/ContainerProperties':
                cpu=value(ctx,resource,owner+'/RuntimePlatform/CpuArchitecture')
                if cpu is not ABSENT:
                    verdict='NEEDS_REVIEW' if not windows or cpu is UNKNOWN else 'PASS' if cpu=='X86_64' else 'FAIL' if cpu=='ARM64' else 'NEEDS_REVIEW'
                    emit('BATCH_NESTED_WINDOWS_FIELDS',owner+'/RuntimePlatform/CpuArchitecture',verdict,'Windows requires X86_64; platform availability and unknown OS/architecture are separate')
                containers=list(expand(ctx,resource,owner+'/Containers/*')) if pattern.endswith('/TaskProperties/*') else [owner]
                paths.extend(c+'/'+key for c in containers for key in ('LinuxParameters','Privileged','User','Ulimits','ReadonlyRootFilesystem'))
            paths.extend(expand(ctx,resource,owner+'/Volumes/*/EfsVolumeConfiguration'))
            for path in paths:
                raw=value(ctx,resource,path)
                if raw is not ABSENT:emit('BATCH_NESTED_WINDOWS_FIELDS',path,'FAIL' if windows and raw is not UNKNOWN else 'NEEDS_REVIEW','documented field cannot be set for Windows containers; unknown OS or value remains under review')
    for pattern in ('/properties/EksProperties/PodProperties/Metadata/Annotations',
                    '/properties/NodeProperties/NodeRangeProperties/*/EksProperties/PodProperties/Metadata/Annotations'):
        for path in expand(ctx,resource,pattern):
            raw=value(ctx,resource,path);pending=not isinstance(raw,dict);invalid=False
            if isinstance(raw,dict):
                for key in raw:
                    if '${' in key or '{{' in key or key.startswith('Fn::') or key=='$state':pending=True
                    elif not annotation_key(key):invalid=True
            emit('BATCH_EKS_ANNOTATION_KEYS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS',
                 'annotation key requires a 1..63-character alphanumeric-ended name and optional DNS subdomain prefix <=253 characters; values and labels are separate')
    return results
