"""Nested Batch enums, volume names and bounded metadata values."""
import re
from ..registry import resource_check
from .capacity import CONTAINERS
from .metadata import WINDOWS, dns_subdomain
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
K8S='https://kubernetes.io/docs/concepts/overview/working-with-objects/'
SOURCES={
    'BATCH_NESTED_ENUM':[CF+'aws-properties-batch-jobdefinition-resourcerequirement.html',CF+'aws-properties-batch-jobdefinition-logconfiguration.html',CF+'aws-properties-batch-jobdefinition-ulimit.html',CF+'aws-properties-batch-jobdefinition-runtimeplatform.html'],
    'BATCH_NESTED_FARGATE_LOG':[CF+'aws-properties-batch-jobdefinition-logconfiguration.html'],
    'BATCH_VOLUME_NAME':[CF+'aws-properties-batch-jobdefinition-volume.html'],
    'BATCH_EKS_DNS_NAMES':[CF+'aws-properties-batch-jobdefinition-eksvolume.html',CF+'aws-properties-batch-jobdefinition-ekssecret.html',K8S+'names/','https://raw.githubusercontent.com/kubernetes/api/master/core/v1/types.go'],
    'BATCH_EKS_ANNOTATION_VALUES':[CF+'aws-properties-batch-jobdefinition-eksmetadata.html'],
    'BATCH_EKS_LABELS':[CF+'aws-properties-batch-jobdefinition-eksmetadata.html',K8S+'labels/'],
}
LOG_DRIVERS=set('awsfirelens awslogs fluentd gelf json-file journald syslog splunk'.split())
ULIMITS=set('core cpu data fsize locks memlock msgqueue nice nofile nproc rss rtprio rttime sigpending stack'.split())


@resource_check('AWS::Batch::JobDefinition')
def evaluate_batch_names(design,resource):
    if resource.type!='AWS::Batch::JobDefinition':return []
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    def enum(path,choices,ambiguous=()):
        raw=value(ctx,resource,path)
        verdict='NEEDS_REVIEW' if not literal(raw) or raw in ambiguous else 'PASS' if raw in choices else 'FAIL'
        emit('BATCH_NESTED_ENUM',path,verdict,'checks documented nested enum membership; logentries is held because prose and Allowed values disagree, runtime/platform support is separate')
    platform=value(ctx,resource,'/properties/PlatformCapabilities')
    for pattern in CONTAINERS[1:]:
        for base in expand(ctx,resource,pattern):
            for suffix,choices in [('ResourceRequirements/*/Type',{'MEMORY','VCPU','GPU'}),
                                   ('Ulimits/*/Name',ULIMITS),('LogConfiguration/LogDriver',LOG_DRIVERS)]:
                for path in expand(ctx,resource,base+'/'+suffix):enum(path,choices,('logentries',) if suffix=='LogConfiguration/LogDriver' else ())
            driver=value(ctx,resource,base+'/LogConfiguration/LogDriver')
            if driver is not ABSENT and platform not in (['EC2'],['MANAGED_INSTANCES']):
                verdict='NEEDS_REVIEW' if platform!=['FARGATE'] or not literal(driver) else 'PASS' if driver in ('awslogs','splunk') else 'FAIL'
                emit('BATCH_NESTED_FARGATE_LOG',base+'/LogConfiguration/LogDriver',verdict,'nested Fargate containers support awslogs or splunk; unknown platforms and log setup remain under review')
    for pattern in ('/properties/NodeProperties/NodeRangeProperties/*/Container','/properties/EcsProperties/TaskProperties/*'):
        for base in expand(ctx,resource,pattern):
            for key,choices in [('CpuArchitecture',{'X86_64','ARM64'}),('OperatingSystemFamily',WINDOWS|{'LINUX'})]:
                path=base+'/RuntimePlatform/'+key
                if value(ctx,resource,path) is not ABSENT:enum(path,choices)
    owners=CONTAINERS[:2]+('/properties/EcsProperties/TaskProperties/*','/properties/NodeProperties/NodeRangeProperties/*/EcsProperties/TaskProperties/*')
    for base in owners:
        for path in expand(ctx,resource,base+'/Volumes/*/Name'):
            raw=value(ctx,resource,path);verdict='NEEDS_REVIEW'
            if literal(raw) and raw.isascii():verdict='PASS' if re.fullmatch(r'[A-Za-z0-9_-]{1,255}',raw) else 'FAIL'
            emit('BATCH_VOLUME_NAME',path,verdict,'literal ASCII volume name permits letters, digits, hyphen and underscore up to 255 characters; empty/Unicode/unresolved values remain under review')
    for pattern in ('/properties/EksProperties/PodProperties','/properties/NodeProperties/NodeRangeProperties/*/EksProperties/PodProperties'):
        for pod in expand(ctx,resource,pattern):
            for suffix in ('Volumes/*/Name','Volumes/*/Secret/SecretName'):
                for path in expand(ctx,resource,pod+'/'+suffix):
                    raw=value(ctx,resource,path);verdict='NEEDS_REVIEW'
                    if isinstance(raw,str) and '${' not in raw and '{{' not in raw:
                        if not dns_subdomain(raw):verdict='FAIL'
                        elif suffix.endswith('/Name') and ('.' in raw or len(raw)>63):verdict='NEEDS_REVIEW'
                        else:verdict='PASS'
                    emit('BATCH_EKS_DNS_NAMES',path,verdict,'checks documented DNS subdomain spelling; EKS volume names with dots/length>63 are held due to Kubernetes DNS_LABEL versus CloudFormation DNS-subdomain mismatch; existence remains external')
            for key,rule in [('Annotations','BATCH_EKS_ANNOTATION_VALUES'),('Labels','BATCH_EKS_LABELS')]:
                path=pod+'/Metadata/'+key;raw=value(ctx,resource,path)
                if raw is ABSENT:continue
                pending=not isinstance(raw,dict);invalid=False
                for name in raw if isinstance(raw,dict) else ():
                    if '/' in name or '~' in name or '${' in name or '{{' in name:
                        pending=True;continue
                    item=value(ctx,resource,path+'/'+name)
                    if not isinstance(item,str) or not item.isascii() or '${' in item or '{{' in item:pending=True;continue
                    if key=='Annotations':
                        if len(item)>255:invalid=True
                    else:
                        if '.' in name or '.' in item or not name.isascii():pending=True;continue
                        if len(name)>63 or len(item)>63 or re.search(r'[^A-Za-z0-9_-]',name+item):invalid=True
                        elif not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?',name) or item and not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?',item):pending=True
                emit(rule,path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS',
                     'checks plain-key ASCII annotation values <=255 or common unprefixed label spelling <=63; escaped/prefixed map keys, Unicode, dotted labels and boundary ambiguities remain under review')
    return results
