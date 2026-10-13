"""Explicit Batch volume/platform constraints and FireLens options."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
    'BATCH_EFS_FARGATE_VERSION':[CF+'aws-properties-batch-jobdefinition-volume.html',CF+'aws-properties-batch-jobdefinition-fargateplatformconfiguration.html',CF+'aws-properties-batch-jobdefinition-ecstaskproperties.html'],
    'BATCH_FARGATE_HOST_VOLUME':[CF+'aws-properties-batch-jobdefinition-volume.html'],
    'BATCH_FIRELENS_OPTIONS':[CF+'aws-properties-batch-jobdefinition-firelensconfiguration.html','https://docs.aws.amazon.com/AmazonECS/latest/developerguide/firelens-taskdef.html'],
}


@resource_check('AWS::Batch::JobDefinition')
def evaluate_batch_storage(design,resource):
    if resource.type!='AWS::Batch::JobDefinition':return []
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    platform=value(ctx,resource,'/properties/PlatformCapabilities')
    fargate=platform==['FARGATE']; pending_platform=platform not in (['FARGATE'],['EC2'],['MANAGED_INSTANCES'])
    owners=[('/properties/ContainerProperties','FargatePlatformConfiguration/PlatformVersion'),
            ('/properties/EcsProperties/TaskProperties/*','PlatformVersion'),
            ('/properties/NodeProperties/NodeRangeProperties/*/Container',None),
            ('/properties/NodeProperties/NodeRangeProperties/*/EcsProperties/TaskProperties/*',None)]
    if fargate or pending_platform:
        for pattern,version_key in owners:
            for base in expand(ctx,resource,pattern):
                for path in expand(ctx,resource,base+'/Volumes/*/Host'):
                    raw=value(ctx,resource,path)
                    emit('BATCH_FARGATE_HOST_VOLUME',path,'FAIL' if fargate and isinstance(raw,dict) else 'NEEDS_REVIEW','Host cannot be provided for Fargate, including an empty object; unresolved platform/value is held')
                for path in expand(ctx,resource,base+'/Volumes/*/EfsVolumeConfiguration'):
                    raw=value(ctx,resource,path); version=value(ctx,resource,base+'/'+version_key) if version_key else UNKNOWN
                    verdict='NEEDS_REVIEW'
                    if fargate and isinstance(raw,dict) and isinstance(version,str) and re.fullmatch(r'(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})',version):
                        verdict='PASS' if tuple(map(int,version.split('.')))>=(1,4,0) else 'FAIL'
                    emit('BATCH_EFS_FARGATE_VERSION',path,verdict,'EFS needs explicit Fargate version >=1.4.0; omitted/LATEST, node inheritance and available versions remain under review')
    for pattern in ('/properties/EcsProperties/TaskProperties/*/Containers/*/FirelensConfiguration',
                    '/properties/NodeProperties/NodeRangeProperties/*/EcsProperties/TaskProperties/*/Containers/*/FirelensConfiguration'):
        for path in expand(ctx,resource,pattern):
            raw=value(ctx,resource,path); router=value(ctx,resource,path+'/Type')
            pending=not isinstance(raw,dict) or not literal(router); invalid=literal(router) and router not in ('fluentd','fluentbit')
            options=value(ctx,resource,path+'/Options')
            if options is not ABSENT:
                if not isinstance(options,dict):pending=True
                else:
                    for key in options:
                        if key not in ('enable-ecs-log-metadata','config-file-type','config-file-value'):pending=True
                    for key,choices in [('enable-ecs-log-metadata',('true','false')),('config-file-type',('s3','file'))]:
                        item=value(ctx,resource,path+'/Options/'+key)
                        if item is ABSENT:continue
                        if not literal(item):pending=True
                        elif item not in choices:invalid=True
                    config=value(ctx,resource,path+'/Options/config-file-type'); source=value(ctx,resource,path+'/Options/config-file-value')
                    if config is not ABSENT or source is not ABSENT:
                        if config is ABSENT or source is ABSENT:invalid=True
                        elif not literal(config) or not literal(source):pending=True
                        else:
                            # Existence, permissions, ARN/path normalization are external checks.
                            pending=True
                            if config=='s3' and fargate:invalid=True
                            if config=='file' and source in ('/fluent-bit/etc/fluent-bit.conf','/fluentd/etc/fluent.conf'):invalid=True
            emit('BATCH_FIRELENS_OPTIONS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','checks router/options enums, custom-file pair, reserved paths and explicit Fargate s3 restriction; file existence, permissions and unknown options remain unverified')
    return results
