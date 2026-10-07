"""Explicit Batch capacities and nested numeric constraints."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
    'BATCH_FARGATE_RESOURCE_PAIR':[CF+'aws-properties-batch-jobdefinition-resourcerequirement.html','https://docs.aws.amazon.com/batch/latest/userguide/fargate-job-definitions.html'],
    'BATCH_FARGATE_GPU':[CF+'aws-properties-batch-jobdefinition-resourcerequirement.html'],
    'BATCH_NESTED_NUMERIC':[CF+'aws-properties-batch-jobdefinition-linuxparameters.html',CF+'aws-properties-batch-jobdefinition-ephemeralstorage.html',CF+'aws-properties-batch-jobdefinition-multinodecontainerproperties.html'],
    'BATCH_NESTED_FARGATE_LINUX':[CF+'aws-properties-batch-jobdefinition-linuxparameters.html'],
    'BATCH_EFS_TRANSIT_PORT':[CF+'aws-properties-batch-jobdefinition-efsvolumeconfiguration.html'],
    'BATCH_TMPFS_OPTIONS':[CF+'aws-properties-batch-jobdefinition-tmpfs.html'],
}
FARGATE_MEMORY={
    '0.25':{512,1024,2048},'0.5':{1024,2048,3072,4096},
    '1':set(range(2048,8193,1024)),'2':set(range(4096,16385,1024)),
    '4':set(range(8192,30721,1024)),'8':set(range(16384,61441,4096)),
    '16':set(range(32768,122881,8192)),'32':{61440,122880,249856},
}
TMPFS_OPTIONS=set('defaults ro rw suid nosuid dev nodev exec noexec sync async dirsync remount mand nomand atime noatime diratime nodiratime bind rbind unbindable runbindable private rprivate shared rshared slave rslave relatime norelatime strictatime nostrictatime mode uid gid nr_inodes nr_blocks mpol'.split())
CONTAINERS=('/properties/ContainerProperties',
            '/properties/NodeProperties/NodeRangeProperties/*/Container',
            '/properties/EcsProperties/TaskProperties/*/Containers/*',
            '/properties/NodeProperties/NodeRangeProperties/*/EcsProperties/TaskProperties/*/Containers/*')


@resource_check('AWS::Batch::JobDefinition')
def evaluate_batch_capacity(design,resource):
    if resource.type!='AWS::Batch::JobDefinition':return []
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    platform=value(ctx,resource,'/properties/PlatformCapabilities')
    fargate=platform==['FARGATE'];unknown_platform=platform not in (['FARGATE'],['EC2'],['MANAGED_INSTANCES'])
    for pattern in CONTAINERS:
        for base in expand(ctx,resource,pattern):
            if base!='/properties/ContainerProperties':
                bounds=[('LinuxParameters/MaxSwap',0,None),('LinuxParameters/Swappiness',0,100)]
                if pattern.endswith('/Container'):bounds.extend([('Memory',4,None),('EphemeralStorage/SizeInGiB',21,200)])
                for suffix,lo,hi in bounds:
                    path=base+'/'+suffix;raw=value(ctx,resource,path)
                    if raw is ABSENT:continue
                    verdict='NEEDS_REVIEW' if type(raw) is not int else 'PASS' if raw>=lo and (hi is None or raw<=hi) else 'FAIL'
                    emit('BATCH_NESTED_NUMERIC',path,verdict,'explicit nested integer must satisfy the documented numeric bounds; platform applicability and inherited values are separate')
                if fargate or unknown_platform:
                    for key in ('Devices','MaxSwap','SharedMemorySize','Swappiness','Tmpfs'):
                        path=base+'/LinuxParameters/'+key;raw=value(ctx,resource,path)
                        if raw is not ABSENT:emit('BATCH_NESTED_FARGATE_LINUX',path,'FAIL' if fargate and raw is not UNKNOWN else 'NEEDS_REVIEW','specified Linux parameter is unsupported on Fargate; unknown platform/value is not inferred')
            for path in expand(ctx,resource,base+'/LinuxParameters/Tmpfs/*/MountOptions'):
                raw=value(ctx,resource,path);pending=not isinstance(raw,list);invalid=False
                if isinstance(raw,list):
                    for i in range(len(raw)):
                        option=value(ctx,resource,path+'/'+str(i))
                        if not literal(option) or '=' in option:pending=True
                        elif option not in TMPFS_OPTIONS:invalid=True
                emit('BATCH_TMPFS_OPTIONS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','checks documented mount-option tokens; key=value syntax and option arguments remain under review')
            path=base+'/ResourceRequirements';raw=value(ctx,resource,path)
            if raw is not ABSENT and (fargate or unknown_platform):
                kinds=[value(ctx,resource,path+'/'+str(i)+'/Type') for i in range(len(raw))] if isinstance(raw,list) else [UNKNOWN]
                emit('BATCH_FARGATE_GPU',path,'FAIL' if fargate and 'GPU' in kinds else 'NEEDS_REVIEW'
                     if unknown_platform or any(k not in ('MEMORY','VCPU','GPU') for k in kinds) else 'PASS','Fargate cannot reserve GPU resources; only explicit platform and requirement types are checked')
            if base=='/properties/ContainerProperties' and (fargate or unknown_platform):
                pending=unknown_platform or raw is not ABSENT and not isinstance(raw,list);values={'MEMORY':[],'VCPU':[]}
                if isinstance(raw,list):
                    for i in range(len(raw)):
                        item=path+'/'+str(i);kind=value(ctx,resource,item+'/Type')
                        if isinstance(kind,str) and kind in values:values[kind].append(value(ctx,resource,item+'/Value'))
                        elif kind!='GPU':pending=True
                if any(len(v)>1 for v in values.values()):pending=True
                verdict='NEEDS_REVIEW'
                if not pending:
                    if any(not v for v in values.values()):verdict='FAIL'
                    else:
                        memory=values['MEMORY'][0];cpu=values['VCPU'][0]
                        if isinstance(memory,str) and re.fullmatch(r'(?:0|[1-9][0-9]{0,19})',memory) and isinstance(cpu,str) and re.fullmatch(r'(?:0|[1-9][0-9]{0,19})(?:\.[0-9]{0,19}[1-9])?',cpu):
                            if cpu in FARGATE_MEMORY:verdict='PASS' if int(memory) in FARGATE_MEMORY[cpu] else 'FAIL'
                            else:verdict='FAIL'
                emit('BATCH_FARGATE_RESOURCE_PAIR',path,verdict,'legacy single-container Fargate definition needs one MEMORY/VCPU pair from the documented matrix; duplicate, unresolved or alternate numeric spellings, multi-container totals and platform-version/OS availability remain separate')
    for task in expand(ctx,resource,'/properties/EcsProperties/TaskProperties/*/EphemeralStorage/SizeInGiB'):
        raw=value(ctx,resource,task)
        emit('BATCH_NESTED_NUMERIC',task,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if 21<=raw<=200 else 'FAIL','task ephemeral storage must be 21..200 GiB; platform availability is separate')
    volume_roots=CONTAINERS[:2]+('/properties/EcsProperties/TaskProperties/*','/properties/NodeProperties/NodeRangeProperties/*/EcsProperties/TaskProperties/*')
    for base in volume_roots:
        for path in expand(ctx,resource,base+'/Volumes/*/EfsVolumeConfiguration/TransitEncryptionPort'):
            port=value(ctx,resource,path)
            emit('BATCH_EFS_TRANSIT_PORT',path,'NEEDS_REVIEW' if type(port) is not int else 'PASS' if 0<=port<=65535 else 'FAIL','explicit EFS transit port must be between 0 and 65535; connectivity is external')
    return results
