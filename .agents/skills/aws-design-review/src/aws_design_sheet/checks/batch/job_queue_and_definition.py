"""Checks for AWS::Batch::JobDefinition, AWS::Batch::JobQueue."""
import re
from decimal import Decimal
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BATCH_TASK_ESSENTIAL': [CF+'aws-properties-batch-jobdefinition-taskcontainerproperties.html'],
    'BATCH_TASK_DEPENDENCY_ESSENTIAL': [CF+'aws-properties-batch-jobdefinition-taskcontainerdependency.html',CF+'aws-properties-batch-jobdefinition-taskcontainerproperties.html'],
    'BATCH_EKS_CONTAINER_NAMES': [CF+'aws-properties-batch-jobdefinition-ekscontainer.html',CF+'aws-properties-batch-jobdefinition-ekspodproperties.html'],
    'BATCH_NODE_RANGE_COVERAGE': [CF+'aws-properties-batch-jobdefinition-noderangeproperty.html'],
    'BATCH_EKS_RESOURCE_PAIR': [CF+'aws-properties-batch-jobdefinition-ekscontainerresourcerequirements.html'],
    'BATCH_EKS_NODE_NAMESPACE': [CF+'aws-properties-batch-jobdefinition-eksmetadata.html'],
    'BATCH_QUEUE_COMPUTE_FAMILY': [CF+'aws-resource-batch-jobqueue.html'],
    'BATCH_QUEUE_TIME_ACTION': [CF+'aws-resource-batch-jobqueue.html',CF+'aws-properties-batch-jobqueue-jobstatetimelimitaction.html'],
    'BATCH_TASK_FARGATE_ROLE': [CF+'aws-properties-batch-jobdefinition-ecstaskproperties.html',CF+'aws-properties-batch-jobdefinition-multinodeecstaskproperties.html'],
    'BATCH_TASK_PLATFORM_FIELDS': [CF+'aws-properties-batch-jobdefinition-ecstaskproperties.html'],
    'BATCH_TASK_FARGATE_TIMEOUT': [CF+'aws-properties-batch-jobdefinition-taskcontainerproperties.html'],
}


@resource_check('AWS::Batch::JobQueue','AWS::Batch::JobDefinition')
def evaluate_batch_job_queue_and_definition(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Batch::JobQueue':
        path='/properties/ComputeEnvironmentOrder';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            families=set();pending=not isinstance(raw,list)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                environment=linked(ctx,resource,path+'/'+str(i)+'/ComputeEnvironment','AWS::Batch::ComputeEnvironment')
                kind=value(ctx,environment,'/properties/ComputeResources/Type') if environment and known_scope(environment) else UNKNOWN
                if kind in ('EC2','SPOT'):families.add('EC2')
                elif kind in ('FARGATE','FARGATE_SPOT'):families.add('FARGATE')
                else:pending=True
            emit('BATCH_QUEUE_COMPUTE_FAMILY',path,'FAIL' if len(families)>1 else 'NEEDS_REVIEW' if pending else 'PASS',
                 'explicit linked compute environments cannot mix EC2 and Fargate families; VALID state and architecture are external')
        path='/properties/JobStateTimeLimitActions';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            kind=value(ctx,resource,'/properties/JobQueueType')
            expected='CANCEL' if kind in ('ECS','EKS','ECS_FARGATE') else 'TERMINATE' if kind=='SAGEMAKER_TRAINING' else None
            if not isinstance(raw,list):emit('BATCH_QUEUE_TIME_ACTION',path,'NEEDS_REVIEW','actions are unresolved')
            else:
                for i in range(len(raw)):
                    base=path+'/'+str(i)+'/Action';action=value(ctx,resource,base)
                    verdict='NEEDS_REVIEW' if expected is None or not literal(action) else 'PASS' if action==expected else 'FAIL'
                    emit('BATCH_QUEUE_TIME_ACTION',base,verdict,'checks action against explicit JobQueueType; omitted/unknown types and ECS_MANAGED_INSTANCES lack a settled mapping here')
    if resource.type!='AWS::Batch::JobDefinition':return results
    capabilities=value(ctx,resource,'/properties/PlatformCapabilities')
    platform=capabilities[0] if isinstance(capabilities,list) and len(capabilities)==1 and capabilities[0] in ('EC2','FARGATE','MANAGED_INSTANCES') else None
    for pattern in ('/properties/EcsProperties/TaskProperties/*',
                    '/properties/NodeProperties/NodeRangeProperties/*/EcsProperties/TaskProperties/*'):
        for task in expand(ctx,resource,pattern):
            role=value(ctx,resource,task+'/ExecutionRoleArn')
            if platform=='FARGATE' or platform is None:
                verdict='NEEDS_REVIEW' if platform is None or role is UNKNOWN else 'FAIL' if role is ABSENT else 'PASS' if literal(role) else 'NEEDS_REVIEW'
                emit('BATCH_TASK_FARGATE_ROLE',task+'/ExecutionRoleArn',verdict,'Fargate task requires an execution role; platform defaults and effective IAM permissions are not inferred')
            if task.startswith('/properties/EcsProperties/'):
                for key,forbidden in [('IpcMode',('FARGATE',)),('NetworkConfiguration',('EC2','MANAGED_INSTANCES')),('NetworkMode',('EC2','FARGATE'))]:
                    raw=value(ctx,resource,task+'/'+key)
                    if raw is ABSENT:continue
                    verdict='NEEDS_REVIEW' if platform is None or raw is UNKNOWN else 'FAIL' if platform in forbidden else 'PASS'
                    emit('BATCH_TASK_PLATFORM_FIELDS',task+'/'+key,verdict,'task field must be supported by the explicitly selected platform; field value validity is checked separately')
            for container in expand(ctx,resource,task+'/Containers/*'):
                for key in ('StartTimeout','StopTimeout'):
                    timeout=value(ctx,resource,container+'/'+key)
                    if timeout is ABSENT or platform in ('EC2','MANAGED_INSTANCES'):continue
                    verdict='NEEDS_REVIEW' if platform is None or type(timeout) is not int else 'FAIL' if timeout>120 else 'PASS'
                    emit('BATCH_TASK_FARGATE_TIMEOUT',container+'/'+key,verdict,'explicit Fargate container timeout must not exceed 120 seconds; lower bound and runtime behavior are separate')
    patterns=['/properties/EcsProperties/TaskProperties/*/Containers',
              '/properties/NodeProperties/NodeRangeProperties/*/EcsProperties/TaskProperties/*/Containers']
    for pattern in patterns:
        for path in expand(ctx,resource,pattern):
            raw=value(ctx,resource,path)
            if not isinstance(raw,list):
                for rule in ('BATCH_TASK_ESSENTIAL','BATCH_TASK_DEPENDENCY_ESSENTIAL'):
                    emit(rule,path,'NEEDS_REVIEW','task container collection is unresolved')
                continue
            names=[];essentials=[]
            for i in range(len(raw)):
                base=path+'/'+str(i);names.append(value(ctx,resource,base+'/Name'))
                flag=value(ctx,resource,base+'/Essential')
                essentials.append(True if flag is ABSENT and isinstance(value(ctx,resource,base),dict) else flag)
            verdict='PASS' if any(e is True for e in essentials) else 'FAIL' if all(e is False for e in essentials) else 'NEEDS_REVIEW'
            emit('BATCH_TASK_ESSENTIAL',path,verdict,'task must contain an essential container; documented omitted Essential defaults to true, unknown containers do not')
            for i in range(len(raw)):
                base=path+'/'+str(i)+'/DependsOn';deps=value(ctx,resource,base)
                if deps is ABSENT:continue
                if not isinstance(deps,list):emit('BATCH_TASK_DEPENDENCY_ESSENTIAL',base,'NEEDS_REVIEW','dependencies are unresolved');continue
                for j in range(len(deps)):
                    dep=base+'/'+str(j);condition=value(ctx,resource,dep+'/Condition');name=value(ctx,resource,dep+'/ContainerName')
                    if condition=='START':continue
                    verdict='NEEDS_REVIEW'
                    matches=[k for k,n in enumerate(names) if literal(n) and n==name] if literal(name) else []
                    if condition in ('COMPLETE','SUCCESS') and len(matches)==1 and all(literal(n) for n in names):
                        flag=essentials[matches[0]]
                        if flag is True:verdict='FAIL'
                        elif flag is False:verdict='PASS'
                    emit('BATCH_TASK_DEPENDENCY_ESSENTIAL',dep,verdict,'COMPLETE/SUCCESS must target a nonessential container; duplicate or unresolved names and unsupported conditions require review')
    for pattern in ('/properties/EksProperties/PodProperties',
                    '/properties/NodeProperties/NodeRangeProperties/*/EksProperties/PodProperties'):
        for path in expand(ctx,resource,pattern):
            names=[];pending=False
            for key in ('Containers','InitContainers'):
                base=path+'/'+key;raw=value(ctx,resource,base)
                if raw is ABSENT:continue
                if not isinstance(raw,list):pending=True;continue
                for i in range(len(raw)):
                    item=base+'/'+str(i);name=value(ctx,resource,item+'/Name')
                    if name is ABSENT and isinstance(value(ctx,resource,item),dict):name='Default'
                    if literal(name):names.append(name)
                    else:pending=True
                    for quantity in ('memory','cpu'):
                        limits=value(ctx,resource,item+'/Resources/Limits/'+quantity)
                        requests=value(ctx,resource,item+'/Resources/Requests/'+quantity)
                        if limits is ABSENT or requests is ABSENT:continue
                        verdict='NEEDS_REVIEW'
                        syntax=r'[0-9]{1,30}Mi' if quantity=='memory' else r'(?:[0-9]{1,30}(?:\.[0-9]{1,30})?|\.[0-9]{1,30})'
                        if all(isinstance(v,str) and re.fullmatch(syntax,v) for v in (limits,requests)):
                            a,b=(int(v[:-2]) for v in (limits,requests)) if quantity=='memory' else (Decimal(v) for v in (limits,requests))
                            verdict='PASS' if (a==b if quantity=='memory' else a>=b) else 'FAIL'
                        emit('BATCH_EKS_RESOURCE_PAIR',item+'/Resources',verdict,
                             quantity+' limits must equal requests for memory, or be at least requests for CPU; supports integer Mi memory and plain decimal CPU only, other quantity spellings and validity constraints remain separate')
            verdict='FAIL' if len(names)!=len(set(names)) else 'NEEDS_REVIEW' if pending else 'PASS'
            emit('BATCH_EKS_CONTAINER_NAMES',path,verdict,'container names within a pod must be unique, including documented Default names; unresolved names require review')
    root='/properties/NodeProperties';raw=value(ctx,resource,root)
    if raw is not ABSENT:
        count=value(ctx,resource,root+'/NumNodes');ranges=value(ctx,resource,root+'/NodeRangeProperties')
        pending=False;intervals=[];verdict='NEEDS_REVIEW'
        if type(count) is int and count>0 and isinstance(ranges,list):
            for i in range(len(ranges)):
                span=value(ctx,resource,root+'/NodeRangeProperties/'+str(i)+'/TargetNodes')
                if not isinstance(span,str) or not re.fullmatch(r'(?:[0-9]+|[0-9]*:[0-9]*)',span):pending=True;continue
                if ':' in span:
                    start,end=span.split(':');lo=int(start or 0);hi=int(end) if end else count-1
                else:lo=hi=int(span)
                if lo>hi or hi>=count:pending=True;continue
                intervals.append((lo,hi))
            covered=0
            for lo,hi in sorted(intervals):
                if lo>covered:break
                covered=max(covered,hi+1)
            verdict='PASS' if covered>=count else 'NEEDS_REVIEW' if pending else 'FAIL'
        emit('BATCH_NODE_RANGE_COVERAGE',root+'/NodeRangeProperties',verdict,'union of explicit node ranges must cover every node; nested ranges are permitted, unresolved or out-of-bound ranges require separate review')
        if isinstance(ranges,list):
            namespaces=[value(ctx,resource,root+'/NodeRangeProperties/'+str(i)+'/EksProperties/PodProperties/Metadata/Namespace') for i in range(len(ranges))]
            if any(n is not ABSENT for n in namespaces):
                known=[n for n in namespaces if literal(n)]
                verdict='FAIL' if len(set(known))>1 else 'PASS' if len(known)==len(namespaces) else 'NEEDS_REVIEW'
                emit('BATCH_EKS_NODE_NAMESPACE',root+'/NodeRangeProperties',verdict,'explicit EKS namespaces must agree across all node ranges; omitted namespaces and RBAC equivalence are not inferred')
    return results
