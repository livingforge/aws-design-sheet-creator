"""Checks for AWS::GameLift::ContainerGroupDefinition."""
from decimal import Decimal
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.numbers import number

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_CPU_SUM': [CF+'aws-resource-gamelift-containergroupdefinition.html',CF+'aws-properties-gamelift-containergroupdefinition-supportcontainerdefinition.html'],
    'GAMELIFT_CONTAINER_NAMES': [CF+'aws-properties-gamelift-containergroupdefinition-gameservercontainerdefinition.html'],
    'GAMELIFT_PORT_OVERLAP': [CF+'aws-properties-gamelift-containergroupdefinition-portconfiguration.html'],
    'GAMELIFT_DEPENDENCY_ESSENTIAL': [CF+'aws-properties-gamelift-containergroupdefinition-containerdependency.html',CF+'aws-properties-gamelift-containergroupdefinition-gameservercontainerdefinition.html'],
}


@resource_check('AWS::GameLift::ContainerGroupDefinition')
def evaluate_gamelift_container_group_definition(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::GameLift::ContainerGroupDefinition':
        support='/properties/SupportContainerDefinitions';raw=get(support);game='/properties/GameServerContainerDefinition'
        inherited=get('/properties/SourceVersionNumber') is not ABSENT
        paths=[support+'/'+str(i) for i in range(len(raw))] if isinstance(raw,list) else []
        pending=raw is not ABSENT and not isinstance(raw,list)
        total=number(get('/properties/TotalVcpuLimit'));subtotal=Decimal(0);cpu_pending=pending or inherited
        for path in paths:
            cpu=get(path+'/Vcpu')
            if cpu is ABSENT:continue
            n=number(cpu)
            if n is None or n<0:cpu_pending=True
            else:subtotal+=n
        verdict='NEEDS_REVIEW'
        if not inherited and total is not None and total>=0:
            verdict='FAIL' if subtotal>total else 'NEEDS_REVIEW' if cpu_pending else 'PASS'
        emit('GAMELIFT_CPU_SUM','/properties/TotalVcpuLimit',verdict,'total vCPU must cover explicit nonnegative support-container reservations; omitted reservations share the total; inherited source versions and unresolved allocations remain under review')
        if get(game) is not ABSENT:paths.append(game)
        names=[];name_pending=pending or inherited;targets={}
        for path in paths:
            name=get(path+'/ContainerName')
            if literal(name):
                names.append(name);targets.setdefault(name,[]).append(path)
            else:name_pending=True
        verdict='NEEDS_REVIEW' if inherited else 'FAIL' if len(set(names))<len(names) else 'NEEDS_REVIEW' if name_pending else 'PASS'
        emit('GAMELIFT_CONTAINER_NAMES','/properties',verdict,'container names must be unique across game server and support containers; unresolved names and inherited source versions remain under review')
        for owner in paths:
            path=owner+'/PortConfiguration/ContainerPortRanges';ranges=get(path)
            if ranges is not ABSENT:
                known=[];port_pending=not isinstance(ranges,list)
                for i in range(len(ranges)) if isinstance(ranges,list) else ():
                    p=path+'/'+str(i);a=get(p+'/FromPort');b=get(p+'/ToPort');protocol=get(p+'/Protocol')
                    if type(a) is int and type(b) is int and 1<=a<=b<=65535 and protocol in ('TCP','UDP'):known.append((a,b,protocol))
                    else:port_pending=True
                overlap=any(p==q and max(a,c)<=min(b,d) for i,(a,b,p) in enumerate(known) for c,d,q in known[i+1:])
                verdict='FAIL' if overlap else 'NEEDS_REVIEW' if port_pending else 'PASS'
                emit('GAMELIFT_PORT_OVERLAP',path,verdict,'inclusive port ranges within this configuration must not overlap for the same protocol; different protocols are allowed; unknown/invalid ranges remain under review')
            for path in expand(ctx,resource,owner+'/DependsOn/*'):
                condition=get(path+'/Condition');name=get(path+'/ContainerName');verdict='NEEDS_REVIEW'
                if condition in ('START','HEALTHY'):verdict='NOT_APPLICABLE'
                elif condition in ('COMPLETE','SUCCESS') and literal(name) and not inherited and not name_pending and len(targets.get(name,[]))==1:
                    target=targets[name][0];essential=True if target==game else get(target+'/Essential')
                    if essential is True:verdict='FAIL'
                    elif essential is False:verdict='PASS'
                emit('GAMELIFT_DEPENDENCY_ESSENTIAL',path,verdict,'COMPLETE/SUCCESS dependencies must target nonessential containers; game server is essential; absent/ambiguous names, omitted Essential and inherited source versions remain under review')
    return results
