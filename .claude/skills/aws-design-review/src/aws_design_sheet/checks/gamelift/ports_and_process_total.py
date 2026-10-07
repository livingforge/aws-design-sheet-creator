"""Checks for AWS::GameLift::ContainerFleet, AWS::GameLift::Fleet."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, known_scope

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_OS_PORTS': [CF+'aws-properties-gamelift-fleet-ippermission.html',CF+'aws-resource-gamelift-build.html'],
    'GAMELIFT_RESERVED_PORTS': [CF+'aws-properties-gamelift-containerfleet-connectionportrange.html'],
    'GAMELIFT_PROCESS_TOTAL': [CF+'aws-properties-gamelift-fleet-runtimeconfiguration.html',CF+'aws-properties-gamelift-fleet-serverprocess.html'],
}


def ports(ctx,resource,path):
    start=value(ctx,resource,path+'/FromPort');end=value(ctx,resource,path+'/ToPort')
    if type(start) is not int or type(end) is not int:return 'NEEDS_REVIEW'
    if not 1<=start<=60000 or not 1<=end<=60000:return 'FAIL'
    if start>end:return 'NEEDS_REVIEW'
    if start<=4191 and end>=4092:return 'FAIL'
    # Pinned prose says higher, current CFN page says equal or greater.
    return 'NEEDS_REVIEW' if start==end else 'PASS'


def process_total(ctx,resource,path):
    raw=value(ctx,resource,path)
    if not isinstance(raw,list) or not raw:return 'NEEDS_REVIEW'
    total=0;pending=False
    for i in range(len(raw)):
        count=value(ctx,resource,path+'/'+str(i)+'/ConcurrentExecutions')
        if type(count) is not int:pending=True;continue
        if count<1:return 'FAIL'
        total+=count
    if total>50:return 'FAIL'
    return 'NEEDS_REVIEW' if pending or total==50 else 'PASS'


@resource_check('AWS::GameLift::ContainerFleet', 'AWS::GameLift::Fleet')
def evaluate_gamelift_ports_and_process_total(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::GameLift::ContainerFleet':
        path='/properties/InstanceConnectionPortRange'
        if get(path) is not ABSENT:emit('GAMELIFT_RESERVED_PORTS',path,ports(ctx,resource,path),'inclusive range must avoid reserved ports 4092..4191; unknown/reversed ranges and single-port ranges outside reserved interval remain held due to pinned/current wording difference')
    if resource.type=='AWS::GameLift::Fleet':
        build=linked(ctx,resource,'/properties/BuildId','AWS::GameLift::Build') if known_scope(resource) else None
        os=value(ctx,build,'/properties/OperatingSystem') if build else None
        for p in expand(ctx,resource,'/properties/EC2InboundPermissions/*'):
            start=get(p+'/FromPort');end=get(p+'/ToPort');verdict='NEEDS_REVIEW'
            if os in ('AMAZON_LINUX','AMAZON_LINUX_2','AMAZON_LINUX_2023','WINDOWS_2012','WINDOWS_2016','WINDOWS_2022') and type(start) is int and type(end) is int:
                valid=1026<=start<=end<=60000 or os.startswith('AMAZON_LINUX') and start==end==22
                verdict='PASS' if valid else 'FAIL'
            emit('GAMELIFT_OS_PORTS',p,verdict,'explicit linked Build OS permits 1026..60000, plus port 22 alone for Linux; entire inclusive interval must fit; unknown/external/conditional build and OS remain held')
        path='/properties/RuntimeConfiguration/ServerProcesses'
        if get(path) is not ABSENT:emit('GAMELIFT_PROCESS_TOTAL',path,process_total(ctx,resource,path),'positive integer ConcurrentExecutions must not total above 50; exactly 50 remains held because pinned prose says fewer than the limit; unknown entries remain held unless known subtotal exceeds 50')
    return results
