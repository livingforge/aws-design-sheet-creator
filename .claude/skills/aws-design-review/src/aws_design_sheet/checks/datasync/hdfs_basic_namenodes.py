"""Checks for AWS::DataSync::LocationHDFS."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value

SOURCES = {
    'DATASYNC_HDFS_BASIC_NAMENODES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-datasync-locationhdfs.html',
    ],
}


@resource_check('AWS::DataSync::LocationHDFS')
def evaluate_datasync_hdfs_basic_namenodes(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::DataSync::LocationHDFS':
        p='/properties/NameNodes';nodes=get(p);basic=False
        for task in design.resources:
            if task.type!='AWS::DataSync::Task' or task.scope!=resource.scope:continue
            if value(ctx,task,'/properties/TaskMode')!='BASIC':continue
            for key in ('SourceLocationArn','DestinationLocationArn'):
                location=linked(ctx,task,'/properties/'+key,resource.type)
                if location and location.id==resource.id:basic=True
        emit('DATASYNC_HDFS_BASIC_NAMENODES',p,'FAIL' if basic and isinstance(nodes,list) and len(nodes)>1 else 'NEEDS_REVIEW','explicit BASIC task referencing this HDFS location permits only one NameNode; omitted modes, enhanced support and external task references held')
    return results
