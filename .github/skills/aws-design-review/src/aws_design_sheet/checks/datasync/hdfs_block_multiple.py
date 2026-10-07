"""Checks for AWS::DataSync::LocationHDFS."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DATASYNC_HDFS_BLOCK_MULTIPLE': [CF+'aws-resource-datasync-locationhdfs.html'],
}


@resource_check('AWS::DataSync::LocationHDFS')
def evaluate_datasync_hdfs_block_multiple(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::DataSync::LocationHDFS':
        path='/properties/BlockSize'; raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('DATASYNC_HDFS_BLOCK_MULTIPLE',path,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if raw%512==0 else 'FAIL','explicit integer BlockSize must be divisible by 512; numeric bounds are existing schema/rule checks and runtime storage support is separate')
    return results
