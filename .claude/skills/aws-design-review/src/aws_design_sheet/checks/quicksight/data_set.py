"""Checks for AWS::QuickSight::DataSet."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'QUICKSIGHT_PHYSICAL_TABLE_VARIANT': [CF+'aws-properties-quicksight-dataset-physicaltable.html'],
    'QUICKSIGHT_FIELD_FOLDER_UNIQUE': [CF+'aws-properties-quicksight-dataset-fieldfolder.html'],
}


def escape(key):return key.replace('~','~0').replace('/','~1')


def physical(ctx,r,path):
    raw=value(ctx,r,path)
    if not isinstance(raw,dict):return 'NEEDS_REVIEW'
    count=0;pending=False
    for key in ('SaaSTable','RelationalTable','CustomSql','S3Source'):
        item=value(ctx,r,path+'/'+key)
        if item is UNKNOWN:pending=True
        elif item is not ABSENT and item is not None:
            if isinstance(item,dict):count+=1
            else:pending=True
    return 'FAIL' if count>1 else 'NEEDS_REVIEW' if pending or count==0 else 'PASS'


def folders(ctx,r):
    base='/properties/FieldFolders';raw=value(ctx,r,base)
    if not isinstance(raw,dict):return 'NEEDS_REVIEW'
    owners={};pending=False;duplicate=False
    for key in raw:
        if not literal(key) or '/' in key or '~' in key:pending=True;continue
        path=base+'/'+escape(key)
        folder=value(ctx,r,path)
        if not isinstance(folder,dict):pending=True;continue
        columns=value(ctx,r,path+'/Columns')
        if columns is ABSENT:continue
        if not isinstance(columns,list):pending=True;continue
        for i in range(len(columns)):
            column=value(ctx,r,path+'/Columns/'+str(i))
            if not literal(column):pending=True;continue
            if column in owners and owners[column]!=key:duplicate=True
            owners[column]=key
    return 'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::QuickSight::DataSet')
def evaluate_quicksight_data_set(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict):
        f=ctx.finding(rule,path,verdict,'bounded explicit structural constraint; unknown values, omitted defaults, other nested conditions and runtime state remain held')
        f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::QuickSight::DataSet':
        base='/properties/PhysicalTableMap';raw=value(ctx,resource,base)
        if raw is not ABSENT:
            if isinstance(raw,dict):
                for key in raw:
                    path=base+'/'+escape(key)
                    emit('QUICKSIGHT_PHYSICAL_TABLE_VARIANT',path,physical(ctx,resource,path) if literal(key) and '/' not in key and '~' not in key else 'NEEDS_REVIEW')
            else:emit('QUICKSIGHT_PHYSICAL_TABLE_VARIANT',base,'NEEDS_REVIEW')
        if value(ctx,resource,'/properties/FieldFolders') is not ABSENT:
            emit('QUICKSIGHT_FIELD_FOLDER_UNIQUE','/properties/FieldFolders',folders(ctx,resource))
    return results
