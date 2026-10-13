"""DynamoDB v1 rule-action key names against an explicit table schema."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'IOT_DYNAMODB_ACTION_KEY_NAMES':[CF+'aws-properties-iot-topicrule-dynamodbaction.html',CF+'aws-properties-dynamodb-table-keyschema.html','https://docs.aws.amazon.com/iot/latest/developerguide/dynamodb-rule-action.html']}


def keys(ctx,r,path):
    if not resolved(r):return 'NEEDS_REVIEW'
    table=linked(ctx,r,path+'/TableName','AWS::DynamoDB::Table')
    if not resolved(table):return 'NEEDS_REVIEW'
    raw=read(ctx,r,path+'/TableName')
    if raw is not ABSENT and (not literal(raw) or raw!=value(ctx,table,'/properties/TableName')):return 'NEEDS_REVIEW'
    schema=value(ctx,table,'/properties/KeySchema')
    if not isinstance(schema,list) or not 1<=len(schema)<=2:return 'NEEDS_REVIEW'
    declared={}
    for i in range(len(schema)):
        base=f'/properties/KeySchema/{i}/'
        typ=value(ctx,table,base+'KeyType');name=value(ctx,table,base+'AttributeName')
        if typ not in ('HASH','RANGE') or not literal(name) or typ in declared:return 'NEEDS_REVIEW'
        declared[typ]=name
    if 'HASH' not in declared or len(set(declared.values()))!=len(declared):return 'NEEDS_REVIEW'
    pending=False
    for typ,field in [('HASH','HashKeyField'),('RANGE','RangeKeyField')]:
        supplied=value(ctx,r,path+'/'+field)
        if typ not in declared:
            if supplied is not ABSENT:pending=True
            continue
        if supplied is ABSENT:return 'FAIL'
        if not literal(supplied):pending=True
        elif supplied!=declared[typ]:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::IoT::TopicRule')
def evaluate_iot_dynamodb_keys(design,resource):
    if resource.type!='AWS::IoT::TopicRule':return []
    ctx=_Context(design,resource);result=[]
    for pattern in ('/properties/TopicRulePayload/Actions/*/DynamoDB','/properties/TopicRulePayload/ErrorAction/DynamoDB'):
        for path in expand(ctx,resource,pattern):
            verdict=keys(ctx,resource,path) if path.endswith('/DynamoDB') else 'NEEDS_REVIEW'
            f=ctx.finding('IOT_DYNAMODB_ACTION_KEY_NAMES',path,verdict,'DynamoDB action table and hash/range key names must match the explicitly referenced table. Compare primary KeySchema, not secondary indexes. PASS covers names only. Substitution expressions, unknown or external tables, extra range fields without a declared sort key, permissions, key-value types and enabled HTTP destinations remain reviewable or outside this check.')
            f['source_checked_at']='2026-10-04';result.append(f)
    return result
