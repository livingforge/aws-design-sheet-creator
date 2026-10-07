"""Checks for AWS::ApplicationSignals::ServiceLevelObjective."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPLICATIONSIGNALS_QUERY_ARRAY': [CF+'aws-properties-applicationsignals-servicelevelobjective-metricdataquery.html'],
    'APPLICATIONSIGNALS_QUERY_RETURN': [CF+'aws-properties-applicationsignals-servicelevelobjective-metricdataquery.html',CF+'aws-properties-applicationsignals-servicelevelobjective-slimetric.html'],
    'APPLICATIONSIGNALS_DIMENSION_TEXT': [CF+'aws-properties-applicationsignals-servicelevelobjective-dimension.html'],
}
QUERY_PATHS=(
    '/properties/Sli/SliMetric/MetricDataQueries',
    '/properties/RequestBasedSli/RequestBasedSliMetric/TotalRequestCountMetric',
    '/properties/RequestBasedSli/RequestBasedSliMetric/MonitoredRequestCountMetric/GoodCountMetric',
    '/properties/RequestBasedSli/RequestBasedSliMetric/MonitoredRequestCountMetric/BadCountMetric',
)


def query_array(ctx,resource,path):
    raw=value(ctx,resource,path)
    if not isinstance(raw,list):return 'NEEDS_REVIEW'
    if len(raw)>20:return 'FAIL'
    ids=set();counts=[0,0];pending=False
    for i in range(len(raw)):
        base=path+'/'+str(i);name=value(ctx,resource,base+'/Id')
        if literal(name):
            if name in ids:return 'FAIL'
            ids.add(name)
        else:pending=True
        parts=[value(ctx,resource,base+'/'+k) for k in ('Expression','MetricStat')]
        known=[v is not ABSENT and v is not UNKNOWN for v in parts]
        for j,present in enumerate(known):counts[j]+=present
        if sum(known)>1 or all(v is ABSENT for v in parts):return 'FAIL'
        if any(v is UNKNOWN for v in parts):pending=True
    if max(counts)>10:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS'


def query_return(ctx,resource,path):
    raw=value(ctx,resource,path)
    if not isinstance(raw,list) or not raw:return 'NEEDS_REVIEW'
    expressions=0;returned=0;metric_returned=False;pending=False
    for i in range(len(raw)):
        p=path+'/'+str(i);expression=value(ctx,resource,p+'/Expression');metric=value(ctx,resource,p+'/MetricStat');flag=value(ctx,resource,p+'/ReturnData')
        if expression is not ABSENT and expression is not UNKNOWN and metric is ABSENT:
            expressions+=1
            if flag is True:returned+=1
            elif flag is not False:pending=True
        elif expression is ABSENT and metric is not ABSENT and metric is not UNKNOWN:
            metric_returned|=flag is True
            if flag is not True and flag is not False:pending=True
        else:pending=True
    if returned>1 or expressions and metric_returned:return 'FAIL'
    if pending:return 'NEEDS_REVIEW'
    if not expressions:return 'NOT_APPLICABLE'
    return 'PASS' if returned==1 else 'FAIL'


def dimension_text(raw,name=False):
    if not isinstance(raw,str) or '${' in raw or '{{' in raw:return 'NEEDS_REVIEW'
    valid=bool(raw.strip()) and all(32<=ord(c)<=126 for c in raw) and (not name or not raw.startswith(':'))
    return 'PASS' if valid else 'FAIL'


@resource_check('AWS::ApplicationSignals::ServiceLevelObjective')
def evaluate_applicationsignals_service_level_objective(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::ApplicationSignals::ServiceLevelObjective':
        for path in QUERY_PATHS:
            if get(path) is ABSENT:continue
            emit('APPLICATIONSIGNALS_QUERY_ARRAY',path,query_array(ctx,resource,path),'each query array allows at most 20 queries, 10 MetricStat and 10 Expression, unique literal IDs and one query kind per item; unknown items remain under review')
            emit('APPLICATIONSIGNALS_QUERY_RETURN',path,query_return(ctx,resource,path),'when expressions are used, exactly one expression returns data and other queries explicitly return false; omitted flags and uncertain query kinds are held; direct-metric-only arrays are separate')
            for p in expand(ctx,resource,path+'/*/MetricStat/Metric/Dimensions/*'):
                for key in ('Name','Value'):
                    emit('APPLICATIONSIGNALS_DIMENSION_TEXT',p+'/'+key,dimension_text(get(p+'/'+key),key=='Name'),'dimension text must be printable ASCII with a non-whitespace character; Name cannot start with colon; unknown text and real metric identity remain under review')
    return results
