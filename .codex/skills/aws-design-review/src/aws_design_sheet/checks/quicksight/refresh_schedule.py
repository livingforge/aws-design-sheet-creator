"""Checks for these resource types:

- AWS::QuickSight::Analysis
- AWS::QuickSight::Dashboard
- AWS::QuickSight::RefreshSchedule
- AWS::QuickSight::Template
"""
import re
from ..registry import resource_check
from ..common.analytics import QUICK
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

SOURCES = {
    'QUICKSIGHT_ANALYSIS_ELEMENT_IDS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-quicksight-analysis-barchartvisual.html',
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-quicksight-analysis-sheettextbox.html',
    ],
    'QUICKSIGHT_DASHBOARD_ELEMENT_IDS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-quicksight-dashboard-barchartvisual.html',
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-quicksight-dashboard-sheettextbox.html',
    ],
    'QUICKSIGHT_TEMPLATE_ELEMENT_IDS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-quicksight-template-barchartvisual.html',
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-quicksight-template-sheettextbox.html',
    ],
    'QUICKSIGHT_REFRESH_EXCLUSIVE': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-quicksight-refreshschedule-schedulefrequency.html',
        'https://docs.aws.amazon.com/quick/latest/userguide/refreshing-imported-data.html',
    ],
}
VISUALS=set(('BarChart BoxPlot ComboChart CustomContent Empty FilledMap FunnelChart GaugeChart GeospatialMap HeatMap Histogram Insight KPI LayerMap LineChart PieChart PivotTable Plugin RadarChart SankeyDiagram ScatterPlot Table TreeMap Waterfall WordCloud').split())
VISUALS={name+'Visual' for name in VISUALS}
HIGH=('MINUTE15','MINUTE30','HOURLY')
INTERVALS=HIGH+('DAILY','WEEKLY','MONTHLY')


def element_ids(ctx,resource,path):
    sheets=value(ctx,resource,path);pending=not isinstance(sheets,list);invalid=False
    visuals=[];boxes=[]
    for i in range(len(sheets)) if isinstance(sheets,list) else ():
        base=path+'/'+str(i)
        for collection,key,ids in [('Visuals','VisualId',visuals),('TextBoxes','SheetTextBoxId',boxes)]:
            p=base+'/'+collection;items=value(ctx,resource,p)
            if items is ABSENT:continue
            if not isinstance(items,list):pending=True;continue
            for j in range(len(items)):
                item=p+'/'+str(j)
                if collection=='Visuals':
                    union=value(ctx,resource,item)
                    if not isinstance(union,dict) or len(union)!=1 or not set(union)<=VISUALS:
                        pending=True;continue
                    item+='/'+next(iter(union))
                ident=value(ctx,resource,item+'/'+key)
                if literal(ident):ids.append(ident)
                else:pending=True
    invalid=any(len(ids)!=len(set(ids)) for ids in (visuals,boxes))
    # The docs do not settle whether VisualId and SheetTextBoxId share a namespace.
    pending|=bool(set(visuals)&set(boxes))
    return 'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS'


def dataset_identity(ctx,resource):
    account=value(ctx,resource,'/properties/AwsAccountId')
    if not known_scope(resource) or account!=resource.scope.account:return None
    dataset=linked(ctx,resource,'/properties/DataSetId','AWS::QuickSight::DataSet')
    if dataset:
        return ('resource',dataset.id) if value(ctx,dataset,'/properties/AwsAccountId')==account else None
    raw=value(ctx,resource,'/properties/DataSetId')
    return ('literal',raw) if literal(raw) and re.fullmatch(r'[A-Za-z0-9_-]+',raw) else None


def refresh_exclusive(ctx,resource):
    own=dataset_identity(ctx,resource);path='/properties/Schedule'
    interval=value(ctx,resource,path+'/ScheduleFrequency/Interval');sid=value(ctx,resource,path+'/ScheduleId')
    pending=own is None or interval not in INTERVALS or not literal(sid);invalid=False
    for other in ctx.design.resources:
        if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
        their=dataset_identity(ctx,other)
        if own and their and own[0]==their[0] and own!=their:continue
        oi=value(ctx,other,path+'/ScheduleFrequency/Interval')
        if interval in INTERVALS and oi in INTERVALS and interval not in HIGH and oi not in HIGH:continue
        osid=value(ctx,other,path+'/ScheduleId')
        if own and their==own and literal(sid) and literal(osid) and sid!=osid and oi in INTERVALS and interval in INTERVALS:
            invalid=True
        else:pending=True
    return 'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::QuickSight::Analysis','AWS::QuickSight::Dashboard','AWS::QuickSight::Template','AWS::QuickSight::RefreshSchedule')
def evaluate_quicksight_refresh_schedule(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    kind=resource.type.split('::')[-1]
    if resource.type.startswith('AWS::QuickSight::') and kind in QUICK:
        path='/properties/Definition/Sheets'
        if get(path) is not ABSENT:
            emit(QUICK[kind],path,element_ids(ctx,resource,path),'checks VisualId and SheetTextBoxId uniqueness across explicit sheets; cross-kind ID overlap, invalid visual unions, unknown IDs and source-entity content remain under review')
    if resource.type=='AWS::QuickSight::RefreshSchedule':
        emit('QUICKSIGHT_REFRESH_EXCLUSIVE','/properties/Schedule',refresh_exclusive(ctx,resource),'minute/hourly refresh cannot coexist with another distinct schedule for the same explicit dataset and scope; same schedule IDs, unresolved aliases and external schedules remain unverified')
    return results
