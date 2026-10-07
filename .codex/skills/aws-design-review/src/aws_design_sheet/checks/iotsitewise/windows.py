"""Checks for AWS::IoTSiteWise::AssetModel, AWS::IoTSiteWise::Portal."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SITEWISE_METRIC_INTERVAL_RANGE': [CF+'aws-properties-iotsitewise-assetmodel-tumblingwindow.html'],
    'SITEWISE_PORTAL_SSO_REGION': [CF+'aws-resource-iotsitewise-portal.html'],
}


def interval_range(raw):
    if not literal(raw) or len(raw)>64:return 'NEEDS_REVIEW'
    match=re.fullmatch(r'([0-9]+)([mhdw])',raw)
    if match:seconds=int(match[1])*{'m':60,'h':3600,'d':86400,'w':604800}[match[2]]
    else:
        match=re.fullmatch(r'PT([0-9]+)([SMH])',raw)
        if match:seconds=int(match[1])*{'S':1,'M':60,'H':3600}[match[2]]
        else:
            match=re.fullmatch(r'P([0-9]+)([DW])',raw)
            if not match:return 'NEEDS_REVIEW'
            seconds=int(match[1])*{'D':86400,'W':604800}[match[2]]
    return 'PASS' if 60<=seconds<=604800 else 'FAIL'


@resource_check('AWS::IoTSiteWise::AssetModel', 'AWS::IoTSiteWise::Portal')
def evaluate_iotsitewise_windows(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::IoTSiteWise::AssetModel':
        for base in ('/properties/AssetModelProperties/*','/properties/AssetModelCompositeModels/*/CompositeModelProperties/*'):
            for path in expand(ctx,resource,base+'/Type/Metric/Window/Tumbling/Interval'):
                emit('SITEWISE_METRIC_INTERVAL_RANGE',path,interval_range(value(ctx,resource,path)),'supported integer m/h/d/w and single-unit ISO S/M/H/D/W durations must be 1 minute through 1 week; compound/fractional/calendar forms, offsets and unknown input remain held')
    if resource.type=='AWS::IoTSiteWise::Portal':
        path='/properties/PortalAuthMode'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW' if raw!='SSO' or not known_scope(resource) else 'FAIL' if resource.scope.region.startswith('cn-') else 'PASS'
            emit('SITEWISE_PORTAL_SSO_REGION',path,verdict,'explicit SSO is unavailable in China Regions; Identity Center enablement, account eligibility, general service availability and omitted defaults remain held')
    return results
