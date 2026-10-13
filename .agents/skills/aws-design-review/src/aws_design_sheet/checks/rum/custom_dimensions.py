"""Custom RUM metric dimension paths in bounded literal event-pattern JSON."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved
from ..common.strict_json import parse

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'RUM_CUSTOM_DIMENSION_PATTERN':[CF+'aws-properties-rum-appmonitor-appmonitorconfiguration.html',CF+'aws-properties-rum-appmonitor-metricdefinition.html','https://docs.aws.amazon.com/cloudwatchrum/latest/APIReference/API_MetricDefinitionRequest.html','https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-custom-and-extended-metrics.html']}
ROOT='/properties/AppMonitorConfiguration/MetricDestinations'
TOP={'account_id','application_Id','application_version','application_name','batch_id','event_details','event_id','event_interaction','event_timestamp','event_type','event_version','log_stream','metadata','sessionId','user_details','userId'}


def contains_dotted_key(node):
    stack=[node]
    while stack:
        obj=stack.pop()
        if isinstance(obj,dict):
            if any('.' in k for k in obj):return True
            stack.extend(obj.values())
        elif isinstance(obj,list):stack.extend(obj)
    return False


def dimensions(ctx,r,path):
    destination=value(ctx,r,path.rsplit('/MetricDefinitions/',1)[0]+'/Destination')
    if destination=='Evidently':return 'NOT_APPLICABLE'
    if destination!='CloudWatch' or not resolved(r):return 'NEEDS_REVIEW'
    namespace=value(ctx,r,path+'/Namespace')
    if namespace is ABSENT or namespace=='AWS/RUM':return 'NOT_APPLICABLE'
    if not literal(namespace) or not namespace or namespace.startswith('AWS/'):return 'NEEDS_REVIEW'
    keys=value(ctx,r,path+'/DimensionKeys')
    if keys is ABSENT or keys=={}:return 'NOT_APPLICABLE'
    if not isinstance(keys,dict) or len(keys)>100 or '$state' in keys:return 'NEEDS_REVIEW'
    raw=value(ctx,r,path+'/EventPattern')
    if not literal(raw) or len(raw)>4000:return 'NEEDS_REVIEW'
    node=parse(raw)
    if node is None or contains_dotted_key(node):return 'NEEDS_REVIEW'
    pending=False
    for field in keys:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*',field) or field.split('.')[0] not in TOP:
            pending=True;continue
        current=node
        for key in field.split('.'):
            if not isinstance(current,dict):pending=True;break
            if key not in current:return 'FAIL'
            current=current[key]
        else:
            if not isinstance(current,list) or not current:pending=True
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::RUM::AppMonitor')
def evaluate_rum_custom_dimensions(design,resource):
    if resource.type!='AWS::RUM::AppMonitor':return []
    ctx=_Context(design,resource);out=[]
    for path in expand(ctx,resource,ROOT+'/*/MetricDefinitions/*'):
        verdict=dimensions(ctx,resource,path) if re.fullmatch(re.escape(ROOT)+r'/\d+/MetricDefinitions/\d+',path) else 'NEEDS_REVIEW'
        f=ctx.finding('RUM_CUSTOM_DIMENSION_PATTERN',path,verdict,'Custom metrics sent to CloudWatch require every declared dimension field path in EventPattern. Parse bounded literal JSON and inspect nested simple paths; extended metrics and Evidently dimension fields are outside this condition. Duplicate/dynamic JSON, dotted-key ambiguity, unsupported path grammar and incomplete evidence remain reviewable. PASS covers path presence only, not all event-pattern semantics or metric validity.')
        f['source_checked_at']='2026-10-04';out.append(f)
    return out
