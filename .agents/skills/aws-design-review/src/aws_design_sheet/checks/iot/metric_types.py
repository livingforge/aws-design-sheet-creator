"""Security profile operators and duration restrictions for known metric types."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
DG='https://docs.aws.amazon.com/iot-device-defender/latest/devguide/'
SOURCES={'IOT_METRIC_CRITERIA_TYPES':[CF+'aws-properties-iot-securityprofile-behaviorcriteria.html',CF+'aws-resource-iot-custommetric.html',DG+'detect-cloud-side-metrics.html',DG+'detect-device-side-metrics.html']}
NUMBER={'less-than','less-than-equals','greater-than','greater-than-equals'}
OPS={'number':NUMBER,'string-list':{'in-set','not-in-set'},'number-list':{'in-set','not-in-set'},'ip-address-list':{'in-cidr-set','not-in-cidr-set'},'port-list':{'in-port-set','not-in-port-set'},'disconnect':{'less-than','less-than-equals'}}
BUILTINS={name:'number' for name in ('message-byte-size','num-messages-sent','num-messages-received','num-authorization-failures','num-connection-attempts','num-disconnects','all-bytes-out','all-bytes-in','num-listening-tcp-ports','num-listening-udp-ports','all-packets-out','all-packets-in','num-established-tcp-connections')}
BUILTINS.update({'source-ip-address':'ip-address-list','destination-ip-addresses':'ip-address-list','listening-tcp-ports':'port-list','listening-udp-ports':'port-list','disconnect-duration':'disconnect'})
ALL_OPERATORS=set().union(*OPS.values())


def metric_type(ctx,r,path):
    if not resolved(r):return None
    other=linked(ctx,r,path,'AWS::IoT::CustomMetric')
    if resolved(other):
        raw=value(ctx,other,'/properties/MetricType')
        return raw if isinstance(raw,str) and raw in ('number','number-list','string-list','ip-address-list') else None
    raw=value(ctx,r,path)
    return BUILTINS.get(raw[4:]) if isinstance(raw,str) and raw.startswith('aws:') else None


@resource_check('AWS::IoT::SecurityProfile')
def evaluate_iot_metric_types(design,resource):
    if resource.type!='AWS::IoT::SecurityProfile':return []
    ctx=_Context(design,resource);results=[]
    for leaf in ('ComparisonOperator','DurationSeconds'):
        pattern='/properties/Behaviors/*/Criteria/'+leaf
        for path in expand(ctx,resource,pattern):
            verdict='NEEDS_REVIEW'
            if path.count('/')==pattern.count('/'):
                kind=metric_type(ctx,resource,path.rsplit('/Criteria/',1)[0]+'/Metric')
                raw=value(ctx,resource,path)
                if kind and leaf=='ComparisonOperator' and isinstance(raw,str) and raw in ALL_OPERATORS:
                    verdict='PASS' if raw in OPS[kind] else 'FAIL'
                elif kind and leaf=='DurationSeconds' and type(raw) is int:
                    verdict='FAIL' if kind.endswith('-list') else 'NOT_APPLICABLE'
            f=ctx.finding('IOT_METRIC_CRITERIA_TYPES',path,verdict,'Compare known built-in or explicitly linked custom metric type with the provided operator. List-based metrics cannot specify DurationSeconds. No operator requiredness, scalar duration range, metric availability or live deployment claim. Unknown metric types and references remain reviewable.')
            f['source_checked_at']='2026-10-04';results.append(f)
    return results
