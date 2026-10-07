"""Checks for AWS::EventsV2::EventSource, AWS::EventsV2::Subscriber."""
import json
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.json_verdict import json_verdict
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EVENTSV2_SERVICE_PATTERN_FIELDS': [CF+'aws-properties-eventsv2-eventsource-awsserviceeventsconfiguration.html'],
    'EVENTSV2_INVOKE_ROLE_ACCOUNT': [CF+'aws-properties-eventsv2-subscriber-invokeconfiguration.html'],
}


def event_pattern(raw):
    if not isinstance(raw,str) or len(raw)>3753:
        return 'NEEDS_REVIEW'
    verdict = json_verdict(raw)
    if verdict!='PASS':
        return verdict
    def pairs(items):
        if len({k for k,v in items})!=len(items):
            raise ValueError('duplicate keys')
        return dict(items)
    try:
        obj = json.loads(raw,object_pairs_hook=pairs,parse_int=str,parse_float=str)
    except (ValueError,RecursionError):
        return 'NEEDS_REVIEW'
    return 'FAIL' if not isinstance(obj,dict) or any(k in obj for k in ('source','account','region')) else 'PASS'


@resource_check('AWS::EventsV2::EventSource', 'AWS::EventsV2::Subscriber')
def evaluate_eventsv2_maps(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::EventsV2::EventSource':
        path = '/properties/Configuration/AwsServiceEventsConfiguration/Pattern'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            emit('EVENTSV2_SERVICE_PATTERN_FIELDS',path,event_pattern(raw),'bounded JSON object must omit top-level source/account/region; nested names allowed; duplicate keys, dynamic/deep/oversized inputs held; other event-pattern operators remain separate')
    if resource.type == 'AWS::EventsV2::Subscriber':
        path = '/properties/InvokeConfiguration/RoleArn'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            match = re.fullmatch(r'arn:aws(?:-[a-z0-9]+)*:iam::([0-9]{12}):role/[A-Za-z0-9_+=,.@/-]+',raw) if literal(raw) else None
            verdict = 'NEEDS_REVIEW' if not match or not re.fullmatch(r'[0-9]{12}',resource.scope.account) else 'PASS' if match[1]==resource.scope.account else 'FAIL'
            emit('EVENTSV2_INVOKE_ROLE_ACCOUNT',path,verdict,'explicit IAM role ARN account must match subscriber account; role existence, trust and target permissions remain held')
    return results
