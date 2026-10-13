"""Scheduled query properties clarified by the CloudWatch Logs API reference."""
import math
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

URL='https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_CreateScheduledQuery.html'
SOURCES={rule:[URL] for rule in ('LOGS_SCHEDULED_QUERY_LANGUAGE','LOGS_SCHEDULED_QUERY_EPOCH_RANGE','LOGS_SCHEDULED_QUERY_TIME_WINDOW')}


def numeric(raw):
    return type(raw) in (int,float) and (type(raw) is int or math.isfinite(raw))


@resource_check('AWS::Logs::ScheduledQuery')
def scheduled_query(design, resource):
    ctx=_Context(design,resource)
    rows=[]
    language=value(ctx,resource,'/properties/QueryLanguage')
    if language is not ABSENT:
        verdict='PASS' if language in ('CWLI','SQL','PPL') else 'FAIL' if isinstance(language,str) and '{' not in language else 'NEEDS_REVIEW'
        row=ctx.finding('LOGS_SCHEDULED_QUERY_LANGUAGE','/properties/QueryLanguage',verdict,
            'the API documents CWLI, SQL and PPL; future language support requires review against newer documentation')
        row['severity']='WARNING'
        rows.append(row)
    for name in ('ScheduleStartTime','ScheduleEndTime'):
        path='/properties/'+name
        raw=value(ctx,resource,path)
        if raw is ABSENT:
            continue
        verdict=('PASS' if raw>=0 else 'FAIL') if numeric(raw) else 'NEEDS_REVIEW'
        rows.append(ctx.finding('LOGS_SCHEDULED_QUERY_EPOCH_RANGE',path,verdict,
            'the API requires nonnegative Unix epoch values; this check does not infer a default or compare with the current time'))
    start=value(ctx,resource,'/properties/ScheduleStartTime')
    end=value(ctx,resource,'/properties/ScheduleEndTime')
    if start is not ABSENT and end is not ABSENT:
        verdict='NEEDS_REVIEW'
        if numeric(start) and numeric(end) and min(start,end)>=0:
            verdict='PASS' if end>start else 'FAIL' if end<start else 'NEEDS_REVIEW'
        row=ctx.finding('LOGS_SCHEDULED_QUERY_TIME_WINDOW','/properties/ScheduleEndTime',verdict,
            'end before start leaves no execution window; this is a configuration warning, not a claim of API rejection, and equal endpoints require review')
        row['severity']='WARNING'
        rows.append(row)
    return rows
