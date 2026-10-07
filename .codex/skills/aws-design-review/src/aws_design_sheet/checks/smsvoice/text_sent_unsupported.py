"""Checks for AWS::SMSVOICE::ConfigurationSet."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SMSVOICE_TEXT_SENT_UNSUPPORTED': [CF+'aws-properties-smsvoice-configurationset-eventdestination.html'],
}


@resource_check('AWS::SMSVOICE::ConfigurationSet')
def evaluate_smsvoice_text_sent_unsupported(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::SMSVOICE::ConfigurationSet':
        for path in expand(ctx,resource,'/properties/EventDestinations/*/MatchingEventTypes/*'):
            raw=value(ctx,resource,path)
            emit('SMSVOICE_TEXT_SENT_UNSUPPORTED',path,'NEEDS_REVIEW' if not literal(raw) else 'FAIL' if raw=='TEXT_SENT' else 'PASS','TEXT_SENT is unsupported; PASS only means this prohibited value is absent, not that other event names are supported; unknown values and destination state remain held')
    return results
