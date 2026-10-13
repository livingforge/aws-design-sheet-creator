"""Checks for AWS::Transcribe::CallAnalyticsCategory, AWS::Transcribe::VocabularyFilter."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

SOURCES = {
    'TRANSCRIBE_ABSOLUTE_TIME_PAIR': ['https://docs.aws.amazon.com/transcribe/latest/APIReference/API_AbsoluteTimeRange.html'],
    'TRANSCRIBE_FILTER_SOURCE_EXCLUSION': ['https://docs.aws.amazon.com/transcribe/latest/APIReference/API_CreateVocabularyFilter.html'],
}


def time_pair(ctx,r,path):
    if not isinstance(value(ctx,r,path),dict):return 'NEEDS_REVIEW'
    a=value(ctx,r,path+'/StartTime');b=value(ctx,r,path+'/EndTime')
    valid=lambda x:type(x) is int and 0<=x<=14400000
    if a is ABSENT and b is ABSENT:return 'PASS'
    if valid(a) and valid(b):return 'PASS'
    if valid(a) and b is ABSENT or valid(b) and a is ABSENT:return 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check('AWS::Transcribe::CallAnalyticsCategory', 'AWS::Transcribe::VocabularyFilter')
def evaluate_transcribe_analytics_and_filters(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Transcribe::CallAnalyticsCategory':
        seen=set()
        for kind in ('NonTalkTimeFilter','InterruptionFilter','TranscriptFilter','SentimentFilter'):
            for path in expand(ctx,resource,'/properties/Rules/*/'+kind+'/AbsoluteTimeRange'):
                if path in seen:continue
                seen.add(path)
                emit('TRANSCRIBE_ABSOLUTE_TIME_PAIR',path,time_pair(ctx,resource,path),'explicit absolute StartTime/EndTime must occur together; PASS covers pair presence only; relative ranges, ordering, First/Last combinations, realtime applicability and unavailable CloudFormation documentation remain held')
    if resource.type=='AWS::Transcribe::VocabularyFilter':
        words=value(ctx,resource,'/properties/Words');uri=value(ctx,resource,'/properties/VocabularyFilterFileUri')
        if words is not ABSENT or uri is not ABSENT:
            known_words=isinstance(words,list)
            known_uri=literal(uri)
            verdict='FAIL' if known_words and known_uri else 'PASS' if known_words and uri is ABSENT or known_uri and words is ABSENT else 'NEEDS_REVIEW'
            emit('TRANSCRIBE_FILTER_SOURCE_EXCLUSION','/properties',verdict,'explicit Words and VocabularyFilterFileUri cannot both be supplied; PASS covers exclusion only; neither-present requiredness, unknowns, content/language/Region checks and unavailable CloudFormation documentation remain held')
    return results
