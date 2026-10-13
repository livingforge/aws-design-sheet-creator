"""Checks for AWS::Rekognition::StreamProcessor."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'REKOGNITION_STREAM_NAME_CHARACTERS': ['https://docs.aws.amazon.com/rekognition/latest/APIReference/API_StreamProcessor.html'],
}


@resource_check('AWS::Rekognition::StreamProcessor')
def evaluate_rekognition_stream_name_characters(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Rekognition::StreamProcessor':
        path='/properties/Name';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('REKOGNITION_STREAM_NAME_CHARACTERS',path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if re.fullmatch(r'[a-zA-Z0-9_.-]+',raw) else 'FAIL','entire literal name uses API-documented characters; schema handles length, unknown/generated names and actual stream state remain held')
    return results
