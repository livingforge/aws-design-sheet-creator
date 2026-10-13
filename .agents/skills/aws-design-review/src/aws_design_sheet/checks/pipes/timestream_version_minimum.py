"""Checks for AWS::Pipes::Pipe."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'PIPES_TIMESTREAM_VERSION_MINIMUM': ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-pipes-pipe-pipetargettimestreamparameters.html'],
}


def version_minimum(raw):
    if not literal(raw) or len(raw)>256 or not re.fullmatch(r'-?[0-9]+',raw):return 'NEEDS_REVIEW'
    return 'PASS' if int(raw)>=1 else 'FAIL'


@resource_check('AWS::Pipes::Pipe')
def evaluate_pipes_timestream_version_minimum(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Pipes::Pipe':
        path='/properties/TargetParameters/TimestreamParameters/VersionValue';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('PIPES_TIMESTREAM_VERSION_MINIMUM',path,version_minimum(raw),'bounded explicit decimal integer string must be at least one; PASS covers lower bound only; dynamic event paths, alternate number spellings, 64-bit upper bound and existing-record versions remain held')
    return results
