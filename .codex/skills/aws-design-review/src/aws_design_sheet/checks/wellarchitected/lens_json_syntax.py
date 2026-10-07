"""Checks for AWS::WellArchitected::Lens."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.json_verdict import json_verdict

SOURCES = {
    'WELLARCHITECTED_LENS_JSON_SYNTAX': ['https://docs.aws.amazon.com/wellarchitected/latest/APIReference/API_ImportLens.html'],
}


@resource_check('AWS::WellArchitected::Lens')
def evaluate_wellarchitected_lens_json_syntax(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::WellArchitected::Lens':
        path='/properties/JSONString';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('WELLARCHITECTED_LENS_JSON_SYNTAX',path,json_verdict(raw),'bounded JSON syntax only, not lens schema/content; requiredness, version semantics, oversized/dynamic input and unavailable CloudFormation documentation remain held')
    return results
