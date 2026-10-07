"""Checks for AWS::Glue::Registry, AWS::Glue::Schema, AWS::Glue::Session."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

API='https://docs.aws.amazon.com/glue/latest/webapi/'
CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GLUE_REGISTRY_NAME_CHARACTERS': [CF+'aws-resource-glue-registry.html',API+'API_CreateRegistry.html'],
    'GLUE_SCHEMA_NAME_CHARACTERS': [CF+'aws-resource-glue-schema.html',API+'API_CreateSchema.html'],
    'GLUE_SESSION_VERSION_FLOOR': [CF+'aws-resource-glue-session.html',API+'API_CreateSession.html'],
}


def name_characters(raw):
    if not literal(raw) or len(raw)>255:
        return 'NEEDS_REVIEW'
    # Both descriptions and API patterns exclude these ASCII characters.
    # Period is in the API pattern but absent from the prose; Unicode letter
    # interpretation is also held, rather than rejecting an ambiguous spelling.
    if any(ord(c)<128 and not re.fullmatch(r'[A-Za-z0-9_$#.-]',c) for c in raw):
        return 'FAIL'
    return 'PASS' if re.fullmatch(r'[A-Za-z0-9_$#-]+',raw) else 'NEEDS_REVIEW'


def session_version(raw):
    if not literal(raw) or len(raw)>32 or not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)',raw):
        return 'NEEDS_REVIEW'
    return 'PASS' if tuple(map(int,raw.split('.')))>(2,0) else 'FAIL'


@resource_check('AWS::Glue::Registry', 'AWS::Glue::Schema', 'AWS::Glue::Session')
def evaluate_glue_names_and_session_version(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type in ('AWS::Glue::Registry','AWS::Glue::Schema'):
        path='/properties/Name'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            emit('GLUE_REGISTRY_NAME_CHARACTERS' if resource.type.endswith('Registry') else 'GLUE_SCHEMA_NAME_CHARACTERS',path,name_characters(raw),'check agreed ASCII name characters; period conflict, Unicode interpretation and unknown names remain held')
    if resource.type=='AWS::Glue::Session':
        path='/properties/GlueVersion'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            emit('GLUE_SESSION_VERSION_FLOOR',path,session_version(raw),'explicit canonical major.minor version must exceed 2.0 per CFN and API; actual supported versions and alternate spellings remain separate')
    return results
