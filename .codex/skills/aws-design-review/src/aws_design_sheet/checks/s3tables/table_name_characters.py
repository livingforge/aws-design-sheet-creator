"""Checks for AWS::S3Tables::Table."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'S3TABLES_TABLE_NAME_CHARACTERS': [CF+'aws-resource-s3tables-table.html'],
}


@resource_check('AWS::S3Tables::Table')
def evaluate_s3tables_table_name_characters(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    def enum(raw,allowed):return 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL'
    if resource.type=='AWS::S3Tables::Table':
        path='/properties/TableName';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('S3TABLES_TABLE_NAME_CHARACTERS',path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if re.fullmatch(r'[0-9a-z_]+',raw) else 'FAIL','literal table name uses documented lowercase ASCII letters/digits/underscore; schema length, unknown names and actual namespace/table state remain separate')
    return results
