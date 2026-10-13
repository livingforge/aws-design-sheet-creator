"""Checks for AWS::Bedrock::Prompt."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BEDROCK_PROMPT_DEFAULT_VARIANT': [CF+'aws-resource-bedrock-prompt.html'],
}


@resource_check('AWS::Bedrock::Prompt')
def evaluate_bedrock_prompt_default_variant(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Bedrock::Prompt':
        path='/properties/DefaultVariant';default=get(path)
        if default is not ABSENT:
            variants=get('/properties/Variants');pending=variants is not ABSENT and not isinstance(variants,list);matches=False
            for i in range(len(variants)) if isinstance(variants,list) else ():
                name=get('/properties/Variants/'+str(i)+'/Name')
                if not literal(name):pending=True
                elif name==default:matches=True
            verdict='NEEDS_REVIEW' if not literal(default) else 'PASS' if matches else 'NEEDS_REVIEW' if pending else 'FAIL'
            emit('BEDROCK_PROMPT_DEFAULT_VARIANT',path,verdict,'literal DefaultVariant must equal a Name in Variants; known membership suffices even with other unknown names; duplicate names, variant contents and external model support remain separate')
    return results
