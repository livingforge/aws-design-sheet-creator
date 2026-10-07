"""Checks for AWS::Bedrock::Agent."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BEDROCK_AGENT_OVERRIDE_PARSER': [CF+'aws-properties-bedrock-agent-'+s+'.html' for s in ('promptoverrideconfiguration','promptconfiguration')],
}


@resource_check('AWS::Bedrock::Agent')
def evaluate_bedrock_agent_override_parser(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Bedrock::Agent':
        base='/properties/PromptOverrideConfiguration'
        if get(base) is not ABSENT:
            raw=get(base+'/PromptConfigurations');function=get(base+'/OverrideLambda');found=False;pending=not isinstance(raw,list)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                mode=get(base+'/PromptConfigurations/'+str(i)+'/ParserMode')
                if mode=='OVERRIDDEN':found=True
                elif mode!='DEFAULT':pending=True
            verdict='NEEDS_REVIEW'
            if found:verdict='FAIL' if function is ABSENT else 'PASS' if literal(function) else 'NEEDS_REVIEW'
            elif not pending:verdict='PASS' if function is ABSENT else 'FAIL' if literal(function) else 'NEEDS_REVIEW'
            emit('BEDROCK_AGENT_OVERRIDE_PARSER',base,verdict,'OverrideLambda and at least one explicit OVERRIDDEN ParserMode require each other; omitted/unknown modes and unresolved function remain held; Lambda ARN validity, existence and permissions are separate')
    return results
