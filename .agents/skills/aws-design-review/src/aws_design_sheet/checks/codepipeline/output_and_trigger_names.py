"""Checks for AWS::CodePipeline::Pipeline."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEPIPELINE_OUTPUT_UNIQUE': [CF+'aws-properties-codepipeline-pipeline-outputartifact.html'],
    'CODEPIPELINE_TRIGGER_SOURCE': [CF+'aws-properties-codepipeline-pipeline-gitconfiguration.html',CF+'aws-properties-codepipeline-pipeline-pipelinetriggerdeclaration.html'],
}


def trigger_source(ctx,resource,path,actions,names):
    name=value(ctx,resource,path+'/GitConfiguration/SourceActionName')
    if not literal(name):return 'NEEDS_REVIEW'
    if names.count(name)>1:return 'FAIL'
    if value(ctx,resource,path+'/ProviderType')!='CodeStarSourceConnection':return 'NEEDS_REVIEW'
    matches=[];pending=False
    for action in actions:
        candidate=value(ctx,resource,action+'/Name')
        if not literal(candidate):pending=True
        elif candidate==name:matches.append(action)
    if len(matches)>1 or pending:return 'NEEDS_REVIEW'
    if not matches:return 'FAIL'
    category=value(ctx,resource,matches[0]+'/ActionTypeId/Category');provider=value(ctx,resource,matches[0]+'/ActionTypeId/Provider')
    if not literal(category) or not literal(provider):return 'NEEDS_REVIEW'
    return 'PASS' if category=='Source' and provider=='CodeStarSourceConnection' else 'FAIL'


@resource_check('AWS::CodePipeline::Pipeline')
def evaluate_codepipeline_output_and_trigger_names(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CodePipeline::Pipeline':
        seen=set();pending=False;duplicate=False
        for p in expand(ctx,resource,'/properties/Stages/*/Actions/*/OutputArtifacts/*'):
            name=get(p+'/Name')
            if not literal(name):pending=True;continue
            if name in seen:duplicate=True
            seen.add(name)
        if get('/properties/Stages') is not ABSENT:
            emit('CODEPIPELINE_OUTPUT_UNIQUE','/properties/Stages','FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS','literal output artifact names must be unique across all pipeline actions; unknown arrays/names remain held; input references and action ordering are separate')
        paths=list(expand(ctx,resource,'/properties/Triggers/*'));actions=list(expand(ctx,resource,'/properties/Stages/*/Actions/*'))
        names=[get(p+'/GitConfiguration/SourceActionName') for p in paths];names=[n for n in names if literal(n)]
        for path in paths:
            emit('CODEPIPELINE_TRIGGER_SOURCE',path,trigger_source(ctx,resource,path,actions,names),'one trigger per literal SourceActionName; name must resolve unambiguously to a Source/CodeStarSourceConnection action in this pipeline; unknown/duplicate action names and external connections remain held')
    return results
