"""Parameter-name coverage of explicitly selected inline workflow documents."""
import re
from ..registry import resource_check
from ..common.bounded_yaml import bounded_yaml
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'IMAGEBUILDER_WORKFLOW_PARAMETER_NAMES':[CF+'aws-properties-imagebuilder-image-workflowconfiguration.html',CF+'aws-resource-imagebuilder-workflow.html','https://docs.aws.amazon.com/imagebuilder/latest/userguide/image-workflow-create-document.html','https://docs.aws.amazon.com/imagebuilder/latest/APIReference/API_StartImagePipelineExecution.html']}


def workflow(ctx,r,path):
    if not resolved(r):return None
    target=linked(ctx,r,path,'AWS::ImageBuilder::Workflow')
    if not resolved(target):return None
    # Full build-version IDs cannot be matched to a declaration's semantic
    # Version without an explicit deployed build ID. Wildcards are also held.
    raw=read(ctx,r,path)
    if raw is not ABSENT:return None
    if value(ctx,target,'/properties/Uri') is not ABSENT:return None
    data=value(ctx,target,'/properties/Data')
    if not literal(data) or len(data)>16000:return None
    try:
        if len(data.encode('utf8'))>16000:return None
    except UnicodeError:return None
    _,doc=bounded_yaml(data)
    if not isinstance(doc,dict) or doc.get('schemaVersion')!='1.0':return None
    params=doc.get('parameters',[])
    if not isinstance(params,list) or len(params)>25:return None
    definitions={}
    for item in params:
        if not isinstance(item,dict):return None
        name=item.get('name');typ=item.get('type')
        if not literal(name) or not re.fullmatch(r'[A-Za-z0-9_-]+',name) or name in definitions:return None
        if typ not in ('string','integer','boolean','stringList'):return None
        definitions[name]='default' in item
    return definitions


def parameters(ctx,r,path):
    definitions=workflow(ctx,r,path+'/WorkflowArn')
    if definitions is None:return 'NEEDS_REVIEW'
    raw=value(ctx,r,path+'/Parameters')
    if raw is ABSENT:raw=[]
    if not isinstance(raw,list) or len(raw)>25:return 'NEEDS_REVIEW'
    names=set();pending=False
    for i in range(len(raw)):
        name=value(ctx,r,path+f'/Parameters/{i}/Name')
        if not literal(name):pending=True;continue
        if name not in definitions:return 'FAIL'
        if name in names:pending=True
        names.add(name)
    if pending:return 'NEEDS_REVIEW'
    if any(not default and name not in names for name,default in definitions.items()):return 'FAIL'
    return 'PASS'


@resource_check('AWS::ImageBuilder::Image', 'AWS::ImageBuilder::ImagePipeline')
def evaluate_imagebuilder_workflow_parameters(design,resource):
    if resource.type not in ('AWS::ImageBuilder::Image','AWS::ImageBuilder::ImagePipeline'):return []
    ctx=_Context(design,resource);result=[]
    for path in expand(ctx,resource,'/properties/Workflows/*'):
        verdict=parameters(ctx,resource,path) if path.count('/')==3 else 'NEEDS_REVIEW'
        f=ctx.finding('IMAGEBUILDER_WORKFLOW_PARAMETER_NAMES',path,verdict,'Match parameter names to a selected inline workflow document and require inputs without defaults. PASS verifies name coverage only. Parameter-value types, runtime expressions, external documents, literal/wildcard version selections and pipeline DeploymentId provenance remain separate. YAML is parsed as bounded data; aliases, duplicate keys and custom tags are held without execution.')
        f['source_checked_at']='2026-10-04';result.append(f)
    return result
