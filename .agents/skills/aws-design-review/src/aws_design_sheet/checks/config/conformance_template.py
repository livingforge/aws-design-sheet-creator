"""Bounded, non-executing inspection of Config conformance template bodies."""
import yaml
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent, DocumentStartEvent
from yaml.nodes import MappingNode, ScalarNode
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'CONFIG_CONFORMANCE_TEMPLATE_CONTENT':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-conformancepack.html']}
ALLOWED={'AWS::Config::ConfigRule','AWS::Config::RemediationConfiguration'}
TAGS={'!Ref','!Sub','!GetAtt','!If','!Join','!FindInMap','!Select','!Split','!ImportValue','!GetAZs','!Base64','!Equals','!Not','!And','!Or','!Condition','!Cidr','!Length','!ToJsonString'}


def mapping(node):
    if not isinstance(node,MappingNode) or node.tag!='tag:yaml.org,2002:map':return None
    result={}
    for key,val in node.value:
        if not isinstance(key,ScalarNode) or key.value in result:return None
        result[key.value]=val
    return result


def content(raw):
    if not isinstance(raw,str):return 'NEEDS_REVIEW'
    try:size=len(raw.encode('utf8'))
    except UnicodeError:return 'NEEDS_REVIEW'
    if not 1<=size<=51200:return 'FAIL'
    try:
        depth=documents=0
        for n,event in enumerate(yaml.parse(raw,Loader=yaml.BaseLoader)):
            tag=getattr(event,'tag',None)
            if n>10000 or isinstance(event,AliasEvent):return 'NEEDS_REVIEW'
            if tag and tag not in TAGS and not tag.startswith('tag:yaml.org,2002:'):return 'NEEDS_REVIEW'
            if isinstance(event,DocumentStartEvent):
                documents+=1
                if documents>1:return 'NEEDS_REVIEW'
            if isinstance(event,CollectionStartEvent):
                depth+=1
                if depth>64:return 'NEEDS_REVIEW'
            if isinstance(event,CollectionEndEvent):depth-=1
        root=mapping(yaml.compose(raw,Loader=yaml.BaseLoader))
    except (yaml.YAMLError,RecursionError,UnicodeError):return 'NEEDS_REVIEW'
    if root is None or 'Transform' in root:return 'NEEDS_REVIEW'
    resources=mapping(root.get('Resources'))
    if not resources:return 'NEEDS_REVIEW'
    pending=False
    for name,node in resources.items():
        row=mapping(node)
        if name.startswith('Fn::') or row is None:pending=True;continue
        kind=row.get('Type')
        if not isinstance(kind,ScalarNode) or kind.tag!='tag:yaml.org,2002:str' or not literal(kind.value):pending=True;continue
        if kind.value not in ALLOWED:
            if 'Condition' in row:pending=True
            else:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::Config::ConformancePack')
def evaluate_config_conformance_template(design,resource):
    if resource.type!='AWS::Config::ConformancePack':return []
    ctx=_Context(design,resource);path='/properties/TemplateBody';raw=value(ctx,resource,path)
    if raw is ABSENT:return []
    f=ctx.finding('CONFIG_CONFORMANCE_TEMPLATE_CONTENT',path,content(raw) if resolved(resource) else 'NEEDS_REVIEW','Check the supplied body UTF-8 byte limit and explicit ConfigRule/RemediationConfiguration resource types. YAML is parsed as nodes without executing tags. Conditional unsupported resources, aliases, macros, dynamic types and bounded-parser limits remain reviewable. S3/SSM object content and general template validity are not certified.')
    f['source_checked_at']='2026-10-04';return [f]
