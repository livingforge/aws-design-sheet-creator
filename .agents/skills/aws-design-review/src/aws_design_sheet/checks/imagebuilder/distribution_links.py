"""Image Builder recipe/distribution compatibility with explicit references."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-properties-imagebuilder-distributionconfiguration-distribution.html',CF+'aws-resource-imagebuilder-imagerecipe.html',CF+'aws-resource-imagebuilder-image.html',CF+'aws-resource-imagebuilder-imagepipeline.html'] for rule in ('IMAGEBUILDER_DISTRIBUTION_RECIPE_TYPE','IMAGEBUILDER_WATERMARK_PUBLIC_DISTRIBUTION')}
CONSUMERS=('AWS::ImageBuilder::Image','AWS::ImageBuilder::ImagePipeline')
DIST='AWS::ImageBuilder::DistributionConfiguration'
RECIPE='AWS::ImageBuilder::ImageRecipe'


def reference(ctx,r,path,kind):
    if not resolved(r):return None
    other=linked(ctx,r,path,kind)
    if not resolved(other):return None
    raw=read(ctx,r,path)
    if raw is ABSENT:return other
    if not literal(raw):return None
    category={DIST:'distribution-configuration',RECIPE:'image-recipe','AWS::ImageBuilder::ContainerRecipe':'container-recipe'}[kind]
    suffix=r'/([0-9]+\.[0-9]+\.[0-9]+)' if kind!=DIST else ''
    m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:imagebuilder:([a-z0-9-]+):([0-9]{12}):'+category+r'/([^/]+)'+suffix,raw)
    if not m or (m[1],m[2],m[3])!=(other.scope.region,other.scope.account,value(ctx,other,'/properties/Name')):return None
    if kind!=DIST and m[4]!=value(ctx,other,'/properties/Version'):return None
    return other


def recipe(ctx,consumer):
    choices=[]
    for name,kind in [('ImageRecipeArn',RECIPE),('ContainerRecipeArn','AWS::ImageBuilder::ContainerRecipe')]:
        path='/properties/'+name
        if read(ctx,consumer,path) is not ABSENT or any(ref.source_resource_id==consumer.id and ref.source_path==path for ref in ctx.design.relations):choices.append((path,kind))
    if len(choices)!=1:return None
    return reference(ctx,consumer,*choices[0])


def distribution_kind(ctx,dist):
    rows=value(ctx,dist,'/properties/Distributions')
    if not isinstance(rows,list) or not 1<=len(rows)<=1000:return None
    kinds=set()
    for i in range(len(rows)):
        base=f'/properties/Distributions/{i}/'
        ami=value(ctx,dist,base+'AmiDistributionConfiguration');container=value(ctx,dist,base+'ContainerDistributionConfiguration')
        if isinstance(ami,dict) and container is ABSENT:kinds.add(RECIPE)
        elif isinstance(container,dict) and ami is ABSENT:kinds.add('AWS::ImageBuilder::ContainerRecipe')
        else:return None
    return kinds


def public(ctx,dist):
    rows=value(ctx,dist,'/properties/Distributions')
    if not isinstance(rows,list) or not 1<=len(rows)<=1000:return None
    pending=False
    for i in range(len(rows)):
        base=f'/properties/Distributions/{i}/AmiDistributionConfiguration'
        if not isinstance(value(ctx,dist,base),dict):pending=True;continue
        groups=value(ctx,dist,base+'/LaunchPermissionConfiguration/UserGroups')
        if groups is ABSENT:continue
        if not isinstance(groups,list):pending=True;continue
        if 'all' in groups:return True
        if any(not literal(v) for v in groups):pending=True
    return None if pending else False


def watermarked(ctx,r):
    raw=value(ctx,r,'/properties/AmiWatermarks')
    return isinstance(raw,list) and 1<=len(raw)<=5 and all(literal(v) for v in raw)


@resource_check(DIST,RECIPE)
def evaluate_imagebuilder_distribution_links(design,resource):
    ctx=_Context(design,resource);pairs=[];pending=False
    for consumer in design.resources:
        if consumer.type not in CONSUMERS:continue
        path='/properties/DistributionConfigurationArn' if resource.type==DIST else '/properties/ImageRecipeArn'
        refs=[ref for ref in design.relations if ref.source_resource_id==consumer.id and ref.source_path==path and ref.target_resource_id==resource.id]
        if not refs:continue
        dist=reference(ctx,consumer,'/properties/DistributionConfigurationArn',DIST);rec=recipe(ctx,consumer)
        if dist is None or rec is None or (dist if resource.type==DIST else rec) is not resource:pending=True;continue
        pairs.append((dist,rec))
    verdicts=[]
    if resource.type==DIST:
        kinds=distribution_kind(ctx,resource) if resolved(resource) else None
        known=[r.type for _,r in pairs]
        verdict='FAIL' if kinds and any(kinds!={k} for k in known) else 'PASS' if kinds and known and not pending else 'NEEDS_REVIEW'
        verdicts.append(('IMAGEBUILDER_DISTRIBUTION_RECIPE_TYPE','/properties/Distributions',verdict))
    seen=False;held=pending;failed=False
    for dist,rec in pairs:
        if rec.type!=RECIPE:continue
        if not watermarked(ctx,rec):held=True;continue
        pub=public(ctx,dist)
        if pub is True:failed=True
        elif pub is None:held=True
        else:seen=True
    verdicts.append(('IMAGEBUILDER_WATERMARK_PUBLIC_DISTRIBUTION','/properties/AmiWatermarks' if resource.type==RECIPE else '/properties/Distributions','FAIL' if failed else 'PASS' if seen and not held else 'NEEDS_REVIEW'))
    out=[]
    for rule,path,verdict in verdicts:
        f=ctx.finding(rule,path,verdict,'Explicit Image/ImagePipeline recipe and distribution references must agree on image/container type. A recipe with explicit AMI watermarks cannot use launch-permission UserGroups all. Absence of recipe watermarks does not establish absence of inherited parent-image watermarks. Conditional/ambiguous references, recipe versions, unknown consumers and external resources remain reviewable. PASS is limited to declared consumers and does not establish distribution availability or live permissions.')
        f['source_checked_at']='2026-10-04';out.append(f)
    return out
