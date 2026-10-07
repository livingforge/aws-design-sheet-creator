"""Checks for AWS::MediaPackageV2::OriginEndpoint."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand

SOURCES = {
    'MEDIAPACKAGE_DVB_PROFILE': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-mediapackagev2-originendpoint-dashbaseurl.html',
    ],
}


@resource_check('AWS::MediaPackageV2::OriginEndpoint')
def evaluate_mediapackagev2_dvb_profile(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::MediaPackageV2::OriginEndpoint':
  for base in expand(ctx,resource,'/properties/DashManifests/*'):
   profiles=get(base+'/Profiles')
   for key in ('DvbPriority','DvbWeight'):
    for p in expand(ctx,resource,base+'/BaseUrls/*/'+key):
     v='NEEDS_REVIEW'
     if isinstance(profiles,list):
      names=[get(base+'/Profiles/'+str(i)) for i in range(len(profiles))]
      v='PASS' if 'DVB_DASH' in names else 'FAIL' if not names else 'NEEDS_REVIEW'
     emit('MEDIAPACKAGE_DVB_PROFILE',p,v,'DVB-only fields require DVB_DASH profile; explicit empty profiles fail; omitted/unknown/future profiles held')
 return results
