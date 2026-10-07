"""Checks for AWS::Cognito::UserPoolClient, AWS::Cognito::UserPoolUser."""
import re
from urllib.parse import urlsplit
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

SOURCES = {
    'COGNITO_USER_CONTACT_REQUIRED': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooluser.html',
    ],
    'COGNITO_CALLBACK_URI': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html',
    ],
}


@resource_check('AWS::Cognito::UserPoolUser', 'AWS::Cognito::UserPoolClient')
def evaluate_cognito_user_pool_client_and_user(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::Cognito::UserPoolUser':
  p='/properties/UserAttributes';raw=get(p);attrs={};pending=raw is not ABSENT and not isinstance(raw,list)
  for i in range(len(raw)) if isinstance(raw,list) else ():
   name=get(p+'/'+str(i)+'/Name');val=get(p+'/'+str(i)+'/Value')
   if not literal(name):pending=True;continue
   if name in attrs:pending=True
   attrs[name]=val
  mediums=get('/properties/DesiredDeliveryMediums');mediums=['SMS'] if mediums is ABSENT else mediums
  known=[x for x in mediums if literal(x)] if isinstance(mediums,list) else []
  for name,medium in [('email','EMAIL'),('phone_number','SMS')]:
   verified=attrs.get(name+'_verified');required=medium in known or verified in ('true','True')
   v='NEEDS_REVIEW'
   if required:
    v='PASS' if literal(attrs.get(name)) and not pending else 'FAIL' if name not in attrs and not pending else 'NEEDS_REVIEW'
    if get('/properties/MessageAction')=='SUPPRESS' and verified not in ('true','True'):v='NEEDS_REVIEW'
   elif isinstance(mediums,list) and all(literal(x) for x in mediums) and not pending and (verified is None or verified in ('false','False')):v='NOT_APPLICABLE'
   emit('COGNITO_USER_CONTACT_REQUIRED',p,v,'explicit delivery medium or verified attribute requires matching contact value; documented omitted delivery defaults SMS; suppressed delivery, duplicate/unknown attributes and unresolved flags held')
 if resource.type=='AWS::Cognito::UserPoolClient':
  for p in expand(ctx,resource,'/properties/CallbackURLs/*'):
   raw=get(p);v='NEEDS_REVIEW'
   if literal(raw):
    try:
     uri=urlsplit(raw)
     if not uri.scheme or '#' in raw or re.search(r'\s',raw):v='FAIL'
     elif uri.scheme=='https':v='PASS' if uri.hostname else 'FAIL'
     elif uri.scheme=='http':v='PASS' if uri.hostname in ('localhost','127.0.0.1','::1') else 'FAIL'
     # Custom app schemes are explicitly supported; do not reject or assume a universal grammar.
    except ValueError:v='FAIL'
   emit('COGNITO_CALLBACK_URI',p,v,'explicit callback URI is absolute and fragment-free; HTTPS or localhost HTTP allowed; custom app schemes and substitutions remain held rather than incorrectly enforcing HTTPS-only')
 return results
