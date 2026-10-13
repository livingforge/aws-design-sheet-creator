"""Cross-realm password presence based on an explicit EMR security configuration."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved
from ..common.strict_json import parse

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'EMR_CROSS_REALM_PASSWORD_REQUIREMENT':[CF+'aws-properties-emr-cluster-kerberosattributes.html',CF+'aws-resource-emr-securityconfiguration.html','https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-create-security-configuration.html','https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos-configure-settings.html']}


def document(raw):
    if isinstance(raw,str):return parse(raw)
    if not isinstance(raw,dict):return None
    stack=[(raw,0)];count=0;size=0
    while stack:
        obj,depth=stack.pop();count+=1
        if count>10000 or depth>64:return None
        if isinstance(obj,dict):
            if any(not isinstance(k,str) or k.startswith(('$','Fn::')) or k=='Ref' for k in obj):return None
            size+=sum(len(k) for k in obj)
            stack.extend((v,depth+1) for v in obj.values())
        elif isinstance(obj,list):stack.extend((v,depth+1) for v in obj)
        elif isinstance(obj,str):
            size+=len(obj)
            if '${' in obj or '{{' in obj:return None
        elif obj is not None and type(obj) not in (bool,int,float):return None
        if size>30000:return None
    return raw


def configured(ctx,r):
    if not resolved(r):return None
    config=linked(ctx,r,'/properties/SecurityConfiguration','AWS::EMR::SecurityConfiguration')
    if not resolved(config):return None
    name=read(ctx,r,'/properties/SecurityConfiguration')
    if name is not ABSENT and (not literal(name) or name!=value(ctx,config,'/properties/Name')):return None
    node=document(value(ctx,config,'/properties/SecurityConfiguration'))
    if node is None:return None
    auth=node.get('AuthenticationConfiguration',{})
    kerberos=auth.get('KerberosConfiguration',{}) if isinstance(auth,dict) else None
    if not isinstance(kerberos,dict) or kerberos.get('Provider')!='ClusterDedicatedKdc':return None
    dedicated=kerberos.get('ClusterDedicatedKdcConfiguration')
    if not isinstance(dedicated,dict) or 'ExternalKdcConfiguration' in kerberos:return None
    trust=dedicated.get('CrossRealmTrustConfiguration',ABSENT)
    if trust is ABSENT:return False
    if not isinstance(trust,dict) or not all(literal(trust.get(k)) for k in ('Realm','Domain','AdminServer','KdcServer')):return None
    return True


@resource_check('AWS::EMR::Cluster')
def evaluate_emr_kerberos_trust(design,resource):
    if resource.type!='AWS::EMR::Cluster':return []
    ctx=_Context(design,resource);trust=configured(ctx,resource)
    path='/properties/KerberosAttributes/CrossRealmTrustPrincipalPassword'
    raw=value(ctx,resource,path)
    if trust is False:verdict='NOT_APPLICABLE'
    elif trust is None:verdict='NEEDS_REVIEW'
    elif raw is ABSENT:verdict='FAIL'
    else:verdict='PASS' if literal(raw) else 'NEEDS_REVIEW'
    f=ctx.finding('EMR_CROSS_REALM_PASSWORD_REQUIREMENT',path,verdict,'An explicit cluster-dedicated KDC cross-realm trust requires a principal password. PASS establishes declared literal presence only; the value is not included in this reason and is not compared to external secrets. Unknown/dynamic security JSON, unresolved name references, external KDCs, actual Active Directory usage and cross-realm password equality remain reviewable. A generic domain name does not prove Active Directory.')
    f['source_checked_at']='2026-10-04';return [f]
