"""Explicit Direct Connect LAG member properties and gateway ASN relations."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'DIRECTCONNECT_LAG_MEMBER_SETTINGS':[CF+'aws-resource-directconnect-lag.html',CF+'aws-resource-directconnect-connection.html'],
 'DIRECTCONNECT_TRANSIT_GATEWAY_ASN_DIFFERENT':[CF+'aws-resource-directconnect-transitvirtualinterface.html',CF+'aws-resource-directconnect-directconnectgatewayassociation.html',CF+'aws-resource-directconnect-directconnectgateway.html',CF+'aws-resource-ec2-transitgateway.html'],
}
DCG='AWS::DirectConnect::DirectConnectGateway'
TGW='AWS::EC2::TransitGateway'


def explicit(ctx,r,path,kind):
    if not resolved(r):return None
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if len(refs)!=1 or refs[0].condition:return None
    raw=read(ctx,r,path)
    if raw is not ABSENT and not literal(raw):return None
    other=ctx.by_id.get(refs[0].target_resource_id)
    if not resolved(other) or other.type!=kind or other.scope.environment!=r.scope.environment:return None
    if literal(raw) and raw.startswith('arn:'):
        if kind==DCG:
            m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:directconnect::([0-9]{12}):dx-gateway/[0-9a-f-]{36}',raw)
            if not m or m[1]!=other.scope.account:return None
        elif kind==TGW:
            m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:ec2:([a-z0-9-]+):([0-9]{12}):transit-gateway/tgw-[a-zA-Z0-9]{8,32}',raw)
            if not m or (m[1],m[2])!=(other.scope.region,other.scope.account):return None
    ctx.evidence.extend(refs[0].evidence_ids)
    return other


def asn(ctx,r):
    raw=value(ctx,r,'/properties/AmazonSideAsn')
    if raw is ABSENT:return 64512
    if r.type==DCG:
        if not isinstance(raw,str) or not re.fullmatch(r'[1-9][0-9]{0,9}',raw):return None
        raw=int(raw)
    return raw if type(raw) is int and 0<raw<4294967295 else None


def gateway_asn(ctx,r):
    gateway=explicit(ctx,r,'/properties/DirectConnectGatewayId',DCG)
    if gateway is None:return 'NEEDS_REVIEW'
    own=asn(ctx,gateway)
    if own is None:return 'NEEDS_REVIEW'
    seen=False;pending=False
    for association in ctx.design.resources:
        if association.type!='AWS::DirectConnect::DirectConnectGatewayAssociation':continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==association.id and ref.source_path=='/properties/DirectConnectGatewayId' and ref.target_resource_id==gateway.id]
        if not refs:continue
        if explicit(ctx,association,'/properties/DirectConnectGatewayId',DCG) is not gateway:pending=True;continue
        peer=explicit(ctx,association,'/properties/AssociatedGatewayId',TGW)
        if peer is None:pending=True;continue
        remote=asn(ctx,peer)
        if remote is None:pending=True;continue
        if own==remote:return 'FAIL'
        seen=True
    return 'PASS' if seen and not pending else 'NEEDS_REVIEW'


def bandwidth(raw):
    m=re.fullmatch(r'([1-9][0-9]{0,11})(M|G)bps',raw) if literal(raw) else None
    return int(m[1])*(1000 if m[2]=='G' else 1) if m else None


def lag_settings(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    speeds=set();locations=set();pending=False;seen=False
    rows=[r]
    for other in ctx.design.resources:
        if other.type!='AWS::DirectConnect::Connection':continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==other.id and ref.source_path=='/properties/LagId' and ref.target_resource_id==r.id]
        if not refs:continue
        if not resolved(other) or linked(ctx,other,'/properties/LagId',r.type) is not r:pending=True;continue
        seen=True;rows.append(other)
    for other in rows:
        speed=bandwidth(value(ctx,other,'/properties/'+('ConnectionsBandwidth' if other is r else 'Bandwidth')))
        location=value(ctx,other,'/properties/Location')
        if speed is None:pending=True
        else:speeds.add(speed)
        if not literal(location) or not re.fullmatch(r'[a-zA-Z0-9-]+',location):pending=True
        else:locations.add(location)
    if len(speeds)>1 or len(locations)>1:return 'FAIL'
    return 'PASS' if seen and not pending else 'NEEDS_REVIEW'


@resource_check('AWS::DirectConnect::Lag','AWS::DirectConnect::TransitVirtualInterface')
def evaluate_directconnect_relations(design,resource):
    ctx=_Context(design,resource)
    if resource.type=='AWS::DirectConnect::Lag':
        rule='DIRECTCONNECT_LAG_MEMBER_SETTINGS';path='/properties/ConnectionsBandwidth';verdict=lag_settings(ctx,resource)
        reason='Explicit LAG members must share declared bandwidth and location; normalize Mbps/Gbps units. Matching locations do not establish live physical endpoint allocation or absence of external members.'
    elif resource.type=='AWS::DirectConnect::TransitVirtualInterface':
        rule='DIRECTCONNECT_TRANSIT_GATEWAY_ASN_DIFFERENT';path='/properties/DirectConnectGatewayId';verdict=gateway_asn(ctx,resource)
        reason='Direct Connect gateway and its explicitly associated transit gateways must use different ASNs, including their documented 64512 defaults. Cross-Region/account references remain explicit and template/ARN guarded; no IAM, association existence or connectivity claim.'
    else:return []
    f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';return [f]
