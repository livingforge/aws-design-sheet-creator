"""Connect attachment transport type from an explicit resource reference."""
from ..registry import resource_check
from ..common.context_values import _Context, linked
from ..common.field_reads import ABSENT, read
from ..common.scoped_resolution import resolved

SOURCES={'NETWORK_MANAGER_CONNECT_TRANSPORT_TYPE':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-networkmanager-connectattachment.html']}


def transport(ctx,r):
    path='/properties/TransportAttachmentId'
    if not resolved(r) or read(ctx,r,path) is not ABSENT:return 'NEEDS_REVIEW'
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if len(refs)!=1 or refs[0].condition:return 'NEEDS_REVIEW'
    matches=[other for other in ctx.design.resources if other.id==refs[0].target_resource_id]
    if len(matches)!=1 or not resolved(matches[0]):return 'NEEDS_REVIEW'
    other=matches[0]
    if linked(ctx,r,path,other.type) is not other:return 'NEEDS_REVIEW'
    return 'PASS' if other.type=='AWS::NetworkManager::VpcAttachment' else 'FAIL'


@resource_check('AWS::NetworkManager::ConnectAttachment')
def evaluate_networkmanager_transport(design,resource):
    if resource.type!='AWS::NetworkManager::ConnectAttachment':return []
    ctx=_Context(design,resource)
    f=ctx.finding('NETWORK_MANAGER_CONNECT_TRANSPORT_TYPE','/properties/TransportAttachmentId',transport(ctx,resource),'A Connect attachment uses a VPC attachment as transport. An explicit resolved relation must target AWS::NetworkManager::VpcAttachment. Literal IDs without deployed identity evidence, conditional references, ambiguous targets and missing inventory remain reviewable. PASS establishes declared transport type, not deployed availability or network reachability.')
    f['source_checked_at']='2026-10-04';return [f]
