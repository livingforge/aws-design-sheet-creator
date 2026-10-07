"""OpenZFS parent-chain storage class and reservation upper bounds."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-properties-fsx-volume-openzfsconfiguration.html',CF+'aws-resource-fsx-filesystem.html','https://docs.aws.amazon.com/fsx/latest/OpenZFSGuide/creating-volumes.html'] for rule in ('FSX_OPENZFS_RECORD_SIZE_CLASS','FSX_OPENZFS_PARENT_RESERVATION_BOUND')}
BASE='/properties/OpenZFSConfiguration'


def parents(ctx,r):
    seen=set()
    for _ in range(32):
        if not resolved(r) or r.id in seen:return
        seen.add(r.id)
        if r.type=='AWS::FSx::FileSystem':
            if value(ctx,r,'/properties/FileSystemType')=='OPENZFS':yield r
            return
        if r.type!='AWS::FSx::Volume' or value(ctx,r,'/properties/VolumeType')!='OPENZFS':return
        yield r
        r=linked(ctx,r,BASE+'/ParentVolumeId','AWS::FSx::Volume') or linked(ctx,r,BASE+'/ParentVolumeId','AWS::FSx::FileSystem')


@resource_check('AWS::FSx::Volume')
def evaluate_fsx_volume_parent(design,resource):
    if resource.type!='AWS::FSx::Volume':return []
    ctx=_Context(design,resource);kind=value(ctx,resource,'/properties/VolumeType')
    if literal(kind) and kind!='OPENZFS':return []
    chain=list(parents(ctx,resource));known=bool(chain) and chain[0] is resource
    fs=chain[-1] if known and chain[-1].type=='AWS::FSx::FileSystem' else None
    size=value(ctx,resource,BASE+'/RecordSizeKiB');reserve=value(ctx,resource,BASE+'/StorageCapacityReservationGiB')
    record='NEEDS_REVIEW';bound='NEEDS_REVIEW'
    if known:
        if size is ABSENT:record='NOT_APPLICABLE'
        elif fs is not None and type(size) is int:
            storage=value(ctx,fs,'/properties/StorageType')
            allowed=(128,256,512,1024,2048,4096) if storage=='INTELLIGENT_TIERING' else (4,8,16,32,64,128,256,512,1024) if storage is ABSENT or storage=='SSD' else None
            if allowed is not None:record='PASS' if size in allowed else 'FAIL'
        if type(reserve) is int and reserve in (0,-1):bound='NOT_APPLICABLE'
        elif type(reserve) is int and reserve>0:
            for parent in chain[1:]:
                if parent is resource:break
                if parent.type=='AWS::FSx::Volume':upper=value(ctx,parent,BASE+'/StorageCapacityQuotaGiB')
                else:
                    storage=value(ctx,parent,'/properties/StorageType')
                    upper=value(ctx,parent,'/properties/StorageCapacity') if storage is ABSENT or storage=='SSD' else None
                if type(upper) is int and upper>=0 and reserve>upper:bound='FAIL';break
    results=[]
    for rule,key,verdict in [('FSX_OPENZFS_RECORD_SIZE_CLASS','RecordSizeKiB',record),('FSX_OPENZFS_PARENT_RESERVATION_BOUND','StorageCapacityReservationGiB',bound)]:
        f=ctx.finding(rule,BASE+'/'+key,verdict,'Follow explicit same-scope OpenZFS parent volumes to the file system root, bounded to 32 resources. Record size values depend on SSD/default versus Intelligent-Tiering. A reservation above a known ancestor quota or SSD filesystem capacity fails; a smaller reservation does not prove available space because sibling reservations and live usage are unknown. Zero/-1 disables reservation. Cycles, conditional links, unknown templates and dynamic fields remain reviewable.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
