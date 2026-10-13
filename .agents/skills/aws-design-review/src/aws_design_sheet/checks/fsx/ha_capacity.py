"""ONTAP storage and throughput arithmetic with explicit HA-pair counts."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-resource-fsx-filesystem.html',CF+'aws-properties-fsx-filesystem-ontapconfiguration.html',CF+'aws-properties-fsx-filesystem-diskiopsconfiguration.html','https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/performance.html','https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/storage-capacity-and-IOPS.html'] for rule in ('FSX_ONTAP_HA_STORAGE','FSX_ONTAP_HA_THROUGHPUT')}
BASE='/properties/OntapConfiguration'


@resource_check('AWS::FSx::FileSystem')
def evaluate_fsx_ha_capacity(design,resource):
    if resource.type!='AWS::FSx::FileSystem':return []
    ctx=_Context(design,resource);kind=value(ctx,resource,'/properties/FileSystemType')
    if literal(kind) and kind!='ONTAP':return []
    pairs=value(ctx,resource,BASE+'/HAPairs')
    if pairs is ABSENT:pairs=1
    ready=kind=='ONTAP' and type(pairs) is int and 1<=pairs<=12 and (resource.template is None or resource.template.state.value=='KNOWN')
    storage=value(ctx,resource,'/properties/StorageCapacity');storage_type=value(ctx,resource,'/properties/StorageType')
    storage_verdict='NEEDS_REVIEW'
    if ready and type(storage) is int and (storage_type is ABSENT or storage_type=='SSD'):
        storage_verdict='PASS' if 1024*pairs<=storage<=min(524288*pairs,1048576) else 'FAIL'
    deployment=value(ctx,resource,BASE+'/DeploymentType')
    total=value(ctx,resource,BASE+'/ThroughputCapacity');per=value(ctx,resource,BASE+'/ThroughputCapacityPerHAPair')
    throughput_verdict='NEEDS_REVIEW'
    if ready and isinstance(deployment,str):
        allowed={'SINGLE_AZ_1':(128,256,512,1024,2048,4096),'MULTI_AZ_1':(128,256,512,1024,2048,4096),'MULTI_AZ_2':(384,768,1536,3072,6144),'SINGLE_AZ_2':((384,768) if pairs==1 else ())+ (1536,3072,6144)}.get(deployment)
        if allowed is not None and (pairs==1 or deployment=='SINGLE_AZ_2'):
            # The descriptions disagree about supplying both throughput fields.
            # Do not certify or reject that combination from these sources.
            if type(total) is int and per is ABSENT:
                throughput_verdict='PASS' if any(total==pairs*x for x in allowed) else 'FAIL'
            elif total is ABSENT and type(per) is int:
                throughput_verdict='PASS' if per in allowed else 'FAIL'
    results=[]
    for rule,path,verdict in [('FSX_ONTAP_HA_STORAGE','/properties/StorageCapacity',storage_verdict),('FSX_ONTAP_HA_THROUGHPUT',BASE+'/ThroughputCapacity',throughput_verdict)]:
        f=ctx.finding(rule,path,verdict,'ONTAP SSD capacity is 1024–524288 GiB per HA pair, capped at 1048576 GiB total. Compare total throughput with HA pairs times a documented per-pair value using integer arithmetic; second-generation single-AZ 384/768 MBps requires one pair. Default HA pairs is one. Both throughput fields, unresolved settings, restore-derived capacity and IOPS formula discrepancies remain reviewable; no live performance or Region availability claim.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
