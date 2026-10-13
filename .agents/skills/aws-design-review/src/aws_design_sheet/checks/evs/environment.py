"""Checks for AWS::EVS::Environment."""
import ipaddress
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EVS_VLAN_NONOVERLAP': [CF+'aws-properties-evs-environment-initialvlans.html'],
    'EVS_VCF_HOSTNAMES': [CF+'aws-properties-evs-environment-vcfhostnames.html'],
}
VLANS=('VmkManagement','VmManagement','VMotion','VSan','VTep','EdgeVTep','NsxUpLink','Hcx','ExpansionVlan1','ExpansionVlan2')
HOSTNAMES=('CloudBuilder','Nsx','NsxEdge1','NsxEdge2','NsxManager1','NsxManager2','NsxManager3','SddcManager','VCenter')


def vlans(ctx,resource,path):
    raw=value(ctx,resource,path);pending=not isinstance(raw,dict);networks=[]
    if isinstance(raw,dict) and any(k not in VLANS+('IsHcxPublic','HcxNetworkAclId') for k in raw):pending=True
    for name in VLANS:
        cidr=value(ctx,resource,path+'/'+name+'/Cidr')
        if not literal(cidr):pending=True;continue
        try:
            if '/' not in cidr:raise ValueError('CIDR prefix required')
            net=ipaddress.IPv4Network(cidr,strict=True)
        except ValueError:pending=True;continue
        if any(net.overlaps(n) for n in networks):return 'FAIL'
        networks.append(net)
    return 'NEEDS_REVIEW' if pending else 'PASS'


def hostnames(ctx,resource,path):
    names=[];pending=False
    raw=value(ctx,resource,path)
    if not isinstance(raw,dict) or any(k not in HOSTNAMES for k in raw):pending=True
    for key in HOSTNAMES:
        name=value(ctx,resource,path+'/'+key)
        if not literal(name) or not re.fullmatch(r'[A-Za-z0-9-]+',name):pending=True;continue
        if name in names:return 'FAIL'
        names.append(name)
    if len({n.lower() for n in names})!=len(names):pending=True
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::EVS::Environment')
def evaluate_evs_environment(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::EVS::Environment':
        path='/properties/InitialVlans'
        if get(path) is not ABSENT:emit('EVS_VLAN_NONOVERLAP',path,vlans(ctx,resource,path),'known canonical IPv4 VLAN CIDRs must not overlap each other; missing/unknown/noncanonical members remain held; VPC subnets and IPAM allocation remain external')
        path='/properties/VcfHostnames'
        if get(path) is not ABSENT:emit('EVS_VCF_HOSTNAMES',path,hostnames(ctx,resource,path),'exact literal hostname duplicates across VCF components are forbidden; case-only collisions, missing/unknown names and DNS resolution remain held; VcfVersion applicability is separate')
    return results
