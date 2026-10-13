"""Checks for AWS::VpcLattice::TargetGroup."""
import ipaddress
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'VPCLATTICE_TARGET_ID_FORM': [CF+'aws-properties-vpclattice-targetgroup-target.html',CF+'aws-resource-lambda-function.html',CF+'aws-resource-elasticloadbalancingv2-loadbalancer.html','https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/resources.html'],
}


def target_id_form(kind,raw):
    if not literal(raw):return 'NEEDS_REVIEW'
    if kind=='INSTANCE':
        if re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})',raw):return 'PASS'
        return 'NEEDS_REVIEW' if raw.startswith('i-') else 'FAIL'
    if kind=='IP':
        if '%' in raw:return 'NEEDS_REVIEW'
        try:ipaddress.ip_address(raw)
        except ValueError:return 'FAIL'
        return 'PASS'
    if kind not in ('LAMBDA','ALB'):return 'NEEDS_REVIEW'
    parts=raw.split(':',5)
    if len(parts)!=6 or parts[0]!='arn':return 'FAIL'
    _,partition,service,region,account,name=parts
    if partition not in ('aws','aws-cn','aws-us-gov') or not re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+',region) or not re.fullmatch(r'[0-9]{12}',account):return 'NEEDS_REVIEW'
    if kind=='LAMBDA':
        if service!='lambda' or not name.startswith('function:'):return 'FAIL'
        return 'PASS' if re.fullmatch(r'function:[A-Za-z0-9_-]{1,64}',name) else 'NEEDS_REVIEW'
    if service!='elasticloadbalancing' or not name.startswith('loadbalancer/app/'):return 'FAIL'
    return 'PASS' if re.fullmatch(r'loadbalancer/app/[A-Za-z0-9-]+/[0-9a-f]+',name) else 'NEEDS_REVIEW'


@resource_check('AWS::VpcLattice::TargetGroup')
def evaluate_vpclattice_target_id_form(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::VpcLattice::TargetGroup':
        kind=get('/properties/Type')
        for path in expand(ctx,resource,'/properties/Targets/*/Id'):
            emit('VPCLATTICE_TARGET_ID_FORM',path,target_id_form(kind,get(path)),'checks bounded literal instance IDs, IP addresses, unqualified Lambda ARNs and application-load-balancer ARNs; qualifiers, unknown partitions/forms/references and actual targets remain under review')
    return results
