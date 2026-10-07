"""Checks for AWS::SES::EmailIdentity, AWS::SES::EmailIdentityCertificate, AWS::SES::ReceiptFilter."""
import ipaddress
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.policy_maps import plain_domain

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SES_MAIL_FROM_SUBDOMAIN': [CF+'aws-properties-ses-emailidentity-mailfromattributes.html'],
    'SES_CERTIFICATE_FROM_IDENTITY': [CF+'aws-resource-ses-emailidentitycertificate.html'],
    'SES_RECEIPT_IP_FILTER': [CF+'aws-properties-ses-receiptfilter-ipfilter.html'],
}


def mailbox(raw):
    """Bounded ASCII dot-atom mailbox; quoted/IDN/display-name forms remain held."""
    if not literal(raw) or raw.count('@')!=1:return None
    local,domain=raw.split('@')
    if len(local)>64 or not plain_domain(domain):return None
    if not all(re.fullmatch(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+",part) for part in local.split('.')):return None
    return local,domain


@resource_check('AWS::SES::EmailIdentity', 'AWS::SES::EmailIdentityCertificate', 'AWS::SES::ReceiptFilter')
def evaluate_ses_runtime_bounds(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::SES::EmailIdentity':
        path='/properties/MailFromAttributes/MailFromDomain';domain=get(path);identity=get('/properties/EmailIdentity')
        if domain is not ABSENT:
            verdict='NEEDS_REVIEW'
            if plain_domain(domain) and plain_domain(identity):verdict='PASS' if domain.endswith('.'+identity) else 'FAIL'
            emit('SES_MAIL_FROM_SUBDOMAIN',path,verdict,'literal lowercase ASCII MAIL FROM domain must be a strict subdomain of a domain identity; mailbox identities, IDN/case variants and actual verification/MX/receiving/feedback usage remain under review')
    if resource.type=='AWS::SES::EmailIdentityCertificate':
        path='/properties/FromAddress';address=get(path);identity=get('/properties/EmailIdentity');parsed=mailbox(address);other=mailbox(identity);verdict='NEEDS_REVIEW'
        if parsed:
            if plain_domain(identity):verdict='PASS' if parsed[1]==identity or parsed[1].endswith('.'+identity) else 'FAIL'
            elif other:verdict='PASS' if address==identity else 'FAIL'
        emit('SES_CERTIFICATE_FROM_IDENTITY',path,verdict,'bounded ASCII FromAddress must belong to domain identity or its subdomain, or exactly match mailbox identity; omitted values, quoted/IDN/case-variant domains and certificate state remain under review')
    if resource.type=='AWS::SES::ReceiptFilter':
        path='/properties/Filter/IpFilter';raw=get(path)
        if raw is not ABSENT:
            cidr=get(path+'/Cidr');policy=get(path+'/Policy');pending=not literal(cidr) or not literal(policy);invalid=literal(policy) and policy not in ('Block','Allow')
            if literal(cidr):
                # Dotted netmasks and scoped IPv6 addresses are held.
                if '%' in cidr or '/' in cidr and not re.fullmatch(r'[0-9]{1,3}',cidr.rsplit('/',1)[1]):pending=True
                else:
                    try:
                        if '/' in cidr:ipaddress.ip_network(cidr,strict=False)
                        else:ipaddress.ip_address(cidr)
                    except ValueError:invalid=True
            emit('SES_RECEIPT_IP_FILTER',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','checks literal IP address/numeric CIDR and Block/Allow policy; host bits are allowed by documented example; dotted masks and scoped addresses remain held, actual SES regional support is external')
    return results
