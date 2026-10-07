"""Private CA import critical-extension policy on supplied bounded PEMs."""
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from ..registry import resource_check
from .chains import BLOCK
from .pem import API, parse_pem
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES={'ACMPCA_IMPORT_CRITICAL_EXTENSIONS':[API+'API_ImportCertificateAuthorityCertificate.html']}
CRITICAL_ALLOWED={
 '2.5.29.35','2.5.29.19','2.5.29.32','2.5.29.37','2.5.29.54','2.5.29.18',
 '2.5.29.15','2.5.29.30','2.5.29.33','2.5.29.17','2.5.29.9','2.5.29.14',
 '1.3.6.1.5.5.7.1.11',
}


def import_extensions(raw):
    _,cert=parse_pem(raw)
    if cert is None:return 'NEEDS_REVIEW'
    try:
        extensions=list(cert.extensions)
        basic=cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not basic.critical or not basic.value.ca:return 'FAIL'
        if any(e.critical and e.oid.dotted_string not in CRITICAL_ALLOWED for e in extensions):return 'FAIL'
        return 'PASS'
    except x509.ExtensionNotFound:
        return 'FAIL'
    except (ValueError,x509.DuplicateExtension,UnsupportedAlgorithm):
        return 'NEEDS_REVIEW'


@resource_check('AWS::ACMPCA::CertificateAuthorityActivation')
def evaluate_acmpca_extensions(design,resource):
    if resource.type!='AWS::ACMPCA::CertificateAuthorityActivation':return []
    ctx=_Context(design,resource);results=[]
    def emit(path,verdict):
        f=ctx.finding('ACMPCA_IMPORT_CRITICAL_EXTENSIONS',path,verdict,'CA import requires critical CA basic constraints and only AWS-allowlisted critical extensions; extension values, path length, identity, validity, trust and live CA key correspondence remain open')
        f['source_checked_at']='2026-10-04';results.append(f)
    raw=value(ctx,resource,'/properties/Certificate')
    if raw is not ABSENT:emit('/properties/Certificate',import_extensions(raw))
    path='/properties/CertificateChain';raw=value(ctx,resource,path)
    if raw is not ABSENT:
        if not literal(raw) or len(raw)>1048576:verdict='NEEDS_REVIEW'
        else:
            blocks=BLOCK.findall(raw)
            if not blocks or len(blocks)>32 or BLOCK.sub('',raw).strip():verdict='NEEDS_REVIEW'
            else:
                verdicts=[import_extensions(b) for b in blocks]
                verdict='FAIL' if 'FAIL' in verdicts else 'NEEDS_REVIEW' if 'NEEDS_REVIEW' in verdicts else 'PASS'
        emit(path,verdict)
    return results
