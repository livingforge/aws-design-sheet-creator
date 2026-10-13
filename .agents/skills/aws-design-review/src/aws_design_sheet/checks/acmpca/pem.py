"""Bounded explicit PEM parsing; never establishes issuer trust or live CA state."""
import re
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
API = 'https://docs.aws.amazon.com/privateca/latest/APIReference/'
SOURCES = {
    'ACMPCA_CSR_SUBJECT': [CF+'aws-resource-acmpca-certificate.html', API+'API_IssueCertificate.html'],
    'ACMPCA_ACTIVATION_PEM': [CF+'aws-resource-acmpca-certificateauthorityactivation.html'],
    'ACMPCA_ACTIVATION_CHAIN_PRESENCE': [CF+'aws-resource-acmpca-certificateauthorityactivation.html', API+'API_ImportCertificateAuthorityCertificate.html'],
}
LIMIT = 65536


def parse_pem(raw, csr=False):
    if not literal(raw) or len(raw) > LIMIT:
        return 'NEEDS_REVIEW', None
    label = r'(?:NEW )?CERTIFICATE REQUEST' if csr else 'CERTIFICATE'
    pattern = r'\s*-----BEGIN ('+label+r')-----\s+([A-Za-z0-9+/=\s]+)-----END \1-----\s*'
    # Noncanonical wrappers may be accepted by a service; do not reject them.
    if not re.fullmatch(pattern, raw):
        return 'NEEDS_REVIEW', None
    try:
        obj = (x509.load_pem_x509_csr if csr else x509.load_pem_x509_certificate)(raw.encode('ascii'))
        return 'PASS', obj
    except UnsupportedAlgorithm:
        return 'NEEDS_REVIEW', None
    except (ValueError, UnicodeError):
        return 'FAIL', None


def csr_subject(raw):
    verdict, csr = parse_pem(raw, csr=True)
    if csr is None:
        return verdict
    try:
        if len(csr.subject):
            return 'PASS'
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return 'PASS' if len(san.value) else 'FAIL'
    except x509.ExtensionNotFound:
        return 'FAIL'
    except (ValueError, UnsupportedAlgorithm, x509.DuplicateExtension):
        return 'NEEDS_REVIEW'


@resource_check('AWS::ACMPCA::Certificate', 'AWS::ACMPCA::CertificateAuthorityActivation')
def evaluate_acmpca_pem(design, resource):
    ctx = _Context(design, resource)
    specs = {
        'AWS::ACMPCA::Certificate': ('ACMPCA_CSR_SUBJECT', 'CertificateSigningRequest', csr_subject,
            'bounded PEM CSR parsing and presence of subject or SAN only; signature, template, issuer constraints and live CA state remain open'),
        'AWS::ACMPCA::CertificateAuthorityActivation': ('ACMPCA_ACTIVATION_PEM', 'Certificate', lambda raw: parse_pem(raw)[0],
            'bounded single X.509 PEM parsing only; chain, key correspondence, CA extensions, validity and trust remain open'),
    }
    findings = []
    if resource.type == 'AWS::ACMPCA::CertificateAuthorityActivation':
        ca = linked(ctx, resource, '/properties/CertificateAuthorityArn', 'AWS::ACMPCA::CertificateAuthority')
        kind = value(ctx, ca, '/properties/Type') if resolved(resource) and resolved(ca) else None
        chain = value(ctx, resource, '/properties/CertificateChain')
        verdict = 'NEEDS_REVIEW'
        if kind in ('ROOT', 'SUBORDINATE'):
            if chain is ABSENT:
                verdict = 'PASS' if kind == 'ROOT' else 'FAIL'
            elif literal(chain):
                verdict = 'FAIL' if kind == 'ROOT' else 'PASS'
        finding = ctx.finding('ACMPCA_ACTIVATION_CHAIN_PRESENCE', '/properties/CertificateChain', verdict,
            'explicit linked CA type determines chain presence only; certificate self-signature, chain ordering, trust and key correspondence remain open')
        finding['source_checked_at'] = '2026-10-04'
        findings.append(finding)
    if resource.type not in specs:
        return []
    rule, key, check, reason = specs[resource.type]
    path = '/properties/'+key
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return findings
    finding = ctx.finding(rule, path, check(raw), reason)
    finding['source_checked_at'] = '2026-10-04'
    return [finding]+findings
