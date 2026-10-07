"""Certificate-chain signatures and local revocation settings, without AWS calls."""
import re
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from ..registry import resource_check
from .pem import API, CF, parse_pem
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES = {
    'ACMPCA_ACTIVATION_SELF_SIGNATURE': [API+'API_ImportCertificateAuthorityCertificate.html'],
    'ACMPCA_ACTIVATION_CHAIN_SIGNATURES': [API+'API_ImportCertificateAuthorityCertificate.html'],
    'ACMPCA_CRL_CNAME_PROTOCOL': [CF+'aws-properties-acmpca-certificateauthority-crlconfiguration.html'],
}
BLOCK = re.compile(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----')


def supported_key(cert):
    key = cert.public_key()
    return isinstance(key, ec.EllipticCurvePublicKey) or isinstance(key, rsa.RSAPublicKey) and key.key_size <= 8192


def self_signature(raw, kind):
    verdict, cert = parse_pem(raw)
    if cert is None or kind not in ('ROOT', 'SUBORDINATE'):
        return 'NEEDS_REVIEW'
    try:
        if not supported_key(cert):
            return 'NEEDS_REVIEW'
        self_signed = False
        if cert.subject == cert.issuer:
            try:
                cert.verify_directly_issued_by(cert)
                self_signed = True
            except InvalidSignature:
                pass
        return 'PASS' if self_signed == (kind == 'ROOT') else 'FAIL'
    except (ValueError, UnsupportedAlgorithm, TypeError):
        return 'NEEDS_REVIEW'


def chain_signatures(raw, chain):
    _, cert = parse_pem(raw)
    if cert is None or not literal(chain) or len(chain) > 1048576:
        return 'NEEDS_REVIEW'
    blocks = BLOCK.findall(chain)
    if not blocks or len(blocks) > 32 or BLOCK.sub('', chain).strip():
        return 'NEEDS_REVIEW'
    try:
        issuers = []
        for block in blocks:
            verdict, issuer = parse_pem(block)
            if issuer is None:
                return verdict
            issuers.append(issuer)
        all_certs = [cert]+issuers
        if not all(supported_key(c) for c in all_certs):
            return 'NEEDS_REVIEW'
        encoded = [c.public_bytes(serialization.Encoding.DER) for c in all_certs]
        if len(set(encoded)) != len(encoded):
            return 'FAIL'
        for child, issuer in zip(all_certs, issuers):
            child.verify_directly_issued_by(issuer)
        issuers[-1].verify_directly_issued_by(issuers[-1])
        return 'PASS'
    except UnsupportedAlgorithm:
        return 'NEEDS_REVIEW'
    except (ValueError, InvalidSignature):
        return 'FAIL'


@resource_check('AWS::ACMPCA::CertificateAuthority', 'AWS::ACMPCA::CertificateAuthorityActivation')
def evaluate_acmpca_chains(design, resource):
    ctx = _Context(design, resource); findings = []
    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason)
        f['source_checked_at'] = '2026-10-04'; findings.append(f)
    if resource.type == 'AWS::ACMPCA::CertificateAuthority':
        path = '/properties/RevocationConfiguration/CrlConfiguration/CustomCname'
        raw = value(ctx, resource, path)
        if raw is not ABSENT:
            verdict = 'NEEDS_REVIEW' if not literal(raw) else 'FAIL' if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', raw) else 'PASS'
            emit('ACMPCA_CRL_CNAME_PROTOCOL', path, verdict, 'explicit CNAME must omit protocol prefix; URI character grammar, CRL options, S3 policies and live revocation remain open')
    if resource.type == 'AWS::ACMPCA::CertificateAuthorityActivation':
        raw = value(ctx, resource, '/properties/Certificate')
        ca = linked(ctx, resource, '/properties/CertificateAuthorityArn', 'AWS::ACMPCA::CertificateAuthority')
        kind = value(ctx, ca, '/properties/Type') if resolved(resource) and resolved(ca) else None
        if raw is not ABSENT:
            emit('ACMPCA_ACTIVATION_SELF_SIGNATURE', '/properties/Certificate', self_signature(raw, kind), 'known linked ROOT requires self-signature; SUBORDINATE forbids it; RSA up to 8192 bits and EC only; CA key match, validity, extensions and trust remain open')
        chain = value(ctx, resource, '/properties/CertificateChain')
        if chain is not ABSENT:
            emit('ACMPCA_ACTIVATION_CHAIN_SIGNATURES', '/properties/CertificateChain', chain_signatures(raw, chain), 'bounded supplied chain excludes imported certificate, follows issuer/signature order and terminates at a self-signed root; trust, validity, CA constraints and live CA key identity remain open')
    return findings
