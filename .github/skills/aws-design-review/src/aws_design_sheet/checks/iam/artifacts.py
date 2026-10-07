"""Checks for AWS::IAM::ServerCertificate, AWS::IAM::SAMLProvider."""
import base64
import binascii
import re
from xml.etree.ElementTree import ParseError
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from ...saml_metadata import validate_metadata
from ..registry import resource_check
from ..common.artifact_values import value
from ..common.context_values import CFN, _Context
from ..common.field_reads import ABSENT, UNKNOWN

IAM_GUIDE = 'https://docs.aws.amazon.com/IAM/latest/UserGuide/'
SOURCES = {
    'IAM_SERVER_CERTIFICATE_MATERIAL': [CFN + 'aws-resource-iam-servercertificate.html',
        IAM_GUIDE + 'id_credentials_server-certs.html',
        'https://docs.aws.amazon.com/IAM/latest/APIReference/API_UploadServerCertificate.html'],
    'IAM_SAML_METADATA_CONTENT': [IAM_GUIDE + 'id_roles_providers_create_saml.html'],
    'IAM_SAML_METADATA_SCHEMA': [IAM_GUIDE + 'id_roles_providers_create_saml.html',
        'https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd'],
    'IAM_SAML_IDP_METADATA': [IAM_GUIDE + 'id_roles_providers_create_saml.html',
        'https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd'],
    'IAM_SAML_PRIVATE_KEY_PEM': [CFN + 'aws-resource-iam-samlprovider.html',
        IAM_GUIDE + 'id_roles_providers_create_saml.html'],
}
PEM_CERT = re.compile(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----')


def certificates(text):
    blocks = PEM_CERT.findall(text)
    if not blocks or PEM_CERT.sub('', text).strip():
        raise ValueError('invalid PEM certificate sequence')
    return [x509.load_pem_x509_certificate(block.encode('ascii')) for block in blocks]


def public_bytes(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@resource_check('AWS::IAM::ServerCertificate')
def server_material(design, resource):
    ctx = _Context(design, resource)
    body, key, chain = [value(ctx, resource, '/properties/' + p)
                        for p in ('CertificateBody', 'PrivateKey', 'CertificateChain')]
    if body is ABSENT and key is ABSENT and chain is ABSENT:
        return []
    verdict = 'NEEDS_REVIEW'
    try:
        certs = certificates(body) if isinstance(body, str) else None
        private = serialization.load_pem_private_key(key.encode('utf-8'), password=None) if isinstance(key, str) else None
        issuers = certificates(chain) if isinstance(chain, str) else []
        if certs is not None and len(certs) != 1:
            verdict = 'FAIL'
        elif certs and private:
            if public_bytes(certs[0].public_key()) != public_bytes(private.public_key()):
                verdict = 'FAIL'
            elif chain is UNKNOWN:
                verdict = 'NEEDS_REVIEW'
            else:
                preceding = certs[0]
                for issuer in issuers:
                    preceding.verify_directly_issued_by(issuer)
                    preceding = issuer
                verdict = 'PASS' if chain is ABSENT or isinstance(chain, str) else 'NEEDS_REVIEW'
    except UnsupportedAlgorithm:
        verdict = 'NEEDS_REVIEW'
    except (ValueError, TypeError, UnicodeError, InvalidSignature):
        verdict = 'FAIL'
    return [ctx.finding('IAM_SERVER_CERTIFICATE_MATERIAL', '/properties/CertificateBody', verdict,
        'checks PEM parsing, unencrypted private-key match and supplied chain order/signatures; upload-time validity and trust are not checked')]


@resource_check('AWS::IAM::SAMLProvider')
def saml_artifacts(design, resource):
    results = []
    for prop, rule in [('SamlMetadataDocument', 'IAM_SAML_METADATA_CONTENT'),
                       ('AddPrivateKey', 'IAM_SAML_PRIVATE_KEY_PEM')]:
        ctx = _Context(design, resource)
        path = '/properties/' + prop
        content = value(ctx, resource, path)
        if content is ABSENT:
            continue
        verdict = 'NEEDS_REVIEW'
        try:
            if isinstance(content, str):
                if prop == 'AddPrivateKey':
                    # AES-GCM/CBC describes assertion encryption, not the PEM
                    # container. Do not infer assertion algorithms from this key.
                    serialization.load_pem_private_key(content.encode('utf-8'), password=None)
                    verdict = 'PASS'
                elif content.startswith('\ufeff'):
                    verdict = 'FAIL'
                else:
                    root = ElementTree.fromstring(content.encode('utf-8'), forbid_dtd=True)
                    md = '{urn:oasis:names:tc:SAML:2.0:metadata}'
                    ds = '{http://www.w3.org/2000/09/xmldsig#}'
                    # A full SAML schema/issuer trust validator is deliberately
                    # not implied by this bounded syntax/certificate check.
                    entities = ([root] if root.tag == md + 'EntityDescriptor' else
                                list(root.iter(md + 'EntityDescriptor')))
                    if not entities or any(not e.get('entityID') for e in entities):
                        verdict = 'NEEDS_REVIEW'
                    else:
                        verdict = 'PASS'
                    nodes = list(root.iter(ds + 'X509Certificate'))
                    if not nodes:
                        verdict = 'NEEDS_REVIEW'
                    for node in nodes:
                        cert = x509.load_der_x509_certificate(base64.b64decode(''.join((node.text or '').split()), validate=True))
                        cert.extensions  # Raises on duplicated extensions.
                        size = getattr(cert.public_key(), 'key_size', None)
                        if size is None:
                            if verdict != 'FAIL':
                                verdict = 'NEEDS_REVIEW'
                        elif size < 1024:
                            verdict = 'FAIL'
        except UnsupportedAlgorithm:
            verdict = 'NEEDS_REVIEW'
        except TypeError:
            # Encrypted PEM requires information outside the current input.
            verdict = 'NEEDS_REVIEW'
        except (ValueError, UnicodeError, ParseError, DefusedXmlException, binascii.Error, x509.DuplicateExtension):
            verdict = 'FAIL'
        results.append(ctx.finding(rule, path, verdict,
            'checks provided PEM private-key structure only; assertion algorithms and IdP key correspondence require review'
            if prop == 'AddPrivateKey' else
            'checks XML/UTF-8 BOM and embedded X.509 key size/extensions; issuer trust, full SAML semantics and assertion validity are not checked; certificate expiry is not an IAM failure'))
        if prop == 'SamlMetadataDocument':
            schema_verdict, idp_verdict, digest = (validate_metadata(content) if isinstance(content, str)
                                                  else ('NEEDS_REVIEW', 'NEEDS_REVIEW', None))
            for extra_rule, extra_verdict, reason in [
                ('IAM_SAML_METADATA_SCHEMA', schema_verdict,
                 'validates pinned SAML 2.0 metadata/assertion/XMLDSig/XML Encryption XSDs offline; extension schemas and signature authenticity are not established'),
                ('IAM_SAML_IDP_METADATA', idp_verdict,
                 'checks a single issuer with a SAML 2.0 IdP role and embedded signing certificate; aggregates, externally resolved keys and live IdP trust require review')]:
                results.append({**ctx.finding(extra_rule, path, extra_verdict, reason),
                                'schema_manifest_sha256': digest})
    return results
