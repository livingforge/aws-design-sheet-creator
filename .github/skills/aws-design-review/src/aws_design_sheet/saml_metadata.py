"""Offline SAML 2.0 XSD and IdP-role checks against pinned official schemas."""
from functools import lru_cache
import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from lxml import etree
from xml.etree.ElementTree import ParseError

ROOT = Path(__file__).resolve().parents[2] / 'schemas/saml'
MD = '{urn:oasis:names:tc:SAML:2.0:metadata}'
DS = '{http://www.w3.org/2000/09/xmldsig#}'
PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'


class PinnedResolver(etree.Resolver):
    def __init__(self, documents):
        self.documents = documents

    def resolve(self, url, public_id, context):
        if url not in self.documents:
            raise OSError('schema dependency is not pinned')
        return self.resolve_string(self.documents[url], context, base_url=url)


@lru_cache(maxsize=1)
def schema_bundle():
    manifest_bytes = (ROOT / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    documents = {}
    for item in manifest['files']:
        path = ROOT / item['file']
        if path.resolve().parent != ROOT.resolve():
            raise ValueError('schema file outside pinned directory')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise ValueError('pinned SAML schema hash mismatch')
        if b'encoding="US-ASCII"' in raw[:100]:
            # libxml2's schema-import reader rejects this encoding alias in
            # some builds. ASCII bytes are identical UTF-8; preserve the
            # downloaded file and normalize only the in-memory declaration.
            raw.decode('ascii')
            raw = raw.replace(b'encoding="US-ASCII"', b'encoding="UTF-8"', 1)
        documents[item['url']] = raw
        documents[item['url'].replace('https://', 'http://', 1)] = raw
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
    parser.resolvers.add(PinnedResolver(documents))
    url = 'https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd'
    root = etree.fromstring(documents[url], parser=parser, base_url=url)
    return etree.XMLSchema(root), hashlib.sha256(manifest_bytes).hexdigest()


def validate_metadata(content):
    """No dynamic schemaLocation, DTD, entity, XInclude, or network resolution."""
    try:
        raw = content.encode('utf-8')
        # Reject DTD/entity declarations before passing the input to libxml2.
        ElementTree.fromstring(raw, forbid_dtd=True)
        parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
        parser.resolvers.add(PinnedResolver({}))
        root = etree.fromstring(raw, parser)
    except (ValueError, UnicodeError, ParseError, DefusedXmlException, etree.XMLSyntaxError):
        return 'FAIL', 'NEEDS_REVIEW', None
    try:
        schema, digest = schema_bundle()
    except (OSError, ValueError, etree.XMLSchemaParseError, etree.XMLSyntaxError):
        return 'NEEDS_REVIEW', 'NEEDS_REVIEW', None
    valid = schema.validate(root)
    if not valid:
        return 'FAIL', 'NEEDS_REVIEW', digest
    # Aggregates can contain multiple issuers. Do not select one implicitly.
    if root.tag != MD + 'EntityDescriptor':
        return 'PASS', 'NEEDS_REVIEW', digest
    descriptors = [d for d in root.findall(MD + 'IDPSSODescriptor')
                   if PROTOCOL in d.get('protocolSupportEnumeration', '').split()]
    if not root.get('entityID', '').strip() or not descriptors:
        return 'PASS', 'FAIL', digest
    signing_certificates = [cert for d in descriptors for k in d.findall(MD + 'KeyDescriptor')
                           if k.get('use') in (None, 'signing')
                           for cert in k.findall(DS + 'KeyInfo/' + DS + 'X509Data/' + DS + 'X509Certificate')]
    return 'PASS', ('PASS' if signing_certificates else 'NEEDS_REVIEW'), digest
