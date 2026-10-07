"""Offline schema, namespace, IdP profile and resolver boundary checks."""
import shutil

import pytest

from aws_design_sheet import saml_metadata as saml
from aws_design_sheet.checks.registry import run_resource_checks
from test_artifacts import material, metadata
from test_autoscaling_group_and_scaling_policy import target
from test_autoscaling_group_nested_constraints import design


def valid_metadata(material):
    return (metadata(material[2])
        .replace('<IDPSSODescriptor>', '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">')
        .replace('</IDPSSODescriptor>', '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></IDPSSODescriptor>'))


def test_valid_schema_and_idp(material):
    a, b, digest = saml.validate_metadata(valid_metadata(material))
    assert (a, b) == ('PASS', 'PASS')
    assert len(digest) == 64


@pytest.mark.parametrize('mutation', ['namespace', 'issuer', 'endpoint', 'protocol-missing',
    'unexpected', 'order', 'bad-date', 'duplicate-id', 'signature'])
def test_xsd_rejects_structurally_invalid_metadata(material, mutation):
    xml = valid_metadata(material)
    if mutation == 'namespace':
        xml = xml.replace('urn:oasis:names:tc:SAML:2.0:metadata', 'urn:wrong')
    elif mutation == 'issuer':
        xml = xml.replace(' entityID="test"', '')
    elif mutation == 'endpoint':
        xml = xml.replace(' Location="https://idp.example.test/sso"', '')
    elif mutation == 'protocol-missing':
        xml = xml.replace(' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"', '')
    elif mutation == 'unexpected':
        xml = xml.replace('</EntityDescriptor>', '<Unexpected/></EntityDescriptor>')
    elif mutation == 'order':
        xml = xml.replace('<KeyDescriptor>', '<SingleSignOnService Binding="urn:test" Location="https://idp.example.test/"/><KeyDescriptor>')
    elif mutation == 'bad-date':
        xml = xml.replace('entityID="test"', 'entityID="test" validUntil="not-a-date"')
    elif mutation == 'duplicate-id':
        xml = xml.replace('entityID="test"', 'entityID="test" ID="same"').replace('<IDPSSODescriptor ', '<IDPSSODescriptor ID="same" ')
    elif mutation == 'signature':
        xml = xml.replace('<IDPSSODescriptor ', '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/><IDPSSODescriptor ')
    assert saml.validate_metadata(xml)[:2] == ('FAIL', 'NEEDS_REVIEW')


def test_profile_does_not_select_an_issuer_or_external_key(material):
    xml = valid_metadata(material)
    aggregate = '<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">' + xml + '</EntitiesDescriptor>'
    assert saml.validate_metadata(aggregate)[:2] == ('PASS', 'NEEDS_REVIEW')
    encryption_only = xml.replace('<KeyDescriptor>', '<KeyDescriptor use="encryption">')
    assert saml.validate_metadata(encryption_only)[:2] == ('PASS', 'NEEDS_REVIEW')
    other_protocol = xml.replace('urn:oasis:names:tc:SAML:2.0:protocol', 'urn:example:other')
    assert saml.validate_metadata(other_protocol)[:2] == ('PASS', 'FAIL')
    empty_issuer = xml.replace('entityID="test"', 'entityID=""')
    assert saml.validate_metadata(empty_issuer)[:2] == ('PASS', 'FAIL')


def test_no_runtime_network_or_dynamic_schema_loading(material, monkeypatch):
    import socket
    def forbidden(*args, **kwargs):
        raise AssertionError('unexpected network access')
    monkeypatch.setattr(socket, 'socket', forbidden)
    saml.schema_bundle.cache_clear()
    xml = valid_metadata(material).replace('entityID="test"',
        'entityID="test" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:metadata https://never-fetch.invalid/a.xsd"')
    assert saml.validate_metadata(xml)[:2] == ('PASS', 'PASS')
    entity = '<!DOCTYPE a [<!ENTITY attack SYSTEM "file:///never-read">]><a>&attack;</a>'
    assert saml.validate_metadata(entity)[:2] == ('FAIL', 'NEEDS_REVIEW')


def test_tampered_schema_is_review_not_a_design_failure(material, tmp_path, monkeypatch):
    shutil.copytree(saml.ROOT, tmp_path / 'saml')
    (tmp_path / 'saml/xml.xsd').write_text('tampered', encoding='utf-8')
    saml.schema_bundle.cache_clear()
    with monkeypatch.context() as m:
        m.setattr(saml, 'ROOT', tmp_path / 'saml')
        assert saml.validate_metadata(valid_metadata(material)) == ('NEEDS_REVIEW', 'NEEDS_REVIEW', None)
    saml.schema_bundle.cache_clear()


def test_findings_include_schema_provenance(material):
    resource = target('idp', 'AWS::IAM::SAMLProvider', SamlMetadataDocument=valid_metadata(material))
    rows = {r['rule_id']: r for r in run_resource_checks(design(resource), resource)}
    for rule in ['IAM_SAML_METADATA_SCHEMA', 'IAM_SAML_IDP_METADATA']:
        assert rows[rule]['verdict'] == 'PASS'
        assert rows[rule]['evidence_ids'] and rows[rule]['schema_manifest_sha256']
