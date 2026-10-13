"""Bounded proofs for existing CFN review findings, not a source of invented values.

Only complete, unconditional imported CFN property declarations qualify.
The original unknown values and every unrelated finding remain intact.
"""
from __future__ import annotations

import re

from .models import ValueState
from .rule_engine import ABSENT, UNKNOWN, _Context


FLOW = 'EC2.FLOWLOG.'
PREFIX_RULES = {'RDS.DBCLUSTER.TAG_VALUE_PREFIX', 'RDS.DBSUBNETGROUP.TAG_VALUE_PREFIX'}
SUPPORTED = PREFIX_RULES | {'RDS.DBCLUSTER.KMS_KEY_REQUIRES_STORAGE_ENCRYPTED',
    'RDS.DBCLUSTER.LATEST_RESTORE_REQUIRES_SOURCE'} | {FLOW + suffix for suffix in (
    'CWL_DESTINATION_SPECIFIED', 'CWL_DESTINATION_ARN', 'S3_DESTINATION_ARN', 'FIREHOSE_DESTINATION_ARN')}


def refine_static_review(rule, resource, finding, evidence_locations):
    if finding['verdict'] != 'NEEDS_REVIEW' or rule.id not in SUPPORTED:
        return finding
    template = resource.template
    if not template or template.state != ValueState.KNOWN or template.property_presence is None:
        return finding
    context = _Context(resource)
    declaration_sources = {evidence_locations[e] for e in template.evidence_ids if e in evidence_locations}

    def source_field(path):
        field = resource.field('/'.join(path.split('/')[:3]))
        if not field or field.state not in (ValueState.KNOWN, ValueState.UNRESOLVED):
            return None
        candidates = [field.selected()] if field.state == ValueState.KNOWN else field.candidates
        if not candidates or not all(c and c.origin in ('extracted', 'reference') and
                {evidence_locations[e] for e in c.evidence_ids if e in evidence_locations} & declaration_sources
                for c in candidates):
            return None
        return field

    def supplied(name):
        path = '/properties/' + name
        declaration = template.property_presence.get(path, False)
        if declaration is False and resource.field(path) is not None:
            return None  # A later edit added a field; the old omission is stale.
        if declaration is True and source_field(path) is None:
            return None
        return declaration

    def value(name):
        return context.lookup('/properties/' + name)[0]

    def proven(verdict, reason, facts):
        return {**finding, 'verdict': verdict, 'reason': reason,
                'evidence_ids': sorted(set(finding.get('evidence_ids', [])) | set(template.evidence_ids)),
                'static_proof': {'basis': 'complete_cfn_property_declaration', 'facts': facts,
                                 'source_checked_at': '2026-10-10', 'source_urls': list(rule.source_urls)}}

    if rule.id in PREFIX_RULES and rule.assertion == {'op': 'matches', 'path': '/Value', 'pattern': '^(?!(?:aws:|rds:))'}:
        hint = template.parameter_hints.get(finding['path'])
        if (hint and hint.type == 'String' and hint.no_echo is not True and hint.literal_prefix
                and source_field(finding['path']) is not None and context.lookup(finding['path'])[0] is UNKNOWN):
            prefix = hint.literal_prefix
            prohibited = ('aws:', 'rds:')
            if any(prefix.startswith(p) for p in prohibited):
                return proven('FAIL', 'fixed literal prefix violates the tag-prefix constraint; remaining value is unresolved', {'literal_prefix': prefix})
            if all(not p.startswith(prefix) for p in prohibited):
                return proven('PASS', 'fixed literal prefix excludes aws: and rds:; only the prefix constraint is proven', {'literal_prefix': prefix})
        return finding

    if rule.id == 'RDS.DBCLUSTER.KMS_KEY_REQUIRES_STORAGE_ENCRYPTED' and rule.assertion == {'op': 'field_equals', 'path': '/properties/StorageEncrypted', 'equals': True}:
        if value('StorageEncrypted') is True:
            return proven('PASS', 'StorageEncrypted is true, so the encryption requirement is satisfied even if KmsKeyId presence is unresolved', {'StorageEncrypted': True})
        return finding

    if rule.id == 'RDS.DBCLUSTER.LATEST_RESTORE_REQUIRES_SOURCE' and supplied('UseLatestRestorableTime') is False:
        return proven('NOT_APPLICABLE', 'complete CFN omits UseLatestRestorableTime; latest-time restore was not requested', {'UseLatestRestorableTime': 'omitted'})

    if not rule.id.startswith(FLOW):
        return finding
    destination = value('LogDestinationType')
    defaulted = supplied('LogDestinationType') is False
    if defaulted:
        destination = 'cloud-watch-logs'
    if destination in (ABSENT, UNKNOWN) or not isinstance(destination, str):
        return finding
    facts = {'LogDestinationType': destination, 'documented_default_used': defaulted}
    if rule.id == FLOW + 'CWL_DESTINATION_SPECIFIED':
        if destination == 'cloud-watch-logs' and any(supplied(p) is True for p in ('LogDestination', 'LogGroupName')):
            return proven('PASS', 'complete CFN definitely supplies a CloudWatch Logs destination property; its value still needs its own validation', facts)
        return finding
    kinds = {'S3_DESTINATION_ARN': 's3', 'CWL_DESTINATION_ARN': 'cloud-watch-logs',
             'FIREHOSE_DESTINATION_ARN': 'kinesis-data-firehose'}
    kind = kinds.get(rule.id.removeprefix(FLOW))
    if kind is None:
        return finding
    if destination != kind:
        return proven('NOT_APPLICABLE', 'effective CFN destination type does not select this ARN constraint', facts)
    if kind == 'cloud-watch-logs' and supplied('LogDestination') is False:
        return proven('NOT_APPLICABLE', 'complete CFN omits LogDestination ARN; LogGroupName is an allowed alternative and destination presence is checked separately', facts)
    arn = value('LogDestination')
    if isinstance(arn, str) and not arn.startswith('@') and rule.assertion.get('op') == 'matches':
        verdict = 'PASS' if re.search(rule.assertion['pattern'], arn) else 'FAIL'
        return proven(verdict, 'ARN constraint evaluated using the documented CFN destination default', facts)
    return finding
