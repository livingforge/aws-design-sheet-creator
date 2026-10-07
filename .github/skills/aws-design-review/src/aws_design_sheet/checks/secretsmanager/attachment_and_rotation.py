"""Checks for AWS::SecretsManager::SecretTargetAttachment, AWS::SecretsManager::RotationSchedule."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check
from ..common.design_uniqueness import _Context, unique_in_design
from ..common.field_reads import read


SOURCES = {
    "SECRET_ATTACHMENT_TARGET_TYPE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-secrettargetattachment.html"],
    "SECRET_ROTATION_DESIGN_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-rotationschedule.html"],
    "SECRET_ATTACHMENT_DESIGN_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-secrettargetattachment.html"],
}


@resource_check('AWS::SecretsManager::SecretTargetAttachment')
def secret_attachment_type(design, resource):
    ctx = _Context(design, resource)
    kind = read(ctx, resource, '/properties/TargetType')
    refs = [r for r in design.relations if r.source_resource_id == resource.id and r.source_path == '/properties/TargetId']
    target = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
    field = resource.field('/properties/TargetId')
    read(ctx, resource, '/properties/TargetId')
    if field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING):
        target = None
    ctx.evidence.extend(e for ref in refs for e in ref.evidence_ids)
    allowed = ('AWS::RDS::DBInstance', 'AWS::RDS::DBCluster', 'AWS::Redshift::Cluster',
               'AWS::DocDB::DBInstance', 'AWS::DocDB::DBCluster',
               'AWS::RedshiftServerless::Namespace', 'AWS::DocDBElastic::Cluster')
    if not isinstance(kind, str) or kind not in allowed or target is None:
        verdict = 'NEEDS_REVIEW'
    else:
        verdict = 'PASS' if target.type == kind and target.scope == resource.scope else 'FAIL'
    return ctx.finding('SECRET_ATTACHMENT_TARGET_TYPE', '/properties/TargetId', verdict,
                       'the linked database resource must match TargetType and scope')


@resource_check('AWS::SecretsManager::RotationSchedule')
def secret_rotation_unique(design: Design, resource: Resource) -> dict:
    return unique_in_design(design, resource, '/properties/SecretId', 'SECRET_ROTATION_DESIGN_UNIQUE')


@resource_check('AWS::SecretsManager::SecretTargetAttachment')
def secret_attachment_unique(design: Design, resource: Resource) -> dict:
    return unique_in_design(design, resource, '/properties/SecretId', 'SECRET_ATTACHMENT_DESIGN_UNIQUE')
