"""Explicit IAM/KMS reference evidence, including cross-account roles."""
import re
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved


def reference(ctx,r,path,types):
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if len(refs)!=1 or refs[0].condition or not resolved(r):return None
    raw=read(ctx,r,path)
    if raw is not ABSENT and not literal(raw):return None
    other=ctx.by_id.get(refs[0].target_resource_id)
    if not resolved(other) or other.type not in types or other.scope.environment!=r.scope.environment:return None
    if literal(raw) and other.type.startswith('AWS::KMS::'):
        if raw.startswith('alias/') and other.type!='AWS::KMS::Alias':return None
        if re.fullmatch(r'(?:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})',raw) and other.type=='AWS::KMS::Alias':return None
    if literal(raw) and raw.startswith('arn:'):
        m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:(iam|kms):([a-z0-9-]*):([0-9]{12}):(role|key|alias)/[^\s]+',raw)
        if not m or m[3]!=other.scope.account:return None
        if other.type=='AWS::IAM::Role':
            if m[1]!='iam' or m[2] or m[4]!='role':return None
        else:
            expected='alias' if other.type=='AWS::KMS::Alias' else 'key'
            if m[1]!='kms' or m[2]!=other.scope.region or m[4]!=expected:return None
    ctx.evidence.extend(refs[0].evidence_ids)
    return other


def referenced_role_account(ctx,r,path):
    other=reference(ctx,r,path,('AWS::IAM::Role',))
    return other.scope.account if other else None


def referenced_key_kind(ctx,r,path):
    other=reference(ctx,r,path,('AWS::KMS::Key','AWS::KMS::ReplicaKey','AWS::KMS::Alias'))
    return None if other is None else 'alias' if other.type=='AWS::KMS::Alias' else 'key'
