"""Checks for AWS::S3::AccessGrantsLocation, AWS::S3::AccessGrant."""
from __future__ import annotations

from ..registry import resource_check
from ..common.context import Context


SOURCES = {
    "S3_ACCESS_GRANTS_LOCATION_BUCKET_REGION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-accessgrantslocation.html"],
    "S3_ACCESS_GRANT_REGISTERED_LOCATION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-accessgrant.html"],
}


@resource_check('AWS::S3::AccessGrantsLocation')
def evaluate_access_grants_location_region(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "S3_ACCESS_GRANTS_LOCATION_BUCKET_REGION"
    path = "/properties/LocationScope"
    location = ctx.value(resource, path)
    if location == "s3://":
        return ctx.finding(rule, path, "NOT_APPLICABLE", "default S3 location is used")
    refs = [ref for ref in design.relations
            if ref.source_resource_id == resource.id and ref.source_path == path]
    ctx.evidence.extend(e for ref in refs for e in ref.evidence_ids)
    bucket = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
    if bucket is None or bucket.type != "AWS::S3::Bucket":
        return ctx.finding(rule, path, "NEEDS_REVIEW", "S3 bucket is not linked in the design")
    if not bucket.scope.region or not resource.scope.region:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "bucket or Access Grants Region is unresolved")
    same = bucket.scope.region == resource.scope.region
    return ctx.finding(rule, path, "PASS" if same else "FAIL",
                       "S3 bucket and Access Grants are in the same Region" if same else
                       "S3 bucket and Access Grants are in different Regions")


@resource_check('AWS::S3::AccessGrant')
def evaluate_access_grant_registered_location(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "S3_ACCESS_GRANT_REGISTERED_LOCATION"
    path = "/properties/AccessGrantsLocationId"
    value = ctx.value(resource, path)
    if value == "default":
        locations = [item for item in design.resources if item.type == "AWS::S3::AccessGrantsLocation"
                     and item.scope == resource.scope and
                     ctx.value(item, "/properties/LocationScope") == "s3://"]
        if locations:
            return ctx.finding(rule, path, "PASS", "default Access Grants location is declared in this Region")
        return ctx.finding(rule, path, "NEEDS_REVIEW", "default Access Grants location registration is external")
    refs = [ref for ref in design.relations
            if ref.source_resource_id == resource.id and ref.source_path == path]
    ctx.evidence.extend(e for ref in refs for e in ref.evidence_ids)
    location = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
    if location is None or location.type != "AWS::S3::AccessGrantsLocation":
        return ctx.finding(rule, path, "NEEDS_REVIEW", "registered location is not linked in the design")
    same = location.scope.region == resource.scope.region and location.scope.account == resource.scope.account
    return ctx.finding(rule, path, "PASS" if same else "FAIL",
                       "registered location is in the grant account and Region" if same else
                       "registered location is in a different account or Region")
