"""Checks for RDS creation modes visible in a design sheet."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check
from ..common.context import Context

DB_CLUSTER = "AWS::RDS::DBCluster"
BASE = "/properties/"


SOURCES = {
    "RDS_DBINSTANCE_CREATION_MODES": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html"],
    "RDS_GLOBAL_SECONDARY_ENGINE_VERSION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html"],
    "RDS_DBINSTANCE_REPLICA_CLUSTER_SOURCE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html"],
    "RDS_DBINSTANCE_IO1_STORAGE_RATIO": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html"],
}


def _presence(design: Design, resource: Resource, name: str) -> bool | None:
    """Whether a property is supplied; None means its design value is unresolved."""
    path = BASE + name
    field = resource.field(path)
    refs = [ref for ref in design.relations
            if ref.source_resource_id == resource.id and ref.source_path == path]
    if field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                 ValueState.NOT_APPLICABLE):
        return None
    if len(refs) > 1:
        return None
    if refs:
        return True
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return False
    value = field.selected().value
    return bool(value) if isinstance(value, str) else value is not None


def _finding(ctx: Context, rule: str, name: str, verdict: str, reason: str) -> dict[str, Any]:
    return ctx.finding(rule, BASE + name, verdict, reason)


@resource_check('AWS::RDS::DBInstance')
def evaluate_rds_dbinstance_modes(design: Design, resource: Resource) -> list[dict[str, Any]]:
    """Check mode conflicts and creation-only inherited properties."""
    ctx = Context(design, resource)
    rule = "RDS_DBINSTANCE_CREATION_MODES"
    names = ("DBSnapshotIdentifier", "SourceDBInstanceIdentifier", "SourceDBClusterIdentifier",
             "SourceDbiResourceId", "SourceDBInstanceAutomatedBackupsArn", "RestoreTime",
             "UseLatestRestorableTime")
    present = {name: _presence(design, resource, name) for name in names}
    for name in names:
        ctx.value(resource, BASE + name)
    snapshot = present["DBSnapshotIdentifier"]
    instance = present["SourceDBInstanceIdentifier"]
    cluster = present["SourceDBClusterIdentifier"]
    dbi = present["SourceDbiResourceId"]
    backups = present["SourceDBInstanceAutomatedBackupsArn"]
    restore = present["RestoreTime"]
    latest_field = resource.field(BASE + "UseLatestRestorableTime")
    if latest_field is None or latest_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        latest = False
    elif latest_field.state == ValueState.KNOWN and type(latest_field.selected().value) is bool:
        latest = latest_field.selected().value
    else:
        latest = None

    findings = []
    incompatible = {
        "DBSnapshotIdentifier": ("SourceDBInstanceIdentifier", "SourceDBClusterIdentifier",
                                 "SourceDbiResourceId", "SourceDBInstanceAutomatedBackupsArn",
                                 "RestoreTime", "UseLatestRestorableTime"),
        "SourceDBClusterIdentifier": ("SourceDBInstanceIdentifier", "SourceDbiResourceId",
                                      "SourceDBInstanceAutomatedBackupsArn", "RestoreTime",
                                      "UseLatestRestorableTime"),
        "RestoreTime": ("UseLatestRestorableTime",),
    }
    for left, rights in incompatible.items():
        left_present = latest if left == "UseLatestRestorableTime" else present[left]
        for right in rights:
            right_present = latest if right == "UseLatestRestorableTime" else present[right]
            if left_present is True and right_present is True:
                findings.append(_finding(ctx, rule, right, "FAIL",
                                         f"{left} cannot be combined with {right}"))

    if restore is True or latest is True:
        sources = (instance, dbi, backups)
        if all(item is False for item in sources):
            findings.append(_finding(ctx, rule, "RestoreTime" if restore else
                                     "UseLatestRestorableTime", "FAIL",
                                     "point-in-time restore requires a DB instance or automated-backup source"))
        elif not any(item is True for item in sources):
            findings.append(_finding(ctx, rule, "RestoreTime" if restore else
                                     "UseLatestRestorableTime", "NEEDS_REVIEW",
                                     "point-in-time restore source is unresolved"))
    if dbi is True or backups is True:
        if restore is False and latest is False:
            findings.append(_finding(ctx, rule, "SourceDbiResourceId" if dbi else
                                     "SourceDBInstanceAutomatedBackupsArn", "FAIL",
                                     "point-in-time restore source requires RestoreTime or UseLatestRestorableTime"))
        elif restore is None or latest is None:
            if restore is not True and latest is not True:
                findings.append(_finding(ctx, rule, "SourceDbiResourceId" if dbi else
                                         "SourceDBInstanceAutomatedBackupsArn", "NEEDS_REVIEW",
                                         "point-in-time restore time is unresolved"))

    excluded = set()
    if snapshot is True:
        excluded.update(("CharacterSetName", "DBClusterIdentifier", "DBName", "KmsKeyId",
                         "MasterUsername", "MasterUserPassword", "PromotionTier", "SourceRegion",
                         "Timezone"))
    if instance is True and restore is False and latest is False:
        excluded.update(("BackupRetentionPeriod", "DBName", "MasterUsername",
                         "MasterUserPassword", "PreferredBackupWindow"))
    for name in sorted(excluded):
        supplied = _presence(design, resource, name)
        if supplied is True:
            ctx.value(resource, BASE + name)
            findings.append(_finding(ctx, rule, name, "FAIL",
                                     f"{name} cannot be specified for this DB instance creation mode"))
        elif supplied is None:
            ctx.value(resource, BASE + name)
            findings.append(_finding(ctx, rule, name, "NEEDS_REVIEW",
                                     f"{name} is unresolved for this DB instance creation mode"))
    if not findings:
        findings.append(_finding(ctx, rule, "DBSnapshotIdentifier",
                                 "NEEDS_REVIEW" if any(item is None for item in present.values()) else
                                 "PASS", "creation mode is unresolved" if any(
                                     item is None for item in present.values()) else
                                 "known DB instance creation mode properties are consistent"))
    return findings


@resource_check('AWS::RDS::DBCluster')
def evaluate_rds_global_secondary_engine_version(design: Design, resource: Resource) -> dict[str, Any]:
    """A secondary global cluster member inherits its engine version."""
    ctx = Context(design, resource)
    rule = "RDS_GLOBAL_SECONDARY_ENGINE_VERSION"
    global_id = _presence(design, resource, "GlobalClusterIdentifier")
    engine_version = _presence(design, resource, "EngineVersion")
    ctx.value(resource, BASE + "GlobalClusterIdentifier")
    ctx.value(resource, BASE + "EngineVersion")
    if global_id is False:
        return _finding(ctx, rule, "EngineVersion", "NOT_APPLICABLE",
                        "DB cluster has no secondary global cluster identifier")
    if global_id is None or engine_version is None:
        return _finding(ctx, rule, "EngineVersion", "NEEDS_REVIEW",
                        "global cluster membership or engine version is unresolved")
    if engine_version:
        return _finding(ctx, rule, "EngineVersion", "FAIL",
                        "a secondary global DB cluster must inherit EngineVersion")
    return _finding(ctx, rule, "EngineVersion", "PASS",
                    "secondary global DB cluster inherits EngineVersion")


@resource_check('AWS::RDS::DBInstance')
def evaluate_rds_replica_cluster_source(design: Design, resource: Resource) -> dict[str, Any]:
    """Check a linked Multi-AZ DB cluster used as a DB instance replica source."""
    ctx = Context(design, resource)
    rule = "RDS_DBINSTANCE_REPLICA_CLUSTER_SOURCE"
    path = BASE + "SourceDBClusterIdentifier"
    presence = _presence(design, resource, "SourceDBClusterIdentifier")
    if presence is False:
        return _finding(ctx, rule, "SourceDBClusterIdentifier", "NOT_APPLICABLE",
                        "no DB cluster replica source is specified")
    if presence is None:
        return _finding(ctx, rule, "SourceDBClusterIdentifier", "NEEDS_REVIEW",
                        "DB cluster replica source is unresolved")
    cluster = ctx.target(resource, path, DB_CLUSTER)
    if cluster is None:
        return _finding(ctx, rule, "SourceDBClusterIdentifier", "NEEDS_REVIEW",
                        "DB cluster replica source is not linked in the design")
    engine = ctx.value(cluster, BASE + "Engine")
    if engine not in ("mysql", "postgres"):
        return _finding(ctx, rule, "SourceDBClusterIdentifier",
                        "NEEDS_REVIEW" if engine is None else "FAIL",
                        "source DB cluster engine is unresolved" if engine is None else
                        "a DB instance replica requires a Multi-AZ DB cluster source")
    retention = ctx.value(cluster, BASE + "BackupRetentionPeriod")
    if retention is None and cluster.field(BASE + "BackupRetentionPeriod") is None:
        retention = 1  # CloudFormation default for DB clusters.
    if retention is None:
        return _finding(ctx, rule, "SourceDBClusterIdentifier", "NEEDS_REVIEW",
                        "source DB cluster backup retention is unresolved")
    if type(retention) is not int:
        return _finding(ctx, rule, "SourceDBClusterIdentifier", "NEEDS_REVIEW",
                        "source DB cluster backup retention is not a known integer")
    if retention <= 0:
        return _finding(ctx, rule, "SourceDBClusterIdentifier", "FAIL",
                        "source DB cluster must have automated backups enabled")
    return _finding(ctx, rule, "SourceDBClusterIdentifier", "PASS",
                    "linked source is a same-region Multi-AZ DB cluster with backups enabled")


@resource_check('AWS::RDS::DBInstance')
def evaluate_rds_io1_storage_ratio(design: Design, resource: Resource) -> dict[str, Any]:
    """Check the documented io1 IOPS and allocated-storage ratio when known."""
    ctx = Context(design, resource)
    rule = "RDS_DBINSTANCE_IO1_STORAGE_RATIO"
    storage_type = ctx.value(resource, BASE + "StorageType")
    storage_field = resource.field(BASE + "StorageType")
    if storage_type is None and storage_field is not None and storage_field.state not in (
            ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _finding(ctx, rule, "StorageType", "NEEDS_REVIEW", "storage type is unresolved")
    if storage_type != "io1":
        return _finding(ctx, rule, "StorageType", "NOT_APPLICABLE", "io1 storage is not selected")
    iops_field = resource.field(BASE + "Iops")
    if iops_field is None or iops_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _finding(ctx, rule, "Iops", "FAIL", "io1 storage requires Iops")
    iops = ctx.value(resource, BASE + "Iops")
    if type(iops) is not int:
        return _finding(ctx, rule, "Iops", "NEEDS_REVIEW", "Iops is unresolved")
    if iops < 1000:
        return _finding(ctx, rule, "Iops", "FAIL", "Iops must be at least 1000")
    raw_storage = ctx.value(resource, BASE + "AllocatedStorage")
    if isinstance(raw_storage, str) and raw_storage.isdecimal():
        storage = int(raw_storage)
    elif type(raw_storage) is int:
        storage = raw_storage
    else:
        return _finding(ctx, rule, "AllocatedStorage", "NEEDS_REVIEW",
                        "allocated storage is inherited or unresolved")
    if storage <= 0:
        return _finding(ctx, rule, "AllocatedStorage", "FAIL",
                        "allocated storage must be positive")
    engine = ctx.value(resource, BASE + "Engine")
    if not isinstance(engine, str):
        return _finding(ctx, rule, "Engine", "NEEDS_REVIEW", "DB engine is unresolved")
    normalized = engine.lower()
    if normalized.startswith("sqlserver-"):
        min_times_two = 2
    elif (normalized in ("mysql", "mariadb", "postgres", "db2-ae", "db2-se") or
          normalized.startswith("oracle-")):
        min_times_two = 1
    else:
        return _finding(ctx, rule, "Engine", "NEEDS_REVIEW",
                        "documented io1 ratio for this engine is not established")
    if 2 * iops < min_times_two * storage or iops > 50 * storage:
        return _finding(ctx, rule, "Iops", "FAIL",
                        "io1 IOPS must be within the engine-specific allocated-storage ratio")
    return _finding(ctx, rule, "Iops", "PASS",
                    "io1 IOPS and allocated storage satisfy the documented ratio")
