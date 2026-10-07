"""RDS creation modes and global secondary member checks."""
import hashlib

import pytest

from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.checks.rds.creation_modes import evaluate_rds_dbinstance_modes, evaluate_rds_global_secondary_engine_version, evaluate_rds_replica_cluster_source, evaluate_rds_io1_storage_ratio


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
ROOT = Path(__file__).resolve().parents[1]


def design(type_name, **props):
    message = "RDS design"
    fields = [FieldValue(path="/properties/" + key, state=ValueState.KNOWN,
                         candidates=[Candidate(id=key, raw=str(value), value=value,
                                               evidence_ids=["e1"])],
                         selected_candidate_id=key) for key, value in props.items()]
    resource = Resource(id="db", name="db", type=type_name, scope=SCOPE, fields=fields)
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="d1", name="input", version="1", text=message,
                                      sha256=hashlib.sha256(message.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                     excerpt=message)], resources=[resource], relations=[]), resource


@pytest.mark.parametrize("props,failed_path", [
    ({"DBSnapshotIdentifier": "snapshot", "MasterUsername": "admin"}, "MasterUsername"),
    ({"DBSnapshotIdentifier": "snapshot", "KmsKeyId": "key"}, "KmsKeyId"),
    ({"DBSnapshotIdentifier": "snapshot", "RestoreTime": "2026-01-01T00:00:00Z"}, "RestoreTime"),
    ({"SourceDBInstanceIdentifier": "source", "MasterUserPassword": "secret"}, "MasterUserPassword"),
    ({"SourceDBInstanceIdentifier": "source", "BackupRetentionPeriod": 1}, "BackupRetentionPeriod"),
    ({"SourceDBClusterIdentifier": "cluster", "SourceDBInstanceIdentifier": "source"},
     "SourceDBInstanceIdentifier"),
    ({"SourceDBClusterIdentifier": "cluster", "UseLatestRestorableTime": True},
     "UseLatestRestorableTime"),
    ({"RestoreTime": "2026-01-01T00:00:00Z"}, "RestoreTime"),
    ({"SourceDbiResourceId": "dbi-123"}, "SourceDbiResourceId"),
    ({"SourceDBInstanceIdentifier": "source", "RestoreTime": "2026-01-01T00:00:00Z",
      "UseLatestRestorableTime": True}, "UseLatestRestorableTime"),
])
def test_rejects_known_creation_mode_conflicts(props, failed_path):
    d, db = design("AWS::RDS::DBInstance", **props)
    findings = evaluate_rds_dbinstance_modes(d, db)
    assert any(item["path"] == "/properties/" + failed_path and item["verdict"] == "FAIL"
               for item in findings)


@pytest.mark.parametrize("props", [
    {"DBSnapshotIdentifier": "snapshot"},
    {"SourceDBInstanceIdentifier": "source"},
    {"SourceDBInstanceIdentifier": "source", "RestoreTime": "2026-01-01T00:00:00Z"},
    {"SourceDbiResourceId": "dbi-123", "UseLatestRestorableTime": True},
    {"Engine": "mysql", "MasterUsername": "admin", "MasterUserPassword": "secret"},
])
def test_accepts_consistent_creation_modes(props):
    d, db = design("AWS::RDS::DBInstance", **props)
    assert all(item["verdict"] == "PASS" for item in evaluate_rds_dbinstance_modes(d, db))


def test_global_secondary_engine_version():
    d, cluster = design("AWS::RDS::DBCluster", GlobalClusterIdentifier="global",
                        EngineVersion="8.0")
    result = evaluate_rds_global_secondary_engine_version(d, cluster)
    assert result["verdict"] == "FAIL"
    assert result["path"] == "/properties/EngineVersion"
    cluster.fields.pop()
    assert evaluate_rds_global_secondary_engine_version(d, cluster)["verdict"] == "PASS"
    cluster.fields.clear()
    assert evaluate_rds_global_secondary_engine_version(d, cluster)["verdict"] == "NOT_APPLICABLE"


def test_linked_replica_cluster_source():
    d, db = design("AWS::RDS::DBInstance", SourceDBClusterIdentifier="source")
    cluster = Resource(id="source", name="source", type="AWS::RDS::DBCluster", scope=SCOPE,
                       fields=[FieldValue(path="/properties/Engine", state=ValueState.KNOWN,
                                          candidates=[Candidate(id="engine", raw="mysql", value="mysql",
                                                                evidence_ids=["e1"])],
                                          selected_candidate_id="engine")])
    d.resources.append(cluster)
    d.relations.append(Relation(id="source-link", source_resource_id="db",
                                source_path="/properties/SourceDBClusterIdentifier",
                                target_resource_id="source", evidence_ids=["e1"]))
    assert evaluate_rds_replica_cluster_source(d, db)["verdict"] == "PASS"
    cluster.fields.append(FieldValue(path="/properties/BackupRetentionPeriod", state=ValueState.KNOWN,
                                     candidates=[Candidate(id="retention", raw="0", value=0,
                                                           evidence_ids=["e1"])],
                                     selected_candidate_id="retention"))
    assert evaluate_rds_replica_cluster_source(d, db)["verdict"] == "FAIL"
    cluster.fields[0].candidates[0].value = "aurora-mysql"
    assert evaluate_rds_replica_cluster_source(d, db)["verdict"] == "FAIL"
    d.relations.clear()
    assert evaluate_rds_replica_cluster_source(d, db)["verdict"] == "NEEDS_REVIEW"


def test_checker_runs_rds_creation_mode_checks():
    d, _ = design("AWS::RDS::DBInstance", DBSnapshotIdentifier="snapshot",
                  MasterUsername="admin")
    results = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(d)["results"]
    assert any(item["rule_id"] == "RDS_DBINSTANCE_CREATION_MODES" and
               item["path"] == "/properties/MasterUsername" and item["verdict"] == "FAIL"
               for item in results)


@pytest.mark.parametrize("props,expected", [
    ({"StorageType": "io1", "Engine": "mysql", "AllocatedStorage": "200"}, "FAIL"),
    ({"StorageType": "io1", "Engine": "mysql", "AllocatedStorage": "200", "Iops": 1000}, "PASS"),
    ({"StorageType": "io1", "Engine": "mysql", "AllocatedStorage": "200", "Iops": 11000}, "FAIL"),
    ({"StorageType": "io1", "Engine": "sqlserver-ee", "AllocatedStorage": "2000", "Iops": 1000}, "FAIL"),
    ({"StorageType": "io1", "Engine": "mysql", "AllocatedStorage": "2000", "Iops": 1000}, "PASS"),
    ({"StorageType": "io1", "Engine": "mysql", "Iops": 1000}, "NEEDS_REVIEW"),
    ({"StorageType": "gp3", "Engine": "mysql", "AllocatedStorage": "200", "Iops": 1000},
     "NOT_APPLICABLE"),
])
def test_io1_storage_ratio(props, expected):
    d, db = design("AWS::RDS::DBInstance", **props)
    assert evaluate_rds_io1_storage_ratio(d, db)["verdict"] == expected
