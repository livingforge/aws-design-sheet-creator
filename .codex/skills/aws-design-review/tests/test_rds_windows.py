"""Cyclic daily and weekly RDS time windows."""
import pytest

from aws_design_sheet.models import Candidate, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.checks.rds.windows import evaluate_rds_windows


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def field(name, value):
    path = "/properties/" + name
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=value, value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def findings(backup, maintenance, type="DBInstance"):
    item = Resource(id="r", name="r", type="AWS::RDS::" + type, scope=SCOPE,
                    fields=[field("PreferredBackupWindow", backup),
                            field("PreferredMaintenanceWindow", maintenance)])
    return {row["rule_id"]: row for row in evaluate_rds_windows(item)}


@pytest.mark.parametrize("type", ["DBInstance", "DBCluster"])
def test_rds_windows_minimum_and_overlap(type):
    result = findings("03:00-03:30", "Mon:04:00-Mon:04:30", type)
    assert all(row["verdict"] == "PASS" for row in result.values())
    result = findings("03:00-03:29", "Mon:04:00-Mon:04:30", type)
    assert result["RDS_BACKUP_WINDOW_MINIMUM"]["verdict"] == "FAIL"
    result = findings("03:00-04:00", "Mon:03:30-Mon:04:30", type)
    assert result["RDS_BACKUP_MAINTENANCE_NONOVERLAP"]["verdict"] == "FAIL"


def test_rds_windows_wrap_midnight_and_week():
    result = findings("23:45-00:30", "Sun:23:55-Mon:00:25")
    assert result["RDS_BACKUP_MAINTENANCE_NONOVERLAP"]["verdict"] == "FAIL"
    result = findings("23:45-00:30", "Mon:01:00-Mon:01:30")
    assert result["RDS_BACKUP_MAINTENANCE_NONOVERLAP"]["verdict"] == "PASS"
