import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('secret,expected',[
    ('arn:aws:secretsmanager:us-east-1:111111111111:secret:db/password-Ab1234','PASS'),
    ('arn:aws-cn:secretsmanager:cn-north-1:111111111111:secret:db','PASS'),
    ('arn:aws:ssm:us-east-1:111111111111:parameter/db','FAIL'),
    ('arn:aws:secretsmanager:us-east-1:111111111111:key/db','FAIL'),
    ('arn:aws:secretsmanager:us-east-1:111111111111:secret:db\n','FAIL'),
    ('$','PASS'),('$.detail.secrets[0].arn','PASS'),('$.items[*]','PASS'),
    ("$['secret']",'FAIL'),('prefix$.secret','NEEDS_REVIEW'),
    ('db/password','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('${Secret}','NEEDS_REVIEW'),
])
def test_redshift_secret_representation(secret,expected):
    main=target('rule','AWS::Events::Rule',Targets=[{'Id':'redshift','RedshiftDataParameters':{'SecretManagerArn':secret}}])
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert rows['EVENTS_REDSHIFT_SECRET_REPRESENTATION']==expected
