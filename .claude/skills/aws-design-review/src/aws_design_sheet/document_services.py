"""Declarative v1 service/field catalog, independent of input and XLSX rendering.

These are documentation fields, not a replacement for AWS schemas or cfn-lint.
"""
CATALOG = {
    'AWS::EC2::VPC': ('VPC', {'CidrBlock':'string','EnableDnsSupport':'boolean','EnableDnsHostnames':'boolean','InstanceTenancy':'string','Tags':'array'}),
    'AWS::EC2::Subnet': ('VPC', {'VpcId':'ref:AWS::EC2::VPC','CidrBlock':'string','AvailabilityZone':'string','MapPublicIpOnLaunch':'boolean','Tags':'array'}),
    'AWS::EC2::SecurityGroup': ('VPC', {'VpcId':'ref:AWS::EC2::VPC','GroupDescription':'string','SecurityGroupIngress':'array','SecurityGroupEgress':'array','Tags':'array'}),
    'AWS::EC2::Instance': ('EC2', {'InstanceType':'string','ImageId':'string','SubnetId':'ref:AWS::EC2::Subnet','SecurityGroupIds':'refs:AWS::EC2::SecurityGroup','IamInstanceProfile':'string','KeyName':'string','Monitoring':'boolean','DisableApiTermination':'boolean','BlockDeviceMappings':'array','Tags':'array'}),
    'AWS::RDS::DBSubnetGroup': ('RDS', {'DBSubnetGroupDescription':'string','SubnetIds':'refs:AWS::EC2::Subnet','Tags':'array'}),
    'AWS::RDS::DBInstance': ('RDS', {'Engine':'string','EngineVersion':'string','DBInstanceClass':'string','AllocatedStorage':'integer','StorageType':'string','StorageEncrypted':'boolean','MultiAZ':'boolean','PubliclyAccessible':'boolean','BackupRetentionPeriod':'integer','DBSubnetGroupName':'ref:AWS::RDS::DBSubnetGroup','VPCSecurityGroups':'refs:AWS::EC2::SecurityGroup','MasterUsername':'string','MasterUserPassword':'secret','KmsKeyId':'string','DeletionProtection':'boolean','Tags':'array'}),
    'AWS::RDS::DBCluster': ('RDS', {'Engine':'string','EngineVersion':'string','DatabaseName':'string','StorageEncrypted':'boolean','BackupRetentionPeriod':'integer','DBSubnetGroupName':'ref:AWS::RDS::DBSubnetGroup','VpcSecurityGroupIds':'refs:AWS::EC2::SecurityGroup','MasterUsername':'string','MasterUserPassword':'secret','KmsKeyId':'string','DeletionProtection':'boolean','Tags':'array'}),
}


def definition(resource_type, name):
    return CATALOG[resource_type][1].get(name)
