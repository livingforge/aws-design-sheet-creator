"""Resolved and unresolved design references for Tier 1 cross-resource rules."""
import hashlib
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.checks.ec2.cross_resource import evaluate_vpc_peering_cidr, evaluate_vpc_bpa_exclusion_mode, evaluate_endpoint_private_dns, evaluate_endpoint_notification_type, evaluate_volume_attachment_az, evaluate_network_acl_entry_number, evaluate_instance_connect_endpoint_unique, evaluate_traffic_mirror_filter_rule_number, evaluate_gateway_route_table_vpc, evaluate_client_vpn_cidr_overlap, evaluate_instance_volumes_az, evaluate_ipam_allocation_pool, evaluate_client_vpn_endpoint_mode
from aws_design_sheet.checks.rds.cross_resource import evaluate_rds_serverless_cluster_capacity
from aws_design_sheet.checks.ec2.cross_resource import evaluate_verified_access_subnet_az, evaluate_client_vpn_association_network, evaluate_eip_instance_interface_count, evaluate_instance_launch_template, evaluate_ec2_fleet_unit_type, evaluate_vpn_tunnel_cidr_uniqueness, evaluate_vpn_route_propagation_vpc, evaluate_ipam_pool_cidr_netmask, evaluate_transit_gateway_subnet_az, evaluate_transit_gateway_route_table_association, evaluate_ipam_pool_source_locale, evaluate_spot_fleet_template_interfaces, evaluate_subnet_dns64_nat, evaluate_spot_fleet_unit_type, evaluate_volume_attachment_outpost, evaluate_instance_template_primary_interface
from aws_design_sheet.checks.rds.cross_resource import evaluate_rds_db_security_group_ingress, evaluate_rds_shard_group_cluster, evaluate_rds_network_type_subnets, evaluate_rds_global_write_forwarding
from aws_design_sheet.checks.lambda_.network_connector import evaluate_lambda_network_connector_vpc
from aws_design_sheet.checks.s3.cross_resource import evaluate_access_grants_location_region, evaluate_access_grant_registered_location


ROOT = Path(__file__).resolve().parents[1]
SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def field(name, value):
    path = "/properties/" + name
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def resource(id, type, **properties):
    return Resource(id=id, name=id, type="AWS::EC2::" + type, scope=SCOPE,
                    fields=[field(k, v) for k, v in properties.items()])


def link(source, path, target):
    return Relation(id=f"{source}-{path}-{target}", source_resource_id=source,
                    source_path="/properties/" + path, target_resource_id=target,
                    evidence_ids=["e1"])


def design(resources, relations):
    message = "Tier 1 cross-resource design"
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="d1", name="input", version="1", text=message,
                                      sha256=hashlib.sha256(message.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                     excerpt=message)], resources=resources, relations=relations)


def test_vpc_bpa_egress_exclusion_matches_account_region_mode():
    exclusion = resource("exclusion", "VPCBlockPublicAccessExclusion",
                         InternetGatewayExclusionMode="allow-egress", VpcId="vpc-123")
    options = resource("options", "VPCBlockPublicAccessOptions",
                       InternetGatewayBlockMode="block-bidirectional")
    d = design([exclusion, options], [])
    assert evaluate_vpc_bpa_exclusion_mode(d, exclusion)["verdict"] == "PASS"
    assert any(row["rule_id"] == "EC2_VPC_BPA_EGRESS_EXCLUSION_MODE" and row["verdict"] == "PASS"
               for row in Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(d)["results"])

    options.fields[0] = field("InternetGatewayBlockMode", "block-ingress")
    assert evaluate_vpc_bpa_exclusion_mode(d, exclusion)["verdict"] == "FAIL"
    options.fields[0] = FieldValue(path="/properties/InternetGatewayBlockMode",
                                  state=ValueState.UNRESOLVED)
    finding = evaluate_vpc_bpa_exclusion_mode(d, exclusion)
    assert finding["verdict"] == "NEEDS_REVIEW"
    assert "options/properties/InternetGatewayBlockMode" in finding["dependencies"]

    assert evaluate_vpc_bpa_exclusion_mode(design([exclusion], []), exclusion)["verdict"] == "NEEDS_REVIEW"
    assert evaluate_vpc_bpa_exclusion_mode(design([exclusion, options, options.model_copy(update={"id": "other"})], []),
                                           exclusion)["verdict"] == "NEEDS_REVIEW"
    different_environment = Scope(environment="staging", account=SCOPE.account, region=SCOPE.region)
    options.fields[0] = field("InternetGatewayBlockMode", "block-bidirectional")
    assert evaluate_vpc_bpa_exclusion_mode(
        design([exclusion, options.model_copy(update={"scope": different_environment})], []), exclusion
    )["verdict"] == "PASS"
    different_region = Scope(environment="prod", account=SCOPE.account, region="us-east-1")
    assert evaluate_vpc_bpa_exclusion_mode(
        design([exclusion, options.model_copy(update={"scope": different_region})], []), exclusion
    )["verdict"] == "NEEDS_REVIEW"
    exclusion.fields[0] = field("InternetGatewayExclusionMode", "allow-bidirectional")
    assert evaluate_vpc_bpa_exclusion_mode(d, exclusion)["verdict"] == "NOT_APPLICABLE"


@pytest.mark.parametrize("family,source,has_parent,expected", [
    ("ipv6", "amazon", False, "PASS"),
    ("ipv6", "byoip", False, "FAIL"),
    ("ipv4", "byoip", False, "FAIL"),
    ("ipv4", "byoip", True, "PASS"),
])
def test_ipam_pool_cidr_netmask_source(family, source, has_parent, expected):
    props = {"AddressFamily": family, "PublicIpSource": source}
    if has_parent:
        props["SourceIpamPoolId"] = "parent"
    items = [resource("cidr", "IPAMPoolCidr", IpamPoolId="pool", NetmaskLength=56),
             resource("pool", "IPAMPool", **props)]
    linked = design(items, [link("cidr", "IpamPoolId", "pool")])
    assert evaluate_ipam_pool_cidr_netmask(linked, items[0])["verdict"] == expected
    assert evaluate_ipam_pool_cidr_netmask(design(items, []), items[0])["verdict"] == "NEEDS_REVIEW"


def test_rds_db_security_group_ingress_vpc_fields():
    ingress = Resource(id="ingress", name="ingress", type="AWS::RDS::DBSecurityGroupIngress",
                       scope=SCOPE, fields=[field("DBSecurityGroupName", "db-group"),
                                            field("EC2SecurityGroupName", "sg")])
    group = Resource(id="db-group", name="db-group", type="AWS::RDS::DBSecurityGroup",
                     scope=SCOPE, fields=[field("EC2VpcId", "vpc-1")])
    linked = design([ingress, group], [link("ingress", "DBSecurityGroupName", "db-group")])
    assert evaluate_rds_db_security_group_ingress(linked, ingress)["verdict"] == "FAIL"
    ingress.fields.append(field("EC2SecurityGroupId", "sg-1"))
    assert evaluate_rds_db_security_group_ingress(linked, ingress)["verdict"] == "PASS"
    assert evaluate_rds_db_security_group_ingress(design([ingress, group], []), ingress)["verdict"] == "NEEDS_REVIEW"


def test_traffic_mirror_filter_rule_number_per_filter_and_direction():
    first = resource("first", "TrafficMirrorFilterRule", TrafficMirrorFilterId="filter-a",
                     RuleNumber=10, TrafficDirection="ingress")
    second = resource("second", "TrafficMirrorFilterRule", TrafficMirrorFilterId="filter-a",
                      RuleNumber=10, TrafficDirection="ingress")
    d = design([first, second], [])
    assert evaluate_traffic_mirror_filter_rule_number(d, first)["verdict"] == "FAIL"
    checked = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(d)["results"]
    assert any(row["rule_id"] == "EC2_TRAFFIC_MIRROR_FILTER_RULE_NUMBER_UNIQUE" and
               row["verdict"] == "FAIL" for row in checked)
    second.fields[-1] = field("TrafficDirection", "egress")
    assert evaluate_traffic_mirror_filter_rule_number(d, first)["verdict"] == "PASS"
    second.fields[-1] = field("TrafficDirection", "ingress")
    second.fields[0] = field("TrafficMirrorFilterId", "filter-b")
    assert evaluate_traffic_mirror_filter_rule_number(d, first)["verdict"] == "PASS"
    first.fields[0] = field("TrafficMirrorFilterId", "filter-a")
    second.fields[0] = field("TrafficMirrorFilterId", "filter-b")
    filter_resource = resource("filter", "TrafficMirrorFilter")
    linked = design([first, second, filter_resource],
                    [link("first", "TrafficMirrorFilterId", "filter"),
                     link("second", "TrafficMirrorFilterId", "filter")])
    assert evaluate_traffic_mirror_filter_rule_number(linked, first)["verdict"] == "FAIL"


@pytest.mark.parametrize("kind,path", [
    ("TransitGatewayAttachment", "SubnetIds"),
    ("TransitGatewayVpcAttachment", "AddSubnetIds"),
])
def test_transit_gateway_subnets_use_distinct_azs(kind, path):
    attachment = resource("attachment", kind, **{path: ["one", "two"]})
    one = resource("one", "Subnet", AvailabilityZone="ap-northeast-1a")
    two = resource("two", "Subnet", AvailabilityZone="ap-northeast-1a")
    links = [link("attachment", f"{path}/0", "one"),
             link("attachment", f"{path}/1", "two")]
    findings = evaluate_transit_gateway_subnet_az(design([attachment, one, two], links), attachment)
    assert any(item["verdict"] == "FAIL" for item in findings)
    two.fields = [field("AvailabilityZone", "ap-northeast-1c")]
    findings = evaluate_transit_gateway_subnet_az(design([attachment, one, two], links), attachment)
    assert all(item["verdict"] in ("PASS", "NOT_APPLICABLE") for item in findings)


def test_transit_gateway_attachment_single_route_table():
    first = resource("first", "TransitGatewayRouteTableAssociation",
                     TransitGatewayAttachmentId="attachment", TransitGatewayRouteTableId="table-a")
    second = resource("second", "TransitGatewayRouteTableAssociation",
                      TransitGatewayAttachmentId="attachment", TransitGatewayRouteTableId="table-b")
    assert evaluate_transit_gateway_route_table_association(design([first, second], []), first)["verdict"] == "FAIL"
    second.fields[0] = field("TransitGatewayAttachmentId", "other")
    assert evaluate_transit_gateway_route_table_association(design([first, second], []), first)["verdict"] == "PASS"


def test_ipam_pool_source_locale():
    child = resource("child", "IPAMPool", SourceIpamPoolId="parent", Locale="ap-northeast-1")
    parent = resource("parent", "IPAMPool", Locale="us-east-1")
    relations = [link("child", "SourceIpamPoolId", "parent")]
    assert evaluate_ipam_pool_source_locale(design([child, parent], relations), child)["verdict"] == "FAIL"
    parent.fields = [field("Locale", "ap-northeast-1")]
    assert evaluate_ipam_pool_source_locale(design([child, parent], relations), child)["verdict"] == "PASS"


@pytest.mark.parametrize("engine,scalability,expected", [
    ("aurora-postgresql", "limitless", "PASS"),
    ("aurora-postgresql", "standard", "FAIL"),
    ("aurora-mysql", "limitless", "FAIL"),
    ("postgres", "limitless", "FAIL"),
])
def test_rds_shard_group_cluster(engine, scalability, expected):
    shard = Resource(id="shard", name="shard", type="AWS::RDS::DBShardGroup",
                     scope=SCOPE, fields=[field("DBClusterIdentifier", "cluster")])
    cluster = Resource(id="cluster", name="cluster", type="AWS::RDS::DBCluster",
                       scope=SCOPE, fields=[field("Engine", engine),
                                            field("ClusterScalabilityType", scalability)])
    assert evaluate_rds_shard_group_cluster(
        design([shard, cluster], [link("shard", "DBClusterIdentifier", "cluster")]), shard)["verdict"] == expected


def test_spot_fleet_linked_template_network_interface_id():
    config = {"LaunchTemplateConfigs": [{"LaunchTemplateSpecification":
                                           {"LaunchTemplateId": "template", "Version": "1"}}]}
    fleet = resource("fleet", "SpotFleet", SpotFleetRequestConfigData=config)
    template = resource("template", "LaunchTemplate", LaunchTemplateData={
        "NetworkInterfaces": [{"DeviceIndex": 0, "NetworkInterfaceId": "eni-123"}]})
    links = [link("fleet", "SpotFleetRequestConfigData/LaunchTemplateConfigs/0/LaunchTemplateSpecification/LaunchTemplateId",
                  "template")]
    d = design([fleet, template], links)
    assert evaluate_spot_fleet_template_interfaces(d, fleet)[0]["verdict"] == "FAIL"
    template.fields = [field("LaunchTemplateData", {"NetworkInterfaces": [{"DeviceIndex": 0}]})]
    assert evaluate_spot_fleet_template_interfaces(d, fleet)[0]["verdict"] == "PASS"
    assert evaluate_spot_fleet_template_interfaces(design([fleet, template], []), fleet)[0]["verdict"] == "NEEDS_REVIEW"


def test_lambda_network_connector_vpc_membership():
    config = {"VpcEgressConfiguration": {"SubnetIds": ["subnet"], "SecurityGroupIds": ["sg"]}}
    connector = Resource(id="connector", name="connector", type="AWS::Lambda::NetworkConnector",
                         scope=SCOPE, fields=[field("Configuration", config)])
    subnet = resource("subnet", "Subnet", VpcId="vpc-a")
    group = resource("sg", "SecurityGroup", VpcId="vpc-b")
    vpc_a = resource("vpc-a", "VPC")
    vpc_b = resource("vpc-b", "VPC")
    links = [link("connector", "Configuration/VpcEgressConfiguration/SubnetIds/0", "subnet"),
             link("connector", "Configuration/VpcEgressConfiguration/SecurityGroupIds/0", "sg"),
             link("subnet", "VpcId", "vpc-a"), link("sg", "VpcId", "vpc-b")]
    d = design([connector, subnet, group, vpc_a, vpc_b], links)
    assert evaluate_lambda_network_connector_vpc(d, connector)["verdict"] == "FAIL"
    links[-1] = link("sg", "VpcId", "vpc-a")
    assert evaluate_lambda_network_connector_vpc(design(d.resources, links), connector)["verdict"] == "PASS"


def test_rds_dual_network_subnets():
    instance = Resource(id="db", name="db", type="AWS::RDS::DBInstance", scope=SCOPE,
                        fields=[field("NetworkType", "DUAL"), field("DBSubnetGroupName", "group")])
    group = Resource(id="group", name="group", type="AWS::RDS::DBSubnetGroup", scope=SCOPE,
                     fields=[field("SubnetIds", ["subnet"])])
    subnet = resource("subnet", "Subnet", Ipv6CidrBlock="2001:db8::/64")
    links = [link("db", "DBSubnetGroupName", "group"), link("group", "SubnetIds/0", "subnet")]
    d = design([instance, group, subnet], links)
    assert evaluate_rds_network_type_subnets(d, instance)["verdict"] == "PASS"
    subnet.fields = [field("Ipv6Native", True)]
    assert evaluate_rds_network_type_subnets(d, instance)["verdict"] == "FAIL"
    subnet.fields = []
    assert evaluate_rds_network_type_subnets(d, instance)["verdict"] == "NEEDS_REVIEW"


def test_access_grants_location_bucket_region():
    location = Resource(id="location", name="location", type="AWS::S3::AccessGrantsLocation",
                        scope=SCOPE, fields=[field("LocationScope", "s3://bucket")])
    bucket = Resource(id="bucket", name="bucket", type="AWS::S3::Bucket",
                      scope=Scope(environment="prod", account=SCOPE.account, region="us-east-1"), fields=[])
    relation = [link("location", "LocationScope", "bucket")]
    assert evaluate_access_grants_location_region(design([location, bucket], relation), location)["verdict"] == "FAIL"
    bucket.scope = SCOPE
    assert evaluate_access_grants_location_region(design([location, bucket], relation), location)["verdict"] == "PASS"


def test_dns64_public_nat_chain():
    subnet = resource("dns", "Subnet", EnableDns64=True, VpcId="vpc")
    nat_subnet = resource("nat-subnet", "Subnet", VpcId="vpc")
    nat = resource("nat", "NatGateway", SubnetId="nat-subnet")
    vpc = resource("vpc", "VPC")
    association = resource("association", "SubnetRouteTableAssociation",
                           SubnetId="nat-subnet", RouteTableId="table")
    table = resource("table", "RouteTable", VpcId="vpc")
    route = resource("route", "Route", RouteTableId="table",
                     DestinationCidrBlock="0.0.0.0/0", GatewayId="gateway")
    gateway = resource("gateway", "InternetGateway")
    attachment = resource("attachment", "VPCGatewayAttachment", VpcId="vpc", InternetGatewayId="gateway")
    items = [subnet, nat_subnet, nat, vpc, association, table, route, gateway, attachment]
    links = [link("dns", "VpcId", "vpc"), link("nat-subnet", "VpcId", "vpc"),
             link("nat", "SubnetId", "nat-subnet"), link("association", "SubnetId", "nat-subnet"),
             link("association", "RouteTableId", "table"), link("route", "RouteTableId", "table"),
             link("route", "GatewayId", "gateway"), link("attachment", "InternetGatewayId", "gateway"),
             link("attachment", "VpcId", "vpc")]
    assert evaluate_subnet_dns64_nat(design(items, links), subnet)["verdict"] == "PASS"
    assert evaluate_subnet_dns64_nat(design(items, links[:-1]), subnet)["verdict"] == "NEEDS_REVIEW"


def test_spot_fleet_unit_type_requires_attribute_selection():
    config = {"TargetCapacityUnitType": "vcpu", "LaunchTemplateConfigs": [
        {"LaunchTemplateSpecification": {"LaunchTemplateId": "template", "Version": "1"}}]}
    fleet = resource("fleet", "SpotFleet", SpotFleetRequestConfigData=config)
    template = resource("template", "LaunchTemplate", LaunchTemplateData={"ImageId": "ami-1"})
    links = [link("fleet", "SpotFleetRequestConfigData/LaunchTemplateConfigs/0/LaunchTemplateSpecification/LaunchTemplateId",
                  "template")]
    d = design([fleet, template], links)
    assert evaluate_spot_fleet_unit_type(d, fleet)["verdict"] == "FAIL"
    template.fields = [field("LaunchTemplateData", {"InstanceRequirements": {"VCpuCount": {"Min": 2}}})]
    assert evaluate_spot_fleet_unit_type(d, fleet)["verdict"] == "PASS"


def test_rds_global_write_forwarding_primary_and_secondary():
    cluster = Resource(id="cluster", name="cluster", type="AWS::RDS::DBCluster", scope=SCOPE,
                       fields=[field("Engine", "aurora-postgresql"),
                               field("EnableGlobalWriteForwarding", True)])
    global_cluster = Resource(id="global", name="global", type="AWS::RDS::GlobalCluster",
                              scope=SCOPE, fields=[field("SourceDBClusterIdentifier", "cluster")])
    assert evaluate_rds_global_write_forwarding(
        design([cluster, global_cluster], [link("global", "SourceDBClusterIdentifier", "cluster")]),
        cluster)["verdict"] == "PASS"
    assert evaluate_rds_global_write_forwarding(design([cluster], []), cluster)["verdict"] == "NEEDS_REVIEW"
    cluster.fields.append(field("GlobalClusterIdentifier", "global"))
    assert evaluate_rds_global_write_forwarding(design([cluster], []), cluster)["verdict"] == "PASS"


def test_volume_attachment_outpost_location():
    attachment = resource("attachment", "VolumeAttachment", VolumeId="volume", InstanceId="instance")
    volume = resource("volume", "Volume", OutpostArn="arn:aws:outposts:ap-northeast-1:111111111111:outpost/op-a")
    instance = resource("instance", "Instance", SubnetId="subnet")
    subnet = resource("subnet", "Subnet", OutpostArn="arn:aws:outposts:ap-northeast-1:111111111111:outpost/op-b")
    links = [link("attachment", "VolumeId", "volume"), link("attachment", "InstanceId", "instance"),
             link("instance", "SubnetId", "subnet")]
    d = design([attachment, volume, instance, subnet], links)
    assert evaluate_volume_attachment_outpost(d, attachment)["verdict"] == "FAIL"
    subnet.fields = [field("OutpostArn", "arn:aws:outposts:ap-northeast-1:111111111111:outpost/op-a")]
    assert evaluate_volume_attachment_outpost(d, attachment)["verdict"] == "PASS"


def test_instance_template_secondary_interface_requires_primary():
    instance = resource("instance", "Instance", LaunchTemplate={
        "LaunchTemplateId": "template", "Version": "1"})
    template = resource("template", "LaunchTemplate", LaunchTemplateData={
        "NetworkInterfaces": [{"DeviceIndex": 1}]})
    links = [link("instance", "LaunchTemplate/LaunchTemplateId", "template")]
    d = design([instance, template], links)
    assert evaluate_instance_template_primary_interface(d, instance)["verdict"] == "FAIL"
    instance.fields.append(field("NetworkInterfaces", [{"DeviceIndex": 0}]))
    assert evaluate_instance_template_primary_interface(d, instance)["verdict"] == "PASS"


def test_access_grant_registered_location():
    grant = Resource(id="grant", name="grant", type="AWS::S3::AccessGrant", scope=SCOPE,
                     fields=[field("AccessGrantsLocationId", "location")])
    location = Resource(id="location", name="location", type="AWS::S3::AccessGrantsLocation",
                        scope=SCOPE, fields=[field("LocationScope", "s3://bucket")])
    links = [link("grant", "AccessGrantsLocationId", "location")]
    assert evaluate_access_grant_registered_location(design([grant, location], links), grant)["verdict"] == "PASS"
    assert evaluate_access_grant_registered_location(design([grant, location], []), grant)["verdict"] == "NEEDS_REVIEW"


@pytest.mark.parametrize("peer_cidr,expected", [
    ("10.0.1.0/24", "FAIL"), ("10.2.0.0/16", "PASS")])
def test_peering_known_cidrs(peer_cidr, expected):
    items = [resource("peering", "VPCPeeringConnection", VpcId="a", PeerVpcId="b"),
             resource("a", "VPC", CidrBlock="10.0.0.0/16"),
             resource("b", "VPC", CidrBlock=peer_cidr)]
    links = [link("peering", "VpcId", "a"), link("peering", "PeerVpcId", "b")]
    d = design(items, links)
    assert evaluate_vpc_peering_cidr(d, items[0])["verdict"] == expected
    if expected == "FAIL":
        findings = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(d)["results"]
        assert any(row["rule_id"] == "EC2_VPC_PEERING_CIDR_OVERLAP" and row["verdict"] == "FAIL"
                   for row in findings)


def test_peering_secondary_cidr_and_missing_relation():
    items = [resource("peering", "VPCPeeringConnection", VpcId="a", PeerVpcId="b"),
             resource("a", "VPC", CidrBlock="10.0.0.0/16"),
             resource("b", "VPC", CidrBlock="10.2.0.0/16"),
             resource("secondary", "VPCCidrBlock", VpcId="b", CidrBlock="10.0.8.0/24")]
    links = [link("peering", "VpcId", "a"), link("peering", "PeerVpcId", "b"),
             link("secondary", "VpcId", "b")]
    assert evaluate_vpc_peering_cidr(design(items, links), items[0])["verdict"] == "FAIL"
    assert evaluate_vpc_peering_cidr(design(items, links[:1]), items[0])["verdict"] == "NEEDS_REVIEW"


@pytest.mark.parametrize("hostnames,support,expected", [
    (True, True, "PASS"), (False, True, "FAIL")])
def test_endpoint_private_dns_vpc_attributes(hostnames, support, expected):
    items = [resource("endpoint", "VPCEndpoint", VpcId="vpc", PrivateDnsEnabled=True),
             resource("vpc", "VPC", EnableDnsHostnames=hostnames, EnableDnsSupport=support)]
    d = design(items, [link("endpoint", "VpcId", "vpc")])
    assert evaluate_endpoint_private_dns(d, items[0])["verdict"] == expected
    assert evaluate_endpoint_private_dns(design(items, []), items[0])["verdict"] == "NEEDS_REVIEW"


def test_notification_endpoint_type():
    items = [resource("notification", "VPCEndpointConnectionNotification", VPCEndpointId="endpoint"),
             resource("endpoint", "VPCEndpoint", VpcEndpointType="Gateway")]
    links = [link("notification", "VPCEndpointId", "endpoint")]
    assert evaluate_endpoint_notification_type(design(items, links), items[0])["verdict"] == "FAIL"
    items[1].fields = [field("VpcEndpointType", "Interface")]
    assert evaluate_endpoint_notification_type(design(items, links), items[0])["verdict"] == "PASS"
    assert evaluate_endpoint_notification_type(design(items, []), items[0])["verdict"] == "NEEDS_REVIEW"


def test_volume_attachment_az_and_unresolved_instance():
    items = [resource("attachment", "VolumeAttachment", VolumeId="volume", InstanceId="instance"),
             resource("volume", "Volume", AvailabilityZone="ap-northeast-1a"),
             resource("instance", "Instance", AvailabilityZone="ap-northeast-1c")]
    links = [link("attachment", "VolumeId", "volume"), link("attachment", "InstanceId", "instance")]
    assert evaluate_volume_attachment_az(design(items, links), items[0])["verdict"] == "FAIL"
    items[2].fields = [field("AvailabilityZone", "ap-northeast-1a")]
    assert evaluate_volume_attachment_az(design(items, links), items[0])["verdict"] == "PASS"
    items[2].fields = []
    assert evaluate_volume_attachment_az(design(items, links), items[0])["verdict"] == "NEEDS_REVIEW"


def test_acl_entry_duplicate_number_with_same_direction():
    items = [resource("first", "NetworkAclEntry", NetworkAclId="acl", RuleNumber=100, Egress=False),
             resource("second", "NetworkAclEntry", NetworkAclId="acl", RuleNumber=100, Egress=False),
             resource("acl", "NetworkAcl")]
    links = [link("first", "NetworkAclId", "acl"), link("second", "NetworkAclId", "acl")]
    assert evaluate_network_acl_entry_number(design(items, links), items[0])["verdict"] == "FAIL"
    items[1].fields[-1] = field("Egress", True)
    assert evaluate_network_acl_entry_number(design(items, links), items[0])["verdict"] == "PASS"
    assert evaluate_network_acl_entry_number(design(items, links[:1]), items[0])["verdict"] == "NEEDS_REVIEW"


def test_instance_connect_endpoint_duplicate_vpc():
    items = [resource("one", "InstanceConnectEndpoint", SubnetId="subnet-a"),
             resource("two", "InstanceConnectEndpoint", SubnetId="subnet-b"),
             resource("subnet-a", "Subnet", VpcId="vpc"),
             resource("subnet-b", "Subnet", VpcId="vpc"),
             resource("vpc", "VPC"), resource("other-vpc", "VPC")]
    links = [link("one", "SubnetId", "subnet-a"), link("two", "SubnetId", "subnet-b"),
             link("subnet-a", "VpcId", "vpc"), link("subnet-b", "VpcId", "vpc")]
    assert evaluate_instance_connect_endpoint_unique(design(items, links), items[0])["verdict"] == "FAIL"
    links[-1] = link("subnet-b", "VpcId", "other-vpc")
    assert evaluate_instance_connect_endpoint_unique(design(items, links), items[0])["verdict"] == "PASS"
    assert evaluate_instance_connect_endpoint_unique(design(items, links[:-1]), items[0])["verdict"] == "NEEDS_REVIEW"


def test_serverless_instance_requires_linked_cluster_capacity():
    instance = Resource(id="instance", name="instance", type="AWS::RDS::DBInstance", scope=SCOPE,
                        fields=[field("DBInstanceClass", "db.serverless"),
                                field("DBClusterIdentifier", "cluster")])
    cluster = Resource(id="cluster", name="cluster", type="AWS::RDS::DBCluster", scope=SCOPE)
    relation = link("instance", "DBClusterIdentifier", "cluster")
    d = design([instance, cluster], [relation])
    assert evaluate_rds_serverless_cluster_capacity(d, instance)["verdict"] == "FAIL"
    cluster.fields = [field("ServerlessV2ScalingConfiguration", {"MinCapacity": 0.5, "MaxCapacity": 2})]
    assert evaluate_rds_serverless_cluster_capacity(d, instance)["verdict"] == "PASS"
    assert evaluate_rds_serverless_cluster_capacity(design([instance, cluster], []), instance)["verdict"] == "NEEDS_REVIEW"


def test_gateway_route_table_association_vpc():
    items = [resource("association", "GatewayRouteTableAssociation", GatewayId="igw", RouteTableId="table"),
             resource("table", "RouteTable", VpcId="vpc-a"),
             resource("igw", "InternetGateway"),
             resource("attachment", "VPCGatewayAttachment", InternetGatewayId="igw", VpcId="vpc-b"),
             resource("vpc-a", "VPC"), resource("vpc-b", "VPC")]
    links = [link("association", "GatewayId", "igw"),
             link("association", "RouteTableId", "table"),
             link("table", "VpcId", "vpc-a"),
             link("attachment", "InternetGatewayId", "igw"),
             link("attachment", "VpcId", "vpc-b")]
    assert evaluate_gateway_route_table_vpc(design(items, links), items[0])["verdict"] == "FAIL"
    links[-1] = link("attachment", "VpcId", "vpc-a")
    assert evaluate_gateway_route_table_vpc(design(items, links), items[0])["verdict"] == "PASS"
    assert evaluate_gateway_route_table_vpc(design(items, links[:-2]), items[0])["verdict"] == "NEEDS_REVIEW"


def test_client_vpn_cidr_vs_associated_vpc_and_route():
    items = [resource("endpoint", "ClientVpnEndpoint", ClientCidrBlock="10.10.0.0/22"),
             resource("association", "ClientVpnTargetNetworkAssociation", ClientVpnEndpointId="endpoint",
                      SubnetId="subnet"),
             resource("subnet", "Subnet", VpcId="vpc"),
             resource("vpc", "VPC", CidrBlock="10.10.2.0/24")]
    links = [link("association", "ClientVpnEndpointId", "endpoint"),
             link("association", "SubnetId", "subnet"), link("subnet", "VpcId", "vpc")]
    assert evaluate_client_vpn_cidr_overlap(design(items, links), items[0])["verdict"] == "FAIL"
    items[-1].fields = [field("CidrBlock", "10.20.0.0/16")]
    assert evaluate_client_vpn_cidr_overlap(design(items, links), items[0])["verdict"] == "PASS"
    route = resource("route", "ClientVpnRoute", ClientVpnEndpointId="endpoint",
                     DestinationCidrBlock="10.10.1.0/24")
    items.append(route)
    links.append(link("route", "ClientVpnEndpointId", "endpoint"))
    assert evaluate_client_vpn_cidr_overlap(design(items, links), items[0])["verdict"] == "FAIL"
    assert evaluate_client_vpn_cidr_overlap(design(items, links[:-2]), items[0])["verdict"] == "NEEDS_REVIEW"


def test_instance_inline_volume_az():
    instance = resource("instance", "Instance", AvailabilityZone="ap-northeast-1a",
                        Volumes=[{"VolumeId": "volume", "Device": "/dev/sdh"}])
    volume = resource("volume", "Volume", AvailabilityZone="ap-northeast-1c")
    relation = link("instance", "Volumes/0/VolumeId", "volume")
    assert evaluate_instance_volumes_az(design([instance, volume], [relation]), instance)[0]["verdict"] == "FAIL"
    volume.fields = [field("AvailabilityZone", "ap-northeast-1a")]
    assert evaluate_instance_volumes_az(design([instance, volume], [relation]), instance)[0]["verdict"] == "PASS"
    assert evaluate_instance_volumes_az(design([instance, volume], []), instance)[0]["verdict"] == "NEEDS_REVIEW"


def test_ipam_allocation_uses_linked_pool_defaults_and_family():
    allocation = resource("allocation", "IPAMAllocation", IpamPoolId="pool")
    pool = resource("pool", "IPAMPool", AddressFamily="ipv4")
    relation = link("allocation", "IpamPoolId", "pool")
    d = design([allocation, pool], [relation])
    assert evaluate_ipam_allocation_pool(d, allocation)[0]["verdict"] == "FAIL"
    pool.fields.append(field("AllocationDefaultNetmaskLength", 24))
    assert evaluate_ipam_allocation_pool(d, allocation)[0]["verdict"] == "PASS"
    allocation.fields.append(field("NetmaskLength", 64))
    findings = {row["rule_id"]: row for row in evaluate_ipam_allocation_pool(d, allocation)}
    assert findings["EC2_IPAM_ALLOCATION_NETMASK_OR_CIDR"]["verdict"] == "PASS"
    assert findings["EC2_IPAM_ALLOCATION_NETMASK_FAMILY"]["verdict"] == "FAIL"
    pool.fields[0] = field("AddressFamily", "ipv6")
    findings = {row["rule_id"]: row for row in evaluate_ipam_allocation_pool(d, allocation)}
    assert findings["EC2_IPAM_ALLOCATION_NETMASK_FAMILY"]["verdict"] == "PASS"
    assert evaluate_ipam_allocation_pool(design([allocation, pool], []), allocation)[-1]["verdict"] == "NEEDS_REVIEW"


def test_client_vpn_route_and_association_follow_endpoint_mode():
    endpoint = resource("endpoint", "ClientVpnEndpoint")
    route = resource("route", "ClientVpnRoute", ClientVpnEndpointId="endpoint")
    association = resource("association", "ClientVpnTargetNetworkAssociation",
                           ClientVpnEndpointId="endpoint")
    links = [link("route", "ClientVpnEndpointId", "endpoint"),
             link("association", "ClientVpnEndpointId", "endpoint")]
    d = design([endpoint, route, association], links)
    assert evaluate_client_vpn_endpoint_mode(d, route)["verdict"] == "FAIL"
    assert evaluate_client_vpn_endpoint_mode(d, association)["verdict"] == "FAIL"
    route.fields.append(field("TargetVpcSubnetId", "local"))
    association.fields.append(field("SubnetId", "subnet"))
    assert evaluate_client_vpn_endpoint_mode(d, route)["verdict"] == "PASS"
    assert evaluate_client_vpn_endpoint_mode(d, association)["verdict"] == "PASS"
    endpoint.fields.append(field("TransitGatewayConfiguration", {"TransitGatewayId": "tgw"}))
    association.fields[-1] = field("AvailabilityZone", "ap-northeast-1a")
    assert evaluate_client_vpn_endpoint_mode(d, association)["verdict"] == "PASS"
    assert evaluate_client_vpn_endpoint_mode(design([endpoint, route], []), route)["verdict"] == "NEEDS_REVIEW"


def test_verified_access_subnets_have_distinct_zones():
    endpoint = resource("endpoint", "VerifiedAccessEndpoint",
                        LoadBalancerOptions={"SubnetIds": ["first", "second"]})
    first = resource("first", "Subnet", AvailabilityZone="ap-northeast-1a")
    second = resource("second", "Subnet", AvailabilityZone="ap-northeast-1a")
    links = [link("endpoint", "LoadBalancerOptions/SubnetIds/0", "first"),
             link("endpoint", "LoadBalancerOptions/SubnetIds/1", "second")]
    assert evaluate_verified_access_subnet_az(design([endpoint, first, second], links), endpoint)[0]["verdict"] == "FAIL"
    second.fields = [field("AvailabilityZone", "ap-northeast-1c")]
    assert evaluate_verified_access_subnet_az(design([endpoint, first, second], links), endpoint)[0]["verdict"] == "PASS"
    assert evaluate_verified_access_subnet_az(design([endpoint, first, second], links[:1]), endpoint)[0]["verdict"] == "NEEDS_REVIEW"


def test_client_vpn_associations_share_vpc_and_distinct_zones():
    endpoint = resource("endpoint", "ClientVpnEndpoint")
    first = resource("first", "ClientVpnTargetNetworkAssociation", ClientVpnEndpointId="endpoint",
                     SubnetId="subnet-a")
    second = resource("second", "ClientVpnTargetNetworkAssociation", ClientVpnEndpointId="endpoint",
                      SubnetId="subnet-b")
    subnet_a = resource("subnet-a", "Subnet", VpcId="vpc-a", AvailabilityZone="ap-northeast-1a")
    subnet_b = resource("subnet-b", "Subnet", VpcId="vpc-a", AvailabilityZone="ap-northeast-1a")
    vpc_a, vpc_b = resource("vpc-a", "VPC"), resource("vpc-b", "VPC")
    items = [endpoint, first, second, subnet_a, subnet_b, vpc_a, vpc_b]
    links = [link("first", "ClientVpnEndpointId", "endpoint"),
             link("second", "ClientVpnEndpointId", "endpoint"),
             link("first", "SubnetId", "subnet-a"), link("second", "SubnetId", "subnet-b"),
             link("subnet-a", "VpcId", "vpc-a"), link("subnet-b", "VpcId", "vpc-a")]
    assert evaluate_client_vpn_association_network(design(items, links), first)["verdict"] == "FAIL"
    subnet_b.fields[-1] = field("AvailabilityZone", "ap-northeast-1c")
    assert evaluate_client_vpn_association_network(design(items, links), first)["verdict"] == "PASS"
    links[-1] = link("subnet-b", "VpcId", "vpc-b")
    assert evaluate_client_vpn_association_network(design(items, links), first)["verdict"] == "FAIL"


def test_eip_instance_interface_count():
    eip = resource("eip", "EIPAssociation", InstanceId="instance")
    instance = resource("instance", "Instance", NetworkInterfaces=[{"DeviceIndex": "0"},
                                                               {"DeviceIndex": "1"}])
    relation = link("eip", "InstanceId", "instance")
    assert evaluate_eip_instance_interface_count(design([eip, instance], [relation]), eip)["verdict"] == "FAIL"
    instance.fields = [field("NetworkInterfaces", [{"DeviceIndex": "0"}])]
    assert evaluate_eip_instance_interface_count(design([eip, instance], [relation]), eip)["verdict"] == "PASS"
    instance.fields = []
    assert evaluate_eip_instance_interface_count(design([eip, instance], [relation]), eip)["verdict"] == "NEEDS_REVIEW"


def test_instance_launch_template_image_and_requirements():
    instance = resource("instance", "Instance", LaunchTemplate={"LaunchTemplateId": "template", "Version": "1"})
    template = resource("template", "LaunchTemplate", LaunchTemplateData={"InstanceRequirements": {"VCpuCount": {"Min": 2}}})
    relation = link("instance", "LaunchTemplate/LaunchTemplateId", "template")
    rows = {row["rule_id"]: row for row in evaluate_instance_launch_template(design([instance, template], [relation]), instance)}
    assert rows["EC2_INSTANCE_LAUNCH_TEMPLATE_IMAGE"]["verdict"] == "FAIL"
    assert rows["EC2_INSTANCE_LAUNCH_TEMPLATE_REQUIREMENTS"]["verdict"] == "FAIL"
    template.fields = [field("LaunchTemplateData", {"ImageId": "ami-123"})]
    rows = {row["rule_id"]: row for row in evaluate_instance_launch_template(design([instance, template], [relation]), instance)}
    assert rows["EC2_INSTANCE_LAUNCH_TEMPLATE_IMAGE"]["verdict"] == "PASS"
    assert rows["EC2_INSTANCE_LAUNCH_TEMPLATE_REQUIREMENTS"]["verdict"] == "PASS"
    rows = evaluate_instance_launch_template(design([instance, template], []), instance)
    assert all(row["verdict"] == "NEEDS_REVIEW" for row in rows)
    instance.fields = [field("LaunchTemplate", {"LaunchTemplateId": "template", "Version": "5"})]
    rows = evaluate_instance_launch_template(design([instance, template], [relation]), instance)
    assert all(row["verdict"] == "NEEDS_REVIEW" for row in rows)


def test_fleet_unit_type_requires_attribute_selection():
    fleet = resource("fleet", "EC2Fleet",
                     TargetCapacitySpecification={"TargetCapacityUnitType": "vcpu"},
                     LaunchTemplateConfigs=[{"Overrides": [{"InstanceRequirements": {"VCpuCount": {"Min": 2}}}]}])
    assert evaluate_ec2_fleet_unit_type(design([fleet], []), fleet)["verdict"] == "PASS"
    template = resource("template", "LaunchTemplate", LaunchTemplateData={"ImageId": "ami-123"})
    fleet.fields[-1] = field("LaunchTemplateConfigs", [{"Overrides": [],
                                                       "LaunchTemplateSpecification": {"LaunchTemplateId": "template"}}])
    relation = link("fleet", "LaunchTemplateConfigs/0/LaunchTemplateSpecification/LaunchTemplateId", "template")
    assert evaluate_ec2_fleet_unit_type(design([fleet, template], [relation]), fleet)["verdict"] == "FAIL"
    template.fields = [field("LaunchTemplateData", {"InstanceRequirements": {"VCpuCount": {"Min": 2}}})]
    assert evaluate_ec2_fleet_unit_type(design([fleet, template], [relation]), fleet)["verdict"] == "PASS"
    assert evaluate_ec2_fleet_unit_type(design([fleet, template], []), fleet)["verdict"] == "NEEDS_REVIEW"


def test_vpn_tunnel_inside_cidr_unique_per_gateway():
    first = resource("first", "VPNConnection", VpnGatewayId="vgw",
                     VpnTunnelOptionsSpecifications=[{"TunnelInsideCidr": "169.254.10.0/30"}])
    second = resource("second", "VPNConnection", VpnGatewayId="vgw",
                      VpnTunnelOptionsSpecifications=[{"TunnelInsideCidr": "169.254.10.0/30"}])
    assert evaluate_vpn_tunnel_cidr_uniqueness(design([first, second], []), first)["verdict"] == "FAIL"
    second.fields[0] = field("VpnGatewayId", "another-vgw")
    assert evaluate_vpn_tunnel_cidr_uniqueness(design([first, second], []), first)["verdict"] == "PASS"
    second.fields[0] = FieldValue(path="/properties/VpnGatewayId", state=ValueState.UNRESOLVED)
    assert evaluate_vpn_tunnel_cidr_uniqueness(design([first, second], []), first)["verdict"] == "NEEDS_REVIEW"


def test_vpn_route_propagation_matches_gateway_vpc():
    propagation = resource("propagation", "VPNGatewayRoutePropagation",
                           VpnGatewayId="gateway", RouteTableIds=["table"])
    gateway = resource("gateway", "VPNGateway")
    attachment = resource("attachment", "VPCGatewayAttachment", VpnGatewayId="gateway", VpcId="vpc-a")
    table = resource("table", "RouteTable", VpcId="vpc-b")
    vpc_a, vpc_b = resource("vpc-a", "VPC"), resource("vpc-b", "VPC")
    items = [propagation, gateway, attachment, table, vpc_a, vpc_b]
    links = [link("propagation", "VpnGatewayId", "gateway"),
             link("propagation", "RouteTableIds/0", "table"),
             link("attachment", "VpnGatewayId", "gateway"),
             link("attachment", "VpcId", "vpc-a"),
             link("table", "VpcId", "vpc-b")]
    assert evaluate_vpn_route_propagation_vpc(design(items, links), propagation)["verdict"] == "FAIL"
    links[-1] = link("table", "VpcId", "vpc-a")
    assert evaluate_vpn_route_propagation_vpc(design(items, links), propagation)["verdict"] == "PASS"
    assert evaluate_vpn_route_propagation_vpc(design(items, links[:-2]), propagation)["verdict"] == "NEEDS_REVIEW"
