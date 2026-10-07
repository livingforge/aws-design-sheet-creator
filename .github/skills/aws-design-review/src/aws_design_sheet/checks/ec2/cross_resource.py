"""Checks for these resource types:

- AWS::EC2::VPCBlockPublicAccessExclusion
- AWS::EC2::VPCPeeringConnection
- AWS::EC2::VPCEndpoint
- AWS::EC2::VPCEndpointConnectionNotification
- AWS::EC2::VolumeAttachment
- AWS::EC2::NetworkAclEntry
- AWS::EC2::TrafficMirrorFilterRule
- AWS::EC2::InstanceConnectEndpoint
- AWS::EC2::GatewayRouteTableAssociation
- AWS::EC2::ClientVpnEndpoint
- AWS::EC2::Instance
- AWS::EC2::IPAMAllocation
- AWS::EC2::ClientVpnRoute
- AWS::EC2::ClientVpnTargetNetworkAssociation
- AWS::EC2::VerifiedAccessEndpoint
- AWS::EC2::EIPAssociation
- AWS::EC2::EC2Fleet
- AWS::EC2::VPNConnection
- AWS::EC2::VPNGatewayRoutePropagation
- AWS::EC2::IPAMPoolCidr
- AWS::EC2::TransitGatewayAttachment
- AWS::EC2::TransitGatewayVpcAttachment
- AWS::EC2::TransitGatewayRouteTableAssociation
- AWS::EC2::IPAMPool
- AWS::EC2::SpotFleet
- AWS::EC2::Subnet
"""
from __future__ import annotations

import ipaddress
from ...models import ValueState
from ..registry import resource_check
from ..common.context import Context


SOURCES = {
    "EC2_VPC_PEERING_CIDR_OVERLAP": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcpeeringconnection.html"],
    "EC2_VPC_BPA_EGRESS_EXCLUSION_MODE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcblockpublicaccessexclusion.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcblockpublicaccessoptions.html"],
    "EC2_VPC_ENDPOINT_PRIVATE_DNS_ATTRIBUTES": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcendpoint.html"],
    "EC2_VPC_ENDPOINT_NOTIFICATION_INTERFACE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcendpointconnectionnotification.html"],
    "EC2_VOLUME_ATTACHMENT_SAME_AZ": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-volumeattachment.html"],
    "EC2_NETWORK_ACL_ENTRY_NUMBER_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-networkaclentry.html"],
    "EC2_TRAFFIC_MIRROR_FILTER_RULE_NUMBER_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-trafficmirrorfilterrule.html"],
    "EC2_INSTANCE_CONNECT_ENDPOINT_VPC_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instanceconnectendpoint.html"],
    "EC2_GATEWAY_ROUTE_TABLE_SAME_VPC": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-gatewayroutetableassociation.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcgatewayattachment.html"],
    "EC2_CLIENT_VPN_CIDR_NONOVERLAP": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-clientvpnendpoint.html"],
    "EC2_INSTANCE_VOLUME_SAME_AZ": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-instance-volume.html"],
    "EC2_IPAM_ALLOCATION_NETMASK_OR_CIDR": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-ipamallocation.html"],
    "EC2_IPAM_ALLOCATION_NETMASK_FAMILY": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-ipamallocation.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-ipampool.html"],
    "EC2_CLIENT_VPN_ROUTE_ENDPOINT_MODE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-clientvpnroute.html"],
    "EC2_CLIENT_VPN_ASSOCIATION_ENDPOINT_MODE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-clientvpntargetnetworkassociation.html"],
    "EC2_VERIFIED_ACCESS_SUBNET_AZ_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-verifiedaccessendpoint-loadbalanceroptions.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-verifiedaccessendpoint-rdsoptions.html"],
    "EC2_CLIENT_VPN_ASSOCIATION_NETWORK": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-clientvpntargetnetworkassociation.html"],
    "EC2_EIP_INSTANCE_SINGLE_INTERFACE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-eipassociation.html"],
    "EC2_INSTANCE_LAUNCH_TEMPLATE_IMAGE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-launchtemplate.html"],
    "EC2_INSTANCE_LAUNCH_TEMPLATE_REQUIREMENTS": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-launchtemplate-instancerequirements.html"],
    "EC2_FLEET_UNIT_TYPE_REQUIRES_ATTRIBUTES": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-ec2fleet-targetcapacityspecificationrequest.html"],
    "EC2_VPN_TUNNEL_CIDR_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-vpnconnection-vpntunneloptionsspecification.html"],
    "EC2_VPN_ROUTE_PROPAGATION_SAME_VPC": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpngatewayroutepropagation.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcgatewayattachment.html"],
    "EC2_IPAM_POOL_CIDR_NETMASK_SOURCE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-ipampoolcidr.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-ipampool.html"],
    "EC2_TRANSIT_GATEWAY_SUBNET_AZ_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-transitgatewayattachment.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-transitgatewayvpcattachment.html"],
    "EC2_TRANSIT_GATEWAY_ATTACHMENT_SINGLE_ROUTE_TABLE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-transitgatewayroutetableassociation.html"],
    "EC2_IPAM_POOL_SOURCE_LOCALE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-ipampool.html"],
    "EC2_SPOT_FLEET_TEMPLATE_INTERFACE_ID": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-spotfleet-launchtemplateconfig.html"],
    "EC2_SUBNET_DNS64_PUBLIC_NAT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnet.html"],
    "EC2_SPOT_FLEET_UNIT_TYPE_REQUIRES_ATTRIBUTES": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-spotfleet-spotfleetrequestconfigdata.html"],
    "EC2_VOLUME_ATTACHMENT_SAME_OUTPOST": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-volume.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnet.html"],
    "EC2_INSTANCE_TEMPLATE_PRIMARY_INTERFACE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-launchtemplate-networkinterface.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(item for candidate in field.candidates for item in candidate.evidence_ids)]


@resource_check('AWS::EC2::VPCBlockPublicAccessExclusion')
def evaluate_vpc_bpa_exclusion_mode(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_VPC_BPA_EGRESS_EXCLUSION_MODE"
    path = "/properties/InternetGatewayExclusionMode"
    field = resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding(rule, path, "NOT_APPLICABLE", "exclusion mode is not specified")
    mode = ctx.value(resource, path)
    if mode == "allow-bidirectional":
        return ctx.finding(rule, path, "NOT_APPLICABLE", "exclusion is bidirectional")
    if mode != "allow-egress":
        return ctx.finding(rule, path, "NEEDS_REVIEW", "exclusion mode is unresolved")

    options = [item for item in design.resources
               if item.type == "AWS::EC2::VPCBlockPublicAccessOptions" and
               item.scope.account == resource.scope.account and
               item.scope.region == resource.scope.region]
    if len(options) != 1:
        ctx.dependencies.append(f"{resource.id}/scope/vpc-block-public-access-options")
        return ctx.finding(rule, path, "NEEDS_REVIEW",
                           "account and Region BPA mode is not uniquely specified in the design")
    block_mode = ctx.value(options[0], "/properties/InternetGatewayBlockMode")
    if block_mode == "block-bidirectional":
        verdict, reason = "PASS", "allow-egress is valid with block-bidirectional BPA"
    elif block_mode == "block-ingress":
        verdict, reason = "FAIL", "allow-egress requires block-bidirectional BPA"
    else:
        verdict, reason = "NEEDS_REVIEW", "account and Region BPA mode is unresolved"
    return ctx.finding(rule, path, verdict, reason)


@resource_check('AWS::EC2::VPCPeeringConnection')
def evaluate_vpc_peering_cidr(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    vpcs = [ctx.target(resource, path, "AWS::EC2::VPC")
            for path in ("/properties/VpcId", "/properties/PeerVpcId")]
    if any(vpc is None for vpc in vpcs):
        return ctx.finding("EC2_VPC_PEERING_CIDR_OVERLAP", "/properties/PeerVpcId",
                           "NEEDS_REVIEW", "both VPCs must be linked in the design")
    cidrs: list[list[ipaddress.IPv4Network]] = []
    for vpc in vpcs:
        values = [ctx.value(vpc, "/properties/CidrBlock")]
        for block in ctx.design.resources:
            if block.type != "AWS::EC2::VPCCidrBlock" or block.scope != vpc.scope:
                continue
            refs = [ref for ref in design.relations
                    if ref.source_resource_id == block.id and ref.source_path == "/properties/VpcId"]
            if len(refs) == 1 and refs[0].target_resource_id == vpc.id:
                values.append(ctx.value(block, "/properties/CidrBlock"))
        networks = []
        for value in values:
            if not isinstance(value, str):
                ctx.dependencies.append(f"{vpc.id}/properties/CidrBlock")
                continue
            try:
                networks.append(ipaddress.IPv4Network(value, strict=False))
            except ValueError:
                ctx.dependencies.append(f"{vpc.id}/properties/CidrBlock")
        cidrs.append(networks)
    if any(left.overlaps(right) for left in cidrs[0] for right in cidrs[1]):
        return ctx.finding("EC2_VPC_PEERING_CIDR_OVERLAP", "/properties/PeerVpcId",
                           "FAIL", "linked VPC IPv4 CIDR blocks overlap")
    if ctx.dependencies:
        return ctx.finding("EC2_VPC_PEERING_CIDR_OVERLAP", "/properties/PeerVpcId",
                           "NEEDS_REVIEW", "VPC CIDR blocks are unresolved")
    return ctx.finding("EC2_VPC_PEERING_CIDR_OVERLAP", "/properties/PeerVpcId",
                       "PASS", "linked VPC IPv4 CIDR blocks do not overlap")


@resource_check('AWS::EC2::VPCEndpoint')
def evaluate_endpoint_private_dns(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    private_dns = resource.field("/properties/PrivateDnsEnabled")
    ctx.evidence.extend(_evidence(private_dns))
    if private_dns is None or private_dns.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding("EC2_VPC_ENDPOINT_PRIVATE_DNS_ATTRIBUTES", "/properties/PrivateDnsEnabled",
                           "NOT_APPLICABLE", "private DNS is not requested")
    if private_dns.state != ValueState.KNOWN:
        ctx.dependencies.append(f"{resource.id}/properties/PrivateDnsEnabled")
        return ctx.finding("EC2_VPC_ENDPOINT_PRIVATE_DNS_ATTRIBUTES", "/properties/PrivateDnsEnabled",
                           "NEEDS_REVIEW", "private DNS setting is unresolved")
    if private_dns.selected().value is not True:
        return ctx.finding("EC2_VPC_ENDPOINT_PRIVATE_DNS_ATTRIBUTES", "/properties/PrivateDnsEnabled",
                           "NOT_APPLICABLE", "private DNS is not enabled")
    vpc = ctx.target(resource, "/properties/VpcId", "AWS::EC2::VPC")
    if vpc is None:
        verdict, reason = "NEEDS_REVIEW", "VPC is not linked in the design"
    else:
        values = [ctx.value(vpc, "/properties/EnableDnsHostnames"),
                  ctx.value(vpc, "/properties/EnableDnsSupport")]
        if False in values:
            verdict, reason = "FAIL", "private DNS requires both VPC DNS attributes to be true"
        elif ctx.dependencies:
            verdict, reason = "NEEDS_REVIEW", "VPC DNS attributes are unresolved"
        else:
            verdict, reason = "PASS", "both VPC DNS attributes are true"
    return ctx.finding("EC2_VPC_ENDPOINT_PRIVATE_DNS_ATTRIBUTES", "/properties/PrivateDnsEnabled",
                       verdict, reason)


@resource_check('AWS::EC2::VPCEndpointConnectionNotification')
def evaluate_endpoint_notification_type(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    path = "/properties/VPCEndpointId"
    field = resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding("EC2_VPC_ENDPOINT_NOTIFICATION_INTERFACE", path,
                           "NOT_APPLICABLE", "notification targets an endpoint service")
    endpoint = ctx.target(resource, path, "AWS::EC2::VPCEndpoint")
    if endpoint is None:
        verdict, reason = "NEEDS_REVIEW", "endpoint is not linked in the design"
    else:
        kind = ctx.value(endpoint, "/properties/VpcEndpointType")
        if kind is None:
            verdict, reason = "NEEDS_REVIEW", "endpoint type is unresolved"
        elif kind != "Interface":
            verdict, reason = "FAIL", "connection notifications require an interface endpoint"
        else:
            verdict, reason = "PASS", "linked endpoint is an interface endpoint"
    return ctx.finding("EC2_VPC_ENDPOINT_NOTIFICATION_INTERFACE", path, verdict, reason)


@resource_check('AWS::EC2::VolumeAttachment')
def evaluate_volume_attachment_az(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    volume = ctx.target(resource, "/properties/VolumeId", "AWS::EC2::Volume")
    instance = ctx.target(resource, "/properties/InstanceId", "AWS::EC2::Instance")
    if volume is None or instance is None:
        return ctx.finding("EC2_VOLUME_ATTACHMENT_SAME_AZ", "/properties/VolumeId",
                           "NEEDS_REVIEW", "volume and instance must be linked in the design")
    volume_az = ctx.value(volume, "/properties/AvailabilityZone")
    instance_az = ctx.value(instance, "/properties/AvailabilityZone")
    if instance_az is None:
        subnet = ctx.target(instance, "/properties/SubnetId", "AWS::EC2::Subnet")
        if subnet is not None:
            instance_az = ctx.value(subnet, "/properties/AvailabilityZone")
    if isinstance(volume_az, str) and isinstance(instance_az, str):
        verdict = "PASS" if volume_az == instance_az else "FAIL"
        reason = ("volume and instance Availability Zones match" if verdict == "PASS"
                  else "volume and instance Availability Zones differ")
    else:
        verdict, reason = "NEEDS_REVIEW", "one or both Availability Zones are unresolved"
    return ctx.finding("EC2_VOLUME_ATTACHMENT_SAME_AZ", "/properties/VolumeId", verdict, reason)


@resource_check('AWS::EC2::NetworkAclEntry')
def evaluate_network_acl_entry_number(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    acl = ctx.target(resource, "/properties/NetworkAclId", "AWS::EC2::NetworkAcl")
    number = ctx.value(resource, "/properties/RuleNumber")
    egress_field = resource.field("/properties/Egress")
    egress = (False if egress_field is None or egress_field.state == ValueState.MISSING
              else ctx.value(resource, "/properties/Egress"))
    if acl is None or not isinstance(number, int) or type(number) is bool or not isinstance(egress, bool):
        return ctx.finding("EC2_NETWORK_ACL_ENTRY_NUMBER_UNIQUE", "/properties/RuleNumber",
                           "NEEDS_REVIEW", "ACL, rule number, or direction is unresolved")
    uncertain = False
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        other_acl = ctx.target(other, "/properties/NetworkAclId", "AWS::EC2::NetworkAcl")
        if other_acl is None:
            uncertain = True
            continue
        if other_acl.id != acl.id:
            continue
        other_number = ctx.value(other, "/properties/RuleNumber")
        other_egress_field = other.field("/properties/Egress")
        other_egress = (False if other_egress_field is None or other_egress_field.state == ValueState.MISSING
                        else ctx.value(other, "/properties/Egress"))
        if other_number == number and other_egress == egress:
            return ctx.finding("EC2_NETWORK_ACL_ENTRY_NUMBER_UNIQUE", "/properties/RuleNumber",
                               "FAIL", f"rule number and direction duplicate {other.id}")
        if other_number is None or other_egress is None:
            uncertain = True
    if uncertain:
        return ctx.finding("EC2_NETWORK_ACL_ENTRY_NUMBER_UNIQUE", "/properties/RuleNumber",
                           "NEEDS_REVIEW", "another ACL entry could use the same number")
    return ctx.finding("EC2_NETWORK_ACL_ENTRY_NUMBER_UNIQUE", "/properties/RuleNumber",
                       "PASS", "rule number and direction are unique in the design ACL")


@resource_check('AWS::EC2::TrafficMirrorFilterRule')
def evaluate_traffic_mirror_filter_rule_number(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_TRAFFIC_MIRROR_FILTER_RULE_NUMBER_UNIQUE"
    filter_path = "/properties/TrafficMirrorFilterId"
    number_path = "/properties/RuleNumber"
    direction_path = "/properties/TrafficDirection"

    def identity(item: Resource) -> tuple[str, str] | None:
        refs = [ref for ref in design.relations
                if ref.source_resource_id == item.id and ref.source_path == filter_path]
        if len(refs) > 1:
            return None
        if refs:
            target = ctx.by_id.get(refs[0].target_resource_id)
            if target is None or target.type != "AWS::EC2::TrafficMirrorFilter":
                return None
            return "resource", target.id
        raw = ctx.value(item, filter_path)
        return ("id", raw) if isinstance(raw, str) and raw else None

    own_filter = identity(resource)
    number = ctx.value(resource, number_path)
    direction = ctx.value(resource, direction_path)
    if own_filter is None or type(number) is not int or direction not in ("ingress", "egress"):
        return ctx.finding(rule, number_path, "NEEDS_REVIEW",
                           "filter, rule number, or traffic direction is unresolved")
    uncertain = False
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        other_filter = identity(other)
        if other_filter is not None and other_filter != own_filter:
            continue
        other_number = ctx.value(other, number_path)
        other_direction = ctx.value(other, direction_path)
        if other_filter is None or other_number is None or other_direction is None:
            uncertain = True
            continue
        if other_filter == own_filter and other_number == number and other_direction == direction:
            return ctx.finding(rule, number_path, "FAIL",
                               f"rule number and direction duplicate {other.id} in the same filter")
    return ctx.finding(rule, number_path, "NEEDS_REVIEW" if uncertain else "PASS",
                       "another filter rule is unresolved" if uncertain else
                       "rule number and direction are unique in the design filter")


@resource_check('AWS::EC2::InstanceConnectEndpoint')
def evaluate_instance_connect_endpoint_unique(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)

    def endpoint_vpc(endpoint: Resource) -> Resource | None:
        subnet = ctx.target(endpoint, "/properties/SubnetId", "AWS::EC2::Subnet")
        return ctx.target(subnet, "/properties/VpcId", "AWS::EC2::VPC") if subnet else None

    vpc = endpoint_vpc(resource)
    if vpc is None:
        return ctx.finding("EC2_INSTANCE_CONNECT_ENDPOINT_VPC_UNIQUE", "/properties/SubnetId",
                           "NEEDS_REVIEW", "endpoint VPC is unresolved")
    uncertain = False
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        other_vpc = endpoint_vpc(other)
        if other_vpc is None:
            uncertain = True
        elif other_vpc.id == vpc.id:
            return ctx.finding("EC2_INSTANCE_CONNECT_ENDPOINT_VPC_UNIQUE", "/properties/SubnetId",
                               "FAIL", f"another endpoint {other.id} is in the same VPC")
    if uncertain:
        return ctx.finding("EC2_INSTANCE_CONNECT_ENDPOINT_VPC_UNIQUE", "/properties/SubnetId",
                           "NEEDS_REVIEW", "another endpoint's VPC is unresolved")
    return ctx.finding("EC2_INSTANCE_CONNECT_ENDPOINT_VPC_UNIQUE", "/properties/SubnetId",
                       "PASS", "no other design endpoint is in this VPC")


@resource_check('AWS::EC2::GatewayRouteTableAssociation')
def evaluate_gateway_route_table_vpc(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    route_table = ctx.target(resource, "/properties/RouteTableId", "AWS::EC2::RouteTable")
    if route_table is None:
        return ctx.finding("EC2_GATEWAY_ROUTE_TABLE_SAME_VPC", "/properties/GatewayId",
                           "NEEDS_REVIEW", "route table is not linked in the design")
    route_vpc = ctx.target(route_table, "/properties/VpcId", "AWS::EC2::VPC")
    gateway_refs = [ref for ref in design.relations
                    if ref.source_resource_id == resource.id and ref.source_path == "/properties/GatewayId"]
    ctx.evidence.extend(item for ref in gateway_refs for item in ref.evidence_ids)
    gateway = ctx.by_id.get(gateway_refs[0].target_resource_id) if len(gateway_refs) == 1 else None
    if gateway is None or gateway.type not in ("AWS::EC2::InternetGateway", "AWS::EC2::VPNGateway"):
        ctx.dependencies.append(f"{resource.id}/properties/GatewayId")
        return ctx.finding("EC2_GATEWAY_ROUTE_TABLE_SAME_VPC", "/properties/GatewayId",
                           "NEEDS_REVIEW", "gateway is not linked in the design")
    gateway_path = ("/properties/InternetGatewayId" if gateway.type == "AWS::EC2::InternetGateway"
                    else "/properties/VpnGatewayId")
    attached_vpcs = []
    for attachment in design.resources:
        if attachment.type != "AWS::EC2::VPCGatewayAttachment" or attachment.scope != resource.scope:
            continue
        refs = [ref for ref in design.relations
                if ref.source_resource_id == attachment.id and ref.source_path == gateway_path]
        if len(refs) == 1 and refs[0].target_resource_id == gateway.id:
            attached_vpcs.append(ctx.target(attachment, "/properties/VpcId", "AWS::EC2::VPC"))
    if route_vpc is None or len(attached_vpcs) != 1 or attached_vpcs[0] is None:
        ctx.dependencies.append(f"{gateway.id} -> VPCGatewayAttachment")
        verdict, reason = "NEEDS_REVIEW", "gateway VPC attachment is unresolved"
    elif route_vpc.id != attached_vpcs[0].id:
        verdict, reason = "FAIL", "gateway and route table are in different VPCs"
    else:
        verdict, reason = "PASS", "gateway and route table are in the same VPC"
    return ctx.finding("EC2_GATEWAY_ROUTE_TABLE_SAME_VPC", "/properties/GatewayId",
                       verdict, reason)


@resource_check('AWS::EC2::ClientVpnEndpoint')
def evaluate_client_vpn_cidr_overlap(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    path = "/properties/ClientCidrBlock"
    field = resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding("EC2_CLIENT_VPN_CIDR_NONOVERLAP", path,
                           "NOT_APPLICABLE", "client CIDR is not specified")
    raw_client = ctx.value(resource, path)
    try:
        client = ipaddress.IPv4Network(raw_client, strict=False) if isinstance(raw_client, str) else None
    except ValueError:
        client = None
    if client is None:
        return ctx.finding("EC2_CLIENT_VPN_CIDR_NONOVERLAP", path,
                           "NEEDS_REVIEW", "client CIDR is unresolved or invalid")
    associated = 0
    for item in design.resources:
        if item.scope != resource.scope:
            continue
        if item.type == "AWS::EC2::ClientVpnTargetNetworkAssociation":
            endpoint_path = "/properties/ClientVpnEndpointId"
            subnet_path = "/properties/SubnetId"
        elif item.type == "AWS::EC2::ClientVpnRoute":
            endpoint_path = "/properties/ClientVpnEndpointId"
            subnet_path = None
        else:
            continue
        refs = [ref for ref in design.relations
                if ref.source_resource_id == item.id and ref.source_path == endpoint_path]
        if len(refs) != 1 or refs[0].target_resource_id != resource.id:
            continue
        if subnet_path:
            associated += 1
            subnet = ctx.target(item, subnet_path, "AWS::EC2::Subnet")
            vpc = ctx.target(subnet, "/properties/VpcId", "AWS::EC2::VPC") if subnet else None
            cidr = ctx.value(vpc, "/properties/CidrBlock") if vpc else None
            source_path = f"{vpc.id}/properties/CidrBlock" if vpc else f"{item.id}{subnet_path}"
        else:
            cidr = ctx.value(item, "/properties/DestinationCidrBlock")
            source_path = f"{item.id}/properties/DestinationCidrBlock"
        try:
            network = ipaddress.IPv4Network(cidr, strict=False) if isinstance(cidr, str) else None
        except ValueError:
            network = None
        if network is None:
            ctx.dependencies.append(source_path)
        elif client.overlaps(network):
            return ctx.finding("EC2_CLIENT_VPN_CIDR_NONOVERLAP", path,
                               "FAIL", f"client CIDR overlaps {source_path}")
    if not associated:
        ctx.dependencies.append("ClientVpnTargetNetworkAssociation")
    if ctx.dependencies:
        return ctx.finding("EC2_CLIENT_VPN_CIDR_NONOVERLAP", path,
                           "NEEDS_REVIEW", "associated VPC or routes are unresolved")
    return ctx.finding("EC2_CLIENT_VPN_CIDR_NONOVERLAP", path,
                       "PASS", "client CIDR does not overlap linked VPC or route CIDRs")


@resource_check('AWS::EC2::Instance')
def evaluate_instance_volumes_az(design: Design, resource: Resource) -> list[dict[str, Any]]:
    field = resource.field("/properties/Volumes")
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return []
    ctx = Context(design, resource)
    values = ctx.value(resource, "/properties/Volumes")
    if not isinstance(values, list):
        return [ctx.finding("EC2_INSTANCE_VOLUME_SAME_AZ", "/properties/Volumes",
                            "NEEDS_REVIEW", "volume attachments are unresolved")]
    instance_az = ctx.value(resource, "/properties/AvailabilityZone")
    if instance_az is None:
        subnet = ctx.target(resource, "/properties/SubnetId", "AWS::EC2::Subnet")
        if subnet:
            instance_az = ctx.value(subnet, "/properties/AvailabilityZone")
    results = []
    for index, item in enumerate(values):
        path = f"/properties/Volumes/{index}/VolumeId"
        if not isinstance(item, dict) or "VolumeId" not in item:
            continue
        volume = ctx.target(resource, path, "AWS::EC2::Volume")
        volume_az = ctx.value(volume, "/properties/AvailabilityZone") if volume else None
        if isinstance(instance_az, str) and isinstance(volume_az, str):
            verdict = "PASS" if instance_az == volume_az else "FAIL"
            reason = "volume and instance Availability Zones match" if verdict == "PASS" else "volume and instance Availability Zones differ"
        else:
            verdict, reason = "NEEDS_REVIEW", "volume or instance Availability Zone is unresolved"
        results.append(ctx.finding("EC2_INSTANCE_VOLUME_SAME_AZ", path, verdict, reason))
    return results


@resource_check('AWS::EC2::IPAMAllocation')
def evaluate_ipam_allocation_pool(design: Design, resource: Resource) -> list[dict[str, Any]]:
    ctx = Context(design, resource)
    netmask_field = resource.field("/properties/NetmaskLength")
    cidr_field = resource.field("/properties/Cidr")

    def present(field: FieldValue | None) -> bool | None:
        if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            return False
        if field.state == ValueState.KNOWN:
            ctx.evidence.extend(_evidence(field))
            return True
        ctx.evidence.extend(_evidence(field))
        return None

    has_netmask, has_cidr = present(netmask_field), present(cidr_field)
    results = []
    pool = None
    if has_netmask is False and has_cidr is False:
        pool = ctx.target(resource, "/properties/IpamPoolId", "AWS::EC2::IPAMPool")
        if pool is None:
            verdict, reason = "NEEDS_REVIEW", "IPAM pool's default netmask is unresolved"
        else:
            default = present(pool.field("/properties/AllocationDefaultNetmaskLength"))
            verdict = "PASS" if default else "FAIL" if default is False else "NEEDS_REVIEW"
            reason = ("pool has a default netmask" if verdict == "PASS" else
                      "allocation requires Cidr or NetmaskLength without a pool default" if verdict == "FAIL" else
                      "IPAM pool's default netmask is unresolved")
    elif has_netmask is True or has_cidr is True:
        verdict, reason = "PASS", "Cidr or NetmaskLength is supplied"
    elif has_netmask is None or has_cidr is None:
        verdict, reason = "NEEDS_REVIEW", "Cidr or NetmaskLength is unresolved"
    results.append(ctx.finding("EC2_IPAM_ALLOCATION_NETMASK_OR_CIDR", "/properties/NetmaskLength",
                               verdict, reason))

    if has_netmask:
        if pool is None:
            pool = ctx.target(resource, "/properties/IpamPoolId", "AWS::EC2::IPAMPool")
        mask = ctx.value(resource, "/properties/NetmaskLength")
        family = ctx.value(pool, "/properties/AddressFamily") if pool else None
        if type(mask) is int and family in ("ipv4", "ipv6"):
            upper = 32 if family == "ipv4" else 128
            verdict = "PASS" if 0 <= mask <= upper else "FAIL"
            reason = f"{family} netmask must be between 0 and {upper}"
        else:
            verdict, reason = "NEEDS_REVIEW", "pool address family or netmask is unresolved"
        results.append(ctx.finding("EC2_IPAM_ALLOCATION_NETMASK_FAMILY", "/properties/NetmaskLength",
                                   verdict, reason))
    return results


@resource_check('AWS::EC2::ClientVpnRoute', 'AWS::EC2::ClientVpnTargetNetworkAssociation')
def evaluate_client_vpn_endpoint_mode(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    endpoint = ctx.target(resource, "/properties/ClientVpnEndpointId", "AWS::EC2::ClientVpnEndpoint")
    rule = ("EC2_CLIENT_VPN_ROUTE_ENDPOINT_MODE" if resource.type == "AWS::EC2::ClientVpnRoute"
            else "EC2_CLIENT_VPN_ASSOCIATION_ENDPOINT_MODE")
    path = ("/properties/TargetVpcSubnetId" if resource.type == "AWS::EC2::ClientVpnRoute"
            else "/properties/SubnetId")
    if endpoint is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "Client VPN endpoint is not linked in the design")
    mode_field = endpoint.field("/properties/TransitGatewayConfiguration")
    ctx.evidence.extend(_evidence(mode_field))
    if mode_field is not None and mode_field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                           ValueState.NOT_APPLICABLE):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "endpoint mode is unresolved")
    transit = mode_field is not None and mode_field.state == ValueState.KNOWN
    target_field = resource.field(path)
    ctx.evidence.extend(_evidence(target_field))
    target_present = target_field is not None and target_field.state == ValueState.KNOWN
    if target_field is not None and target_field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                               ValueState.NOT_APPLICABLE):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "target field is unresolved")
    if resource.type == "AWS::EC2::ClientVpnRoute":
        verdict = "PASS" if transit or target_present else "FAIL"
        reason = ("route target matches endpoint mode" if verdict == "PASS" else
                  "VPC-based Client VPN route requires TargetVpcSubnetId")
    elif transit:
        az_fields = [resource.field("/properties/AvailabilityZone"),
                     resource.field("/properties/AvailabilityZoneId")]
        ctx.evidence.extend(id for field in az_fields for id in _evidence(field))
        if any(field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                         ValueState.NOT_APPLICABLE) for field in az_fields):
            verdict, reason = "NEEDS_REVIEW", "Transit Gateway association Availability Zone is unresolved"
        elif target_present or not any(field is not None and field.state == ValueState.KNOWN
                                       for field in az_fields):
            verdict, reason = "FAIL", "Transit Gateway association requires AvailabilityZone or AvailabilityZoneId instead of SubnetId"
        else:
            verdict, reason = "PASS", "Transit Gateway association has an Availability Zone"
    else:
        verdict = "PASS" if target_present else "FAIL"
        reason = ("VPC association has SubnetId" if verdict == "PASS" else
                  "VPC-based Client VPN association requires SubnetId")
    return ctx.finding(rule, path, verdict, reason)


@resource_check('AWS::EC2::VerifiedAccessEndpoint')
def evaluate_verified_access_subnet_az(design: Design, resource: Resource) -> list[dict[str, Any]]:
    results = []
    for option in ("LoadBalancerOptions", "RdsOptions"):
        ctx = Context(design, resource)
        option_field = resource.field(f"/properties/{option}")
        if option_field is None or option_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            continue
        options = ctx.value(resource, f"/properties/{option}")
        path = f"/properties/{option}/SubnetIds"
        if not isinstance(options, dict) or not isinstance(options.get("SubnetIds"), list):
            results.append(ctx.finding("EC2_VERIFIED_ACCESS_SUBNET_AZ_UNIQUE", path,
                                       "NEEDS_REVIEW", "subnet list is unresolved"))
            continue
        zones: set[str] = set()
        unresolved = False
        duplicate = False
        for index in range(len(options["SubnetIds"])):
            subnet = ctx.target(resource, f"{path}/{index}", "AWS::EC2::Subnet")
            if subnet is None:
                unresolved = True
                continue
            zone = ctx.value(subnet, "/properties/AvailabilityZone")
            if not isinstance(zone, str):
                unresolved = True
            elif zone in zones:
                duplicate = True
            else:
                zones.add(zone)
        if duplicate:
            verdict, reason = "FAIL", "multiple subnets are in one Availability Zone"
        elif unresolved:
            verdict, reason = "NEEDS_REVIEW", "one or more subnet Availability Zones are unresolved"
        else:
            verdict, reason = "PASS", "each subnet is in a distinct Availability Zone"
        results.append(ctx.finding("EC2_VERIFIED_ACCESS_SUBNET_AZ_UNIQUE", path, verdict, reason))
    return results


@resource_check('AWS::EC2::ClientVpnTargetNetworkAssociation')
def evaluate_client_vpn_association_network(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_CLIENT_VPN_ASSOCIATION_NETWORK"
    endpoint = ctx.target(resource, "/properties/ClientVpnEndpointId", "AWS::EC2::ClientVpnEndpoint")
    if endpoint is not None:
        mode = endpoint.field("/properties/TransitGatewayConfiguration")
        if mode is not None and mode.state == ValueState.KNOWN:
            return ctx.finding(rule, "/properties/SubnetId", "NOT_APPLICABLE",
                               "Transit Gateway association does not use a VPC subnet")
        if mode is not None and mode.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            return ctx.finding(rule, "/properties/SubnetId", "NEEDS_REVIEW",
                               "endpoint mode is unresolved")
    subnet = ctx.target(resource, "/properties/SubnetId", "AWS::EC2::Subnet")
    if endpoint is None or subnet is None:
        return ctx.finding(rule, "/properties/SubnetId", "NEEDS_REVIEW",
                           "endpoint or subnet is unresolved")
    zone = ctx.value(subnet, "/properties/AvailabilityZone")
    vpc = ctx.target(subnet, "/properties/VpcId", "AWS::EC2::VPC")
    unknown = zone is None or vpc is None
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        other_endpoint = ctx.target(other, "/properties/ClientVpnEndpointId", "AWS::EC2::ClientVpnEndpoint")
        if other_endpoint is None:
            unknown = True
            continue
        if other_endpoint.id != endpoint.id:
            continue
        other_subnet = ctx.target(other, "/properties/SubnetId", "AWS::EC2::Subnet")
        if other_subnet is None:
            unknown = True
            continue
        other_zone = ctx.value(other_subnet, "/properties/AvailabilityZone")
        other_vpc = ctx.target(other_subnet, "/properties/VpcId", "AWS::EC2::VPC")
        if isinstance(zone, str) and isinstance(other_zone, str) and zone == other_zone:
            return ctx.finding(rule, "/properties/SubnetId", "FAIL",
                               f"association {other.id} uses the same Availability Zone")
        if vpc is not None and other_vpc is not None and vpc.id != other_vpc.id:
            return ctx.finding(rule, "/properties/SubnetId", "FAIL",
                               f"association {other.id} uses a different VPC")
        if other_zone is None or other_vpc is None:
            unknown = True
    return ctx.finding(rule, "/properties/SubnetId",
                       "NEEDS_REVIEW" if unknown else "PASS",
                       "association network is unresolved" if unknown else
                       "linked associations use distinct Availability Zones in one VPC")


@resource_check('AWS::EC2::EIPAssociation')
def evaluate_eip_instance_interface_count(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    path = "/properties/InstanceId"
    field = resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding("EC2_EIP_INSTANCE_SINGLE_INTERFACE", path,
                           "NOT_APPLICABLE", "association targets a network interface")
    instance = ctx.target(resource, path, "AWS::EC2::Instance")
    if instance is None:
        return ctx.finding("EC2_EIP_INSTANCE_SINGLE_INTERFACE", path,
                           "NEEDS_REVIEW", "instance is not linked in the design")
    interfaces = ctx.value(instance, "/properties/NetworkInterfaces")
    count = len(interfaces) if isinstance(interfaces, list) else None
    for attachment in design.resources:
        if attachment.type != "AWS::EC2::NetworkInterfaceAttachment" or attachment.scope != resource.scope:
            continue
        refs = [ref for ref in design.relations
                if ref.source_resource_id == attachment.id and ref.source_path == "/properties/InstanceId"]
        if len(refs) == 1 and refs[0].target_resource_id == instance.id:
            count = (count if count is not None else 1) + 1
    if count is None:
        verdict, reason = "NEEDS_REVIEW", "instance network interface count is unresolved"
    elif count > 1:
        verdict, reason = "FAIL", "InstanceId cannot be used when the instance has multiple interfaces"
    else:
        verdict, reason = "PASS", "design instance has one network interface"
    return ctx.finding("EC2_EIP_INSTANCE_SINGLE_INTERFACE", path, verdict, reason)


@resource_check('AWS::EC2::Instance')
def evaluate_instance_launch_template(design: Design, resource: Resource) -> list[dict[str, Any]]:
    field = resource.field("/properties/LaunchTemplate")
    refs = [ref for ref in design.relations if ref.source_resource_id == resource.id and
            ref.source_path in ("/properties/LaunchTemplate/LaunchTemplateId",
                                "/properties/LaunchTemplate/LaunchTemplateName")]
    if (field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE)) and not refs:
        return []
    ctx = Context(design, resource)
    ctx.evidence.extend(_evidence(field))
    if field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                ValueState.NOT_APPLICABLE):
        return [ctx.finding(rule, "/properties/LaunchTemplate", "NEEDS_REVIEW",
                            "instance launch template setting is unresolved") for rule in (
                                "EC2_INSTANCE_LAUNCH_TEMPLATE_IMAGE",
                                "EC2_INSTANCE_LAUNCH_TEMPLATE_REQUIREMENTS")]
    ctx.evidence.extend(id for ref in refs for id in ref.evidence_ids)
    template = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
    if template is None or template.type != "AWS::EC2::LaunchTemplate" or template.scope != resource.scope:
        return [ctx.finding(rule, "/properties/LaunchTemplate", "NEEDS_REVIEW",
                            "launch template is not linked in the design") for rule in (
                                "EC2_INSTANCE_LAUNCH_TEMPLATE_IMAGE",
                                "EC2_INSTANCE_LAUNCH_TEMPLATE_REQUIREMENTS")]

    spec = field.selected().value if field and field.state == ValueState.KNOWN else None
    version_field = resource.field("/properties/LaunchTemplate/Version")
    ctx.evidence.extend(_evidence(version_field))
    version = (version_field.selected().value if version_field and version_field.state == ValueState.KNOWN
               else spec.get("Version") if isinstance(spec, dict) else None)
    if version not in ("1", "$Latest"):
        return [ctx.finding(rule, "/properties/LaunchTemplate/Version", "NEEDS_REVIEW",
                            "selected launch template version cannot be matched to design data") for rule in (
                                "EC2_INSTANCE_LAUNCH_TEMPLATE_IMAGE",
                                "EC2_INSTANCE_LAUNCH_TEMPLATE_REQUIREMENTS")]

    data_field = template.field("/properties/LaunchTemplateData")
    ctx.evidence.extend(_evidence(data_field))
    data = data_field.selected().value if data_field and data_field.state == ValueState.KNOWN else None

    def item(name: str) -> tuple[bool | None, Any]:
        child = template.field(f"/properties/LaunchTemplateData/{name}")
        ctx.evidence.extend(_evidence(child))
        if child is not None:
            if child.state == ValueState.KNOWN:
                return True, child.selected().value
            if child.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
                return False, None
            return None, None
        if isinstance(data, dict):
            return name in data, data.get(name)
        return None, None

    template_image, _ = item("ImageId")
    instance_image = resource.field("/properties/ImageId")
    ctx.evidence.extend(_evidence(instance_image))
    if instance_image and instance_image.state == ValueState.KNOWN:
        image_verdict, image_reason = "PASS", "instance supplies ImageId"
    elif instance_image and instance_image.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        image_verdict, image_reason = "NEEDS_REVIEW", "instance ImageId is unresolved"
    elif template_image is True:
        image_verdict, image_reason = "PASS", "linked launch template supplies ImageId"
    elif template_image is False:
        image_verdict, image_reason = "FAIL", "neither instance nor launch template supplies ImageId"
    else:
        image_verdict, image_reason = "NEEDS_REVIEW", "launch template ImageId is unresolved"

    requirements, _ = item("InstanceRequirements")
    requirements_verdict = "FAIL" if requirements is True else "PASS" if requirements is False else "NEEDS_REVIEW"
    requirements_reason = ("AWS::EC2::Instance cannot use launch template InstanceRequirements"
                           if requirements_verdict == "FAIL" else
                           "linked launch template has no InstanceRequirements" if requirements_verdict == "PASS" else
                           "launch template InstanceRequirements is unresolved")
    return [ctx.finding("EC2_INSTANCE_LAUNCH_TEMPLATE_IMAGE", "/properties/ImageId",
                        image_verdict, image_reason),
            ctx.finding("EC2_INSTANCE_LAUNCH_TEMPLATE_REQUIREMENTS", "/properties/LaunchTemplate",
                        requirements_verdict, requirements_reason)]


@resource_check('AWS::EC2::EC2Fleet')
def evaluate_ec2_fleet_unit_type(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_FLEET_UNIT_TYPE_REQUIRES_ATTRIBUTES"
    path = "/properties/TargetCapacitySpecification"
    specification = ctx.value(resource, path)
    if not isinstance(specification, dict):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "target capacity specification is unresolved")
    if "TargetCapacityUnitType" not in specification:
        return ctx.finding(rule, path, "NOT_APPLICABLE", "target capacity unit type is not specified")
    configs = ctx.value(resource, "/properties/LaunchTemplateConfigs")
    if not isinstance(configs, list) or not configs:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "launch template configurations are unresolved")
    uncertain = False
    for index, config in enumerate(configs):
        if not isinstance(config, dict):
            uncertain = True
            continue
        overrides = config.get("Overrides", [])
        if not isinstance(overrides, list):
            uncertain = True
        elif any(isinstance(item, dict) and "InstanceRequirements" in item for item in overrides):
            return ctx.finding(rule, path, "PASS", "an override uses attribute-based instance selection")
        paths = (f"/properties/LaunchTemplateConfigs/{index}/LaunchTemplateSpecification/LaunchTemplateId",
                 f"/properties/LaunchTemplateConfigs/{index}/LaunchTemplateSpecification/LaunchTemplateName")
        refs = [ref for ref in design.relations
                if ref.source_resource_id == resource.id and ref.source_path in paths]
        if len(refs) != 1:
            uncertain = True
            continue
        template = ctx.by_id.get(refs[0].target_resource_id)
        if template is None or template.type != "AWS::EC2::LaunchTemplate" or template.scope != resource.scope:
            uncertain = True
            continue
        data = ctx.value(template, "/properties/LaunchTemplateData")
        if not isinstance(data, dict):
            uncertain = True
        elif "InstanceRequirements" in data:
            return ctx.finding(rule, path, "PASS", "linked launch template uses attribute-based instance selection")
    if uncertain:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "attribute-based selection may be in an unresolved launch template")
    return ctx.finding(rule, path, "FAIL", "TargetCapacityUnitType requires InstanceRequirements")


@resource_check('AWS::EC2::VPNConnection')
def evaluate_vpn_tunnel_cidr_uniqueness(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_VPN_TUNNEL_CIDR_UNIQUE"
    path = "/properties/VpnTunnelOptionsSpecifications"
    options = ctx.value(resource, path)
    if options is None and resource.field(path) is None:
        return ctx.finding(rule, path, "NOT_APPLICABLE", "no inside tunnel CIDRs are specified")
    if not isinstance(options, list):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "tunnel options are unresolved")
    uncertain = False
    for family_path, cidr_key in (("/properties/VpnGatewayId", "TunnelInsideCidr"),
                                  ("/properties/TransitGatewayId", "TunnelInsideIpv6Cidr")):
        current = [item[cidr_key] for item in options if isinstance(item, dict) and
                   isinstance(item.get(cidr_key), str)]
        if len(current) != len(set(current)):
            return ctx.finding(rule, path, "FAIL", f"duplicate {cidr_key} within VPN connection")
        if not current:
            continue
        gateway = ctx.value(resource, family_path)
        if not isinstance(gateway, str):
            uncertain = True
            continue
        for other in design.resources:
            if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
                continue
            other_gateway_field = other.field(family_path)
            if other_gateway_field is None or other_gateway_field.state in (ValueState.MISSING,
                                                                             ValueState.NOT_APPLICABLE):
                continue
            other_gateway = ctx.value(other, family_path)
            if not isinstance(other_gateway, str):
                uncertain = True
                continue
            if other_gateway != gateway:
                continue
            other_options = ctx.value(other, path)
            if not isinstance(other_options, list):
                uncertain = True
                continue
            others = [item[cidr_key] for item in other_options if isinstance(item, dict) and
                      isinstance(item.get(cidr_key), str)]
            if set(current) & set(others):
                return ctx.finding(rule, path, "FAIL", f"{cidr_key} duplicates VPN connection {other.id}")
    return ctx.finding(rule, path, "NEEDS_REVIEW" if uncertain else "PASS",
                       "gateway or tunnel CIDRs are unresolved" if uncertain else
                       "inside tunnel CIDRs are unique among design VPN connections")


@resource_check('AWS::EC2::VPNGatewayRoutePropagation')
def evaluate_vpn_route_propagation_vpc(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_VPN_ROUTE_PROPAGATION_SAME_VPC"
    path = "/properties/RouteTableIds"
    gateway = ctx.target(resource, "/properties/VpnGatewayId", "AWS::EC2::VPNGateway")
    tables = ctx.value(resource, path)
    if gateway is None or not isinstance(tables, list):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "VPN gateway or route table list is unresolved")
    attached_vpcs = []
    for attachment in design.resources:
        if attachment.type != "AWS::EC2::VPCGatewayAttachment" or attachment.scope != resource.scope:
            continue
        refs = [ref for ref in design.relations
                if ref.source_resource_id == attachment.id and ref.source_path == "/properties/VpnGatewayId"]
        if len(refs) == 1 and refs[0].target_resource_id == gateway.id:
            attached_vpcs.append(ctx.target(attachment, "/properties/VpcId", "AWS::EC2::VPC"))
    if len(attached_vpcs) != 1 or attached_vpcs[0] is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "VPN gateway VPC attachment is unresolved")
    attached_vpc = attached_vpcs[0]
    unknown = False
    for index in range(len(tables)):
        table = ctx.target(resource, f"{path}/{index}", "AWS::EC2::RouteTable")
        table_vpc = ctx.target(table, "/properties/VpcId", "AWS::EC2::VPC") if table else None
        if table_vpc is None:
            unknown = True
        elif table_vpc.id != attached_vpc.id:
            return ctx.finding(rule, f"{path}/{index}", "FAIL",
                               "route table is in a different VPC from the VPN gateway")
    return ctx.finding(rule, path, "NEEDS_REVIEW" if unknown else "PASS",
                       "one or more route table VPCs are unresolved" if unknown else
                       "route tables and VPN gateway are in the same VPC")


@resource_check('AWS::EC2::IPAMPoolCidr')
def evaluate_ipam_pool_cidr_netmask(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_IPAM_POOL_CIDR_NETMASK_SOURCE"
    path = "/properties/NetmaskLength"
    netmask = resource.field(path)
    if netmask is None or netmask.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding(rule, path, "NOT_APPLICABLE", "NetmaskLength is not specified")
    if netmask.state != ValueState.KNOWN:
        ctx.dependencies.append(f"{resource.id}{path}")
        return ctx.finding(rule, path, "NEEDS_REVIEW", "NetmaskLength is unresolved")
    ctx.evidence.extend(_evidence(netmask))
    pool = ctx.target(resource, "/properties/IpamPoolId", "AWS::EC2::IPAMPool")
    if pool is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "IPAM pool is not linked in the design")
    parent_field = pool.field("/properties/SourceIpamPoolId")
    if parent_field is not None and parent_field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        if parent_field.state != ValueState.KNOWN:
            ctx.dependencies.append(f"{pool.id}/properties/SourceIpamPoolId")
            return ctx.finding(rule, path, "NEEDS_REVIEW", "source pool is unresolved")
        ctx.evidence.extend(_evidence(parent_field))
        return ctx.finding(rule, path, "PASS", "pool has a source pool")
    family = ctx.value(pool, "/properties/AddressFamily")
    source = ctx.value(pool, "/properties/PublicIpSource")
    if family == "ipv6" and source == "amazon":
        return ctx.finding(rule, path, "PASS", "top-level pool uses Amazon-provided IPv6")
    if family == "ipv4" or (family == "ipv6" and
                             (source == "byoip" or pool.field("/properties/PublicIpSource") is None)):
        return ctx.finding(rule, path, "FAIL", "NetmaskLength requires Amazon-provided IPv6 in a top-level pool")
    return ctx.finding(rule, path, "NEEDS_REVIEW", "top-level pool CIDR source is unresolved")


@resource_check('AWS::EC2::TransitGatewayAttachment', 'AWS::EC2::TransitGatewayVpcAttachment')
def evaluate_transit_gateway_subnet_az(design: Design, resource: Resource) -> list[dict[str, Any]]:
    results = []
    for name in (("SubnetIds", "AddSubnetIds") if resource.type.endswith("VpcAttachment")
                 else ("SubnetIds",)):
        ctx = Context(design, resource)
        rule = "EC2_TRANSIT_GATEWAY_SUBNET_AZ_UNIQUE"
        path = f"/properties/{name}"
        field = resource.field(path)
        if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            results.append(ctx.finding(rule, path, "NOT_APPLICABLE", f"{name} is not specified"))
            continue
        subnets = ctx.value(resource, path)
        if not isinstance(subnets, list):
            results.append(ctx.finding(rule, path, "NEEDS_REVIEW", f"{name} is unresolved"))
            continue
        zones: set[str] = set()
        unknown = False
        for index in range(len(subnets)):
            subnet = ctx.target(resource, f"{path}/{index}", "AWS::EC2::Subnet")
            az = ctx.value(subnet, "/properties/AvailabilityZone") if subnet else None
            if not isinstance(az, str):
                unknown = True
            elif az in zones:
                results.append(ctx.finding(rule, f"{path}/{index}", "FAIL",
                                           "multiple transit gateway subnets use the same Availability Zone"))
                break
            else:
                zones.add(az)
        else:
            results.append(ctx.finding(rule, path, "NEEDS_REVIEW" if unknown else "PASS",
                                       "subnet Availability Zones are unresolved" if unknown else
                                       "subnets use distinct Availability Zones"))
    return results


@resource_check('AWS::EC2::TransitGatewayRouteTableAssociation')
def evaluate_transit_gateway_route_table_association(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_TRANSIT_GATEWAY_ATTACHMENT_SINGLE_ROUTE_TABLE"
    path = "/properties/TransitGatewayAttachmentId"
    current = ctx.value(resource, path)
    refs = [ref for ref in design.relations
            if ref.source_resource_id == resource.id and ref.source_path == path]
    current_id = refs[0].target_resource_id if len(refs) == 1 else current
    if not isinstance(current_id, str):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "attachment ID is unresolved")
    uncertain = False
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type or other.scope != resource.scope:
            continue
        other_refs = [ref for ref in design.relations
                      if ref.source_resource_id == other.id and ref.source_path == path]
        other_id = other_refs[0].target_resource_id if len(other_refs) == 1 else ctx.value(other, path)
        if not isinstance(other_id, str):
            uncertain = True
        elif other_id == current_id:
            return ctx.finding(rule, path, "FAIL",
                               f"attachment is also associated by {other.id}")
    return ctx.finding(rule, path, "NEEDS_REVIEW" if uncertain else "PASS",
                       "another association's attachment is unresolved" if uncertain else
                       "attachment has one design route table association")


@resource_check('AWS::EC2::IPAMPool')
def evaluate_ipam_pool_source_locale(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_IPAM_POOL_SOURCE_LOCALE"
    path = "/properties/Locale"
    source_field = resource.field("/properties/SourceIpamPoolId")
    if source_field is None or source_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding(rule, path, "NOT_APPLICABLE", "pool has no source pool")
    source = ctx.target(resource, "/properties/SourceIpamPoolId", "AWS::EC2::IPAMPool")
    if source is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "source pool is not linked in the design")
    parent_locale_field = source.field(path)
    if parent_locale_field is None or parent_locale_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding(rule, path, "NOT_APPLICABLE", "source pool has no locale constraint")
    parent_locale = ctx.value(source, path)
    child_locale = ctx.value(resource, path)
    if not isinstance(parent_locale, str) or not isinstance(child_locale, str):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "pool locale is unresolved")
    return ctx.finding(rule, path, "PASS" if parent_locale == child_locale else "FAIL",
                       "pool locale matches source pool" if parent_locale == child_locale else
                       "pool locale differs from source pool")


@resource_check('AWS::EC2::SpotFleet')
def evaluate_spot_fleet_template_interfaces(design: Design, resource: Resource) -> list[dict[str, Any]]:
    ctx = Context(design, resource)
    rule = "EC2_SPOT_FLEET_TEMPLATE_INTERFACE_ID"
    base = "/properties/SpotFleetRequestConfigData/LaunchTemplateConfigs"
    configs = ctx.value(resource, base)
    if configs is None:
        parent = ctx.value(resource, "/properties/SpotFleetRequestConfigData")
        configs = parent.get("LaunchTemplateConfigs") if isinstance(parent, dict) else None
    if configs is None:
        parent_field = resource.field("/properties/SpotFleetRequestConfigData")
        unresolved = parent_field is not None and parent_field.state not in (
            ValueState.KNOWN, ValueState.MISSING, ValueState.NOT_APPLICABLE)
        return [ctx.finding(rule, base, "NEEDS_REVIEW" if unresolved else "NOT_APPLICABLE",
                            "launch template configs are unresolved" if unresolved else
                            "no launch template configs are specified")]
    if not isinstance(configs, list):
        return [ctx.finding(rule, base, "NEEDS_REVIEW", "launch template configs are unresolved")]
    results = []
    for index, config in enumerate(configs):
        path = f"{base}/{index}/LaunchTemplateSpecification"
        spec = config.get("LaunchTemplateSpecification") if isinstance(config, dict) else None
        if not isinstance(spec, dict):
            results.append(ctx.finding(rule, path, "NEEDS_REVIEW", "launch template specification is unresolved"))
            continue
        version = spec.get("Version")
        if version not in ("1", "$Latest"):
            results.append(ctx.finding(rule, path, "NEEDS_REVIEW", "selected template version cannot be matched to design data"))
            continue
        refs = [ref for ref in design.relations if ref.source_resource_id == resource.id and
                ref.source_path in (f"{path}/LaunchTemplateId", f"{path}/LaunchTemplateName")]
        ctx.evidence.extend(e for ref in refs for e in ref.evidence_ids)
        template = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
        if template is None or template.type != "AWS::EC2::LaunchTemplate" or template.scope != resource.scope:
            results.append(ctx.finding(rule, path, "NEEDS_REVIEW", "launch template is not linked in the design"))
            continue
        interfaces = ctx.value(template, "/properties/LaunchTemplateData/NetworkInterfaces")
        if interfaces is None:
            data = ctx.value(template, "/properties/LaunchTemplateData")
            interfaces = data.get("NetworkInterfaces") if isinstance(data, dict) else None
        if interfaces is None:
            results.append(ctx.finding(rule, path, "PASS" if isinstance(data, dict) else "NEEDS_REVIEW",
                                       "launch template has no network interfaces" if isinstance(data, dict) else
                                       "launch template data is unresolved"))
        elif not isinstance(interfaces, list):
            results.append(ctx.finding(rule, path, "NEEDS_REVIEW", "launch template interfaces are unresolved"))
        elif any(isinstance(item, dict) and item.get("NetworkInterfaceId") for item in interfaces):
            results.append(ctx.finding(rule, path, "FAIL", "Spot Fleet launch template specifies NetworkInterfaceId"))
        elif any(not isinstance(item, dict) for item in interfaces):
            results.append(ctx.finding(rule, path, "NEEDS_REVIEW", "launch template interfaces are unresolved"))
        else:
            results.append(ctx.finding(rule, path, "PASS", "launch template has no NetworkInterfaceId"))
    return results


@resource_check('AWS::EC2::Subnet', when=lambda design, resource: resource.field('/properties/EnableDns64') is not None)
def evaluate_subnet_dns64_nat(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_SUBNET_DNS64_PUBLIC_NAT"
    path = "/properties/EnableDns64"
    enabled = ctx.value(resource, path)
    if (enabled is None and resource.field(path) is None) or enabled is False:
        return ctx.finding(rule, path, "NOT_APPLICABLE", "DNS64 is not enabled")
    if enabled is not True:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "DNS64 setting is unresolved")
    dns_vpc = ctx.target(resource, "/properties/VpcId", "AWS::EC2::VPC")
    if dns_vpc is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "DNS64 subnet VPC is unresolved")

    def linked(source: Resource, source_path: str, target_id: str) -> bool:
        return any(ref.source_resource_id == source.id and ref.source_path == source_path and
                   ref.target_resource_id == target_id for ref in design.relations)

    for nat in design.resources:
        if nat.type != "AWS::EC2::NatGateway" or nat.scope != resource.scope:
            continue
        if ctx.value(nat, "/properties/ConnectivityType") == "private":
            continue
        nat_subnet = ctx.target(nat, "/properties/SubnetId", "AWS::EC2::Subnet")
        if nat_subnet is None or nat_subnet.id == resource.id:
            continue
        nat_vpc = ctx.target(nat_subnet, "/properties/VpcId", "AWS::EC2::VPC")
        if nat_vpc is None or nat_vpc.id != dns_vpc.id:
            continue
        for association in design.resources:
            if association.type != "AWS::EC2::SubnetRouteTableAssociation" or not linked(
                    association, "/properties/SubnetId", nat_subnet.id):
                continue
            table = ctx.target(association, "/properties/RouteTableId", "AWS::EC2::RouteTable")
            if table is None:
                continue
            for route in design.resources:
                if route.type != "AWS::EC2::Route" or not linked(
                        route, "/properties/RouteTableId", table.id):
                    continue
                if ctx.value(route, "/properties/DestinationCidrBlock") != "0.0.0.0/0":
                    continue
                gateway = ctx.target(route, "/properties/GatewayId", "AWS::EC2::InternetGateway")
                if gateway is None:
                    continue
                if any(attachment.type == "AWS::EC2::VPCGatewayAttachment" and
                       linked(attachment, "/properties/InternetGatewayId", gateway.id) and
                       linked(attachment, "/properties/VpcId", dns_vpc.id)
                       for attachment in design.resources):
                    return ctx.finding(rule, path, "PASS",
                                       "separate NAT subnet has an internet gateway route in the same VPC")
    return ctx.finding(rule, path, "NEEDS_REVIEW",
                       "a suitable public NAT subnet and route are not resolved in the design")


@resource_check('AWS::EC2::SpotFleet')
def evaluate_spot_fleet_unit_type(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_SPOT_FLEET_UNIT_TYPE_REQUIRES_ATTRIBUTES"
    path = "/properties/SpotFleetRequestConfigData/TargetCapacityUnitType"
    config = ctx.value(resource, "/properties/SpotFleetRequestConfigData")
    if not isinstance(config, dict):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "Spot Fleet request configuration is unresolved")
    if "TargetCapacityUnitType" not in config:
        return ctx.finding(rule, path, "NOT_APPLICABLE", "target capacity unit type is not specified")
    configs = config.get("LaunchTemplateConfigs")
    if not isinstance(configs, list) or not configs:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "launch template configurations are unresolved")
    uncertain = False
    for index, template_config in enumerate(configs):
        if not isinstance(template_config, dict):
            uncertain = True
            continue
        overrides = template_config.get("Overrides", [])
        if isinstance(overrides, list) and any(isinstance(item, dict) and
                                               "InstanceRequirements" in item for item in overrides):
            return ctx.finding(rule, path, "PASS", "an override uses attribute-based instance selection")
        spec = template_config.get("LaunchTemplateSpecification")
        if not isinstance(spec, dict) or spec.get("Version") not in ("1", "$Latest"):
            uncertain = True
            continue
        base = f"/properties/SpotFleetRequestConfigData/LaunchTemplateConfigs/{index}/LaunchTemplateSpecification"
        refs = [ref for ref in design.relations if ref.source_resource_id == resource.id and
                ref.source_path in (f"{base}/LaunchTemplateId", f"{base}/LaunchTemplateName")]
        template = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
        if template is None or template.type != "AWS::EC2::LaunchTemplate" or template.scope != resource.scope:
            uncertain = True
            continue
        data = ctx.value(template, "/properties/LaunchTemplateData")
        if not isinstance(data, dict):
            uncertain = True
        elif "InstanceRequirements" in data:
            return ctx.finding(rule, path, "PASS", "linked launch template uses attribute-based instance selection")
    return ctx.finding(rule, path, "NEEDS_REVIEW" if uncertain else "FAIL",
                       "attribute-based selection may be in an unresolved template" if uncertain else
                       "TargetCapacityUnitType requires InstanceRequirements")


@resource_check('AWS::EC2::VolumeAttachment')
def evaluate_volume_attachment_outpost(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_VOLUME_ATTACHMENT_SAME_OUTPOST"
    path = "/properties/VolumeId"
    volume = ctx.target(resource, path, "AWS::EC2::Volume")
    instance = ctx.target(resource, "/properties/InstanceId", "AWS::EC2::Instance")
    if volume is None or instance is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "volume or instance is not linked in the design")
    volume_outpost = ctx.value(volume, "/properties/OutpostArn")
    subnet = ctx.target(instance, "/properties/SubnetId", "AWS::EC2::Subnet")
    if subnet is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "instance subnet is not linked in the design")
    subnet_outpost = ctx.value(subnet, "/properties/OutpostArn")
    if volume_outpost is None and subnet_outpost is None:
        return ctx.finding(rule, path, "NOT_APPLICABLE", "volume and instance subnet are regional")
    if not isinstance(volume_outpost, str) and volume.field("/properties/OutpostArn") is not None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "volume OutpostArn is unresolved")
    if not isinstance(subnet_outpost, str) and subnet.field("/properties/OutpostArn") is not None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "subnet OutpostArn is unresolved")
    same = volume_outpost == subnet_outpost
    return ctx.finding(rule, path, "PASS" if same else "FAIL",
                       "volume and instance subnet share an Outpost" if same else
                       "volume and instance subnet are on different Outposts or locations")


def _uses_launch_template(design: Design, resource: Resource) -> bool:
    return resource.field("/properties/LaunchTemplate") is not None or any(
        ref.source_resource_id == resource.id and ref.source_path.startswith("/properties/LaunchTemplate/")
        for ref in design.relations)


@resource_check('AWS::EC2::Instance', when=_uses_launch_template)
def evaluate_instance_template_primary_interface(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "EC2_INSTANCE_TEMPLATE_PRIMARY_INTERFACE"
    path = "/properties/LaunchTemplate"
    field = resource.field(path)
    if field is None and not any(ref.source_resource_id == resource.id and
                                  ref.source_path.startswith(f"{path}/") for ref in design.relations):
        return ctx.finding(rule, path, "NOT_APPLICABLE", "instance has no launch template")
    spec = ctx.value(resource, path)
    version = spec.get("Version") if isinstance(spec, dict) else None
    version_field = resource.field(f"{path}/Version")
    if version_field is not None:
        version = ctx.value(resource, f"{path}/Version")
    if version not in ("1", "$Latest"):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "launch template version is unresolved")
    refs = [ref for ref in design.relations if ref.source_resource_id == resource.id and
            ref.source_path in (f"{path}/LaunchTemplateId", f"{path}/LaunchTemplateName")]
    template = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
    if template is None or template.type != "AWS::EC2::LaunchTemplate" or template.scope != resource.scope:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "launch template is not linked in the design")
    interfaces = ctx.value(template, "/properties/LaunchTemplateData/NetworkInterfaces")
    if interfaces is None:
        data = ctx.value(template, "/properties/LaunchTemplateData")
        interfaces = data.get("NetworkInterfaces") if isinstance(data, dict) else None
        if interfaces is None and isinstance(data, dict):
            return ctx.finding(rule, path, "NOT_APPLICABLE", "launch template has no network interfaces")
    if not isinstance(interfaces, list):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "launch template interfaces are unresolved")
    indices = [item.get("DeviceIndex") for item in interfaces if isinstance(item, dict)]
    if len(indices) != len(interfaces) or any(type(index) is not int for index in indices):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "launch template device indices are unresolved")
    if 0 in indices or not any(index > 0 for index in indices):
        return ctx.finding(rule, path, "NOT_APPLICABLE", "launch template includes a primary interface or no secondary interface")
    instance_interfaces = ctx.value(resource, "/properties/NetworkInterfaces")
    if not isinstance(instance_interfaces, list):
        instance_field = resource.field("/properties/NetworkInterfaces")
        children = [item for item in resource.fields
                    if item.path.startswith("/properties/NetworkInterfaces/")]
        absent = not children and (instance_field is None or instance_field.state in (
            ValueState.MISSING, ValueState.NOT_APPLICABLE))
        return ctx.finding(rule, "/properties/NetworkInterfaces", "FAIL" if absent else
                           "NEEDS_REVIEW", "instance must supply a primary network interface")
    if any(isinstance(item, dict) and item.get("DeviceIndex") == 0 for item in instance_interfaces):
        return ctx.finding(rule, "/properties/NetworkInterfaces", "PASS", "instance supplies a primary interface")
    if any(not isinstance(item, dict) or "DeviceIndex" not in item for item in instance_interfaces):
        return ctx.finding(rule, "/properties/NetworkInterfaces", "NEEDS_REVIEW", "instance interface indices are unresolved")
    return ctx.finding(rule, "/properties/NetworkInterfaces", "FAIL", "instance lacks a primary interface")
