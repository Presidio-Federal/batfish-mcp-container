"""
Tools package for Batfish MCP Server
"""

from .batfish_run_tagged_tests_tool import RunTaggedTestsTool, run_tagged_tests_tool, RunTaggedTestsInput
from .batfish_get_inventory_tool import GetInventoryTool, get_inventory_tool, GetInventoryInput, ResourceType
from .batfish_check_routing_tool import CheckRoutingTool, check_routing_tool, CheckRoutingInput, ProtocolType
from .batfish_simulate_traffic_tool import SimulateTrafficTool, simulate_traffic_tool, SimulateTrafficInput
from .batfish_failure_impact_tool import FailureImpactTool, failure_impact_tool, FailureImpactInput, FailureType

# AWS analysis tools
from .aws_reachability_tool import execute as aws_reachability_execute
from .aws_reachability_tool import ReachabilityInput
from .aws_trace_route_tool import execute as aws_trace_route_execute
from .aws_trace_route_tool import TraceRouteInput
from .aws_internet_exposure_tool import execute as aws_internet_exposure_execute
from .aws_internet_exposure_tool import AwsInternetExposureInput
from .aws_security_evaluation_tool import execute as aws_security_evaluation_execute
from .aws_security_evaluation_tool import SecurityEvaluationInput
from .aws_subnet_segmentation_tool import execute as aws_subnet_segmentation_execute
from .aws_subnet_segmentation_tool import SubnetSegmentationInput
from .aws_route_analysis_tool import execute as aws_route_analysis_execute
from .aws_route_analysis_tool import AwsRouteAnalysisInput
from .aws_node_inventory_tool import execute as aws_node_inventory_execute
from .aws_node_inventory_tool import AwsNodeInventoryInput
from .aws_change_impact_tool import execute as aws_change_impact_execute
from .aws_change_impact_tool import AwsChangeImpactInput
from .aws_find_unrestricted_ssh_tool import execute as aws_find_unrestricted_ssh_execute
from .aws_find_unrestricted_ssh_tool import FindUnrestrictedSshInput

# Network configuration tools
from .network_generate_topology_tool import execute as network_generate_topology_execute
from .network_list_subnets_tool import network_list_subnets_tool
from .network_list_boundary_devices_tool import execute as network_list_boundary_devices_execute
from .network_reachability_summary_tool import execute as network_reachability_summary_execute
from .network_summary_tool import execute as network_summary_execute
from .network_segment_tool import execute as network_segment_execute
from .network_vlan_discovery_tool import execute as network_vlan_discovery_execute
from .network_get_allowed_services_tool import execute as network_get_allowed_services_execute
from .network_classify_devices_tool import execute as network_classify_devices_execute
from .network_analyze_acl_rules_tool import execute as network_analyze_acl_rules_execute
from .network_traceroute_tool import network_traceroute_tool
from .network_bidirectional_reachability_tool import network_bidirectional_reachability_tool
from .network_vlan_device_count_tool import execute as network_vlan_device_count_execute
from .network_device_connections_tool import execute as network_device_connections_execute
from .network_interface_vlan_count_tool import execute as network_interface_vlan_count_execute
from .network_node_inventory_tool import execute as network_node_inventory_execute
from .network_topology_connections_tool import execute as network_topology_connections_execute

# Management tools
from .management_list_networks_tool import list_networks_tool, ListNetworksInput, ListNetworksOutput
from .management_list_snapshots_tool import list_snapshots_tool, ListSnapshotsInput, ListSnapshotsOutput
from .management_delete_network_tool import delete_network_tool, DeleteNetworkInput, DeleteNetworkOutput
from .management_delete_snapshot_tool import delete_snapshot_tool, DeleteSnapshotInput, DeleteSnapshotOutput
from .management_get_snapshot_info_tool import get_snapshot_info_tool, GetSnapshotInfoInput, GetSnapshotInfoOutput
from .management_get_parse_status_tool import get_parse_status_tool, GetParseStatusInput, GetParseStatusOutput
from .management_cleanup_tool import cleanup_tool, CleanupInput

# Create the execute function for cleanup
def cleanup_execute(input_data):
    """Execute the cleanup tool."""
    return cleanup_tool.execute(input_data)

# Compliance tools
from .compliance_update_classification_rules_tool import execute as update_classification_rules_execute
from .compliance_list_classification_rules_tool import execute as list_classification_rules_execute
from .compliance_check_zone_compliance_tool import execute as check_zone_compliance_execute
from .compliance_auto_classify_zones_tool import execute as auto_classify_zones_execute
from .compliance_get_enforcement_points_tool import execute as get_enforcement_points_execute
from .compliance_list_models_tool import execute as list_models_execute

# Initialize tools - AWS
from .initialize_aws_init_snapshot_tool import init_aws_snapshot_tool, InitAwsSnapshotInput, InitAwsSnapshotOutput
from .initialize_aws_add_data_chunk_tool import execute as aws_add_data_chunk_execute, AddAwsDataChunkInput
from .initialize_aws_finalize_snapshot_tool import execute as aws_finalize_snapshot_execute, FinalizeAwsSnapshotInput
from .initialize_aws_remove_chunk_tool import execute as aws_remove_chunk_execute, RemoveAwsChunkInput
from .initialize_aws_view_staging_tool import execute as aws_view_staging_execute, ViewAwsStagingInput

# Initialize tools - Network
from .initialize_network_prepare_snapshot_tool import execute as network_prepare_snapshot_execute
from .initialize_network_finalize_snapshot_tool import execute as network_finalize_snapshot_execute
from .initialize_network_view_staging_tool import execute as network_view_staging_execute
from .initialize_network_remove_config_tool import execute as network_remove_config_execute
from .initialize_network_upload_zip_tool import execute as network_upload_zip_execute
from .initialize_network_init_snapshot_tool import init_snapshot_tool, InitSnapshotInput

# Initialize tools - GitHub
from .initialize_github_snapshot_tool import github_snapshot_tool, GitHubSnapshotInput

# Create the execute function for network init_snapshot
def init_snapshot_execute(input_data):
    """Execute the network init snapshot tool."""
    return init_snapshot_tool.execute(input_data)

__all__ = [
    "RunTaggedTestsTool",
    "run_tagged_tests_tool",
    "RunTaggedTestsInput",
    "GetInventoryTool",
    "get_inventory_tool",
    "GetInventoryInput",
    "ResourceType",
    "CheckRoutingTool",
    "check_routing_tool",
    "CheckRoutingInput",
    "ProtocolType",
    "SimulateTrafficTool",
    "simulate_traffic_tool",
    "SimulateTrafficInput",
    "FailureImpactTool",
    "failure_impact_tool",
    "FailureImpactInput",
    "FailureType",
    "aws_reachability_execute",
    "ReachabilityInput",
    "aws_trace_route_execute",
    "TraceRouteInput",
    "aws_internet_exposure_execute",
    "AwsInternetExposureInput",
    "aws_security_evaluation_execute",
    "SecurityEvaluationInput",
    "aws_subnet_segmentation_execute",
    "SubnetSegmentationInput",
    "aws_route_analysis_execute",
    "AwsRouteAnalysisInput",
    "aws_node_inventory_execute",
    "AwsNodeInventoryInput",
    "aws_change_impact_execute",
    "AwsChangeImpactInput",
    "aws_find_unrestricted_ssh_execute",
    "FindUnrestrictedSshInput",
    "network_generate_topology_execute",
    "network_list_subnets_tool",
    "network_list_boundary_devices_execute",
    "network_reachability_summary_execute",
    "network_summary_execute",
    "network_segment_execute",
    "network_vlan_discovery_execute",
    "network_get_allowed_services_execute",
    "network_classify_devices_execute",
    "network_analyze_acl_rules_execute",
    "network_traceroute_tool",
    "network_bidirectional_reachability_tool",
    "network_vlan_device_count_execute",
    "network_device_connections_execute",
    "network_interface_vlan_count_execute",
    "network_node_inventory_execute",
    "network_topology_connections_execute",
    "list_networks_tool",
    "list_snapshots_tool",
    "delete_network_tool",
    "delete_snapshot_tool",
    "get_snapshot_info_tool",
    "get_parse_status_tool",
    "cleanup_execute",
    "cleanup_tool",
    "ListNetworksInput",
    "ListSnapshotsInput",
    "DeleteNetworkInput",
    "DeleteSnapshotInput",
    "GetSnapshotInfoInput",
    "GetParseStatusInput",
    "CleanupInput",
    "ListNetworksOutput",
    "ListSnapshotsOutput",
    "DeleteNetworkOutput",
    "DeleteSnapshotOutput",
    "GetSnapshotInfoOutput",
    "GetParseStatusOutput",
    "update_classification_rules_execute",
    "list_classification_rules_execute",
    "check_zone_compliance_execute",
    "auto_classify_zones_execute",
    "get_enforcement_points_execute",
    "list_models_execute",
    # Initialize tools
    "init_aws_snapshot_tool",
    "aws_add_data_chunk_execute",
    "aws_finalize_snapshot_execute",
    "aws_remove_chunk_execute",
    "aws_view_staging_execute",
    "network_prepare_snapshot_execute",
    "network_finalize_snapshot_execute",
    "network_view_staging_execute",
    "network_remove_config_execute",
    "network_upload_zip_execute",
    "init_snapshot_execute",
    "init_snapshot_tool",
    "github_snapshot_tool",
    # Input Models
    "InitAwsSnapshotInput",
    "AddAwsDataChunkInput",
    "FinalizeAwsSnapshotInput",
    "RemoveAwsChunkInput",
    "ViewAwsStagingInput",
    "InitSnapshotInput",
    "GitHubSnapshotInput",
    # Output Models
    "InitAwsSnapshotOutput",
]
