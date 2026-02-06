"""
Batfish MCP Server
Main server implementation using Python's fastmcp library.
"""

import logging
import os
import sys
from typing import Any, Dict, List, Optional

# Properly load environment variables from .env file
# This must be done BEFORE importing any modules that use these variables
from dotenv import load_dotenv
from fastmcp import Context, FastMCP

# Environment variables are loaded at the top of the file


# Get absolute path to the root directory where .env file is located
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
dotenv_path = os.path.join(root_dir, ".env")

# Load environment variables from .env file with high priority
load_dotenv(dotenv_path=dotenv_path, override=True)

# Add parent directory to path for middleware import
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import middleware
from middleware.tool_filter_middleware import ToolFilterMiddleware, tool

# Import utility functions
try:
    # Try relative import first
    from .utilities import configure_auth, get_batfish_host, log_user_access
except ImportError:
    # Fall back to direct import when running as script
    from utilities import configure_auth, get_batfish_host, log_user_access

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Import tools with error handling
try:
    # Try relative imports first (when run as module)
    logger.info("Trying relative imports...")
    try:
        from .tools import (
            CleanupInput,
            DeleteNetworkInput,
            DeleteSnapshotInput,
            GetParseStatusInput,
            GetSnapshotInfoInput,
            GitHubSnapshotInput,
            InitAwsSnapshotInput,
            InitSnapshotInput,
            ListNetworksInput,
            ListSnapshotsInput,
            auto_classify_zones_execute,
            aws_add_data_chunk_execute,
            aws_change_impact_execute,
            aws_finalize_snapshot_execute,
            aws_find_unrestricted_ssh_execute,
            aws_internet_exposure_execute,
            aws_node_inventory_execute,
            aws_reachability_execute,
            aws_remove_chunk_execute,
            aws_route_analysis_execute,
            aws_security_evaluation_execute,
            aws_subnet_segmentation_execute,
            aws_trace_route_execute,
            aws_view_staging_execute,
            check_routing_tool,
            check_zone_compliance_execute,
            cleanup_execute,
            delete_network_tool,
            delete_snapshot_tool,
            failure_impact_tool,
            get_enforcement_points_execute,
            get_inventory_tool,
            get_parse_status_tool,
            get_snapshot_info_tool,
            github_snapshot_tool,
            init_aws_snapshot_tool,
            init_snapshot_execute,
            list_classification_rules_execute,
            list_models_execute,
            list_networks_tool,
            list_snapshots_tool,
            network_analyze_acl_rules_execute,
            network_bidirectional_reachability_tool,
            network_classify_devices_execute,
            network_device_connections_execute,
            network_finalize_snapshot_execute,
            network_generate_topology_execute,
            network_get_allowed_services_execute,
            network_interface_vlan_count_execute,
            network_list_boundary_devices_execute,
            network_list_subnets_tool,
            network_node_inventory_execute,
            network_topology_connections_execute,
            network_prepare_snapshot_execute,
            network_reachability_summary_execute,
            network_remove_config_execute,
            network_segment_execute,
            network_summary_execute,
            network_traceroute_tool,
            network_upload_zip_execute,
            network_view_staging_execute,
            network_vlan_device_count_execute,
            network_vlan_discovery_execute,
            run_tagged_tests_tool,
            simulate_traffic_tool,
            update_classification_rules_execute,
        )
        from .tools.batfish_check_routing_tool import CheckRoutingInput, ProtocolType
        from .tools.batfish_failure_impact_tool import FailureImpactInput, FailureType
        from .tools.batfish_get_inventory_tool import GetInventoryInput, ResourceType
        from .tools.batfish_run_tagged_tests_tool import RunTaggedTestsInput
        from .tools.batfish_simulate_traffic_tool import SimulateTrafficInput

        logger.info("Successfully imported tools with relative imports")
    except ImportError as e:
        logger.warning(f"Error importing with relative imports: {e}")
        raise
except ImportError:
    # Fall back to absolute imports (when run directly)
    logger.info("Falling back to absolute imports...")
    from tools import (
        CleanupInput,
        DeleteNetworkInput,
        DeleteSnapshotInput,
        GetParseStatusInput,
        GetSnapshotInfoInput,
        GitHubSnapshotInput,
        InitAwsSnapshotInput,
        InitSnapshotInput,
        ListNetworksInput,
        ListSnapshotsInput,
        auto_classify_zones_execute,
        aws_add_data_chunk_execute,
        aws_change_impact_execute,
        aws_finalize_snapshot_execute,
        aws_find_unrestricted_ssh_execute,
        aws_internet_exposure_execute,
        aws_node_inventory_execute,
        aws_reachability_execute,
        aws_remove_chunk_execute,
        aws_route_analysis_execute,
        aws_security_evaluation_execute,
        aws_subnet_segmentation_execute,
        aws_trace_route_execute,
        aws_view_staging_execute,
        check_routing_tool,
        check_zone_compliance_execute,
        cleanup_execute,
        delete_network_tool,
        delete_snapshot_tool,
        failure_impact_tool,
        get_enforcement_points_execute,
        get_inventory_tool,
        get_parse_status_tool,
        get_snapshot_info_tool,
        github_snapshot_tool,
        init_aws_snapshot_tool,
        init_snapshot_execute,
        list_classification_rules_execute,
        list_models_execute,
        list_networks_tool,
        list_snapshots_tool,
        network_analyze_acl_rules_execute,
        network_bidirectional_reachability_tool,
        network_classify_devices_execute,
        network_device_connections_execute,
        network_finalize_snapshot_execute,
        network_generate_topology_execute,
        network_get_allowed_services_execute,
        network_interface_vlan_count_execute,
        network_list_boundary_devices_execute,
        network_list_subnets_tool,
        network_node_inventory_execute,
        network_topology_connections_execute,
        network_prepare_snapshot_execute,
        network_reachability_summary_execute,
        network_remove_config_execute,
        network_segment_execute,
        network_summary_execute,
        network_traceroute_tool,
        network_upload_zip_execute,
        network_view_staging_execute,
        network_vlan_device_count_execute,
        network_vlan_discovery_execute,
        run_tagged_tests_tool,
        simulate_traffic_tool,
        update_classification_rules_execute,
    )
    from tools.batfish_check_routing_tool import CheckRoutingInput, ProtocolType
    from tools.batfish_failure_impact_tool import FailureImpactInput, FailureType
    from tools.batfish_get_inventory_tool import GetInventoryInput, ResourceType
    from tools.batfish_run_tagged_tests_tool import RunTaggedTestsInput
    from tools.batfish_simulate_traffic_tool import SimulateTrafficInput

    logger.info("Successfully imported tools with absolute imports")


def create_server() -> FastMCP:
    """Create and configure the FastMCP server.

    Returns:
        Configured FastMCP server instance
    """
    # Configure authentication using utility function
    auth_provider = configure_auth()

    # Create FastMCP instance with configured auth provider
    mcp = FastMCP(name="Batfish MCP Server", version="1.0.0", auth=auth_provider)
    mcp.add_middleware(ToolFilterMiddleware(mcp, header_name="x-mcp-tools"))

    # Authentication is handled globally by FastMCP

    # Register init_snapshot tool
    @tool(
        mcp,
        name="initialize_snapshot",
        toolset="initialization",
        description="Initialize: Snapshot - Initialize a Batfish snapshot with provided network configurations",
    )
    def initialize_snapshot(
        network: str, snapshot: str, configs: Dict[str, str], ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Initialize a Batfish snapshot with provided network configurations.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier
            configs: Dictionary of {filename: configContent}

        Returns:
            Dictionary containing operation status and snapshot details
        """
        try:
            logger.info(
                f"Received request to initialize Batfish snapshot '{snapshot}' for network '{network}'"
            )

            # Log user access
            log_user_access(None, "batfish_init_snapshot")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "configs": configs,
                "host": batfish_host,
            }

            # Execute the tool
            result = init_snapshot_execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_init_snapshot: {error_msg}")
            return {
                "ok": False,
                "network": network,
                "snapshot": snapshot,
                "error": error_msg,
            }

    # ============================================
    # INITIALIZE CATEGORY - Snapshot Initialization & Staging
    # ============================================

    # Register init_aws_snapshot tool
    @tool(
        mcp,
        name="initialize_aws_init_snapshot",
        toolset="initialization",
        description="Initialize: AWS Init Snapshot - Upload complete AWS configuration in one shot",
    )
    def initialize_aws_init_snapshot(
        snapshot_name: str,
        region: str,
        aws_data: Dict[str, Any],
        network_name: str = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Initialize a Batfish snapshot with RAW AWS API data.

        Creates the correct directory structure for AWS snapshots: aws_configs/<region>/aws.json

        The aws_data should be the RAW AWS API response format from the aws_collect_all tool,
        containing: vpcs, subnets, route_tables, internet_gateways, nat_gateways, security_groups,
        network_acls, network_interfaces, and instances (reservations).

        Args:
            snapshot_name: Snapshot identifier
            region: AWS region (e.g., 'us-east-1')
            aws_data: RAW AWS API data from aws_collect_all tool
            network_name: Logical network name (defaults to snapshot_name if not provided)

        Returns:
            Dictionary containing operation status and snapshot details
        """
        try:
            logger.info(
                f"Received request to initialize Batfish AWS snapshot '{snapshot_name}' for region '{region}'"
            )

            # Log user access
            log_user_access(None, "batfish_init_aws_snapshot")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "snapshot_name": snapshot_name,
                "region": region,
                "aws_data": aws_data,
                "host": batfish_host,
            }

            # Only include network_name if provided
            if network_name is not None:
                input_data["network_name"] = network_name

            # Execute the tool
            result = init_aws_snapshot_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_init_aws_snapshot: {error_msg}")
            return {"ok": False, "error": error_msg}

    # Register add_aws_data_chunk tool
    @tool(
        mcp,
        name="initialize_aws_add_data_chunk",
        toolset="initialization",
        description="Initialize: AWS Add Data Chunk - Incrementally upload AWS resources by type",
    )
    def initialize_aws_add_data_chunk(
        snapshot_name: str,
        region: str,
        resource_type: str,
        data: List[Dict[str, Any]],
        network_name: str = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Add a chunk of AWS resource data to staging directory for incremental snapshot building.

        This tool allows you to build AWS snapshots incrementally by adding one resource type at a time.
        After adding all chunks, use batfish_finalize_aws_snapshot to consolidate and initialize.

        Supported resource types:
        - Vpcs: VPC data from DescribeVpcs
        - Subnets: Subnet data from DescribeSubnets
        - RouteTables: Route table data from DescribeRouteTables
        - InternetGateways: IGW data from DescribeInternetGateways
        - NatGateways: NAT gateway data from DescribeNatGateways
        - SecurityGroups: Security group data from DescribeSecurityGroups
        - NetworkAcls: Network ACL data from DescribeNetworkAcls
        - NetworkInterfaces: ENI data from DescribeNetworkInterfaces
        - Reservations: EC2 instance data from DescribeInstances

        Args:
            snapshot_name: Snapshot identifier (used as staging key)
            region: AWS region (e.g., 'us-east-1')
            resource_type: AWS resource type (e.g., 'Vpcs', 'Subnets', 'SecurityGroups')
            data: List of AWS resources of this type (raw AWS API format)
            network_name: Logical network name (defaults to snapshot_name if not provided)

        Returns:
            Dictionary containing operation status, staging details, and list of chunks staged
        """
        try:
            logger.info(
                f"Received request to add AWS data chunk for snapshot '{snapshot_name}'"
            )

            # Extract headers from context
            logger.info(f"Resource type: {resource_type}, count: {len(data)}")

            # Log user access
            log_user_access(None, "batfish_add_aws_data_chunk")

            # Create input model
            input_data = {
                "snapshot_name": snapshot_name,
                "region": region,
                "resource_type": resource_type,
                "data": data,
            }

            # Only include network_name if provided
            if network_name is not None:
                input_data["network_name"] = network_name

            # Execute the tool
            result = aws_add_data_chunk_execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_add_aws_data_chunk: {error_msg}")
            return {"ok": False, "error": error_msg}

    # Register finalize_aws_snapshot tool
    @tool(
        mcp,
        name="initialize_aws_finalize_snapshot",
        toolset="initialization",
        description="Initialize: AWS Finalize Snapshot - Consolidate chunks and initialize Batfish",
    )
    def initialize_aws_finalize_snapshot(
        snapshot_name: str, clear_staging: bool = True, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Consolidate all staged AWS data chunks into a single aws.json and initialize Batfish snapshot.

        This tool finalizes the incremental snapshot building process by:
        1. Automatically finding the staging directory for your snapshot
        2. Reading network name and region from metadata (no need to specify again!)
        3. Reading all chunk files from the staging directory
        4. Merging them into a single aws.json file
        5. Creating the proper Batfish directory structure
        6. Initializing the Batfish snapshot
        7. Optionally clearing the staging directory

        Must be called after using batfish_add_aws_data_chunk to add all resource types.

        Args:
            snapshot_name: Snapshot identifier (must match the one used in add_aws_data_chunk)
            clear_staging: Whether to clear staging directory after success (default: True)

        Returns:
            Dictionary containing operation status, network, region, and consolidation details
        """
        try:
            logger.info(
                f"Received request to finalize Batfish AWS snapshot '{snapshot_name}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "batfish_finalize_aws_snapshot")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "snapshot_name": snapshot_name,
                "host": batfish_host,
                "clear_staging": clear_staging,
            }

            # Execute the tool
            result = aws_finalize_snapshot_execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_finalize_aws_snapshot: {error_msg}")
            return {"ok": False, "error": error_msg}

    # Register run_tagged_tests tool
    @tool(
        mcp,
        toolset="batfish",
        name="batfish_run_tagged_tests",
        description="Run tagged Batfish tests",
    )
    def batfish_run_tagged_tests(
        network: str, snapshot: str, tags: List[str], ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Run tagged Batfish tests.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier
            tags: List of test tags to run

        Returns:
            Dictionary containing overall status and individual test results
        """
        try:
            logger.info(
                f"Received request to run tagged tests for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context
            logger.info(f"Tags to run: {tags}")

            # Log user access
            log_user_access(None, "batfish_run_tagged_tests")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "tags": tags,
                "host": batfish_host,
            }

            # Execute the tool
            result = run_tagged_tests_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_run_tagged_tests: {error_msg}")
            return {"overall": "FAIL", "results": [], "error": error_msg}

    # Register remove_aws_chunk tool
    @tool(
        mcp,
        name="initialize_aws_remove_chunk",
        toolset="initialization",
        description="Initialize: AWS Remove Chunk - Delete a specific resource chunk from staging",
    )
    def initialize_aws_remove_chunk(
        snapshot_name: str,
        region: str,
        resource_type: str,
        network_name: str = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Remove a specific resource type chunk from the AWS staging directory.

        This tool allows you to remove incorrectly added chunks before finalization.
        For example, if you accidentally added 'Instances' instead of 'Reservations',
        you can remove it and add the correct resource type.

        Args:
            snapshot_name: Snapshot identifier (staging key)
            region: AWS region (e.g., 'us-east-1')
            resource_type: AWS resource type to remove (e.g., 'Instances', 'Vpcs', 'Subnets')
            network_name: Logical network name (defaults to snapshot_name if not provided)

        Returns:
            Dictionary containing operation status and remaining chunks
        """
        try:
            logger.info(
                f"Received request to remove AWS chunk '{resource_type}' from snapshot '{snapshot_name}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "batfish_remove_aws_chunk")

            # Create input model
            input_data = {
                "snapshot_name": snapshot_name,
                "region": region,
                "resource_type": resource_type,
            }

            # Only include network_name if provided
            if network_name is not None:
                input_data["network_name"] = network_name

            # Execute the tool
            result = aws_remove_chunk_execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_remove_aws_chunk: {error_msg}")
            return {"ok": False, "error": error_msg}

    # Register view_aws_staging tool
    @tool(
        mcp,
        name="initialize_aws_view_staging",
        toolset="initialization",
        description="Initialize: AWS View Staging - See what chunks have been uploaded",
    )
    def initialize_aws_view_staging(
        snapshot_name: str, region: str, network_name: str = None, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        View what AWS data chunks have been staged for a snapshot.

        This tool shows you what resource types have been added to the staging directory
        and provides resource counts and file sizes for each chunk.

        Args:
            snapshot_name: Snapshot identifier (staging key)
            region: AWS region (e.g., 'us-east-1')
            network_name: Logical network name (defaults to snapshot_name if not provided)

        Returns:
            Dictionary containing staging details including chunks staged and resource counts
        """
        try:
            logger.info(
                f"Received request to view AWS staging for snapshot '{snapshot_name}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "batfish_view_aws_staging")

            # Create input model
            input_data = {"snapshot_name": snapshot_name, "region": region}

            # Only include network_name if provided
            if network_name is not None:
                input_data["network_name"] = network_name

            # Execute the tool
            result = aws_view_staging_execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_view_aws_staging: {error_msg}")
            return {"ok": False, "error": error_msg}

    # Register cleanup tool
    @tool(
        mcp,
        name="management_cleanup",
        toolset="management",
        description="Management: Cleanup - Clean up after a test run by deleting the snapshot and removing temp directories",
    )
    def management_cleanup(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Clean up after a test run by deleting the snapshot and removing temp directories.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier

        Returns:
            Dictionary containing operation status and cleanup details
        """
        try:
            logger.info(
                f"Received request to clean up snapshot '{snapshot}' for network '{network}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "batfish_cleanup")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            # Execute the tool
            result = cleanup_execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_cleanup: {error_msg}")
            return {
                "ok": False,
                "network": network,
                "snapshot": snapshot,
                "error": error_msg,
            }

    # Register get_inventory tool
    @tool(
        mcp,
        name="batfish_get_inventory",
        toolset="batfish",
        description="Get Batfish inventory",
    )
    def batfish_get_inventory(
        network: str, snapshot: str, resource: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Returns inventory information (nodes, interfaces, VRFs, or routes) from a Batfish snapshot.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier
            resource: Resource type to retrieve (nodes, interfaces, vrfs, routes)

        Returns:
            Dictionary containing inventory items
        """
        try:
            logger.info(
                f"Received request to get inventory '{resource}' for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "batfish_get_inventory")

            # Validate resource type
            if resource not in [r.value for r in ResourceType]:
                return {
                    "success": False,
                    "error": f"Unknown resource type: {resource}. Must be one of: {', '.join([r.value for r in ResourceType])}",
                    "items": [],
                }

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "resource": resource,
                "host": batfish_host,
            }

            # Execute the tool
            result = get_inventory_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_get_inventory: {error_msg}")
            return {"success": False, "error": error_msg, "items": []}

    # Register check_routing tool
    @tool(
        mcp,
        name="batfish_check_routing",
        toolset="batfish",
        description="Check Batfish routing health",
    )
    def batfish_check_routing(
        network: str, snapshot: str, protocols: List[str], ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Check routing/control plane health (BGP sessions, OSPF adjacencies).

        Args:
            network: Logical network name
            snapshot: Snapshot identifier
            protocols: List of routing protocols to check (ospf, bgp)

        Returns:
            Dictionary containing overall status and individual protocol check results
        """
        try:
            logger.info(
                f"Received request to check routing health for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context
            logger.info(f"Protocols to check: {protocols}")

            # Log user access
            log_user_access(None, "batfish_check_routing")

            # Validate protocol types
            valid_protocols = [p.value for p in ProtocolType]
            for protocol in protocols:
                if protocol.lower() not in valid_protocols:
                    return {
                        "overall": "FAIL",
                        "results": [],
                        "error": f"Unknown protocol: {protocol}. Must be one of: {', '.join(valid_protocols)}",
                    }

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "protocols": protocols,
                "host": batfish_host,
            }

            # Execute the tool
            result = check_routing_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_check_routing: {error_msg}")
            return {"overall": "FAIL", "results": [], "error": error_msg}

    # Register simulate_traffic tool
    @tool(
        mcp,
        name="batfish_simulate_traffic",
        toolset="batfish",
        description="Simulate Batfish traffic",
    )
    def batfish_simulate_traffic(
        network: str,
        snapshot: str,
        src: str,
        dst: str,
        applications: List[str] = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Simulate traffic between two nodes/interfaces to check ACLs and reachability.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier
            src: Source node or interface
            dst: Destination node or interface
            applications: List of applications to simulate (e.g., http, ssh, dns)

        Returns:
            Dictionary containing overall status and simulation results
        """
        try:
            logger.info(
                f"Received request to simulate traffic for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context
            logger.info(f"Source: {src}, Destination: {dst}")
            logger.info(f"Applications: {applications or []}")

            # Log user access (no request context in FastMCP)
            log_user_access(None, "batfish_simulate_traffic")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "src": src,
                "dst": dst,
                "applications": applications or [],
                "host": batfish_host,
            }

            # Execute the tool
            result = simulate_traffic_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_simulate_traffic: {error_msg}")
            return {"overall": "FAIL", "results": [], "error": error_msg}

    # Register failure_impact tool
    @tool(
        mcp,
        name="batfish_failure_impact",
        toolset="batfish",
        description="Simulate node or interface failure and report traffic impact.",
    )
    def batfish_failure_impact(
        network: str, snapshot: str, failure_type: str, target: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Simulate node or interface failure and report traffic impact.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier
            failure_type: Type of failure to simulate (node or interface)
            target: Target node or interface to fail

        Returns:
            Dictionary containing overall impact assessment and detailed results
        """
        try:
            logger.info(
                f"Received request to analyze failure impact for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context
            logger.info(f"Failure type: {failure_type}, Target: {target}")

            # Log user access (no request context in FastMCP)
            log_user_access(None, "batfish_failure_impact")

            # Validate failure type
            valid_failure_types = [f.value for f in FailureType]
            if failure_type.lower() not in valid_failure_types:
                return {
                    "overall": "ERROR",
                    "results": [],
                    "error": f"Unknown failure type: {failure_type}. Must be one of: {', '.join(valid_failure_types)}",
                }

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "failure_type": failure_type.lower(),
                "target": target,
                "host": batfish_host,
            }

            # Execute the tool
            result = failure_impact_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_failure_impact: {error_msg}")
            return {"overall": "ERROR", "results": [], "error": error_msg}

    # ============================================
    # MANAGEMENT CATEGORY - Core Batfish Operations
    # ============================================

    @tool(
        mcp,
        name="management_list_networks",
        toolset="management",
        description="Management: List Networks - Get all available Batfish networks",
    )
    def management_list_networks(ctx: Context = None) -> Dict[str, Any]:
        """
        List available Batfish networks on the configured Batfish server.

        Returns:
            Dictionary containing operation status and list of network names
        """
        try:
            logger.info("Received request to list Batfish networks")

            # Extract headers from context
            # Log user access
            log_user_access(None, "management_list_networks")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {"host": batfish_host}

            # Execute the tool
            result = list_networks_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in management_list_networks: {error_msg}")
            return {"ok": False, "error": error_msg, "networks": []}

    @tool(
        mcp,
        name="management_list_snapshots",
        toolset="management",
        description="Management: List Snapshots - Get all snapshots in a network",
    )
    def management_list_snapshots(network: str, ctx: Context = None) -> Dict[str, Any]:
        """
        List all snapshots inside a given network.

        Args:
            network: Logical network name

        Returns:
            Dictionary containing operation status and list of snapshot names
        """
        try:
            logger.info(
                f"Received request to list Batfish snapshots for network '{network}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "management_list_snapshots")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {"network": network, "host": batfish_host}

            # Execute the tool
            result = list_snapshots_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in management_list_snapshots: {error_msg}")
            return {"ok": False, "error": error_msg, "snapshots": []}

    @tool(
        mcp,
        name="management_delete_snapshot",
        toolset="management",
        description="Management: Delete Snapshot - Remove a snapshot from a network",
    )
    def management_delete_snapshot(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Delete a snapshot within a network.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier to delete

        Returns:
            Dictionary containing operation status and deleted snapshot name
        """
        try:
            logger.info(
                f"Received request to delete Batfish snapshot '{snapshot}' from network '{network}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "management_delete_snapshot")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            # Execute the tool
            result = delete_snapshot_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in management_delete_snapshot: {error_msg}")
            return {"ok": False, "error": error_msg}

    @tool(
        mcp,
        name="management_delete_network",
        toolset="management",
        description="Management: Delete Network - Remove an entire network from Batfish",
    )
    def management_delete_network(network: str, ctx: Context = None) -> Dict[str, Any]:
        """
        Delete an entire network from Batfish.

        Args:
            network: Logical network name to delete

        Returns:
            Dictionary containing operation status and deleted network name
        """
        try:
            logger.info(f"Received request to delete Batfish network '{network}'")

            # Extract headers from context
            # Log user access
            log_user_access(None, "management_delete_network")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {"network": network, "host": batfish_host}

            # Execute the tool
            result = delete_network_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in management_delete_network: {error_msg}")
            return {"ok": False, "error": error_msg}

    @tool(
        mcp,
        name="management_get_snapshot_info",
        toolset="management",
        description="Management: Get Snapshot Info - Retrieve detailed metadata about a snapshot",
    )
    def management_get_snapshot_info(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Return metadata about a snapshot including nodes, vendors, warnings, errors, and interfaces.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier

        Returns:
            Dictionary containing snapshot metadata including nodes, warnings, errors, vendors, and interfaces
        """
        try:
            logger.info(
                f"Received request to get snapshot info for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "management_get_snapshot_info")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            # Execute the tool
            result = get_snapshot_info_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in management_get_snapshot_info: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "nodes": [],
                "warnings": [],
                "errors": [],
                "vendors": [],
                "interfaces": [],
            }

    @tool(
        mcp,
        toolset="management",
        name="management_get_parse_status",
        description="Management: Get Parse Status - Check parsing warnings and errors for a snapshot",
    )
    def management_get_parse_status(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Return parse warnings and errors for a snapshot.

        Args:
            network: Logical network name
            snapshot: Snapshot identifier

        Returns:
            Dictionary containing parse warnings and errors
        """
        try:
            logger.info(
                f"Received request to get parse status for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context
            # Log user access
            log_user_access(None, "management_get_parse_status")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            # Execute the tool
            result = get_parse_status_tool.execute(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in management_get_parse_status: {error_msg}")
            return {"ok": False, "error": error_msg, "warnings": [], "errors": []}

    # Register github_snapshot tool
    @tool(
        mcp,
        toolset="initialization",
        name="initialize_github_load_snapshot",
        description="Initialize: GitHub Load Snapshot - Clone and load a Batfish snapshot from a GitHub repository",
    )
    def initialize_github_load_snapshot(
        repo_url: str,
        snapshot_name: str,
        network_name: str = None,
        github_username: str = None,
        github_pat: str = None,
        branch: str = "main",
        subpath: str = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Load a Batfish snapshot directly from a GitHub repository.

        This tool clones a GitHub repository containing Batfish snapshot data and initializes it in Batfish.
        Supports both public and private repositories with authentication.

        **Workflow:**
        1. Clones the specified GitHub repository
        2. Optionally checks out a specific branch
        3. Optionally navigates to a subdirectory within the repo
        4. Initializes the snapshot in Batfish
        5. Cleans up temporary files

        **Repository Structure:**
        The repository should contain either:
        - A 'configs/' directory with network configuration files
        - Configuration files in the root (will be treated as configs)
        - Standard Batfish snapshot structure with hosts/, batfish/, etc.

        **URL Formats Supported:**
        - https://github.com/owner/repo
        - https://github.com/owner/repo.git
        - https://github.com/owner/repo/tree/branch/path/to/snapshot

        **Private Repositories:**
        For private repos, provide both github_username and github_pat (Personal Access Token).
        Generate a PAT at: https://github.com/settings/tokens
        Required scopes: repo (for private repos)

        Args:
            repo_url: GitHub repository URL (full URL or owner/repo format)
            snapshot_name: Snapshot identifier to use in Batfish
            network_name: Logical network name (defaults to snapshot_name if not provided)
            github_username: GitHub username (required for private repos)
            github_pat: GitHub Personal Access Token (required for private repos)
            branch: Branch to clone (default: main)
            subpath: Subdirectory path within repo containing snapshot data

        Returns:
            Dictionary containing:
            - ok: Success status
            - network: Network name
            - snapshot: Snapshot name
            - repo_url: Repository URL used
            - branch: Branch cloned
            - subpath: Subpath used (if any)
            - file_count: Number of files in the snapshot
            - node_count: Number of nodes discovered
            - nodes: List of node names
            - message: Status message
        """
        try:
            logger.info(f"Loading snapshot '{snapshot_name}' from GitHub: {repo_url}")

            # Extract headers from context
            # Log user access
            log_user_access(None, "batfish_github_load_snapshot")

            # Get Batfish host from headers or environment
            batfish_host = get_batfish_host()

            # Create input model with host information
            input_data = {
                "repo_url": repo_url,
                "snapshot_name": snapshot_name,
                "host": batfish_host,
                "branch": branch,
            }

            # Add optional parameters if provided
            if network_name is not None:
                input_data["network_name"] = network_name

            if github_username is not None:
                input_data["github_username"] = github_username

            if github_pat is not None:
                input_data["github_pat"] = github_pat

            if subpath is not None:
                input_data["subpath"] = subpath

            # Execute the tool
            result = github_snapshot_tool(input_data)

            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_github_load_snapshot: {error_msg}")
            return {"ok": False, "error": error_msg}

    # Register github_load_snapshot tool
    @tool(
        mcp,
        toolset="github",
        name="github_load_snapshot",
        description="Load a Batfish snapshot from a GitHub repository",
    )
    def github_load_snapshot(
        repo_url: str,
        snapshot_name: str,
        network_name: str = None,
        github_username: str = None,
        github_pat: str = None,
        branch: str = "main",
        subpath: str = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """Load a Batfish snapshot from a GitHub repository."""
        try:
            # Extract headers from context

            log_user_access(None, "github_load_snapshot")
            batfish_host = get_batfish_host()

            input_data = {
                "repo_url": repo_url,
                "snapshot_name": snapshot_name,
                "host": batfish_host,
                "branch": branch,
            }

            if network_name:
                input_data["network_name"] = network_name
            if github_username:
                input_data["github_username"] = github_username
            if github_pat:
                input_data["github_pat"] = github_pat
            if subpath:
                input_data["subpath"] = subpath

            return github_snapshot_tool(input_data)
        except Exception as e:
            logger.error(f"Error in github_load_snapshot: {e}")
            return {"ok": False, "error": str(e)}

    # =============================================================================
    # AWS-SPECIFIC ANALYSIS TOOLS
    # =============================================================================

    # Register aws_reachability tool
    # ============================================
    # AWS CATEGORY - Cloud Infrastructure Analysis
    # ============================================

    @tool(
        mcp,
        toolset="aws",
        name="aws_reachability",
        description="AWS: Reachability - Test traffic flow between source and destination",
    )
    def aws_reachability(
        network: str,
        snapshot: str,
        source_location: str,
        dest_ip: str,
        dest_port: int = None,
        protocol: str = "tcp",
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Test traffic reachability between source and destination in AWS.

        **PRIMARY AWS TROUBLESHOOTING TOOL** - Simulates ANY traffic (src → dst → protocol → port).
        Returns CONCISE results: allowed/denied, exact SG/NACL rule, route table, path taken, drop location.

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            source_location: Source (subnet ID or 'internet')
            dest_ip: Destination IP address
            dest_port: Destination port (optional)
            protocol: Protocol: tcp, udp, icmp (default: tcp)

        Returns:
            Dictionary containing:
            - ok: Success status
            - allowed: True if traffic is allowed
            - result: ALLOWED or DENIED
            - path: List of hops taken
            - route_table: Route table ID used
            - blocking_rule: Rule that blocked traffic (if denied)
            - reason: Human-readable explanation
        """
        try:
            logger.info(
                f"Testing AWS reachability: {source_location} → {dest_ip}:{dest_port}/{protocol}"
            )

            # Extract headers from context

            log_user_access(None, "batfish_aws_reachability")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "source_location": source_location,
                "dest_ip": dest_ip,
                "protocol": protocol,
                "host": batfish_host,
            }

            if dest_port is not None:
                input_data["dest_port"] = dest_port

            result = aws_reachability_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_aws_reachability: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "allowed": False,
                "result": "ERROR",
            }

    @tool(
        mcp,
        toolset="aws",
        name="aws_traceroute",
        description="AWS: Traceroute - Trace packet path through AWS infrastructure with hop-by-hop details",
    )
    def aws_traceroute(
        network: str,
        snapshot: str,
        source_location: str,
        dest_ip: str,
        dest_port: int = None,
        ip_protocol: str = "tcp",
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Trace the path from source to destination through AWS infrastructure.

        Shows detailed hop-by-hop information:
        - Routing decisions at each hop
        - Security group permit/deny decisions
        - Network ACL evaluations
        - Final disposition (accepted/denied/dropped)

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            source_location: Source location (subnet ID like 'subnet-xxx' or node name)
            dest_ip: Destination IP address
            dest_port: Destination port (optional)
            ip_protocol: IP protocol: tcp, udp, icmp (default: tcp)

        Returns:
            Dictionary containing:
            - ok: Success status
            - source_location: Source location
            - dest_ip: Destination IP
            - dest_port: Destination port
            - protocol: Protocol used
            - trace_count: Number of traces found
            - accepted: Count of accepted traces
            - denied: Count of denied traces
            - traces: Detailed trace information with hops and decisions
            - summary: Human-readable summary
        """
        try:
            logger.info(
                f"Tracing AWS route: {source_location} → {dest_ip}:{dest_port}/{ip_protocol}"
            )

            # Extract headers from context

            log_user_access(None, "aws_traceroute")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "source_location": source_location,
                "dest_ip": dest_ip,
                "ip_protocol": ip_protocol,
                "host": batfish_host,
            }

            if dest_port is not None:
                input_data["dest_port"] = dest_port

            result = aws_trace_route_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in aws_traceroute: {error_msg}")
            return {"ok": False, "error": error_msg, "traces": []}

    # Register aws_internet_exposure tool
    @tool(
        mcp,
        toolset="aws",
        name="aws_internet_exposure",
        description="AWS: Internet Exposure - Find all resources exposed to the internet",
    )
    def aws_internet_exposure(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Identify all AWS resources exposed to the internet.

        **#1 GOVERNANCE/COMPLIANCE TOOL** - Comprehensive internet exposure audit.

        Identifies:
        - EC2 instances with public IPs
        - ENIs reachable from the internet
        - Subnets with IGW exposure
        - Route tables allowing 0.0.0.0/0
        - Security groups allowing 0.0.0.0/0 or wide-open ports
        - NACLs permitting inbound traffic
        - Any destination reachable from the internet node in Batfish

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - exposed_instances: List of instances reachable from internet
            - exposed_enis: List of ENIs reachable from internet
            - exposed_subnets: List of public subnets
            - exposed_security_groups: List of SGs allowing internet access
            - exposed_nacls: List of NACLs with permissive rules
            - reasons: Detailed findings categorized by severity
            - summary: Human-readable summary
        """
        try:
            logger.info(
                f"Analyzing AWS internet exposure for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_aws_internet_exposure")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = aws_internet_exposure_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_aws_internet_exposure: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "exposed_instances": [],
                "exposed_subnets": [],
                "exposed_enis": [],
                "reasons": [],
            }

    # Register aws_security_evaluation tool
    @tool(
        mcp,
        toolset="aws",
        name="aws_security_evaluation",
        description="AWS: Security Evaluation - Deep security analysis of AWS infrastructure",
    )
    def aws_security_evaluation(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive security evaluation of AWS infrastructure.

        **DEEP SECURITY ANALYSIS TOOL** - Analyzes security posture in detail.
        Detects: overly-permissive SGs, shadowed rules, SG/NACL conflicts, unused SGs,
        inconsistent firewall patterns, and least privilege violations.

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - total_findings: Total number of findings
            - critical/high/medium/low: Count by severity
            - statistics: Detailed breakdown by issue type
            - findings: Categorized findings with remediation recommendations
        """
        try:
            logger.info(
                f"Performing AWS security evaluation for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_aws_security_evaluation")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = aws_security_evaluation_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_aws_security_evaluation: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "total_findings": 0,
                "findings": {},
            }

    # Register aws_subnet_segmentation tool
    @tool(
        mcp,
        toolset="aws",
        name="aws_subnet_segmentation",
        description="AWS: Subnet Segmentation - Test network isolation between subnets",
    )
    def aws_subnet_segmentation(
        network: str,
        snapshot: str,
        expected_isolation: Dict[str, List[str]] = None,
        allowed_pairs: List[List[str]] = None,
        denied_pairs: List[List[str]] = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Check AWS subnet-to-subnet segmentation inside a Batfish snapshot.

        **NETWORK SEGMENTATION TOOL** - Tests reachability between all subnet pairs
        and validates against expected isolation policies.

        For every pair of subnets, determines whether traffic is allowed or blocked,
        and reports unexpected allows/blocks based on user expectations.

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            expected_isolation: Dictionary of isolation rules (e.g., {"prod": ["dev"]} means prod should be isolated from dev)
            allowed_pairs: List of [source_subnet, dest_subnet] pairs that should allow traffic
            denied_pairs: List of [source_subnet, dest_subnet] pairs that should deny traffic

        Returns:
            Dictionary containing:
            - ok: Success status
            - subnet_count: Number of subnets discovered
            - subnets: List of subnet IDs
            - summary: Statistics (total_pairs_tested, violations, etc.)
            - allowed: List of subnet pairs allowing traffic
            - denied: List of subnet pairs denying traffic
            - unexpected_allows: Violations where traffic is allowed but shouldn't be
            - unexpected_blocks: Violations where traffic is blocked but should be allowed
        """
        try:
            logger.info(
                f"Analyzing AWS subnet segmentation for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_aws_subnet_segmentation")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            # Add optional parameters if provided
            if expected_isolation is not None:
                input_data["expected_isolation"] = expected_isolation

            if allowed_pairs is not None:
                # Convert list of lists to list of tuples
                input_data["allowed_pairs"] = [tuple(pair) for pair in allowed_pairs]

            if denied_pairs is not None:
                # Convert list of lists to list of tuples
                input_data["denied_pairs"] = [tuple(pair) for pair in denied_pairs]

            result = aws_subnet_segmentation_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_aws_subnet_segmentation: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "allowed": [],
                "denied": [],
                "unexpected_allows": [],
                "unexpected_blocks": [],
            }

    # Register aws_route_analysis tool
    @tool(
        mcp,
        toolset="aws",
        name="aws_route_analysis",
        description="AWS: Route Analysis - Identify routing issues and misconfigurations",
    )
    def aws_route_analysis(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Analyze AWS routing and identify routing issues.

        **AWS ROUTE ANALYSIS TOOL** - Comprehensive routing validation.

        Identifies:
        - Blackhole routes
        - Missing return paths
        - Subnets with no default route
        - Misconfigured IGW/NATGW paths
        - Asymmetric routing
        - Overlapping or shadowed routes
        - TGW propagation issues (if present)
        - Subnets that cannot reach expected destinations

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - total_issues: Total number of routing issues
            - blackholes: List of blackhole routes
            - missing_defaults: Subnets with no default route
            - asymmetric_routes: Asymmetric routing issues
            - route_conflicts: Overlapping or conflicting routes
            - unreachable_subnets: Subnets that cannot reach destinations
            - invalid_igw_or_nat_paths: Misconfigured IGW/NAT paths
            - summary: Human-readable summary
        """
        try:
            logger.info(
                f"Analyzing AWS routes for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_aws_route_analysis")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = aws_route_analysis_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_aws_route_analysis: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "blackholes": [],
                "missing_defaults": [],
                "asymmetric_routes": [],
                "route_conflicts": [],
                "unreachable_subnets": [],
                "invalid_igw_or_nat_paths": [],
            }

    # Register aws_node_inventory tool
    @tool(
        mcp,
        toolset="aws",
        name="aws_node_inventory",
        description="AWS: Node Inventory - Get compact summary of AWS resources",
    )
    def aws_node_inventory(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Return compact AWS inventory - token-efficient, no verbose metadata.

        **AWS NODE INVENTORY TOOL** - Compressed network object summary.

        Returns TOON-style compressed inventory with:
        - Object IDs only
        - Minimal key fields (≤ 3-6 per object)
        - ID references (no nested raw structures)
        - NO full Batfish frames
        - NO AWS vendor data
        - NO large nested structures

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - vpcs: VPC inventory (IDs, CIDRs, subnet references)
            - subnets: Subnet inventory (CIDR, VPC, type, instance refs)
            - instances: Instance inventory (IPs, subnet, SG refs)
            - security_groups: SG inventory (rule counts, attachments)
            - enis: ENI inventory (subnet, instance, IP)
            - route_tables: Route table inventory (subnets, default route)
            - summary: Human-readable summary
        """
        try:
            logger.info(
                f"Building compact AWS inventory for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_aws_node_inventory")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = aws_node_inventory_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_aws_node_inventory: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "vpcs": {},
                "subnets": {},
                "instances": {},
                "security_groups": {},
                "enis": {},
                "route_tables": {},
            }

    # Register aws_change_impact tool
    @tool(
        mcp,
        name="aws_change_impact",
        toolset="aws",
        description="AWS: Change Impact - Pre-deployment validation to prevent outages",
    )
    def aws_change_impact(
        network: str,
        base_snapshot: str,
        candidate_snapshot: str,
        critical_flows: List[Dict[str, Any]] = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Pre-deployment change validation - compare snapshots to identify impact.

        **AWS CHANGE IMPACT TOOL** - Prevents outages by validating changes BEFORE deployment.

        Compares two snapshots to identify:
        - Breaking changes (critical flows that will stop working)
        - New reachability (new paths opened - potential security risk)
        - Lost reachability (paths that will be blocked)
        - Risk assessment (CRITICAL/HIGH/MEDIUM/LOW/SAFE)

        Args:
            network: Batfish network name
            base_snapshot: Current/baseline snapshot name
            candidate_snapshot: Proposed change snapshot name
            critical_flows: Optional list of critical flows to test
                Format: [{"src": "subnet-a", "dst": "8.8.8.8", "port": 443, "protocol": "tcp"}]

        Returns:
            Dictionary containing:
            - ok: Success status
            - risk_level: CRITICAL/HIGH/MEDIUM/LOW/SAFE
            - risk_summary: Human-readable risk description
            - breaking_changes: Critical flows that will break
            - lost_reachability: Connectivity that will be lost
            - new_reachability: New connectivity enabled
            - recommendations: Deployment recommendations
            - summary: Concise impact summary
        """
        try:
            logger.info(
                f"Analyzing change impact: {base_snapshot} → {candidate_snapshot}"
            )

            # Extract headers from context

            log_user_access(None, "batfish_aws_change_impact")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "base_snapshot": base_snapshot,
                "candidate_snapshot": candidate_snapshot,
                "host": batfish_host,
            }

            if critical_flows is not None:
                input_data["critical_flows"] = critical_flows

            result = aws_change_impact_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_aws_change_impact: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "breaking_changes": [],
                "lost_reachability": [],
                "new_reachability": [],
                "risk_level": "UNKNOWN",
            }

    @tool(
        mcp,
        name="aws_find_unrestricted_ssh",
        toolset="aws",
        description="AWS: Find Unrestricted SSH - Identify Security Groups allowing SSH from 0.0.0.0/0",
    )
    def aws_find_unrestricted_ssh(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Find AWS Security Groups that allow SSH (port 22) from anywhere (0.0.0.0/0 or ::/0).

        This is a critical security finding - SSH should only be allowed from specific IPs.

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - findings: List of security groups with unrestricted SSH
            - total_findings: Count of findings
            - severity: Risk level (CRITICAL if any found)
        """
        try:
            logger.info(
                f"Finding unrestricted SSH in network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "aws_find_unrestricted_ssh")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = aws_find_unrestricted_ssh_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in aws_find_unrestricted_ssh: {error_msg}")
            return {
                "ok": False,
                "error": error_msg,
                "findings": [],
                "total_findings": 0,
            }

    # =============================================================================
    # NETWORK CONFIGURATION TOOLS (Traditional network devices)
    # =============================================================================

    # Register network_prepare_snapshot tool
    @tool(
        mcp,
        toolset="initialization",
        name="initialize_network_prepare_snapshot",
        description="Initialize: Network Prepare Snapshot - Stage network device configurations incrementally",
    )
    def initialize_network_prepare_snapshot(
        snapshot_name: str,
        configs: Dict[str, str],
        network_name: str = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Stage network device configurations for a snapshot.

        Allows incremental adding of configs before pushing to Batfish.
        Creates/updates a staging directory and tracks what's been staged.

        **Workflow:**
        1. Call this tool multiple times to add configs incrementally
        2. View staged configs with network_view_staging
        3. Remove incorrect configs with network_remove_config (if needed)
        4. Finalize with network_finalize_snapshot to push to Batfish

        Args:
            snapshot_name: Snapshot identifier (used as staging key)
            configs: Dictionary of {filename: configContent} to add (one or multiple configs)
            network_name: Logical network name (defaults to snapshot_name if not provided)

        Returns:
            Dictionary containing:
            - ok: Success status
            - snapshot_name: Snapshot identifier
            - network_name: Network name
            - staging_dir: Path to staging directory
            - added_configs: List of configs just added
            - staged_configs: Full list of all staged configs
            - total_configs: Total number of staged configs
            - message: Status message
        """
        try:
            logger.info(
                f"Received request to prepare network snapshot '{snapshot_name}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_network_prepare_snapshot")

            input_data = {"snapshot_name": snapshot_name, "configs": configs}

            if network_name is not None:
                input_data["network_name"] = network_name

            result = network_prepare_snapshot_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_network_prepare_snapshot: {error_msg}")
            return {"ok": False, "error": error_msg, "staged_configs": []}

    # Register network_finalize_snapshot tool
    @tool(
        mcp,
        toolset="initialization",
        name="initialize_network_finalize_snapshot",
        description="Initialize: Network Finalize Snapshot - Push staged configs to Batfish and initialize",
    )
    def initialize_network_finalize_snapshot(
        snapshot_name: str,
        network_name: str = None,
        clear_staging: bool = True,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Finalize and initialize network snapshot in Batfish.

        Reads all staged configs from the staging directory and pushes them to Batfish
        as a complete snapshot. Must be called after network_prepare_snapshot.

        Args:
            snapshot_name: Snapshot identifier (must match staging key)
            network_name: Logical network name (will auto-detect if not provided)
            clear_staging: Whether to clear staging directory after success (default: True)

        Returns:
            Dictionary containing:
            - ok: Success status
            - network: Network name
            - snapshot: Snapshot name
            - configs_loaded: Number of configs loaded
            - config_files: List of config filenames
            - node_count: Number of nodes in snapshot
            - staging_cleared: Whether staging was cleared
            - message: Status message
        """
        try:
            logger.info(
                f"Received request to finalize network snapshot '{snapshot_name}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_network_finalize_snapshot")

            batfish_host = get_batfish_host()

            input_data = {
                "snapshot_name": snapshot_name,
                "host": batfish_host,
                "clear_staging": clear_staging,
            }

            if network_name is not None:
                input_data["network_name"] = network_name

            result = network_finalize_snapshot_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_network_finalize_snapshot: {error_msg}")
            return {"ok": False, "error": error_msg}

    # Register network_view_staging tool
    @tool(
        mcp,
        toolset="initialization",
        name="initialize_network_view_staging",
        description="Initialize: Network View Staging - See what configs have been staged",
    )
    def initialize_network_view_staging(
        snapshot_name: str, network_name: str = None, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        View staged network configurations for a snapshot.

        Shows what configs have been staged, their sizes, and metadata.

        Args:
            snapshot_name: Snapshot identifier (staging key)
            network_name: Logical network name (will auto-detect if not provided)

        Returns:
            Dictionary containing:
            - ok: Success status
            - snapshot_name: Snapshot identifier
            - network_name: Network name
            - staging_dir: Path to staging directory
            - total_configs: Number of staged configs
            - total_size_bytes: Total size of all configs
            - total_lines: Total lines across all configs
            - staged_configs: Detailed list of staged configs with metadata
            - message: Status message
        """
        try:
            logger.info(
                f"Received request to view staging for snapshot '{snapshot_name}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_network_view_staging")

            input_data = {"snapshot_name": snapshot_name}

            if network_name is not None:
                input_data["network_name"] = network_name

            result = network_view_staging_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_network_view_staging: {error_msg}")
            return {"ok": False, "error": error_msg, "staged_configs": []}

    # Register network_remove_config tool
    @tool(
        mcp,
        toolset="initialization",
        name="initialize_network_remove_config",
        description="Initialize: Network Remove Config - Remove a specific config from staging",
    )
    def initialize_network_remove_config(
        snapshot_name: str, filename: str, network_name: str = None, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Remove a configuration file from staging.

        Useful for removing incorrectly added configs before finalization.
        You can then re-add the correct config with network_prepare_snapshot.

        Args:
            snapshot_name: Snapshot identifier (staging key)
            filename: Config filename to remove
            network_name: Logical network name (will auto-detect if not provided)

        Returns:
            Dictionary containing:
            - ok: Success status
            - snapshot_name: Snapshot identifier
            - network_name: Network name
            - removed_config: Filename that was removed
            - remaining_configs: List of configs still staged
            - total_remaining: Number of remaining configs
            - message: Status message
        """
        try:
            logger.info(
                f"Received request to remove config '{filename}' from snapshot '{snapshot_name}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_network_remove_config")

            input_data = {"snapshot_name": snapshot_name, "filename": filename}

            if network_name is not None:
                input_data["network_name"] = network_name

            result = network_remove_config_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_network_remove_config: {error_msg}")
            return {"ok": False, "error": error_msg, "remaining_configs": []}

    # Register network_upload_zip tool
    @tool(
        mcp,
        toolset="initialization",
        name="initialize_network_upload_zip",
        description="Initialize: Network Upload ZIP - Upload complete zip file of configs",
    )
    def initialize_network_upload_zip(
        snapshot_name: str, zip_data: str, network_name: str = None, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Upload a complete zip file of network configurations and initialize snapshot.

        The zip file should be base64-encoded and contain a 'configs/' directory.
        If no 'configs/' directory exists, all files in the root will be treated as configs.

        **Expected zip structure:**
        ```
        your-snapshot.zip
        └── configs/
            ├── router1.cfg
            ├── router2.cfg
            └── switch1.cfg
        ```

        **Usage:**
        1. Create a zip file with your network configs
        2. Base64-encode the zip file
        3. Send the encoded data to this tool
        4. Batfish snapshot is initialized immediately

        This is a **single-shot upload** - no staging required.
        Use this when you have all configs ready in a zip file.

        For incremental config addition, use network_prepare_snapshot instead.

        Args:
            snapshot_name: Snapshot identifier
            zip_data: Base64-encoded zip file content
            network_name: Logical network name (defaults to snapshot_name)

        Returns:
            Dictionary containing:
            - ok: Success status
            - network: Network name
            - snapshot: Snapshot name
            - zip_size_bytes: Size of uploaded zip
            - configs_loaded: Number of configs found
            - config_files: List of config filenames
            - node_count: Number of nodes discovered
            - nodes: List of node names
            - message: Status message
        """
        try:
            logger.info(
                f"Received request to upload zip for snapshot '{snapshot_name}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_network_upload_zip")

            batfish_host = get_batfish_host()

            input_data = {
                "snapshot_name": snapshot_name,
                "zip_data": zip_data,
                "host": batfish_host,
            }

            if network_name is not None:
                input_data["network_name"] = network_name

            result = network_upload_zip_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_network_upload_zip: {error_msg}")
            return {"ok": False, "error": error_msg}

    # Register network_generate_topology tool
    @tool(
        mcp,
        toolset="network",
        name="network_generate_topology",
        description="Network: Generate Topology - Create interactive HTML visualization and return content",
    )
    def batfish_network_generate_topology(
        network: str, snapshot: str, include_hosts: bool = True, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Generate interactive HTML visualization of network topology.

        Creates a D3.js-based interactive topology map and returns the HTML content
        directly in the response so it can be saved by the client.

        **Shows:**
        - Network devices (routers, switches, firewalls)
        - Hosts (servers, endpoints, workstations)
        - Physical connections between devices
        - Interface details and IP addressing
        - Layer 3 connectivity

        **Features:**
        - Interactive draggable nodes
        - Zoom and pan
        - Hover tooltips with device details
        - Color-coded by device type
        - Export topology data as JSON
        - Fix/unfix node positions

        **Returns HTML content in response** - just copy and save it!

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            include_hosts: Include host nodes in topology (default: True)

        Returns:
            Dictionary containing:
            - ok: Success status
            - network: Network name
            - snapshot: Snapshot name
            - html_content: Complete HTML content (ready to save)
            - html_size_bytes: Size of HTML content
            - device_count: Number of devices in topology
            - connection_count: Number of connections
            - message: Status message
        """
        try:
            logger.info(
                f"Received request to generate topology for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "batfish_network_generate_topology")

            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
                "include_hosts": include_hosts,
                "output_path": None,  # Let tool generate path automatically
            }

            result = network_generate_topology_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in batfish_network_generate_topology: {error_msg}")
            return {"ok": False, "error": error_msg}

    @tool(
        mcp,
        toolset="network",
        name="network_list_subnets",
        description=(
            "Network: List Subnets - Get unique IP subnets from network devices. "
            "Shows which devices own interfaces in each subnet with VRF assignments."
        ),
    )
    async def network_list_subnets(network: str, snapshot: str) -> Dict[str, Any]:
        """
        List all unique IP subnets in the network with their owners.

        Returns a structured summary of IP subnets showing which network devices
        have interfaces in each subnet, along with interface details and VRF assignments.

        **ONLY includes real network infrastructure devices** - excludes hosts, CLI nodes,
        and management interfaces.

        **Supported vendors:** Cisco, Juniper, Arista, Palo Alto, F5, VyOS

        **Returns:**
        - Subnet prefix (CIDR notation)
        - Device owners (list of nodes with interfaces in subnet)
        - Interfaces (formatted as Node[Interface])
        - VRF assignment (default or named VRF)

        **Use cases:**
        - IP address planning and documentation
        - Subnet overlap detection
        - Network segmentation analysis
        - Multi-device subnet identification

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - subnets: List of subnet objects with prefix, owners, interfaces, and vrf
            - summary: Human-readable summary (e.g., "Detected X unique subnets across Y network devices")
        """
        try:
            logger.info(
                f"Listing subnets for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_list_subnets")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = network_list_subnets_tool.execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_list_subnets: {error_msg}")
            return {"ok": False, "error": error_msg, "subnets": []}

    # Register network_list_boundary_devices tool
    @tool(
        mcp,
        toolset="network",
        name="network_list_boundary_devices",
        description="Network: List Boundary Devices - Identify segmentation enforcement points",
    )
    def network_list_boundary_devices(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Identify network boundary devices that connect different subnet groups.

        Analyzes Layer 3 adjacencies to find devices (routers, switches, firewalls)
        that bridge different subnets, indicating segmentation enforcement points
        in the network.

        **PURPOSE:** Find network boundary devices based on Batfish L3 adjacencies
        and subnet ownership. These are segmentation enforcement points.

        **FILTERING:**
        - Only includes valid network devices (cisco, juniper, arista, palo alto, f5, vyos)
        - Excludes sensors, hosts, and endpoints
        - Compares subnet sets across Layer 3 adjacencies

        **USE CASES:**
        - Identify segmentation boundaries
        - Find inter-zone routing devices
        - Locate firewall and gateway devices
        - Map security policy enforcement points

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - boundaries: List of boundary devices with connected prefixes
              [{"node": "FW-OT", "connects": ["10.10.0.0/16", "10.20.0.0/16"]}, ...]
            - summary: Human-readable summary (e.g., "Identified X network boundary devices")
        """
        try:
            logger.info(
                f"Identifying boundary devices for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_list_boundary_devices")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = network_list_boundary_devices_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_list_boundary_devices: {error_msg}")
            return {"ok": False, "error": error_msg, "boundaries": []}

    # Register network_reachability_summary tool
    @tool(
        mcp,
        toolset="network",
        name="network_reachability_summary",
        description="Network: Reachability Summary - Cross-subnet reachability analysis",
    )
    def network_reachability_summary(
        network: str, snapshot: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Summarize cross-subnet reachability between network-owned prefixes.

        Analyzes reachability summary data to identify which subnets can communicate
        with each other, providing a concise set of (src subnet → dst subnet) pairs
        that represent real L3 reachability paths.

        **PURPOSE:** Summarize cross-subnet reachability between network-owned prefixes.
        This is used for OT/IT segmentation and compliance analysis.

        **FILTERING:**
        - Only includes valid network devices (cisco, juniper, arista, palo alto, f5, vyos)
        - Only includes flows with DELIVERED_TO_SUBNET disposition
        - Excludes dropped flows
        - Excludes flows where src == dst
        - Only includes subnets owned by valid network devices
        - Automatically deduplicates entries

        **USE CASES:**
        - OT/IT segmentation analysis
        - Compliance verification
        - Network isolation validation
        - Cross-zone communication mapping
        - Security policy validation

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - reachable_pairs: List of reachability objects
              [{"src": "10.10.1.0/24", "dst": "10.20.5.0/24", "via": "CORE1", "reason": "reachable"}, ...]
            - summary: Human-readable summary (e.g., "X cross-subnet reachability pairs detected")
        """
        try:
            logger.info(
                f"Generating reachability summary for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_reachability_summary")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = network_reachability_summary_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_reachability_summary: {error_msg}")
            return {"ok": False, "error": error_msg, "reachable_pairs": []}

    @tool(mcp, toolset="network", name="network_summary")
    def network_summary(network: str, snapshot: str, ctx: Context = None) -> dict:
        """
        Generate a comprehensive network summary with device counts, vendor breakdown, and key statistics.

        **WHAT IT DOES:**
        Provides a high-level overview of the network including:
        - Total device count
        - Network devices vs sensors/hosts
        - Vendor breakdown (Cisco, Juniper, Arista, etc.)
        - Device type distribution
        - Interface statistics (total and L3)
        - Unique subnet count
        - Top platforms by count

        **OUTPUT:**
        Returns a structured summary with:
        - summary: Key statistics (total devices, network devices, sensors, interfaces, subnets)
        - vendors: Vendor counts sorted by frequency
        - device_breakdown: Lists of network infrastructure vs sensors/hosts
        - top_platforms: Most common platform types
        - summary_text: Human-readable overview

        **USE CASES:**
        - Quick network overview
        - Asset inventory
        - Vendor diversity analysis
        - Network documentation
        - Planning and capacity assessment

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - summary: Statistics object with counts
            - vendors: Vendor breakdown
            - device_breakdown: Device categorization
            - top_platforms: Platform distribution
            - summary_text: Human-readable summary
        """
        try:
            logger.info(
                f"Generating network summary for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_summary")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = network_summary_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_summary: {error_msg}")
            return {"ok": False, "error": error_msg}

    @tool(mcp, toolset="network", name="network_segment")
    def network_segment(
        network: str, snapshot: str, sample_size: int = 10, ctx: Context = None
    ) -> dict:
        """
        Analyze network segmentation by VLAN/VRF and show devices within each segment.

        **WHAT IT DOES:**
        For each network segment (VLAN/VRF), provides:
        - Which subnets belong to this VLAN
        - Total device count in the segment
        - Device type breakdown (normalized names with counts)
        - Sample devices for each type
        - Smart device name normalization (removes MACs, serial numbers, etc.)

        **STRUCTURE:**
        VLAN → Subnets → Devices
        - Vlan400 → [10.42.88.0/24] → 45 devices (25 honeywell, 10 siemens, 5 hp)
        - Vlan1 → [10.42.92.0/24] → 26 devices (20 cisco-switch, 6 sensor)

        **DEVICE NAME NORMALIZATION:**
        Automatically normalizes device names to group similar devices:
        - honeywell-device-0040842014ba → honeywell-device
        - honeywell-device-0040842062c0 → honeywell-device
        - hp-inc-device-7c4d8f986228 → hp-inc-device

        Shows counts like: "honeywell-device: 45 instances"

        **OUTPUT STRUCTURE:**
        Returns VLANs sorted by device count (largest first), each containing:
        - segment: Segment name (e.g., "Vlan400", "Vlan1")
        - subnets: List of subnets in this VLAN (e.g., ["10.42.88.0/24", "10.42.89.0/24"])
        - total_devices: Total device count in this VLAN
        - device_types: List of device type summaries (top N based on sample_size)
          - type: Normalized device name
          - count: Number of instances
          - examples: Sample device names (up to 5)
        - showing_top: Number of device types shown
        - total_types: Total number of device types in VLAN

        **USE CASES:**
        - OT/IT segmentation visibility
        - Understanding which devices are in which VLAN
        - Asset inventory by VLAN
        - Security zone analysis
        - Network documentation

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            sample_size: Number of device types to show per segment (default: 10)

        Returns:
            Dictionary containing:
            - ok: Success status
            - segments: List of VLAN analysis objects
            - summary: Human-readable summary
        """
        try:
            logger.info(
                f"Analyzing network segments for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_segment")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "sample_size": sample_size,
                "host": batfish_host,
            }

            result = network_segment_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_segment: {error_msg}")
            return {"ok": False, "error": error_msg, "segments": []}

    @tool(mcp, toolset="network", name="network_vlan_discovery")
    def network_vlan_discovery(
        network: str, snapshot: str, vlans: list[int] | None = None, ctx: Context = None
    ) -> dict:
        """
        Discover VLANs in the network and show which devices/ports have them configured.

        **TWO MODES:**

        1. **Discovery Mode** (no VLANs specified):
           - Returns a list of ALL active VLANs in the network
           - Shows basic statistics for each VLAN
           - Use this to explore what VLANs exist

        2. **Detail Mode** (VLANs specified):
           - Returns detailed port-level information for specific VLANs
           - Shows exactly which devices have those VLANs
           - Shows which ports on each device have the VLAN (access or trunk)
           - Use this to find where a specific VLAN is configured

        **DISCOVERY MODE OUTPUT:**
        For each VLAN, shows:
        - vlan_id: VLAN number (e.g., 400)
        - name: VLAN name (e.g., "Vlan400")
        - device_count: Number of devices with this VLAN
        - port_count: Total number of ports in this VLAN
        - subnets: List of subnets associated with this VLAN
        - devices: List of device names with this VLAN

        Example:
        ```json
        {
          "vlan_id": 400,
          "name": "Vlan400",
          "device_count": 15,
          "port_count": 120,
          "subnets": ["10.42.88.0/24"],
          "devices": ["switch1", "switch2", ...]
        }
        ```

        **DETAIL MODE OUTPUT:**
        For each requested VLAN, shows:
        - vlan_id: VLAN number
        - name: VLAN name
        - subnets: Subnets in this VLAN
        - devices: List of devices with detailed port information
          - device: Device name
          - ports: List of ports with this VLAN
            - interface: Port name (e.g., "GigabitEthernet0/1")
            - type: "access", "trunk", or "SVI"
            - mode: Switchport mode
            - active: Whether port is active
        - total_ports: Total port count

        Example:
        ```json
        {
          "vlan_id": 400,
          "name": "Vlan400",
          "subnets": ["10.42.88.0/24"],
          "devices": [
            {
              "device": "switch1",
              "ports": [
                {"interface": "GigabitEthernet0/1", "type": "access", "mode": "access", "active": true},
                {"interface": "GigabitEthernet0/24", "type": "trunk", "mode": "trunk", "active": true}
              ]
            }
          ],
          "total_ports": 45
        }
        ```

        **USE CASES:**
        - Find all VLANs in the network
        - Locate which devices have a specific VLAN
        - Identify which ports are in a VLAN (access vs trunk)
        - Map VLANs to subnets
        - Troubleshoot VLAN connectivity
        - Audit VLAN configurations

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            vlans: Optional list of VLAN IDs to query (e.g., [1, 400, 120]). If None, returns all VLANs.

        Returns:
            Dictionary containing:
            - ok: Success status
            - mode: "discovery" or "detail"
            - vlans: List of VLAN information objects
            - summary: Human-readable summary
        """
        try:
            logger.info(
                f"VLAN discovery for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_vlan_discovery")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            if vlans is not None:
                input_data["vlans"] = vlans

            result = network_vlan_discovery_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_vlan_discovery: {error_msg}")
            return {"ok": False, "error": error_msg, "vlans": []}

    @tool(
        mcp,
        toolset="compliance",
        name="compliance_get_enforcement_points",
        description="Compliance: Get Enforcement Points - Identify devices/interfaces that perform inter-segment security control",
    )
    def compliance_get_enforcement_points(
        network: str, snapshot: str, ctx: Context = None
    ) -> dict:
        """
        Identify all enforcement points in a network - devices/interfaces that perform inter-segment security control.

        **WHAT IS AN ENFORCEMENT POINT:**
        Any device with multiple L3 interfaces (routing between segments). These are the choke points
        where security controls (ACLs) MUST be applied to enforce segmentation.

        **WHAT THIS TOOL DOES:**
        1. Finds all devices with 2+ L3 interfaces (SVIs or routed ports)
        2. For each interface, checks if ACLs are applied (inbound/outbound)
        3. Retrieves ACL rule counts (permit/deny)
        4. Identifies gaps: enforcement points with NO ACLs (unprotected segments)

        **OUTPUT STRUCTURE:**
        Returns enforcement points with detailed interface information:
        ```json
        {
          "enforcement_points": [
            {
              "device": "CORE-SW1",
              "has_any_enforcement": true,
              "interfaces": [
                {
                  "interface": "Vlan400",
                  "subnets": ["10.42.88.0/26"],
                  "has_enforcement": true,
                  "acls": [
                    {
                      "name": "OT-TO-IT-FILTER",
                      "direction": "inbound",
                      "total_rules": 45,
                      "permit_rules": 10,
                      "deny_rules": 35
                    }
                  ]
                },
                {
                  "interface": "Vlan1",
                  "subnets": ["10.42.92.0/24"],
                  "has_enforcement": false,
                  "acls": []
                }
              ]
            }
          ],
          "summary": {
            "total_enforcement_points": 1,
            "devices_with_zero_acls": 0,
            "interfaces_with_filtering": 1,
            "interfaces_without_filtering": 1,
            "warning": "1 enforcement point(s) have NO ACLs applied..."
          },
          "network_is_flat": false
        }
        ```

        **KEY FIELDS:**
        - `has_enforcement`: Boolean per interface - true if ANY ACL is applied
        - `has_any_enforcement`: Boolean per device - true if ANY interface has ACLs
        - `network_is_flat`: True if NO ACLs exist anywhere (major security gap!)
        - `devices_with_zero_acls`: Count of enforcement points with ZERO protection

        **SECURITY GAP DETECTION:**
        The tool explicitly identifies:
        - Devices routing between segments with NO ACLs
        - Interfaces without filtering (segmentation bypass risk)
        - Whether the entire network is flat (no security controls)

        **USE CASES:**
        - Security audit: Find where ACLs should be but aren't
        - Compliance: Verify segmentation enforcement
        - Risk assessment: Identify unprotected inter-segment paths
        - Remediation planning: Prioritize ACL deployment
        - OT/IT segmentation validation

        **DOES NOT:**
        - Perform Purdue classification
        - Analyze ACL rule content (only counts rules)
        - Test reachability
        - Recommend specific ACL rules

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - enforcement_points: List of enforcement point details
            - summary: Statistics and gap analysis
            - network_is_flat: True if no ACLs exist anywhere
        """
        try:
            logger.info(
                f"Getting enforcement points for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_get_enforcement_points")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = get_enforcement_points_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in compliance_get_enforcement_points: {error_msg}")
            return {"ok": False, "error": error_msg, "enforcement_points": []}

    @tool(mcp, toolset="network", name="network_get_allowed_services")
    def network_get_allowed_services(
        network: str, snapshot: str, ctx: Context = None
    ) -> dict:
        """
        Discover what protocols/services are allowed between network segments based on ACL rules.

        **CRITICAL FOR POLICY VALIDATION** - Shows what traffic is actually permitted between zones.

        **WHAT IT DOES:**
        Analyzes ACL rules to determine which protocols/ports can flow between VLANs/segments.
        For each enforcement point with ACLs, shows:
        - Which services are permitted (Modbus, HTTP, SSH, etc.)
        - Which services are explicitly denied
        - Source → Destination flow patterns
        - ACL rule counts

        **OUTPUT STRUCTURE:**
        ```json
        {
          "zone_communications": [
            {
              "enforcement_point": "CORE1[Vlan400]",
              "vlan": "Vlan400",
              "direction": "inbound",
              "acl_name": "OT-FILTER",
              "services_permitted": [
                {
                  "service": "Modbus-TCP",
                  "flows": [{"src": "10.42.88.0/24", "dst": "10.42.92.0/24"}]
                },
                {
                  "service": "HTTPS",
                  "flows": [{"src": "10.42.92.0/24", "dst": "any"}]
                }
              ],
              "services_blocked": [
                {
                  "service": "SSH",
                  "flows": [{"src": "any", "dst": "10.42.88.0/24"}]
                }
              ],
              "total_permit_rules": 15,
              "total_deny_rules": 30
            }
          ],
          "summary": {
            "total_acls": 3,
            "enforcement_points": 5,
            "unique_services_allowed": 8,
            "unique_services_denied": 12,
            "services_allowed_list": ["Modbus-TCP", "HTTPS", "NTP", ...],
            "services_denied_list": ["SSH", "Telnet", "RDP", ...]
          }
        }
        ```

        **COMMON SERVICES DETECTED:**
        - Industrial: Modbus-TCP (502), DNP3 (20000), IEC-104 (2404)
        - Management: SSH (22), HTTPS (443), SNMP (161)
        - Time: NTP (123)
        - Remote Access: RDP (3389), Telnet (23)

        **USE CASES:**
        - Validate segmentation policy: "Is OT zone only allowing industrial protocols?"
        - Compliance: "Are management protocols blocked from OT?"
        - Security audit: "What services are actually permitted?"
        - Policy comparison: "Does this match Purdue model requirements?"

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - zone_communications: List of inter-zone service permissions
            - acl_details: Detailed ACL breakdown
            - summary: Statistics about allowed/denied services
        """
        try:
            logger.info(
                f"Getting allowed services for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_get_allowed_services")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = network_get_allowed_services_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_get_allowed_services: {error_msg}")
            return {"ok": False, "error": error_msg, "zone_communications": []}

    @tool(mcp, toolset="network", name="network_classify_devices")
    def network_classify_devices(
        network: str, snapshot: str, ctx: Context = None
    ) -> dict:
        """
        Classify network devices by type (PLC, SCADA, workstation, switch, etc.) for policy validation.

        **CRITICAL FOR POLICY ENFORCEMENT** - Determines what each device IS for zone placement validation.

        **WHAT IT DOES:**
        Uses multiple signals to classify each device:
        - Vendor (Siemens, Allen-Bradley, etc.)
        - Naming patterns (plc-, scada-, etc.)
        - Configuration format
        - VLAN membership

        Returns classification with confidence level (high/medium/low) and evidence.

        **DEVICE TYPES DETECTED:**
        - **Industrial**: PLC, SCADA, RTU, IED
        - **Infrastructure**: Switch, Router, Firewall
        - **IT**: Workstation, Server
        - **Security**: Sensor (Nozomi, Claroty, etc.)

        **OUTPUT STRUCTURE:**
        ```json
        {
          "device_classifications": [
            {
              "device": "honeywell-device-0040842014ba",
              "classification": "plc",
              "confidence": "high",
              "score": 10,
              "evidence": ["vendor:honeywell", "naming:device", "vlan:ot"],
              "vendor": "honeywell",
              "vlans": ["Vlan400"]
            },
            {
              "device": "nakanmaincs1",
              "classification": "switch",
              "confidence": "high",
              "score": 8,
              "evidence": ["vendor:cisco", "config_format:cisco_ios", "naming:cs"],
              "vlans": ["Vlan1", "Vlan400"]
            }
          ],
          "device_type_summary": {
            "plc": 45,
            "switch": 26,
            "workstation": 120,
            "unknown": 15
          },
          "summary": {
            "total_devices": 206,
            "classified": 191,
            "unclassified": 15,
            "high_confidence": 150,
            "medium_confidence": 41,
            "low_confidence": 15
          }
        }
        ```

        **CONFIDENCE LEVELS:**
        - **High**: Multiple strong signals (vendor + naming + VLAN)
        - **Medium**: Some signals match (naming or vendor)
        - **Low**: Weak or no matches

        **USE CASES:**
        - Policy validation: "Are all PLCs in Level 0?"
        - Device inventory: "What types of devices exist?"
        - Compliance: "Are workstations separated from OT?"
        - Risk assessment: "Where are critical assets?"
        - Zone mapping: "Assign devices to proper zones"

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name

        Returns:
            Dictionary containing:
            - ok: Success status
            - device_classifications: List of classified devices
            - device_type_summary: Count by type
            - summary: Statistics
        """
        try:
            logger.info(
                f"Classifying devices for network '{network}', snapshot '{snapshot}'"
            )

            # Extract headers from context

            log_user_access(None, "network_classify_devices")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            result = network_classify_devices_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_classify_devices: {error_msg}")
            return {"ok": False, "error": error_msg, "device_classifications": []}

    @tool(mcp, toolset="network", name="network_analyze_acl_rules")
    def network_analyze_acl_rules(
        network: str, snapshot: str, acl_name: str | None = None, ctx: Context = None
    ) -> dict:
        """
        Analyze ACL rule content in detail - shows WHAT is actually permitted/denied in each ACL.

        **CRITICAL FOR SECURITY ANALYSIS** - Reveals exact permit/deny decisions, not just "ACL exists".

        **WHAT IT DOES:**
        For each ACL (or a specific ACL), provides line-by-line analysis:
        - Every rule with action (permit/deny)
        - Source and destination IP ranges
        - Protocol and port information
        - Rule categorization (default deny, specific service, etc.)
        - Security findings (default permits, missing denies, etc.)

        **OUTPUT STRUCTURE:**
        ```json
        {
          "acls": [
            {
              "name": "OT-FILTER",
              "applied_on": [
                {"device": "CORE1", "interface": "Vlan400", "direction": "inbound"}
              ],
              "rules": [
                {
                  "line": 10,
                  "action": "permit",
                  "src": "10.42.88.0/24",
                  "dst": "10.42.92.0/24",
                  "protocol": "tcp",
                  "dst_ports": "502",
                  "category": "permit_specific_service"
                },
                {
                  "line": 100,
                  "action": "deny",
                  "src": "any",
                  "dst": "any",
                  "protocol": "ip",
                  "category": "default_deny"
                }
              ],
              "statistics": {
                "total_rules": 45,
                "permit_rules": 10,
                "deny_rules": 35,
                "default_deny": true,
                "default_permit": false
              },
              "rule_categories": {
                "permit_specific_service": 8,
                "deny_specific_service": 20,
                "default_deny": 1
              }
            }
          ],
          "security_findings": [
            {
              "severity": "high",
              "acl": "UNSAFE-ACL",
              "finding": "Default permit rule detected - allows all traffic by default"
            },
            {
              "severity": "medium",
              "acl": "OT-FILTER",
              "finding": "No explicit default deny - may allow unintended traffic"
            }
          ],
          "summary": {
            "total_acls": 3,
            "total_rules": 156,
            "permit_rules": 45,
            "deny_rules": 111,
            "security_findings": 2
          }
        }
        ```

        **RULE CATEGORIES:**
        - `default_deny`: Catch-all deny at end (best practice)
        - `default_permit`: Catch-all permit (security risk!)
        - `permit_specific_service`: Allow specific protocol/port
        - `deny_specific_service`: Block specific protocol/port
        - `permit_specific_subnet`: Allow traffic from/to specific subnet
        - `deny_specific_subnet`: Block traffic from/to specific subnet

        **SECURITY FINDINGS:**
        - Missing default deny rules
        - Dangerous default permit rules
        - ACLs with only deny rules (blocking-only)

        **USE CASES:**
        - Policy validation: "Does ACL match expected rules?"
        - Security audit: "What's actually allowed?"
        - Troubleshooting: "Why is this traffic blocked/permitted?"
        - Compliance: "Are required denies in place?"
        - Rule optimization: "Are there redundant rules?"

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            acl_name: Optional - analyze specific ACL only (default: all ACLs)

        Returns:
            Dictionary containing:
            - ok: Success status
            - acls: List of ACL analysis objects
            - security_findings: List of security issues found
            - summary: Statistics
        """
        try:
            logger.info(
                f"Analyzing ACL rules for network '{network}', snapshot '{snapshot}'"
            )
            if acl_name:
                logger.info(f"Filtering to ACL: {acl_name}")

            # Extract headers from context

            log_user_access(None, "network_analyze_acl_rules")
            batfish_host = get_batfish_host()

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
            }

            if acl_name:
                input_data["acl_name"] = acl_name

            result = network_analyze_acl_rules_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_analyze_acl_rules: {error_msg}")
            return {"ok": False, "error": error_msg, "acls": []}

    @tool(
        mcp,
        toolset="compliance",
        name="compliance_list_models",
        description=(
            "Compliance: List Models - List available security/compliance models (Purdue, ISA-95, NIST CSF, etc.) for network analysis. "
            "Can show all models or detailed view of a specific model including zones, allowed/prohibited communications, and enforcement requirements."
        ),
    )
    async def compliance_list_models(
        model_name: str | None = None, show_details: bool = False
    ) -> dict:
        """
        List available security/compliance models or show details of a specific model.

        Args:
            model_name: Optional - specific model to view (e.g., 'purdue', 'isa95', 'nist_csf'). If None, lists all models.
            show_details: Show full model details including all zones, rules, and requirements. Default: False

        Returns:
            If listing all: List of available models with descriptions
            If viewing specific: Detailed model information
        """
        try:
            logger.info(f"Listing security models...")

            input_data = {"model_name": model_name, "show_details": show_details}

            result = list_models_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in compliance_list_models: {error_msg}")
            return {"ok": False, "error": error_msg, "models": []}

    @tool(
        mcp,
        toolset="compliance",
        name="compliance_auto_classify_zones",
        description=(
            "Compliance: Auto Classify Zones - Automatically classify network devices into security model zones (e.g., Purdue levels). "
            "This tool orchestrates device classification and network segmentation internally to build a zone mapping automatically. "
            "Saves ~95% of AI processing by doing the heavy lifting: parsing thousands of device classifications, "
            "mapping devices to appropriate zones, and generating a ready-to-use zone_mapping for compliance checking. "
            "Output can be directly fed into compliance_check_zone_compliance tool."
        ),
    )
    async def compliance_auto_classify_zones(
        network: str,
        snapshot: str,
        model_name: str,
        rule_set: str = "default",
        host: str = "localhost",
    ) -> dict:
        """
        Automatically classify network into security model zones with minimal AI intervention.

        This tool does ALL the work that would normally require the AI agent to:
        1. Run network_classify_devices and parse 6,000+ lines
        2. Run network_segment and parse 1,000+ lines
        3. Manually map each device/subnet/VLAN to zones
        4. Build the zone_mapping JSON structure

        Instead, this tool:
        - Runs classification internally
        - Runs segmentation internally
        - Auto-maps devices based on classification + model rules
        - Calculates confidence scores
        - Returns ready-to-use zone_mapping

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            model_name: Security model ('purdue', 'isa95', 'nist_csf')
            rule_set: Classification rule set to use (default: 'default')
            host: Batfish host (default: localhost)

        Returns:
            Auto-classified zone mapping with:
            - auto_classified_zones: Ready-to-use zone mapping
            - confidence_summary: Confidence assessment per zone
            - device_distribution: Device counts per zone
            - ready_for_compliance_check: Boolean
            - warnings: Any issues detected

        Example workflow:
            1. Run this tool → get auto_classified_zones
            2. Review confidence scores
            3. Pass auto_classified_zones to network_check_zone_compliance
        """
        try:
            logger.info(
                f"Auto-classifying zones for network '{network}', snapshot '{snapshot}', model '{model_name}'"
            )

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "model_name": model_name,
                "rule_set": rule_set,
                "host": host,
            }

            result = auto_classify_zones_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in compliance_auto_classify_zones: {error_msg}")
            return {"ok": False, "error": error_msg}

    @tool(
        mcp,
        toolset="compliance",
        name="compliance_check_zone_compliance",
        description=(
            "Compliance: Check Zone Compliance - Check network compliance against a security/compliance model (Purdue, ISA-95, NIST CSF). "
            "Requires zone_mapping which can be auto-generated using compliance_auto_classify_zones tool or manually created. "
            "Identifies violations (unauthorized communications), gaps (missing enforcement points), and compliance status."
        ),
    )
    async def compliance_check_zone_compliance(
        network: str,
        snapshot: str,
        model_name: str,
        zone_mapping: dict,
        host: str = "localhost",
    ) -> dict:
        """
        Analyze network compliance against a security model.

        Recommended Workflow:
        1. Run network_auto_classify_zones to get zone_mapping automatically
        2. Review the auto-classification results
        3. Pass zone_mapping to this tool for compliance checking

        Manual Workflow (if needed):
        1. AI agent calls network_segment_tool to see device distribution
        2. AI agent classifies zones manually
        3. AI agent calls this tool with zone_mapping

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            model_name: Security model to check against (e.g., 'purdue', 'isa95', 'nist_csf')
            zone_mapping: Dict mapping zone names to ZoneDefinition objects with subnets/vlans/devices
                Can be auto-generated by network_auto_classify_zones or manually created.
                Example: {
                    "Level_0": {"subnets": ["10.42.88.0/24"], "vlans": [400], "devices": []},
                    "Level_1": {"subnets": ["10.42.90.0/24"], "vlans": [120], "devices": []}
                }
            host: Batfish host (default: localhost)

        Returns:
            Compliance report with violations, gaps, and recommendations
        """
        try:
            logger.info(
                f"Checking zone compliance for network '{network}', snapshot '{snapshot}' against model '{model_name}'"
            )

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "model_name": model_name,
                "zone_mapping": zone_mapping,
                "host": host,
            }

            result = check_zone_compliance_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in compliance_check_zone_compliance: {error_msg}")
            return {"ok": False, "error": error_msg}

    @tool(
        mcp,
        toolset="network",
        name="network_traceroute",
        description=(
            "Network: Traceroute - Trace packet path from source to destination through network devices. "
            "Shows hop-by-hop routing decisions, ACL evaluations, NAT transformations, and final disposition. "
            "Use this to understand exactly how traffic flows through routers, switches, and firewalls."
        ),
    )
    async def network_traceroute(
        network: str,
        snapshot: str,
        source_location: str,
        dest_ip: str,
        dest_port: int = None,
        ip_protocol: str = "tcp",
        src_ip: str = None,
        host: str = "localhost",
    ) -> dict:
        """
        Trace the path from source to destination through network infrastructure.

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            source_location: Source location (node name, interface, or IP)
            dest_ip: Destination IP address
            dest_port: Optional destination port (e.g., 443, 22, 80)
            ip_protocol: IP protocol (tcp, udp, icmp - default: tcp)
            src_ip: Optional source IP (useful for multi-homed devices)
            host: Batfish host (default: localhost)

        Returns:
            Trace results with hops, routing decisions, ACL evaluations, and disposition
        """
        try:
            logger.info(f"Tracing route from {source_location} to {dest_ip}")

            # Extract headers from context

            log_user_access(None, "network_traceroute")

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "source_location": source_location,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "ip_protocol": ip_protocol,
                "src_ip": src_ip,
                "host": host,
            }

            result = network_traceroute_tool.execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_traceroute: {error_msg}")
            return {"ok": False, "error": error_msg}

    @tool(
        mcp,
        toolset="network",
        name="network_bidirectional_reachability",
        description=(
            "Network: Bidirectional Reachability - Test traffic flow in both directions between two locations. "
            "Critical for TCP connections and detecting asymmetric routing. Tests A→B and B→A, identifies blocking ACLs, "
            "and warns about one-way communication issues."
        ),
    )
    async def network_bidirectional_reachability(
        network: str,
        snapshot: str,
        location_a: str,
        location_b: str,
        ip_a: str,
        ip_b: str,
        port: int = None,
        protocol: str = "tcp",
        host: str = "localhost",
    ) -> dict:
        """
        Test bidirectional reachability between two network locations.

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            location_a: Location A (node name, interface, or IP)
            location_b: Location B (node name, interface, or IP)
            ip_a: IP address at location A
            ip_b: IP address at location B
            port: Optional port to test
            protocol: IP protocol (tcp, udp, icmp - default: tcp)
            host: Batfish host (default: localhost)

        Returns:
            Bidirectional test results with forward/reverse reachability status,
            path information, and warnings about asymmetric routing or one-way blocks
        """
        try:
            logger.info(
                f"Testing bidirectional reachability: {location_a} ↔ {location_b}"
            )

            # Extract headers from context

            log_user_access(None, "network_bidirectional_reachability")

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "location_a": location_a,
                "location_b": location_b,
                "ip_a": ip_a,
                "ip_b": ip_b,
                "port": port,
                "protocol": protocol,
                "host": host,
            }

            result = network_bidirectional_reachability_tool.execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_bidirectional_reachability: {error_msg}")
            return {"ok": False, "error": error_msg}

    @tool(
        mcp,
        toolset="network",
        name="network_vlan_device_count",
        description=(
            "Network: VLAN Device Count - Calculate and display device counts per VLAN for each network device. "
            "Shows how many devices are connected to each VLAN on each switch/router. "
            "Supports 'detailed' format (default) or 'matrix' format for compact tabular view. "
            "Useful for understanding network density and VLAN utilization."
        ),
    )
    def network_vlan_device_count(
        network: str,
        snapshot: str,
        format: str = "detailed",
        host: str = "localhost",
        ctx: Context = None,
    ) -> dict:
        """
        Analyze device counts per VLAN for each network device.

        Shows a breakdown of how many devices are connected to each VLAN,
        organized by network device (switch/router).

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            format: Output format - 'detailed' (default) or 'matrix' (compact table view)
            host: Batfish host (default: localhost)

        Returns:
            Dictionary with per-device VLAN breakdown and summary statistics
        """
        try:
            # Extract headers from context

            log_user_access(None, "network_vlan_device_count")

            batfish_host = os.getenv("BATFISH_HOST", host)
            logger.info(
                f"Analyzing VLAN device counts for network={network}, snapshot={snapshot}, format={format}"
            )

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
                "format": format,
            }

            result = network_vlan_device_count_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_vlan_device_count: {error_msg}")
            return {"ok": False, "error": error_msg, "devices": []}

    @tool(
        mcp,
        toolset="network",
        name="network_device_connections",
        description=(
            "Network: Device Connections - Show all interfaces, VLANs, and connected devices for a specific network device. "
            "Displays detailed interface-level information including VLAN assignments, connected neighbors, and IP addresses. "
            "Essential for understanding device topology and troubleshooting connectivity."
        ),
    )
    def network_device_connections(
        network: str,
        snapshot: str,
        device: str,
        host: str = "localhost",
        ctx: Context = None,
    ) -> dict:
        """
        Show all interfaces, VLANs, and connected devices for a specific device.

        Provides a complete view of a device's interfaces including:
        - Interface name and status
        - VLAN assignment
        - Connected device and interface (if any)
        - IP address
        - Switchport mode

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            device: Device name to analyze
            host: Batfish host (default: localhost)

        Returns:
            Dictionary with interface details and connection information
        """
        try:
            # Extract headers from context

            log_user_access(None, "network_device_connections")

            batfish_host = os.getenv("BATFISH_HOST", host)
            logger.info(
                f"Analyzing connections for device={device}, network={network}, snapshot={snapshot}"
            )

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "device": device,
                "host": batfish_host,
            }

            result = network_device_connections_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_device_connections: {error_msg}")
            return {"ok": False, "error": error_msg, "interfaces": []}

    @tool(
        mcp,
        toolset="network",
        name="network_interface_vlan_count",
        description=(
            "Network: Interface VLAN Count - Count ALL interfaces/ports per VLAN on each device (connected or not). "
            "Shows total port allocation and capacity per VLAN. "
            "Different from network_vlan_device_count which only counts connected ports. "
            "Supports 'detailed' format (default) or 'matrix' format for compact tabular view. "
            "Useful for VLAN capacity planning and port allocation analysis."
        ),
    )
    def network_interface_vlan_count(
        network: str,
        snapshot: str,
        format: str = "detailed",
        host: str = "localhost",
        ctx: Context = None,
    ) -> dict:
        """
        Analyze total interface/port counts per VLAN for each network device.
        Counts ALL ports with VLAN assignments (connected, empty, shutdown, etc).

        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            format: Output format - 'detailed' (default) or 'matrix' (compact table view)
            host: Batfish host (default: localhost)

        Returns:
            Dictionary with per-device VLAN breakdown showing total port allocation
        """
        try:
            # Extract headers from context

            log_user_access(None, "network_interface_vlan_count")

            batfish_host = os.getenv("BATFISH_HOST", host)
            logger.info(
                f"Analyzing interface VLAN counts for network={network}, snapshot={snapshot}, format={format}"
            )

            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host,
                "format": format,
            }

            result = network_interface_vlan_count_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_interface_vlan_count: {error_msg}")
            return {"ok": False, "error": error_msg, "devices": []}

    @tool(
        mcp,
        toolset="network",
        name="network_node_inventory",
        description=(
            "Network: Node Inventory - List all network devices with configuration format, vendor, and inferred role. "
            "Returns raw device data without CML-specific mappings. "
            "Use this to understand device types before mapping to lab environments. "
            "Provides: node name, config format (CISCO_IOS, JUNIPER, etc.), vendor, and inferred role (router/switch/firewall)."
        ),
    )
    def network_node_inventory(
        network: str,
        snapshot: str,
        host: str = "localhost",
        ctx: Context = None,
    ) -> dict:
        """
        Return inventory of all network nodes with configuration details.
        
        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            host: Batfish host (default: localhost)
            
        Returns:
            Dictionary with nodes list and count
        """
        try:
            log_user_access(None, "network_node_inventory")
            
            batfish_host = get_batfish_host()
            logger.info(f"Retrieving node inventory for network={network}, snapshot={snapshot}")
            
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "host": batfish_host
            }
            
            result = network_node_inventory_execute(input_data)
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_node_inventory: {error_msg}")
            return {"ok": False, "error": error_msg, "nodes": [], "total_nodes": 0}

    @tool(
        mcp,
        toolset="network",
        name="network_topology_connections",
        description=(
            "Network: Topology Connections - Get Layer 3 network connections as a connection mapping table. "
            "Returns node-to-node connections with interface names and IP addresses. "
            "Raw data output without CML formatting - agent can use this to create topology links. "
            "Provides: node_a, interface_a, node_b, interface_b, and optional IP addresses."
        ),
    )
    def network_topology_connections(
        network: str,
        snapshot: str,
        include_layer1: bool = True,
        host: str = "localhost",
        ctx: Context = None,
    ) -> dict:
        """
        Return network topology as a list of node-to-node connections.
        
        Args:
            network: Batfish network name
            snapshot: Batfish snapshot name
            include_layer1: Include Layer 1 connections if available (default: True)
            host: Batfish host (default: localhost)
            
        Returns:
            Dictionary with connections list, total count, and connection type
        """
        try:
            log_user_access(None, "network_topology_connections")
            
            batfish_host = get_batfish_host()
            logger.info(f"Retrieving topology connections for network={network}, snapshot={snapshot}")
            
            input_data = {
                "network": network,
                "snapshot": snapshot,
                "include_layer1": include_layer1,
                "host": batfish_host
            }
            
            result = network_topology_connections_execute(input_data)
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in network_topology_connections: {error_msg}")
            return {"ok": False, "error": error_msg, "connections": [], "total_connections": 0}

    @tool(
        mcp,
        toolset="compliance",
        name="compliance_list_classification_rules",
        description=(
            "Compliance: List Classification Rules - List and view device classification rule sets used by network_classify_devices tool. "
            "Rule sets define how devices are classified (PLC, SCADA, workstation, etc.) based on vendors, naming patterns, and VLAN indicators. "
            "Can list all available rule sets or show detailed rules for a specific rule set."
        ),
    )
    async def compliance_list_classification_rules(
        rule_set: str | None = None, show_details: bool = False
    ) -> dict:
        """
        List or view device classification rule sets.

        Modes:
        1. List all rule sets: rule_set=None, show_details=False
        2. View rule set summary: rule_set="name", show_details=False
        3. View full rule details: rule_set="name", show_details=True

        Args:
            rule_set: Optional - specific rule set name to view (e.g., 'default', 'custom_my_site'). If None, lists all rule sets.
            show_details: If True, shows full rule definitions including all patterns and vendors. Default: False

        Returns:
            If listing all: List of available rule sets with metadata
            If viewing specific: Rule set data (summary or full details)
        """
        try:
            logger.info(f"Listing classification rules...")

            input_data = {"rule_set": rule_set, "show_details": show_details}

            result = list_classification_rules_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in compliance_list_classification_rules: {error_msg}")
            return {"ok": False, "error": error_msg, "rule_sets": []}

    @tool(
        mcp,
        toolset="compliance",
        name="compliance_update_classification_rules",
        description=(
            "Compliance: Update Classification Rules - Update device classification rules using category-based approach with smart input normalization. "
            "Modify vendors, name patterns (regex), VLAN indicators, OUI vendors, config formats, or subnet patterns. "
            "Automatically creates backups before making changes. Accepts flexible input formats for subnets (CIDR, wildcard) and VLANs."
        ),
    )
    async def compliance_update_classification_rules(
        rule_set: str,
        device_type: str,
        category: str,
        operation: str,
        value: str,
        create_backup: bool = True,
    ) -> dict:
        """
        Update device classification rules safely with category-based operations and smart normalization.

        Categories:
        - vendors: Vendor keywords (e.g., 'siemens', 'rockwell')
        - oui_vendors: MAC OUI vendors (e.g., 'honeywell')
        - name_patterns: Regex patterns (e.g., 'plc', 's7-.*')
        - config_formats: Config format identifiers (e.g., 'cisco_ios')
        - vlan_indicators: VLAN indicators - accepts '400', 'vlan400', or 'voice'
        - subnet_patterns: Subnet patterns - accepts '10.42.100.0/24', '10.42.100.*', etc.

        Operations:
        - add: Add value to category
        - remove: Remove value from category

        Smart Normalization:
        - Subnets: '10.42.100.0/24' -> '10\\.42\\.100\\..*' (regex)
        - VLANs: 'vlan400' -> '400', 'VLAN_400' -> '400'

        Args:
            rule_set: Rule set name (e.g., 'default', 'purdue_aligned')
            device_type: Device type (e.g., 'plc', 'firewall', 'router')
            category: Category to modify (see list above)
            operation: 'add' or 'remove'
            value: Value to add/remove (will be normalized)
            create_backup: Create timestamped backup (default: True)

        Returns:
            Result with confirmation, normalized value, and backup file path

        Examples:
            Move juniper from firewall to router:
            1. rule_set="default", device_type="firewall", category="vendors", operation="remove", value="juniper"
            2. rule_set="default", device_type="router", category="vendors", operation="add", value="juniper"

            Add subnet pattern (flexible format):
            rule_set="default", device_type="plc", category="subnet_patterns", operation="add", value="10.42.100.0/24"
        """
        try:
            logger.info(
                f"Updating classification rules: {rule_set}/{device_type}/{category} - {operation} '{value}'"
            )

            input_data = {
                "rule_set": rule_set,
                "device_type": device_type,
                "category": category,
                "operation": operation,
                "value": value,
                "create_backup": create_backup,
            }

            result = update_classification_rules_execute(input_data)
            return result

        except Exception as e:
            error_msg = str(e)
            logger.error(
                f"Error in compliance_update_classification_rules: {error_msg}"
            )
            return {"ok": False, "error": error_msg}

    return mcp


# Create module-level server instance for FastMCP CLI
mcp = create_server()


def main():
    """Main entry point for the server."""
    # Get configuration from environment
    transport = os.getenv("TRANSPORT", "streamable-http").lower()
    port = int(os.getenv("PORT", "3009"))
    host = os.getenv("HOST", "0.0.0.0")  # Use 0.0.0.0 to allow external connections

    logger.info(f"Starting Batfish MCP Server with transport: {transport}")
    logger.info(f"Using Batfish host: {os.getenv('BATFISH_HOST', 'localhost')}")
    logger.info(
        f"JWT Authentication: {'Disabled' if os.getenv('DISABLE_JWT_AUTH', '').lower() == 'true' else 'Enabled'}"
    )

    try:
        if transport == "stdio":
            # STDIO transport for local development
            mcp.run(transport="stdio")
        else:
            # HTTP Stream transport (default, recommended)
            mcp.run(transport="streamable-http", host=host, port=port)

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
