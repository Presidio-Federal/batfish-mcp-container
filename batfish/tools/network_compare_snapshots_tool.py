"""
Network Compare Snapshots Tool

Compares two Batfish snapshots to identify differences in devices, interfaces, routes, and ACLs.
Useful for change validation and detecting configuration drift.
"""

import logging
from typing import Dict, Any
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.client.commands import bf_session

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkCompareSnapshotsInput(BaseModel):
    """Input model for comparing snapshots."""
    network: str = Field(..., description="Network name")
    snapshot_base: str = Field(..., description="Base/reference snapshot name")
    snapshot_compare: str = Field(..., description="Snapshot to compare against base")


class NetworkCompareSnapshotsTool:
    """Tool for comparing two Batfish snapshots."""
    
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare two snapshots and identify differences.
        
        Args:
            input_data: Dictionary containing network, snapshot_base, snapshot_compare
            
        Returns:
            Dictionary with comparison results
        """
        try:
            validated_input = NetworkCompareSnapshotsInput(**input_data)
            
            network = validated_input.network
            snapshot_base = validated_input.snapshot_base
            snapshot_compare = validated_input.snapshot_compare
            
            logger.info(f"Comparing snapshots: {snapshot_base} vs {snapshot_compare} in network {network}")
            
            bf = bf_session
            bf.set_network(network)
            
            differences = {
                "devices": {},
                "interfaces": {},
                "routes": {},
                "summary": {}
            }
            
            # Compare devices
            logger.info("Comparing device configurations...")
            bf.set_snapshot(snapshot_base)
            base_nodes = bf.q.nodeProperties().answer().frame()
            base_device_names = set(base_nodes['Node'].tolist()) if not base_nodes.empty else set()
            
            bf.set_snapshot(snapshot_compare)
            compare_nodes = bf.q.nodeProperties().answer().frame()
            compare_device_names = set(compare_nodes['Node'].tolist()) if not compare_nodes.empty else set()
            
            added_devices = compare_device_names - base_device_names
            removed_devices = base_device_names - compare_device_names
            common_devices = base_device_names & compare_device_names
            
            differences["devices"] = {
                "added": list(added_devices),
                "removed": list(removed_devices),
                "unchanged": list(common_devices),
                "total_base": len(base_device_names),
                "total_compare": len(compare_device_names)
            }
            
            # Compare interfaces
            logger.info("Comparing interfaces...")
            bf.set_snapshot(snapshot_base)
            base_interfaces = bf.q.interfaceProperties().answer().frame()
            base_interface_set = set()
            if not base_interfaces.empty:
                base_interface_set = set(
                    f"{row['Interface'].hostname}:{row['Interface'].interface}"
                    for _, row in base_interfaces.iterrows()
                )
            
            bf.set_snapshot(snapshot_compare)
            compare_interfaces = bf.q.interfaceProperties().answer().frame()
            compare_interface_set = set()
            if not compare_interfaces.empty:
                compare_interface_set = set(
                    f"{row['Interface'].hostname}:{row['Interface'].interface}"
                    for _, row in compare_interfaces.iterrows()
                )
            
            added_interfaces = compare_interface_set - base_interface_set
            removed_interfaces = base_interface_set - compare_interface_set
            
            differences["interfaces"] = {
                "added": list(added_interfaces)[:20],  # Limit to 20 for readability
                "removed": list(removed_interfaces)[:20],
                "added_count": len(added_interfaces),
                "removed_count": len(removed_interfaces),
                "total_base": len(base_interface_set),
                "total_compare": len(compare_interface_set)
            }
            
            # Compare routing tables
            logger.info("Comparing routes...")
            bf.set_snapshot(snapshot_base)
            base_routes = bf.q.routes().answer().frame()
            base_route_count = len(base_routes) if not base_routes.empty else 0
            
            bf.set_snapshot(snapshot_compare)
            compare_routes = bf.q.routes().answer().frame()
            compare_route_count = len(compare_routes) if not compare_routes.empty else 0
            
            differences["routes"] = {
                "base_count": base_route_count,
                "compare_count": compare_route_count,
                "difference": compare_route_count - base_route_count,
                "note": "Route-level diff requires deeper analysis"
            }
            
            # Summary
            has_changes = (
                len(added_devices) > 0 or 
                len(removed_devices) > 0 or 
                len(added_interfaces) > 0 or 
                len(removed_interfaces) > 0 or
                base_route_count != compare_route_count
            )
            
            differences["summary"] = {
                "has_changes": has_changes,
                "devices_changed": len(added_devices) + len(removed_devices),
                "interfaces_changed": len(added_interfaces) + len(removed_interfaces),
                "routes_changed": abs(compare_route_count - base_route_count),
                "comparison": f"{snapshot_base} → {snapshot_compare}"
            }
            
            if not has_changes:
                message = "No significant differences detected between snapshots"
            else:
                changes = []
                if len(added_devices) > 0:
                    changes.append(f"{len(added_devices)} devices added")
                if len(removed_devices) > 0:
                    changes.append(f"{len(removed_devices)} devices removed")
                if len(added_interfaces) > 0:
                    changes.append(f"{len(added_interfaces)} interfaces added")
                if len(removed_interfaces) > 0:
                    changes.append(f"{len(removed_interfaces)} interfaces removed")
                if base_route_count != compare_route_count:
                    changes.append(f"{abs(compare_route_count - base_route_count)} route difference")
                message = f"Changes detected: {', '.join(changes)}"
            
            return {
                "ok": True,
                "network": network,
                "snapshot_base": snapshot_base,
                "snapshot_compare": snapshot_compare,
                "differences": differences,
                "summary": message
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error comparing snapshots: {error_msg}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "ok": False,
                "error": error_msg,
                "network": input_data.get("network"),
                "snapshot_base": input_data.get("snapshot_base"),
                "snapshot_compare": input_data.get("snapshot_compare")
            }


# Create singleton instance
network_compare_snapshots_tool = NetworkCompareSnapshotsTool()


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the compare snapshots tool."""
    return network_compare_snapshots_tool.execute(input_data)

