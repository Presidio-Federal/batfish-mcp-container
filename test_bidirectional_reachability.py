"""
Batfish Bidirectional Reachability Test

Tests if traffic can flow in both directions between two locations.
This is a fundamental network connectivity test.

Usage:
    pytest test_bidirectional_reachability.py \
        --network="my_network" \
        --snapshot="my_snapshot" \
        --location_a="router-01" \
        --location_b="router-02" \
        --ip_a="10.0.1.1" \
        --ip_b="10.0.2.1" \
        --port=443 \
        --protocol=tcp

Parameters:
    --network: Batfish network name
    --snapshot: Batfish snapshot name
    --location_a: Source location (node name, interface, or IP)
    --location_b: Destination location (node name, interface, or IP)
    --ip_a: Source IP address
    --ip_b: Destination IP address
    --port: (Optional) Destination port number
    --protocol: (Optional) Protocol (tcp, udp, icmp) - default: tcp
    --host: (Optional) Batfish host - default: localhost
"""

import pytest
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints


def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption("--network", action="store", required=True, help="Batfish network name")
    parser.addoption("--snapshot", action="store", required=True, help="Batfish snapshot name")
    parser.addoption("--location_a", action="store", required=True, help="Source location")
    parser.addoption("--location_b", action="store", required=True, help="Destination location")
    parser.addoption("--ip_a", action="store", required=True, help="Source IP address")
    parser.addoption("--ip_b", action="store", required=True, help="Destination IP address")
    parser.addoption("--port", action="store", default=None, help="Destination port (optional)")
    parser.addoption("--protocol", action="store", default="tcp", help="Protocol (tcp/udp/icmp)")
    parser.addoption("--host", action="store", default="localhost", help="Batfish host")


@pytest.fixture(scope="session")
def bf(request):
    """Initialize Batfish session"""
    network = request.config.getoption("--network")
    snapshot = request.config.getoption("--snapshot")
    host = request.config.getoption("--host")
    
    bf = Session(host=host)
    bf.set_network(network)
    bf.set_snapshot(snapshot)
    
    return bf


@pytest.fixture(scope="session")
def test_params(request):
    """Get test parameters from command line"""
    return {
        "location_a": request.config.getoption("--location_a"),
        "location_b": request.config.getoption("--location_b"),
        "ip_a": request.config.getoption("--ip_a"),
        "ip_b": request.config.getoption("--ip_b"),
        "port": request.config.getoption("--port"),
        "protocol": request.config.getoption("--protocol"),
    }


def test_forward_reachability(bf, test_params):
    """Test forward direction: A → B"""
    location_a = test_params["location_a"]
    location_b = test_params["location_b"]
    ip_a = test_params["ip_a"]
    ip_b = test_params["ip_b"]
    port = test_params["port"]
    protocol = test_params["protocol"]
    
    print(f"\n{'='*60}")
    print(f"Testing Forward: {location_a} ({ip_a}) → {location_b} ({ip_b})")
    print(f"Protocol: {protocol.upper()}{f', Port: {port}' if port else ''}")
    print(f"{'='*60}")
    
    # Build header constraints
    header_kwargs = {
        "srcIps": ip_a,
        "dstIps": ip_b,
        "ipProtocols": [protocol]
    }
    
    if port:
        header_kwargs["dstPorts"] = str(port)
    
    headers = HeaderConstraints(**header_kwargs)
    
    # Run traceroute
    result = bf.q.traceroute(
        startLocation=location_a,
        headers=headers
    ).answer().frame()
    
    # Check result
    assert not result.empty, f"No route found from {location_a} to {location_b}"
    
    first_flow = result.iloc[0]
    traces = first_flow.get("Traces", [])
    
    assert traces, f"No trace data returned"
    
    first_trace = traces[0]
    disposition = str(first_trace.disposition)
    
    print(f"\nDisposition: {disposition}")
    
    # Print path
    if hasattr(first_trace, 'hops'):
        path = []
        for hop in first_trace.hops:
            if hasattr(hop, 'node'):
                node_name = hop.node.name if hasattr(hop.node, 'name') else str(hop.node)
                path.append(node_name)
        print(f"Path: {' → '.join(path)}")
    
    assert "ACCEPT" in disposition.upper(), f"Forward traffic DENIED: {disposition}"
    
    print(f"\n✓ Forward traffic ALLOWED")


def test_reverse_reachability(bf, test_params):
    """Test reverse direction: B → A"""
    location_a = test_params["location_a"]
    location_b = test_params["location_b"]
    ip_a = test_params["ip_a"]
    ip_b = test_params["ip_b"]
    port = test_params["port"]
    protocol = test_params["protocol"]
    
    print(f"\n{'='*60}")
    print(f"Testing Reverse: {location_b} ({ip_b}) → {location_a} ({ip_a})")
    print(f"Protocol: {protocol.upper()}{f', Port: {port}' if port else ''}")
    print(f"{'='*60}")
    
    # Build header constraints
    header_kwargs = {
        "srcIps": ip_b,
        "dstIps": ip_a,
        "ipProtocols": [protocol]
    }
    
    if port:
        header_kwargs["dstPorts"] = str(port)
    
    headers = HeaderConstraints(**header_kwargs)
    
    # Run traceroute
    result = bf.q.traceroute(
        startLocation=location_b,
        headers=headers
    ).answer().frame()
    
    # Check result
    assert not result.empty, f"No route found from {location_b} to {location_a}"
    
    first_flow = result.iloc[0]
    traces = first_flow.get("Traces", [])
    
    assert traces, f"No trace data returned"
    
    first_trace = traces[0]
    disposition = str(first_trace.disposition)
    
    print(f"\nDisposition: {disposition}")
    
    # Print path
    if hasattr(first_trace, 'hops'):
        path = []
        for hop in first_trace.hops:
            if hasattr(hop, 'node'):
                node_name = hop.node.name if hasattr(hop.node, 'name') else str(hop.node)
                path.append(node_name)
        print(f"Path: {' → '.join(path)}")
    
    assert "ACCEPT" in disposition.upper(), f"Reverse traffic DENIED: {disposition}"
    
    print(f"\n✓ Reverse traffic ALLOWED")


def test_bidirectional_summary(bf, test_params):
    """Summary test - both directions must pass"""
    location_a = test_params["location_a"]
    location_b = test_params["location_b"]
    ip_a = test_params["ip_a"]
    ip_b = test_params["ip_b"]
    
    print(f"\n{'='*60}")
    print(f"BIDIRECTIONAL REACHABILITY: PASSED")
    print(f"{'='*60}")
    print(f"✓ Forward:  {location_a} ({ip_a}) → {location_b} ({ip_b})")
    print(f"✓ Reverse:  {location_b} ({ip_b}) → {location_a} ({ip_a})")
    print(f"{'='*60}\n")
