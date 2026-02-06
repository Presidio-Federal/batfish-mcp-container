# Security & Compliance Models

This directory contains JSON-based security and compliance models for OT/IT network analysis.

## Available Models

### 1. Purdue Model (`purdue.json`)
**Reference**: ISA-95 / ISA-99 (IEC 62443)

The Purdue Enterprise Reference Architecture (PERA) is the most widely-adopted framework for securing Industrial Control Systems (ICS) and Operational Technology (OT) networks.

**Zones**:
- **Level 0**: Physical Process (sensors, actuators, field devices)
- **Level 1**: Basic Control (SCADA, DCS, historians)
- **Level 2**: Supervisory Control (HMIs, engineering workstations)
- **Level 3**: Operations Management (MES, LIMS, maintenance systems)
- **Level 4**: Enterprise Network (ERP, corporate IT)
- **DMZ**: Buffer zone between OT and IT

**Use Case**: OT security segmentation, critical infrastructure protection, industrial cybersecurity audits

---

### 2. ISA-95 Model (`isa95.json`)
**Reference**: ANSI/ISA-95 / IEC 62264

International standard for enterprise-control system integration. Focuses on the interface and information exchange between enterprise systems and control systems.

**Zones**:
- **Level 0**: Physical Processes
- **Level 1**: Sensing and Manipulation (PLCs, DCS)
- **Level 2**: Monitoring and Supervisory Control (SCADA, HMI)
- **Level 3**: Manufacturing Operations Management (MES, batch management)
- **Level 4**: Business Planning and Logistics (ERP, supply chain)

**Use Case**: MES integration, ERP-to-control system integration, manufacturing operations optimization

---

### 3. NIST Cybersecurity Framework for OT (`nist_csf.json`)
**Reference**: NIST CSF 2.0 + NIST SP 800-82

NIST Cybersecurity Framework adapted for Operational Technology environments, focusing on the five core functions: Identify, Protect, Detect, Respond, Recover.

**Zones**:
- **Safety_Critical**: Emergency shutdown systems, safety PLCs
- **Process_Critical**: Production control systems
- **Operations**: Engineering workstations, HMIs
- **Business**: Corporate IT systems
- **Remote_Access**: Controlled vendor/third-party access

**Use Case**: Federal compliance, NIST SP 800-82 compliance, cybersecurity risk management, critical infrastructure

---

## Model Structure

Each model JSON file contains:

```json
{
  "name": "Model Name",
  "version": "1.0",
  "description": "Detailed description",
  "type": "ot_security | ot_integration | security_framework",
  "reference": "Standard reference (e.g., ISA-95)",
  
  "zones": {
    "Zone_Name": {
      "name": "Human-readable name",
      "description": "Zone purpose and scope",
      "typical_devices": ["Device types"],
      "typical_vendors": ["Vendor names"],
      "typical_protocols": ["Protocol names"],
      "security_requirements": {}
    }
  },
  
  "allowed_communications": [
    {
      "from": "Zone_A",
      "to": "Zone_B",
      "bidirectional": true,
      "protocols": ["protocol list"],
      "rationale": "Why this is allowed"
    }
  ],
  
  "prohibited_communications": [
    {
      "from": "Zone_A",
      "to": "Zone_C",
      "rationale": "Why this is prohibited"
    }
  ],
  
  "required_enforcement_points": [
    {
      "between": ["Zone_A", "Zone_B"],
      "type": "firewall | acl | data_diode",
      "severity": "critical | high | medium",
      "rationale": "Why enforcement is required"
    }
  ],
  
  "compliance_standards": ["List of applicable standards"]
}
```

---

## Usage

### 1. List Available Models
```python
# Use the network_list_models tool
result = network_list_models()
# Returns: List of all models with descriptions
```

### 2. View Model Details
```python
# Get detailed view of a specific model
result = network_list_models(model_name="purdue", show_details=True)
# Returns: Full model JSON with all zones, rules, requirements
```

### 3. Check Network Compliance
```python
# AI agent workflow:
# Step 1: Analyze network segments
segments = network_segment_tool(network="my-network", snapshot="latest")

# Step 2: AI classifies zones
zone_mapping = {
    "Level_0": {"subnets": ["10.42.88.0/24"], "vlans": [400]},
    "Level_1": {"subnets": ["10.42.90.0/24"], "vlans": [120]},
    "Level_4": {"subnets": ["10.42.93.0/24"], "vlans": []}
}

# Step 3: Check compliance
result = network_check_zone_compliance(
    network="my-network",
    snapshot="latest",
    model_name="purdue",
    zone_mapping=zone_mapping
)
# Returns: Violations, gaps, compliance status
```

---

## Adding Custom Models

To add a new security model:

1. Create a new JSON file in this directory (e.g., `custom_model.json`)
2. Follow the structure above
3. Define zones, allowed/prohibited communications, and enforcement requirements
4. The model will automatically be discovered by `network_list_models`

**Example**: Creating a custom model for a specific industry vertical (pharma, energy, etc.) with unique compliance requirements.

---

## Compliance Standards Supported

- **NERC CIP** (Energy sector)
- **FDA 21 CFR Part 11** (Pharmaceutical)
- **ISA/IEC 62443** (Industrial automation)
- **NIST SP 800-82** (ICS security)
- **NIST CSF 2.0** (Cybersecurity framework)

---

## Notes

- Models are **descriptive, not prescriptive** - they define ideal architectures but should be adapted to specific operational requirements
- Zone classifications require human validation - automated tools provide suggestions but critical infrastructure decisions should be reviewed by domain experts
- Enforcement requirements are security best practices - actual implementation depends on risk tolerance and operational constraints

