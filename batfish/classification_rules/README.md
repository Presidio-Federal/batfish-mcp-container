# Device Classification Rules

This directory contains **modular, customizable classification rules** for the `network_classify_devices` tool.

## Overview

Classification rules are stored as **JSON files** that define:
- Device types (PLC, SCADA, workstation, etc.)
- Vendor patterns
- Naming patterns (regex)
- VLAN indicators
- OUI vendors (MAC address prefixes)
- Scoring weights
- Confidence thresholds

## Files

- **`default.json`** - Standard classification rules for OT/IT networks
- **`custom_*.json`** - Custom rule sets (create your own!)

## Rule File Structure

```json
{
  "version": "1.0",
  "name": "Rule Set Name",
  "description": "What this rule set does",
  "scoring_weights": {
    "vendor_match": 3,
    "oui_vendor_match": 4,
    "name_pattern_match": 5,
    "config_format_match": 2,
    "vlan_indicator_match": 3
  },
  "confidence_thresholds": {
    "high": 7,
    "medium": 3,
    "low": 0
  },
  "device_types": {
    "plc": {
      "display_name": "Programmable Logic Controller",
      "category": "ot_control",
      "purdue_level": "Level_0",
      "vendors": ["siemens", "rockwell", ...],
      "name_patterns": ["plc", "controller", ...],
      "config_formats": [],
      "vlan_indicators": ["ot", "process", ...],
      "oui_vendors": ["honeywell", ...],
      "subnet_patterns": []
    },
    ...
  }
}
```

## Device Type Categories

| Category | Description | Example Types |
|----------|-------------|---------------|
| `ot_control` | Field devices & controllers | PLC, RTU, IED |
| `ot_supervisory` | Supervisory control | SCADA, HMI, Historian |
| `it_server` | Enterprise servers | Windows, Linux, VMware |
| `it_endpoint` | End-user devices | Workstation, Phone, Printer |
| `infrastructure` | Network equipment | Switch, Router |
| `security` | Security devices | Firewall, IDS, Sensor |

## Purdue Levels

Classification rules can include recommended Purdue levels:
- `Level_0` - Physical Process (PLCs, RTUs, IEDs)
- `Level_1` - Basic Control (SCADA, HMI)
- `Level_2` - Supervisory Control (Engineering workstations)
- `Level_3` - Operations (MES, LIMS)
- `Level_4` - Enterprise (ERP, Email, etc.)
- `DMZ` - Demilitarized zone
- `null` - Not applicable (infrastructure devices)

## Customization

### Option 1: Modify Existing Rules

Edit `default.json` directly to:
- Add new vendors
- Add new name patterns
- Adjust VLAN indicators
- Change scoring weights

### Option 2: Create Custom Rule Set

1. Copy `default.json` to `custom_my_site.json`
2. Modify as needed
3. Use the tool with: `rule_set: "custom_my_site"`

### Option 3: Per-Network Rules

Create network-specific rules:
```
classification_rules/
  ├── default.json
  ├── owens_corning.json      ← Custom for Owens Corning
  ├── manufacturing_plant_a.json
  └── refinery_site_b.json
```

## Pattern Syntax

### Name Patterns (Regex)

```json
"name_patterns": [
  "plc",                    // Matches "plc" anywhere in name
  "^controller-",           // Starts with "controller-"
  "s7-\\d+",               // Matches "s7-300", "s7-1200", etc.
  "device-[0-9a-f]{12}"    // Matches MAC-based device names
]
```

### VLAN Indicators

```json
"vlan_indicators": [
  "ot",        // Matches "vlan-ot", "ot_network", etc.
  "process",   // Matches "process_control"
  "400"        // Matches "vlan400", "vlan_400"
]
```

### Subnet Patterns

```json
"subnet_patterns": [
  "10\\.42\\.100\\.",      // Matches 10.42.100.x
  "192\\.168\\.1[0-9]{2}\\." // Matches 192.168.100.x - 192.168.199.x
]
```

## Scoring System

Each match type has a weight:

| Match Type | Default Weight | Description |
|------------|----------------|-------------|
| `vendor_match` | 3 | Device vendor matches rule |
| `oui_vendor_match` | 4 | MAC OUI vendor matches (for endpoints) |
| `name_pattern_match` | 5 | Device name matches regex |
| `config_format_match` | 2 | Config format matches (Cisco IOS, etc.) |
| `vlan_indicator_match` | 3 | VLAN name/number matches indicator |

**Total Score → Confidence Level:**
- Score ≥ 7 → **High confidence**
- Score ≥ 3 → **Medium confidence**
- Score < 3 → **Low confidence**

## Tools

Use these tools to manage classification rules:

### 1. List Available Rule Sets
```bash
network_list_classification_rules
```

### 2. View Specific Rule Set
```bash
network_list_classification_rules --rule_set "default"
```

### 3. Validate Rule Set
```bash
network_validate_classification_rules --rule_set "custom_my_site"
```

### 4. Update Rules
```bash
network_update_classification_rules \
  --rule_set "default" \
  --device_type "plc" \
  --add_vendor "delta" \
  --add_pattern "dvp-.*"
```

### 5. Classify Devices (with custom rules)
```bash
network_classify_devices \
  --network "my-network" \
  --snapshot "latest" \
  --rule_set "custom_my_site"
```

## Best Practices

1. **Start with default rules** - Copy and customize rather than starting from scratch
2. **Test incrementally** - Add one pattern, test, refine
3. **Use specific patterns** - More specific = higher confidence
4. **Document changes** - Update `description` field when modifying
5. **Version control** - Keep rule files in git
6. **Audit classifications** - Review low-confidence matches regularly

## Examples

### Add Custom PLC Vendor

```json
{
  "device_types": {
    "plc": {
      "vendors": [
        "siemens",
        "rockwell",
        "delta",           // ← Add new vendor
        "beckhoff"         // ← Add new vendor
      ],
      "name_patterns": [
        "plc",
        "dvp-.*",          // ← Delta PLC pattern
        "cx\\d{4}"         // ← Beckhoff pattern
      ]
    }
  }
}
```

### Site-Specific VLAN Naming

```json
{
  "device_types": {
    "plc": {
      "vlan_indicators": [
        "factory-floor",   // Custom VLAN naming
        "assembly-line",
        "production-zone"
      ]
    }
  }
}
```

### Adjust Confidence Thresholds

```json
{
  "confidence_thresholds": {
    "high": 10,    // ← Stricter: need more evidence
    "medium": 5,   // ← Stricter
    "low": 0
  }
}
```

## Troubleshooting

### Device Classified as "unknown"
- Check if vendor is in any rule's `vendors` list
- Check if device name matches any `name_patterns`
- Add debug logging to see which rules matched

### Incorrect Classification
- Review the `evidence` field in classification output
- Check if multiple device types are scoring similarly
- Adjust scoring weights to prefer correct type
- Add more specific patterns to reduce ambiguity

### Too Many Low-Confidence Classifications
- Lower the `medium` threshold
- Add more VLAN indicators for your environment
- Add more name patterns
- Add OUI vendors for endpoint devices

## Support

For questions or to contribute new rule patterns, contact the HAI Infrastructure team.

