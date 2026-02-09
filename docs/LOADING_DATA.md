# Loading Your Data Into Batfish

Batfish works with **snapshots** - collections of network configuration files bundled together that represent your network at a specific point in time. Once a snapshot is loaded, you can run all sorts of analysis on it without touching your production environment.

Here's the challenge: network configs are big. Really big. And when you're working with AI agents, every piece of data you move costs tokens. So we've built three different approaches to get your data into Batfish, each optimized for different situations.

---

## Understanding Snapshots

Before we dive into the methods, let's talk about what Batfish expects:

A snapshot is basically a directory structure that looks like this:

```
my-snapshot/
└── configs/
    ├── router1.cfg
    ├── router2.cfg
    ├── switch1.cfg
    └── firewall1.cfg
```

That's it. Just a `configs/` folder with your device configuration files. Batfish will parse these files, build a model of your network, and then you can start asking questions.

---

## Method 1: Incremental Loading (Best for Large Networks)

**When to use this:** You have a lot of configs and want to upload them one at a time, verify everything is staged correctly, and then push to Batfish.

This uses a three-step process with a staging area:

### Step 1: Prepare (Add Configs to Staging)

Use `initialize.network_prepare_snapshot` to add configurations to a staging area. You can call this multiple times to add configs incrementally.

```
"Add these three router configs to my prod-network snapshot"
```

The agent will:
- Create a staging directory
- Validate each config
- Track what's been staged
- Return a list of all staged configs

You can call this tool multiple times, adding configs in batches:
- First call: Add 10 router configs
- Second call: Add 15 switch configs  
- Third call: Add 5 firewall configs

### Step 2: View Staging (Verify Before Pushing)

Use `initialize.network_view_staging` to see what you've staged:

```
"Show me what configs are staged for prod-network"
```

This returns:
- List of all staged configs
- File sizes
- Line counts
- Total staged configs

Perfect for making sure you've got everything before finalizing.

### Step 3: Finalize (Push to Batfish)

Use `initialize.network_finalize_snapshot` to push everything to Batfish:

```
"Finalize the prod-network snapshot and load it into Batfish"
```

This:
- Validates all staged configs exist
- Pushes to Batfish
- Verifies the snapshot loaded correctly
- Optionally clears the staging area

### Bonus: Remove Configs

Made a mistake? Use `initialize.network_remove_config` to remove a specific file from staging before you finalize:

```
"Remove router3.cfg from staging, I uploaded the wrong version"
```

### Why This Method Rocks

- **Token efficient**: Upload configs in batches, not all at once
- **Verifiable**: Check what's staged before pushing
- **Correctable**: Remove wrong configs before finalizing
- **Resumable**: Stage some configs, come back later and stage more

---

## Method 2: Base64 ZIP Upload (All-in-One)

**When to use this:** You have all your configs in a zip file and want to just send it all in one shot.

This method lets you base64-encode an entire zip file and upload it directly. The container decodes it, extracts it, and pushes to Batfish.

### How It Works

Use `initialize.network_upload_zip`:

```
"Load this base64-encoded zip file as snapshot prod-baseline"
```

The agent will:
1. Decode the base64 data
2. Validate it's a valid zip
3. Extract to temporary directory
4. Look for a `configs/` directory (or create one)
5. Push to Batfish
6. Clean up temporary files

### Expected ZIP Structure

Your zip should look like this:

```
snapshot.zip
└── configs/
    ├── router1.cfg
    ├── router2.cfg
    └── switch1.cfg
```

If you don't have a `configs/` directory, the tool will create one and move all your files into it.

### Why This Method Rocks

- **Simple**: One call, done
- **Portable**: Zip file can be created anywhere
- **Complete**: Everything in one package

### The Catch

This moves ALL the data through the AI agent. If you have 100MB of configs, that's a lot of tokens. Use this for smaller networks or when you need the simplicity.

---

## Method 3: GitHub Integration (The Token Saver)

**When to use this:** Your configs are in GitHub (and they should be). This is the most token-efficient method by far.

Instead of passing config data through the AI agent, you just tell it to pull from GitHub. The container clones your repo directly, saving massive amounts of tokens.

### How It Works

Use `initialize.github_snapshot`:

```
"Load snapshot from https://github.com/myorg/network-configs/tree/main/production"
```

The agent will:
1. Parse the GitHub URL
2. Clone the repository (or specific subdirectory)
3. Support both public and private repos (with PAT)
4. Handle zip files automatically
5. Push to Batfish
6. Clean up cloned files

### Supported URL Formats

- Full repo: `https://github.com/owner/repo`
- Specific branch: `https://github.com/owner/repo/tree/develop`
- Subdirectory: `https://github.com/owner/repo/tree/main/snapshots/production`

### Private Repositories

For private repos, provide your GitHub username and Personal Access Token (PAT):

```
"Load snapshot from my private repo using my GitHub credentials"
```

The agent will prompt for credentials if needed.

### Why This Method is the Best

- **Zero token cost for data**: Configs never pass through the agent
- **Version controlled**: Your snapshots are in git (as they should be)
- **Automated**: Pair with GitHub MCP tools for full automation
- **Subdirectory support**: Pull from specific paths in your repo

### The Ultimate Workflow

Combine this with the GitHub MCP server:

1. Update your network configs
2. Commit and push to GitHub
3. Tell the agent: "Load the latest snapshot from GitHub"
4. Run your analysis

No manual file handling. No massive token costs. Just version-controlled network analysis.

---

## Quick Comparison

| Method | Token Cost | Complexity | Best For |
|--------|-----------|------------|----------|
| **Incremental** | Medium | Medium | Large networks, verification needed |
| **Base64 ZIP** | High | Low | Small networks, simple uploads |
| **GitHub** | Very Low | Low | Any size, especially if configs in git |

---

## Tool Reference

### Incremental Loading Tools

- `initialize.network_prepare_snapshot` - Add configs to staging
- `initialize.network_view_staging` - View what's staged
- `initialize.network_finalize_snapshot` - Push to Batfish
- `initialize.network_remove_config` - Remove a config from staging

### One-Shot Tools

- `initialize.network_upload_zip` - Upload base64-encoded zip file

### GitHub Tools

- `initialize.github_snapshot` - Load from GitHub repository

### Traditional Tool (Still Works)

- `initialize.snapshot` - Direct load with configs dict (good for very small snapshots)

---

## Pro Tips

1. **Use GitHub whenever possible**: It saves tokens and gives you version control.

2. **For large networks**: Use incremental loading and verify with view_staging before finalizing.

3. **For quick tests**: Base64 zip is fine for small snapshots under 10MB.

4. **Keep staging organized**: Use clear snapshot names like `prod-2024-02-06` or `lab-testing`.

5. **Pair with GitHub MCP**: Let the agent check GitHub, see changes, and auto-load updated snapshots.

6. **Private repos**: Store your PAT in your AI client's context, not in the configs themselves.

---

## Common Questions

**Q: Can I mix and match methods?**  
A: Kind of. Each method creates a complete snapshot. Use one method per snapshot.

**Q: What happens to staging if I don't finalize?**  
A: It stays there. You can come back later and finalize, or remove configs and start over.

**Q: Can I update an existing snapshot?**  
A: Yes! Just use the same snapshot name and set `overwrite=True` (default). The old snapshot is replaced.

**Q: What config formats does Batfish support?**  
A: Cisco IOS, Juniper JunOS, Arista EOS, Palo Alto, AWS, and many more. See [Batfish docs](https://www.batfish.org/) for the full list.

**Q: Do I need a configs/ directory?**  
A: Batfish expects it, but the upload_zip tool will create one if it's missing.

---

## Next Steps

Once your snapshot is loaded, you can start analyzing:
- [Using the Tools](TOOLS.md) - Available analysis tools
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues

---

## Loading AWS Data (Cloud Environments)

Cloud data models are massive. An AWS VPC with a few dozen resources can generate hundreds of thousands of lines of JSON. Moving that through an AI agent? Token explosion. So we built AWS-specific tools that work just like the network config tools, but optimized for cloud data.

### Understanding AWS Snapshots in Batfish

Batfish analyzes AWS environments by loading AWS API responses into a special directory structure:

```
aws-snapshot/
└── aws_configs/
    └── us-east-1/
        └── aws.json
```

That `aws.json` file contains the raw AWS API data for VPCs, subnets, route tables, security groups, network ACLs, NAT gateways, internet gateways, network interfaces, and EC2 instances (as Reservations).

Batfish parses this, builds a model of your AWS network, and then you can analyze security groups, routing, internet exposure, and more.

### The Challenge: AWS Data is HUGE

A typical production AWS environment:
- 5 VPCs
- 50 subnets
- 200 security groups
- 500 network interfaces
- 100 EC2 instances

That's easily 2-5MB of JSON. At ~$3-15 per million tokens (depending on model), that's $0.02-$0.10 per load. Do that 10 times during analysis? You're spending real money just moving data.

### Two Methods for Loading AWS Data

Just like network configs, we give you options optimized for different situations.

---

## AWS Method 1: All-in-One Upload (Small Environments)

**When to use this:** You have a small AWS environment (1-2 VPCs, &lt;50 resources) and want simplicity.

Use `initialize.aws_init_snapshot`:

```
"Load this AWS data as snapshot prod-aws"
```

The agent will:
1. Accept the complete AWS data dict
2. Sanitize resource names (AWS names often break Batfish parsers)
3. Create the correct directory structure
4. Push to Batfish

### What AWS Data Format?

This tool expects the **raw AWS API response format** - exactly what you'd get from:

```python
{
  "Vpcs": [...],              # ec2.describe_vpcs()
  "Subnets": [...],           # ec2.describe_subnets()
  "RouteTables": [...],       # ec2.describe_route_tables()
  "InternetGateways": [...],  # ec2.describe_internet_gateways()
  "NatGateways": [...],       # ec2.describe_nat_gateways()
  "SecurityGroups": [...],    # ec2.describe_security_groups()
  "NetworkAcls": [...],       # ec2.describe_network_acls()
  "NetworkInterfaces": [...], # ec2.describe_network_interfaces()
  "Reservations": [...]       # ec2.describe_instances()
}
```

This is the EXACT format Batfish expects - no transformation needed.

### The Catch

You're moving 2-5MB of JSON through the AI agent. Fine for small environments or one-time loads. Not great for large environments or repeated analysis.

---

## AWS Method 2: Incremental Chunk Loading (Large Environments)

**When to use this:** Production AWS environments with lots of resources, or when you want to control token costs.

This works just like the network config incremental method - add data in chunks, verify, then finalize.

### Step 1: Add Data Chunks

Use `initialize.aws_add_data_chunk` to upload each resource type separately:

```
"Add these 50 Subnets to my prod-aws snapshot for us-east-1"
```

Then:
```
"Add these 100 SecurityGroups to prod-aws"
```

The agent will:
- Validate the resource type and data structure
- Store each chunk in a staging directory
- Track what's been staged
- Return what chunks are loaded

You can add resource types in any order, one at a time:
1. First call: Add Vpcs
2. Second call: Add Subnets  
3. Third call: Add SecurityGroups
4. Fourth call: Add RouteTables
... and so on

### Valid Resource Types

- `Vpcs` - Virtual Private Clouds
- `Subnets` - Subnets within VPCs
- `RouteTables` - Routing tables
- `InternetGateways` - Internet gateways
- `NatGateways` - NAT gateways
- `SecurityGroups` - Security groups
- `NetworkAcls` - Network ACLs
- `NetworkInterfaces` - ENIs
- `Reservations` - EC2 instances (must include Instances array)

### Step 2: View Staging (Verify)

Use `initialize.aws_view_staging` to see what you've staged:

```
"Show me what AWS chunks are staged for prod-aws in us-east-1"
```

This returns:
- List of staged resource types
- Count of each resource type
- File sizes
- Total chunks

Perfect for verifying you've got all your data before pushing to Batfish.

### Step 3: Finalize (Push to Batfish)

Use `initialize.aws_finalize_snapshot`:

```
"Finalize the prod-aws snapshot and load it into Batfish"
```

This:
- Consolidates all chunks into a single `aws.json`
- Sanitizes resource names (prevents Batfish crashes)
- Creates proper directory structure
- Pushes to Batfish
- Optionally clears staging

### Bonus: Remove Chunks

Made a mistake? Use `initialize.aws_remove_chunk`:

```
"Remove the SecurityGroups chunk from staging, I got the wrong data"
```

### Why This Method Rocks

- **Token efficient**: Upload 50 subnets at a time instead of 500 resources at once
- **Verifiable**: Check what's staged before finalizing
- **Correctable**: Remove wrong chunks before finalizing
- **Resumable**: Stage some data, come back later and add more
- **Cost effective**: For large environments, this can save $0.10-$0.50 per analysis session

---

## AWS Data Collection

"But how do I get the AWS data in the first place?"

You have options:

### Option 1: AWS CLI

Use the AWS CLI to collect data:

```bash
aws ec2 describe-vpcs --region us-east-1 > vpcs.json
aws ec2 describe-subnets --region us-east-1 > subnets.json
# ... etc
```

Then feed these to the agent incrementally.

### Option 2: Python boto3

```python
import boto3
ec2 = boto3.client('ec2', region_name='us-east-1')

data = {
    "Vpcs": ec2.describe_vpcs()['Vpcs'],
    "Subnets": ec2.describe_subnets()['Subnets'],
    # ... etc
}
```

### Option 3: AWS MCP Server (If Available)

If you have an AWS MCP server configured, the agent can collect the data directly:

```
"Collect AWS data from my us-east-1 VPC and load it into Batfish"
```

The agent orchestrates:
1. Call AWS MCP to collect data
2. Stage data incrementally into Batfish MCP
3. Finalize the snapshot
4. Run analysis

All without you manually handling JSON files.

---

## AWS vs Network Config Loading: Side by Side

| Aspect | Network Configs | AWS Data |
|--------|----------------|----------|
| **Data Format** | Text config files | JSON API responses |
| **Size** | 1KB-100KB per device | 50KB-500KB per resource type |
| **One-Shot Tool** | `initialize.snapshot` | `initialize.aws_init_snapshot` |
| **Incremental Prepare** | `initialize.network_prepare_snapshot` | `initialize.aws_add_data_chunk` |
| **View Staging** | `initialize.network_view_staging` | `initialize.aws_view_staging` |
| **Finalize** | `initialize.network_finalize_snapshot` | `initialize.aws_finalize_snapshot` |
| **Remove** | `initialize.network_remove_config` | `initialize.aws_remove_chunk` |
| **GitHub Support** | Yes (`initialize.github_snapshot`) | No (use AWS APIs) |

---

## Pro Tips for AWS Data

1. **Always use incremental loading for production**: Unless you have &lt;20 total resources, incremental is worth it.

2. **Collect data with pagination**: AWS APIs paginate. Make sure you're getting ALL resources.

3. **One region at a time**: Batfish expects one region per snapshot. Multi-region? Create multiple snapshots.

4. **Sanitization is automatic**: The tools auto-sanitize resource names (dots, special chars) that break Batfish. You don't need to worry about it.

5. **Missing resource types are OK**: If you don't have NatGateways, don't add them. The finalize tool will use empty arrays.

6. **Reservations format matters**: EC2 instances must be in Reservations format (same as AWS API returns).

---

## Common AWS Questions

**Q: Do I need all 9 resource types?**  
A: No. Batfish will use empty arrays for missing types. But at minimum, you need Vpcs and Subnets.

**Q: Can I load multiple regions into one snapshot?**  
A: No. One snapshot = one region. Create separate snapshots for each region.

**Q: What if my resource names have dots or special characters?**  
A: The tools automatically sanitize names. AWS names like `ec2-1-2-3-4.compute.amazonaws.com` become `ec2_1_2_3_4_compute_amazonaws_com`.

**Q: Can I update an existing AWS snapshot?**  
A: Yes. Use the same snapshot name and it will overwrite.

**Q: How do I get the AWS data into the agent?**  
A: Either paste JSON (small environments), use file upload features in your AI client, or use an AWS MCP server to collect it directly.

**Q: What about other AWS resources like ELBs, RDS, Lambda?**  
A: Currently, Batfish focuses on core networking resources (VPCs, subnets, security groups, routing). Other resources aren't analyzed.

---

## Next Steps

Once your snapshot is loaded, you can start analyzing:
- [Using the Tools](TOOLS.md) - Available analysis tools
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues
