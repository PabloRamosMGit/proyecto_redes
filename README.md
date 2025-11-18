# QoS Policy Synchronization for Cisco IOS XE

This project automates the synchronization of Quality of Service (QoS) policies across Cisco IOS XE routers using RESTCONF API.

## Overview

The system enables automated QoS policy management across multiple network devices:

- **Master Router Configuration**: A master router exposes its QoS policies via RESTCONF API
- **Automated Replication**: The script automatically replicates QoS policies from the master to target devices
- **Consistency & Standardization**: Ensures uniform QoS configuration across the entire network
- **Error Reduction**: Eliminates manual configuration errors and improves operational efficiency

### Key Features

- **Policy Discovery**: Automatic detection of QoS policies (class-maps, policy-maps, service-policies)
- **One-to-Many Deployment**: Replicate from one source to multiple target routers in a single operation
- **Dry-Run Mode**: Preview changes before applying to production devices
- **RESTCONF-Based**: Leverages Cisco IOS XE RESTCONF API for programmatic configuration
- **Safety First**: Built-in validation and rollback-friendly PATCH operations

---

## Required Configuration

This project requires access to the Lab Network via VPN. The recommended environment is Ubuntu or WSL (Windows Subsystem for Linux).

1. **Install OpenConnect:**
   ```bash
   sudo apt install openconnect
   ```
2. **Connect to the Lab Network:**
   ```bash
   sudo openconnect --protocol=anyconnect <Lab Network Address> --user=<username>
   ```
   Replace `<Lab Network Address>` with the address provided by your lab administrator and `<username>` with your own username.

---

## How to Use This Project

1. Clone or download the repository to your local machine.
2. Ensure you are connected to the Lab Network VPN as described above.
3. Install Python 3 if not already available.
4. Setup a Python virtual environment (recommended)

  It's best to run the project inside a virtual environment to keep dependencies isolated.

  Create and activate a venv in the project root:

  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

  Install the project dependencies:

  ```bash
  pip install -r requirements.txt
  ```

  When you're done, deactivate the environment:

  ```bash
  deactivate
  ```
4. Run the CLI tool:
   ```bash
   python3 restconf_cli.py --help
   ```
   This will show all available commands and options.

### Example Usage

**Important: Global flags (--host, --user, --password, --raw, --secure) MUST be placed BEFORE the subcommand.**

#### Connection Options
By default, commands use:
- Host: `10.10.20.48`
- User: `developer`
- Password: `C1sco12345`
- SSL verification: disabled

Override these with global flags:
```bash
python3 restconf_cli.py --host <IP> --user <user> --password <pass> <subcommand>
```

#### Interface Management
View interface status:
```bash
python3 restconf_cli.py get-interfaces
```

Create a Loopback interface:
```bash
python3 restconf_cli.py post-loopback --name Loopback123 --ip 10.123.123.123 --desc "Test Loopback"
```

Delete a Loopback interface:
```bash
python3 restconf_cli.py delete-loopback --name Loopback123
```

#### QoS Discovery and Configuration

List available YANG modules (filter optional):
```bash
python3 restconf_cli.py list-modules
python3 restconf_cli.py list-modules --filter qos
```

Auto-discover valid QoS RESTCONF paths:
```bash
python3 restconf_cli.py auto-probe-qos
python3 restconf_cli.py auto-probe-qos --filter native --max-modules 10
```

Retrieve QoS configuration from a device:
```bash
# Using default path (Cisco-IOS-XE-qos:qos)
python3 restconf_cli.py get-qos

# Using discovered path (Cisco-IOS-XE-native:native)
python3 restconf_cli.py get-qos --yang-path Cisco-IOS-XE-native:native

# Get raw JSON output (--raw flag BEFORE subcommand)
python3 restconf_cli.py --raw get-qos --yang-path Cisco-IOS-XE-native:native

# Filter for policy-related config
python3 restconf_cli.py --raw get-qos --yang-path Cisco-IOS-XE-native:native | grep -i policy
```

**Configure QoS via RESTCONF (recommended method):**
```bash
# Test configuration with dry-run (safe - no changes applied)
python3 restconf_cli.py configure-qos \
  --class-name CLASE-CRITICA \
  --policy-name POLITICA-QOS-DEMO \
  --interface GigabitEthernet2 \
  --bandwidth-percent 60 \
  --protocols http https dns \
  --dry-run

# Apply QoS configuration
python3 restconf_cli.py configure-qos \
  --class-name CLASE-CRITICA \
  --policy-name POLITICA-QOS-DEMO \
  --interface GigabitEthernet2 \
  --bandwidth-percent 60 \
  --protocols http https dns

# Simple example with defaults (50% bandwidth, http+dns protocols)
python3 restconf_cli.py configure-qos \
  --class-name MI-CLASE \
  --policy-name MI-POLITICA \
  --interface Gi2
```

**Note**: Protocol matches must be added via CLI after RESTCONF creation due to YANG model limitations:
```bash
ssh developer@10.10.20.48
conf t
class-map match-any CLASE-CRITICA
 match protocol http
 match protocol dns
end
```

#### QoS Synchronization Workflow - Automated Multi-Device Deployment

**Step 1: Verify Master Router has QoS policies configured**
```bash
# Check current QoS configuration on master router
python3 restconf_cli.py get-qos

# Should display class-maps, policy-maps, and service-policies
```

**Step 2: Test synchronization with dry-run (safe - no changes applied)**
```bash
# Preview what would be replicated WITHOUT making changes
python3 restconf_cli.py replicate-qos \
  --source 10.10.20.48 \
  --targets 10.10.20.50 10.10.20.51 10.10.20.52 \
  --dry-run

# Review the JSON payload that would be sent to each target
```

**Step 3: Execute automated synchronization**
```bash
# Replicate QoS from master to all targets
python3 restconf_cli.py replicate-qos \
  --source 10.10.20.48 \
  --targets 10.10.20.50 10.10.20.51

# The script will:
# 1. GET QoS policies from master (10.10.20.48)
# 2. Extract policy configuration (class-maps, policy-maps)
# 3. PATCH configuration to each target router
# 4. Report success/failure for each device
```

**Step 4: Verify synchronization**
```bash
# Verify QoS was applied on target routers
python3 restconf_cli.py --host 10.10.20.50 get-qos
python3 restconf_cli.py --host 10.10.20.51 get-qos

# Compare with master to ensure consistency
diff <(python3 restconf_cli.py --host 10.10.20.48 get-qos) \
     <(python3 restconf_cli.py --host 10.10.20.50 get-qos)
```



#### Alternative: Configure QoS Manually on Master (Traditional Method)

If you prefer to configure the master router via CLI instead of RESTCONF:
```bash
# Connect to source router and configure QoS
ssh developer@10.10.20.48

# Example QoS configuration
conf t
  class-map match-any CLASE-CRITICA
    match protocol http
    match protocol dns
  exit

  policy-map POLITICA-QOS-DEMO
    class CLASE-CRITICA
      bandwidth percent 50
  exit

  interface GigabitEthernet2
    service-policy output POLITICA-QOS-DEMO
  exit
end

write memory
```

Then proceed with the automated synchronization workflow described above.

---

### Additional Commands

For more details on any command, use the `--help` option:
```bash
python3 restconf_cli.py --help
python3 restconf_cli.py replicate-qos --help
python3 restconf_cli.py configure-qos --help
python3 restconf_cli.py get-qos --help
```

---

## Project Architecture

**Components:**
- `restconf_cli.py`: Main CLI tool with QoS automation functions
- `qos_demo.json`: Example QoS policy payload
- `requirements.txt`: Python dependencies

**Key Functions:**
- `get_qos()`: Retrieve QoS policies from a device
- `push_qos()`: Apply QoS policies to a device
- `replicate_qos()`: Automated multi-device synchronization
- `configure_qos()`: Create QoS policies programmatically
- `auto_probe_qos()`: Discover available QoS YANG paths

Feel free to customize the commands and options as needed for your lab environment.
