# SentinelCore

## Overview
SentinelCore is a comprehensive security scanning and vulnerability management system designed to help organizations identify, track, and remediate security vulnerabilities across their network infrastructure. It provides multi-cloud support, real-time alerting, and containerized deployment options for modern security operations.

## Main Objectives

### 1. Automated Asset Discovery and Inventory Management
SentinelCore automatically discovers and catalogs all devices on your network, creating a comprehensive inventory of assets including servers, workstations, network devices, and cloud resources. This provides organizations with complete visibility into their infrastructure, ensuring no device goes unmonitored.

**Benefits:**
- Eliminates blind spots in your network
- Maintains an up-to-date inventory of all assets
- Tracks operating systems, services, and software versions
- Integrates with multiple cloud providers (AWS, Azure, GCP, and Oracle Cloud) for comprehensive coverage

### 2. Continuous Vulnerability Assessment and Prioritization
The system continuously scans for vulnerabilities across all discovered assets, leveraging the National Vulnerability Database (NVD) to identify potential security issues. SentinelCore goes beyond simple detection by prioritizing vulnerabilities based on severity, exploitability, and business impact.

**Benefits:**
- Real-time vulnerability detection
- CVSS scoring for risk assessment
- Exploit availability tracking
- Focused remediation efforts on critical issues

### 3. Actionable Security Insights and Reporting
SentinelCore transforms complex security data into actionable insights through intuitive dashboards and comprehensive reports. This enables security teams, management, and stakeholders to understand their security posture and make informed decisions.

**Benefits:**
- Visual security dashboards
- Detailed vulnerability reports
- Compliance status tracking
- Executive summaries for management

## Getting Started

### Prerequisites
- Python 3.6+
- Nmap network scanner
- SQLite (included)

### Installation
1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `.env.template` to `.env` and configure your settings:
   ```
   cp .env.template .env
   ```
6. Edit the `.env` file with your specific configuration:
   - NVD API key for vulnerability data
   - Telegram bot token and chat ID for alerts
   - Cloud provider credentials

### Usage

#### Network Scanning
```bash
# Scan a local network
python cli.py scan 192.168.1.0/24

# Scan for vulnerabilities
python cli.py scan-vuln
```

#### Cloud Discovery
```bash
# Discover AWS resources
python cli.py discover-aws

# Discover Azure resources
python cli.py discover-azure --subscription-id YOUR_SUBSCRIPTION_ID

# Discover Google Cloud resources
python cli.py discover-gcp

# Discover Oracle Cloud resources
python cli.py discover-oci
```

#### Web Dashboard and Automation
```bash
# Start the web dashboard
python run.py

# Schedule automated scans
python scheduler.py
```

#### Docker Deployment
```bash
# Build and start containers
docker-compose up -d

# View logs
docker-compose logs -f
```

## Architecture
SentinelCore follows a modular architecture with the following components:
- **Network Scanner**: Discovers assets and services on local networks
- **Cloud Integration**: Discovers resources across multiple cloud providers (AWS, Azure, GCP, Oracle)
- **Vulnerability Scanner**: Identifies security issues using NVD data
- **Database**: Stores asset and vulnerability data
- **Web Dashboard**: Visualizes security information
- **Alerting System**: Sends real-time notifications via Telegram
- **Enforcement Engine**: Implements security controls and isolation
- **Scheduler**: Automates scanning tasks
- **CLI**: Provides command-line interface for all operations

### 4. Real-Time Security Alerting
SentinelCore provides real-time security alerts through Telegram integration, notifying security teams immediately when critical vulnerabilities or new assets are discovered.

**Benefits:**
- Instant notifications for critical security events
- Configurable alert severity levels
- Detailed vulnerability information in alerts
- Mobile-friendly notifications for on-the-go monitoring

## Deployment Options

### Docker Containerization
SentinelCore can be deployed as a containerized application using Docker, making it easy to deploy, scale, and maintain.

```bash
# Build and run using Docker Compose
docker-compose up -d
```

### Cloud Deployment
SentinelCore can be deployed to cloud platforms like Render for a fully managed experience.

## Future Enhancements
- Integration with ticketing systems
- Automated remediation workflows
- Advanced threat intelligence
- Multi-tenant support
- Additional cloud provider integrations