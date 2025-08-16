# SentinelCore User Guide

## Getting Started

### Installation

1. Clone the repository to your local machine
2. Set up a Python virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate  # On Windows
   source venv/bin/activate  # On Linux/Mac
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Copy `.env.template` to `.env` and configure your settings:
   ```
   cp .env.template .env
   ```
5. Edit the `.env` file with your specific configuration

### First Run

1. Initialize the database (happens automatically on first run)
2. Run your first network scan:
   ```
   python cli.py scan 192.168.1.0/24
   ```
   Replace the IP range with your network subnet
3. Run a vulnerability scan:
   ```
   python cli.py scan-vuln
   ```
4. Start the web dashboard:
   ```
   python run.py
   ```
5. Open your browser to `http://localhost:5000`

## Using SentinelCore

### Command Line Interface

SentinelCore provides a powerful CLI for various operations:

- **Network Scanning**:
  ```
  python cli.py scan <subnet>
  ```
  Example: `python cli.py scan 10.0.0.0/24`

- **Vulnerability Scanning**:
  ```
  python cli.py scan-vuln
  ```

- **Listing Assets**:
  ```
  python cli.py list-assets
  ```

- **Listing Vulnerabilities**:
  ```
  python cli.py list-vulns
  ```

- **Generating Reports**:
  ```
  python cli.py report <report_type> <output_file>
  ```
  Example: `python cli.py report csv vulnerabilities.csv`

### Web Dashboard

The web dashboard provides a visual interface to your security data:

1. **Dashboard**: Overview of your security posture
2. **Assets**: Complete inventory of discovered devices
3. **Vulnerabilities**: List of all identified security issues

### Automated Scanning

To set up automated scanning:

1. Configure your scan schedule in the `.env` file
2. Run the scheduler in the background:
   ```
   python scheduler.py
   ```

## Best Practices

### Scanning Frequency

- Run asset discovery scans daily to maintain an accurate inventory
- Run vulnerability scans weekly to identify new security issues
- Schedule scans during off-hours to minimize network impact

### Vulnerability Management

1. **Prioritize**: Focus on high-severity vulnerabilities first
2. **Verify**: Confirm vulnerabilities before remediation
3. **Remediate**: Apply patches or mitigations
4. **Verify Again**: Scan again to confirm successful remediation

### Security Considerations

- Use a dedicated account with limited privileges for scanning
- Inform network administrators before running scans
- Be cautious with aggressive scanning options that might disrupt services
- Keep your NVD API key secure

## Troubleshooting

### Common Issues

- **Scan Not Finding Devices**: Check firewall settings and ensure proper network access
- **API Rate Limiting**: Obtain an NVD API key for higher rate limits
- **Database Errors**: Check file permissions for the SQLite database

### Logging

SentinelCore logs information to the console by default. Check the logs for error messages and debugging information.

## Extending SentinelCore

SentinelCore is designed to be modular and extensible. Consider these enhancement opportunities:

- Add support for additional vulnerability databases
- Implement automated remediation workflows
- Create custom reports for specific compliance frameworks
- Add integration with ticketing systems

## Getting Help

If you encounter issues or have questions:

1. Check the documentation and troubleshooting guide
2. Review the code comments for implementation details
3. Submit issues through the project's issue tracker