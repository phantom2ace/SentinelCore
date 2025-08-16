import argparse
import logging
import sys
from sqlalchemy.orm import joinedload
from scanner import full_scan
from vulnerability_scanner import scan_vulnerabilities
from database import Asset, Vulnerability, Service, engine
from sqlalchemy.orm import sessionmaker
from cloud_integration import discover_aws_resources, discover_azure_resources
from reporting import generate_csv_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('SentinelCLI')
Session = sessionmaker(bind=engine)

def list_assets():
    """List all discovered assets in database"""
    session = Session()
    assets = session.query(Asset).all()
    
    if not assets:
        logger.info("No devices found. Run discovery scan first.")
        return
    
    logger.info("\n📋 Discovered Assets")
    logger.info("ID  | IP Address     | Hostname       | OS")
    logger.info("----|----------------|----------------|----------------")
    
    for asset in assets:
        logger.info(f"{asset.id:<3} | {asset.ip:<14} | {asset.hostname[:12]:<14} | {asset.os[:20]}")

def list_vulnerabilities():
    """List all discovered vulnerabilities"""
    session = Session()
    vulns = session.query(Vulnerability).options(joinedload(Vulnerability.asset)).all()
    
    if not vulns:
        logger.info("\n✅ No vulnerabilities found")
        return
    
    logger.info("\n⚠️ Discovered Vulnerabilities")
    logger.info("CVE ID       | CVSS | Exploit | Asset IP       | Description")
    logger.info("-------------|------|---------|----------------|------------")
    
    for vuln in vulns:
        exploit = "YES" if vuln.exploit_available else "NO"
        logger.info(f"{vuln.cve_id:<12} | {vuln.cvss_score:<4.1f} | {exploit:<7} | {vuln.asset.ip:<14} | {vuln.description[:30]}")

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Core - Zero Trust Security Platform",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands:')
    
    # Scan command
    scan_parser = subparsers.add_parser(
        'scan', 
        help='Discover assets in a network subnet'
    )
    scan_parser.add_argument(
        'subnet', 
        help='Network subnet to scan (e.g., 192.168.1.0/24 or 10.0.0.1-100)'
    )
    
    # List command
    list_parser = subparsers.add_parser(
        'list', 
        help='List discovered items'
    )
    list_parser.add_argument(
        '--type', 
        choices=['assets', 'vulns'], 
        default='assets',
        help='Type of items to list (default: assets)'
    )
    
    # Vulnerability scan command
    subparsers.add_parser(
        'scan-vuln', 
        help='Scan for vulnerabilities in discovered assets'
    )
    
    # Cloud discovery commands
    aws_parser = subparsers.add_parser(
        'discover-aws',
        help='Discover AWS resources'
    )
    
    azure_parser = subparsers.add_parser(
        'discover-azure',
        help='Discover Azure resources'
    )
    azure_parser.add_argument(
        '--subscription-id', 
        required=True,
        help='Azure subscription ID'
    )
    
    # Reporting command
    report_parser = subparsers.add_parser(
        'generate-report',
        help='Generate security report'
    )
    report_parser.add_argument(
        '--format',
        choices=['csv'],
        default='csv',
        help='Report format (default: csv)'
    )
    
    # Dashboard command
    subparsers.add_parser(
        'run-dashboard',
        help='Start the web dashboard'
    )
    
    # Database management command
    db_parser = subparsers.add_parser(
        'db-reset',
        help='Reset the database (DANGER: Deletes all data!)'
    )
    
    # Help fallback
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    args = parser.parse_args()
    
    try:
        if args.command == 'scan':
            logger.info(f"🚀 Starting network scan: {args.subnet}")
            full_scan(args.subnet)
            logger.info("✅ Network scan completed successfully!")
            
        elif args.command == 'list':
            if args.type == 'assets':
                list_assets()
            elif args.type == 'vulns':
                list_vulnerabilities()
                
        elif args.command == 'scan-vuln':
            logger.info("🔍 Starting vulnerability scan")
            scan_vulnerabilities()
            logger.info("✅ Vulnerability scan completed!")
            
        elif args.command == 'discover-aws':
            logger.info("☁️ Discovering AWS resources...")
            assets = discover_aws_resources()
            logger.info(f"Found {len(assets)} AWS resources")
            
        elif args.command == 'discover-azure':
            logger.info("☁️ Discovering Azure resources...")
            assets = discover_azure_resources(args.subscription_id)
            logger.info(f"Found {len(assets)} Azure resources")
            
        elif args.command == 'generate-report':
            if args.format == 'csv':
                filename = generate_csv_report()
                logger.info(f"✅ Report generated: {filename}")
                
        elif args.command == 'run-dashboard':
            logger.info("🌐 Starting web dashboard...")
            from dashboard import app
            app.run(debug=True)
                
        elif args.command == 'db-reset':
            confirm = input("⚠️ WARNING: This will delete ALL data! Continue? (y/N): ")
            if confirm.lower() == 'y':
                from database import Base, engine
                Base.metadata.drop_all(engine)
                Base.metadata.create_all(engine)
                logger.info("✅ Database reset complete")
            else:
                logger.info("Database reset canceled")
                
    except Exception as e:
        logger.error(f"❌ Error: {str(e)}")
        logger.info("Check logs for details or use --help for assistance")

if __name__ == "__main__":
    main()