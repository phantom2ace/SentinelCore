import csv
from datetime import datetime
from database import Session, Vulnerability

def generate_csv_report(filename="security_report.csv"):
    session = Session()
    vulns = session.query(Vulnerability).filter(Vulnerability.cvss_score >= 5.0).all()
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['CVE ID', 'CVSS Score', 'Asset IP', 'Description'])
        
        for vuln in vulns:
            writer.writerow([
                vuln.cve_id,
                vuln.cvss_score,
                vuln.asset.ip,
                vuln.description[:100] + '...' if len(vuln.description) > 100 else vuln.description
            ])
    
    return filename

def generate_html_report():
    # Similar to CSV but with HTML formatting
    pass