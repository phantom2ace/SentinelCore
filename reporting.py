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

def generate_html_report(filename="security_report.html"):
    """Generate an HTML security report with vulnerability details
    
    Args:
        filename: Output HTML file name
        
    Returns:
        str: Path to the generated HTML file
    """
    from policy_engine import generate_recommendations, generate_compliance_report
    from datetime import datetime
    
    session = Session()
    vulns = session.query(Vulnerability).filter(Vulnerability.cvss_score >= 4.0).all()
    assets = session.query(Asset).all()
    
    # Get recommendations and compliance status
    recommendations = generate_recommendations()
    compliance = generate_compliance_report()
    
    # Generate HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SentinelCore Security Report</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ padding: 20px; }}
            .critical {{ background-color: #ffdddd; }}
            .high {{ background-color: #ffffcc; }}
            .medium {{ background-color: #e6f3ff; }}
            .dashboard {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 30px; }}
            .dashboard-item {{ flex: 1; min-width: 200px; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .dashboard-number {{ font-size: 2.5rem; font-weight: bold; }}
            .report-section {{ margin-bottom: 30px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="mb-4">SentinelCore Security Report</h1>
            <p class="text-muted">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
            
            <div class="dashboard">
                <div class="dashboard-item bg-light">
                    <h3>Assets</h3>
                    <div class="dashboard-number">{len(assets)}</div>
                </div>
                <div class="dashboard-item bg-warning bg-opacity-25">
                    <h3>Vulnerabilities</h3>
                    <div class="dashboard-number">{len(vulns)}</div>
                </div>
                <div class="dashboard-item bg-danger bg-opacity-25">
                    <h3>Critical Issues</h3>
                    <div class="dashboard-number">{compliance['critical_vulnerabilities']}</div>
                </div>
                <div class="dashboard-item {('bg-success' if compliance['compliant'] else 'bg-danger') + ' bg-opacity-25'}">
                    <h3>Compliance</h3>
                    <div class="dashboard-number">{('PASS' if compliance['compliant'] else 'FAIL')}</div>
                </div>
            </div>
            
            <div class="report-section">
                <h2>Compliance Status: {compliance['framework']}</h2>
                <div class="card">
                    <div class="card-body">
                        <h5>Requirements:</h5>
                        <ul>
                            {''.join([f'<li>{req}</li>' for req in compliance['requirements']])}
                        </ul>
                        
                        <h5>Findings:</h5>
                        <ul>
                            {''.join([f'<li>{finding}</li>' for finding in compliance['findings']]) if compliance['findings'] else '<li>No compliance issues found</li>'}
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="report-section">
                <h2>Top Recommendations</h2>
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Risk Score</th>
                            <th>Asset</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join([f'''
                        <tr class="{'critical' if rec['risk_score'] > 8.5 else 'high' if rec['risk_score'] > 7.0 else 'medium' if rec['risk_score'] > 5.0 else ''}">
                            <td>{rec['cve']}</td>
                            <td>{rec['risk_score']}</td>
                            <td>{rec['hostname']} ({rec['asset']})</td>
                            <td>{rec['action']}</td>
                        </tr>''' for rec in recommendations[:10]])}
                    </tbody>
                </table>
            </div>
            
            <div class="report-section">
                <h2>Vulnerability Details</h2>
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>CVSS</th>
                            <th>Asset</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join([f'''
                        <tr class="{'table-danger' if vuln.cvss_score >= 7.0 else 'table-warning' if vuln.cvss_score >= 4.0 else ''}">
                            <td>{vuln.cve_id}</td>
                            <td>{vuln.cvss_score}</td>
                            <td>{vuln.asset.ip}</td>
                            <td>{vuln.description[:150] + '...' if len(vuln.description) > 150 else vuln.description}</td>
                        </tr>''' for vuln in vulns])}
                    </tbody>
                </table>
            </div>
        </div>
        
        <footer class="text-center mt-5 mb-3 text-muted">
            <p>Generated by SentinelCore Security Platform</p>
        </footer>
    </body>
    </html>
    """
    
    # Write to file
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename