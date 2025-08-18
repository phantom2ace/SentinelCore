from database import Asset, Vulnerability, Session
from sqlalchemy.orm import joinedload
import logging
import time

logger = logging.getLogger('PolicyEngine')

CRITICALITY_SCORES = {
    'database': 1.5,
    'server': 1.3,
    'workstation': 1.0,
    'iot': 0.8
}

BUSINESS_IMPACT = {
    'critical': 2.0,
    'high': 1.5,
    'medium': 1.0,
    'low': 0.5
}

def calculate_risk(vulnerability, business_impact='medium'):
    """Calculate risk score based on CVSS, asset criticality, and business impact
    
    Args:
        vulnerability: The vulnerability object
        business_impact: Business impact level ('critical', 'high', 'medium', 'low')
        
    Returns:
        tuple: (risk_score, risk_factors)
    """
    # Base score
    score = vulnerability.cvss_score
    risk_factors = []
    
    # Asset criticality
    asset_type = vulnerability.asset.asset_type.lower()
    criticality_factor = CRITICALITY_SCORES.get(asset_type, 1.0)
    score *= criticality_factor
    if criticality_factor > 1.0:
        risk_factors.append(f"Critical asset type: {asset_type}")
    
    # Exploit availability
    if vulnerability.exploit_available:
        score *= 1.5
        risk_factors.append("Exploit publicly available")
        
    # External exposure (check if attribute exists)
    is_external = getattr(vulnerability.asset, 'is_external', False)
    if is_external:
        score *= 1.8
        risk_factors.append("Externally exposed asset")
    
    # Business impact
    impact_factor = BUSINESS_IMPACT.get(business_impact.lower(), 1.0)
    score *= impact_factor
    if impact_factor > 1.0:
        risk_factors.append(f"High business impact: {business_impact}")
    
    # Log the calculation
    logger.debug(f"Risk calculation for {vulnerability.cve_id}: {score:.2f}")
    
    return (min(score, 10.0), risk_factors)  # Cap at max

def generate_recommendations(business_context=None):
    """Generate security recommendations based on vulnerabilities and business context
    
    Args:
        business_context: Optional dict mapping asset IDs to business impact levels
        
    Returns:
        list: Sorted recommendations by risk score
    """
    session = Session()
    vulns = session.query(Vulnerability).options(joinedload(Vulnerability.asset)).all()
    
    if business_context is None:
        business_context = {}
    
    recommendations = []
    for vuln in vulns:
        # Get business impact for this asset, default to 'medium'
        impact = business_context.get(vuln.asset.id, 'medium')
        
        # Calculate risk with factors
        risk_score, risk_factors = calculate_risk(vuln, impact)
        
        # Determine recommended action based on risk score
        if risk_score > 8.5:
            action = "CRITICAL: Patch immediately and verify"
        elif risk_score > 7.0:
            action = "HIGH: Patch within 7 days"
        elif risk_score > 5.0:
            action = "MEDIUM: Schedule patching within 30 days"
        else:
            action = "LOW: Address in next patch cycle"
        
        recommendations.append({
            'cve': vuln.cve_id,
            'asset': vuln.asset.ip,
            'hostname': vuln.asset.hostname,
            'risk_score': round(risk_score, 2),
            'risk_factors': risk_factors,
            'action': action
        })
    
    logger.info(f"Generated {len(recommendations)} recommendations")
    return sorted(recommendations, key=lambda x: x['risk_score'], reverse=True)

def generate_compliance_report(framework='pci-dss'):
    """Generate compliance report for specified security framework
    
    Args:
        framework: Security framework to check compliance against
                  (pci-dss, nist, hipaa, gdpr)
    
    Returns:
        dict: Compliance status with details
    """
    session = Session()
    assets = session.query(Asset).all()
    vulns = session.query(Vulnerability).options(joinedload(Vulnerability.asset)).all()
    
    # Framework-specific requirements
    frameworks = {
        'pci-dss': {
            'max_high_vulns': 0,
            'max_vuln_age_days': 30,
            'required_scans': ['quarterly', 'after_changes'],
            'requirements': [
                'No critical vulnerabilities allowed',
                'All high vulnerabilities must be patched within 30 days',
                'Regular vulnerability scanning required'
            ]
        },
        'nist': {
            'max_high_vulns': 0,
            'max_vuln_age_days': 15,
            'required_scans': ['monthly', 'after_changes'],
            'requirements': [
                'Continuous monitoring required',
                'All critical vulnerabilities must be patched within 15 days',
                'Risk assessment must be performed regularly'
            ]
        }
    }
    
    # Get framework requirements or default to PCI-DSS
    framework_reqs = frameworks.get(framework.lower(), frameworks['pci-dss'])
    
    # Count high and critical vulnerabilities
    high_vulns = [v for v in vulns if v.cvss_score >= 7.0]
    critical_vulns = [v for v in vulns if v.cvss_score >= 9.0]
    
    # Check compliance status
    is_compliant = len(critical_vulns) == 0
    
    # Generate findings
    findings = []
    if critical_vulns:
        findings.append(f"Found {len(critical_vulns)} critical vulnerabilities that must be addressed immediately")
    
    if high_vulns:
        findings.append(f"Found {len(high_vulns)} high severity vulnerabilities that must be addressed within {framework_reqs['max_vuln_age_days']} days")
    
    # Generate report
    report = {
        'framework': framework.upper(),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'compliant': is_compliant,
        'requirements': framework_reqs['requirements'],
        'findings': findings,
        'assets_scanned': len(assets),
        'vulnerabilities_found': len(vulns),
        'critical_vulnerabilities': len(critical_vulns),
        'high_vulnerabilities': len(high_vulns),
        'recommendations': generate_recommendations()
    }
    
    logger.info(f"Generated compliance report for {framework.upper()}: {'PASS' if is_compliant else 'FAIL'}")
    return report