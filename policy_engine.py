from database import Asset, Vulnerability, Session
from sqlalchemy.orm import joinedload

CRITICALITY_SCORES = {
    'database': 1.5,
    'server': 1.3,
    'workstation': 1.0,
    'iot': 0.8
}

def calculate_risk(vulnerability):
    # Base score
    score = vulnerability.cvss_score
    
    # Asset criticality
    asset_type = vulnerability.asset.asset_type.lower()
    score *= CRITICALITY_SCORES.get(asset_type, 1.0)
    
    # Exploit availability
    if vulnerability.exploit_available:
        score *= 1.5
        
    # External exposure
    if vulnerability.asset.is_external:
        score *= 1.8
        
    return min(score, 10.0)  # Cap at max

def generate_recommendations():
    session = Session()
    vulns = session.query(Vulnerability).options(joinedload(Vulnerability.asset)).all()
    
    recommendations = []
    for vuln in vulns:
        risk_score = calculate_risk(vuln)
        recommendations.append({
            'cve': vuln.cve_id,
            'asset': vuln.asset.ip,
            'risk_score': risk_score,
            'action': "Patch immediately" if risk_score > 7.0 else "Schedule patching"
        })
    
    return sorted(recommendations, key=lambda x: x['risk_score'], reverse=True)