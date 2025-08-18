import logging
import time
from database import Asset, Vulnerability, Service, Session
from sqlalchemy.orm import joinedload
from enforcement import isolate_asset

logger = logging.getLogger('Remediation')

def apply_patch(asset_id, vulnerability_id):
    """Simulate applying a patch to an asset for a specific vulnerability
    
    Args:
        asset_id: ID of the asset to patch
        vulnerability_id: ID of the vulnerability to patch
        
    Returns:
        dict: Status of the patching operation
    """
    session = Session()
    
    try:
        # Get the asset and vulnerability
        asset = session.query(Asset).filter(Asset.id == asset_id).first()
        vulnerability = session.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        
        if not asset or not vulnerability:
            logger.error(f"Cannot apply patch: Asset or vulnerability not found")
            return {"success": False, "message": "Asset or vulnerability not found"}
        
        # Log the remediation attempt
        logger.info(f"Applying patch for {vulnerability.cve_id} on {asset.hostname} ({asset.ip})")
        
        # Simulate patching process
        time.sleep(2)  # Simulate time taken to apply patch
        
        # Mark vulnerability as remediated by removing it from the database
        session.delete(vulnerability)
        session.commit()
        
        return {
            "success": True, 
            "message": f"Successfully patched {vulnerability.cve_id} on {asset.hostname}"
        }
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error applying patch: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}
    finally:
        session.close()

def auto_remediate_critical_vulnerabilities(cvss_threshold=9.0):
    """Automatically remediate critical vulnerabilities above the threshold
    
    Args:
        cvss_threshold: CVSS score threshold for auto-remediation
        
    Returns:
        dict: Summary of remediation actions
    """
    session = Session()
    results = {
        "attempted": 0,
        "successful": 0,
        "failed": 0,
        "details": []
    }
    
    try:
        # Get all critical vulnerabilities above the threshold
        critical_vulns = session.query(Vulnerability).options(
            joinedload(Vulnerability.asset)
        ).filter(Vulnerability.cvss_score >= cvss_threshold).all()
        
        logger.info(f"Found {len(critical_vulns)} critical vulnerabilities for auto-remediation")
        
        # Apply patches for each vulnerability
        for vuln in critical_vulns:
            results["attempted"] += 1
            
            # Apply the patch
            patch_result = apply_patch(vuln.asset_id, vuln.id)
            
            if patch_result["success"]:
                results["successful"] += 1
            else:
                results["failed"] += 1
            
            # Record the result
            results["details"].append({
                "cve_id": vuln.cve_id,
                "asset": f"{vuln.asset.hostname} ({vuln.asset.ip})",
                "cvss_score": vuln.cvss_score,
                "success": patch_result["success"],
                "message": patch_result["message"]
            })
        
        return results
        
    except Exception as e:
        logger.error(f"Error in auto-remediation: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}
    finally:
        session.close()

def quarantine_infected_assets(reason="Automated security response"):
    """Identify and isolate potentially compromised assets
    
    Args:
        reason: Reason for quarantine action
        
    Returns:
        dict: Summary of quarantine actions
    """
    session = Session()
    results = {
        "attempted": 0,
        "successful": 0,
        "failed": 0,
        "details": []
    }
    
    try:
        # Find assets with critical vulnerabilities (CVSS >= 9.0) and known exploits
        high_risk_assets = session.query(Asset).join(Asset.vulnerabilities).filter(
            Vulnerability.cvss_score >= 9.0,
            Vulnerability.exploit_available == True
        ).distinct().all()
        
        logger.info(f"Found {len(high_risk_assets)} high-risk assets for quarantine")
        
        # Isolate each high-risk asset
        for asset in high_risk_assets:
            results["attempted"] += 1
            
            # Isolate the asset
            isolation_result = isolate_asset(
                asset.id, 
                reason=f"Automated quarantine: Critical vulnerability with exploit detected"
            )
            
            if isolation_result["success"]:
                results["successful"] += 1
            else:
                results["failed"] += 1
            
            # Record the result
            results["details"].append({
                "asset_id": asset.id,
                "asset": f"{asset.hostname} ({asset.ip})",
                "success": isolation_result["success"],
                "message": isolation_result["message"]
            })
        
        return results
        
    except Exception as e:
        logger.error(f"Error in quarantine operation: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}
    finally:
        session.close()