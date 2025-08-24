import logging
import time
from database import Asset, Session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('Enforcement')

def isolate_asset(asset_id, reason="Security policy enforcement"):
    """Isolate an asset from the network by applying firewall rules or security group changes
    
    Args:
        asset_id: The ID of the asset to isolate
        reason: Reason for isolation
        
    Returns:
        dict: Status of isolation operation with details
    """
    session = Session()
    asset = session.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        logger.error(f"Cannot isolate asset: Asset with ID {asset_id} not found")
        return {"success": False, "message": f"Asset with ID {asset_id} not found"}
    
    logger.info(f"Isolating asset {asset.hostname} ({asset.ip}) due to: {reason}")
    
    # Determine isolation method based on asset type and environment
    if asset.cloud_provider:
        result = _isolate_cloud_asset(asset)
    else:
        result = _isolate_onprem_asset(asset)
    
    # Record isolation action in audit log
    _record_isolation_event(asset, reason, result)
    
    return result

def _isolate_cloud_asset(asset):
    """Isolate a cloud-based asset by modifying security groups"""
    try:
        if asset.cloud_provider.lower() == "aws":
            # Simulate AWS security group modification
            logger.info(f"Applying AWS security group isolation for {asset.ip}")
            time.sleep(1)  # Simulate API call
            return {"success": True, "message": f"Applied AWS security group isolation for {asset.ip}"}
            
        elif asset.cloud_provider.lower() == "azure":
            # Simulate Azure NSG modification
            logger.info(f"Applying Azure NSG isolation for {asset.ip}")
            time.sleep(1)  # Simulate API call
            return {"success": True, "message": f"Applied Azure NSG isolation for {asset.ip}"}
            
        elif asset.cloud_provider.lower() == "gcp":
            # Simulate GCP firewall rule modification
            logger.info(f"Applying GCP firewall rule isolation for {asset.ip}")
            time.sleep(1)  # Simulate API call
            return {"success": True, "message": f"Applied GCP firewall rule isolation for {asset.ip}"}
            
        elif asset.cloud_provider.lower() == "oci":
            # Simulate OCI security list modification
            logger.info(f"Applying OCI security list isolation for {asset.ip}")
            time.sleep(1)  # Simulate API call
            return {"success": True, "message": f"Applied OCI security list isolation for {asset.ip}"}
            
        else:
            logger.warning(f"Unsupported cloud provider: {asset.cloud_provider}")
            return {"success": False, "message": f"Unsupported cloud provider: {asset.cloud_provider}"}
    
    except Exception as e:
        logger.error(f"Error isolating cloud asset {asset.ip}: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}

def _isolate_onprem_asset(asset):
    """Isolate an on-premises asset by applying firewall rules"""
    try:
        # Simulate firewall rule application
        logger.info(f"Applying firewall isolation rules for {asset.ip}")
        
        # This would contain actual firewall rule application logic
        # For example, using a network management API or executing commands
        time.sleep(1.5)  # Simulate longer operation time
        
        return {"success": True, "message": f"Applied firewall isolation rules for {asset.ip}"}
    
    except Exception as e:
        logger.error(f"Error isolating on-premises asset {asset.ip}: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}

def _record_isolation_event(asset, reason, result):
    """Record isolation action in audit log"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - ISOLATION - Asset: {asset.hostname} ({asset.ip}) - Reason: {reason} - Result: {'SUCCESS' if result['success'] else 'FAILED'}"
    
    # In a real implementation, this would write to a secure audit log
    logger.info(f"Audit: {log_entry}")
    
    try:
        with open("security_audit.log", "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        logger.error(f"Failed to write to audit log: {str(e)}")

def restore_asset(asset_id, reason="Isolation period complete"):
    """Restore network access for a previously isolated asset
    
    Args:
        asset_id: The ID of the asset to restore
        reason: Reason for restoration
        
    Returns:
        dict: Status of restoration operation with details
    """
    session = Session()
    asset = session.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        logger.error(f"Cannot restore asset: Asset with ID {asset_id} not found")
        return {"success": False, "message": f"Asset with ID {asset_id} not found"}
    
    logger.info(f"Restoring network access for {asset.hostname} ({asset.ip}) due to: {reason}")
    
    # Determine restoration method based on asset type and environment
    if asset.cloud_provider:
        result = _restore_cloud_asset(asset)
    else:
        result = _restore_onprem_asset(asset)
    
    # Record restoration action in audit log
    _record_restoration_event(asset, reason, result)
    
    return result

def _restore_cloud_asset(asset):
    """Restore a cloud-based asset by reverting security group changes"""
    try:
        if asset.cloud_provider.lower() == "aws":
            # Simulate AWS security group restoration
            logger.info(f"Reverting AWS security group isolation for {asset.ip}")
            time.sleep(1)  # Simulate API call
            return {"success": True, "message": f"Restored AWS security group access for {asset.ip}"}
            
        elif asset.cloud_provider.lower() == "azure":
            # Simulate Azure NSG restoration
            logger.info(f"Reverting Azure NSG isolation for {asset.ip}")
            time.sleep(1)  # Simulate API call
            return {"success": True, "message": f"Restored Azure NSG access for {asset.ip}"}
            
        elif asset.cloud_provider.lower() == "gcp":
            # Simulate GCP firewall rule restoration
            logger.info(f"Reverting GCP firewall rule isolation for {asset.ip}")
            time.sleep(1)  # Simulate API call
            return {"success": True, "message": f"Restored GCP firewall rule access for {asset.ip}"}
            
        elif asset.cloud_provider.lower() == "oci":
            # Simulate OCI security list restoration
            logger.info(f"Reverting OCI security list isolation for {asset.ip}")
            time.sleep(1)  # Simulate API call
            return {"success": True, "message": f"Restored OCI security list access for {asset.ip}"}
            
        else:
            logger.warning(f"Unsupported cloud provider: {asset.cloud_provider}")
            return {"success": False, "message": f"Unsupported cloud provider: {asset.cloud_provider}"}
    
    except Exception as e:
        logger.error(f"Error restoring cloud asset {asset.ip}: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}

def _restore_onprem_asset(asset):
    """Restore an on-premises asset by reverting firewall rules"""
    try:
        # Simulate firewall rule reversion
        logger.info(f"Reverting firewall isolation rules for {asset.ip}")
        
        # This would contain actual firewall rule reversion logic
        time.sleep(1.5)  # Simulate longer operation time
        
        return {"success": True, "message": f"Restored network access for {asset.ip}"}
    
    except Exception as e:
        logger.error(f"Error restoring on-premises asset {asset.ip}: {str(e)}")
        return {"success": False, "message": f"Error: {str(e)}"}

def _record_restoration_event(asset, reason, result):
    """Record restoration action in audit log"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - RESTORATION - Asset: {asset.hostname} ({asset.ip}) - Reason: {reason} - Result: {'SUCCESS' if result['success'] else 'FAILED'}"
    
    # In a real implementation, this would write to a secure audit log
    logger.info(f"Audit: {log_entry}")
    
    try:
        with open("security_audit.log", "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        logger.error(f"Failed to write to audit log: {str(e)}")
    
    return result