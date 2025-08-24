# alerting.py
import os
import logging
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SentinelAlerts')

# Telegram configuration
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

def send_telegram_alert(message, severity="info"):
    """
    Send an alert message to Telegram
    
    Args:
        message (str): The alert message to send
        severity (str): Alert severity level (info, warning, critical)
    
    Returns:
        bool: True if message was sent successfully, False otherwise
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram alerts not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env file.")
        return False
    
    # Format message based on severity
    if severity == "critical":
        formatted_message = f"🚨 CRITICAL ALERT: {message}"
    elif severity == "warning":
        formatted_message = f"⚠️ WARNING: {message}"
    else:
        formatted_message = f"ℹ️ INFO: {message}"
    
    # Add SentinelCore branding
    formatted_message = f"*SentinelCore Security Alert*\n\n{formatted_message}"
    
    # Send message to Telegram
    try:
        payload = {
            'chat_id': TELEGRAM_CHAT_ID,
            'text': formatted_message,
            'parse_mode': 'Markdown'
        }
        response = requests.post(TELEGRAM_API_URL, data=payload, timeout=10)
        
        if response.status_code == 200:
            logger.info(f"Alert sent to Telegram: {message[:50]}...")
            return True
        else:
            logger.error(f"Failed to send Telegram alert. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return False
    
    except Exception as e:
        logger.error(f"Error sending Telegram alert: {str(e)}")
        return False

def send_vulnerability_alert(cve_id, description, cvss_score, asset_ip, asset_hostname=None):
    """
    Send an alert about a newly discovered critical vulnerability
    
    Args:
        cve_id (str): The CVE ID of the vulnerability
        description (str): Brief description of the vulnerability
        cvss_score (float): The CVSS score of the vulnerability
        asset_ip (str): IP address of the affected asset
        asset_hostname (str, optional): Hostname of the affected asset
    """
    # Determine severity based on CVSS score
    if cvss_score >= 9.0:
        severity = "critical"
    elif cvss_score >= 7.0:
        severity = "warning"
    else:
        severity = "info"
    
    # Format the hostname part
    hostname_text = f" ({asset_hostname})" if asset_hostname else ""
    
    # Create the alert message
    message = f"New vulnerability detected:\n" \
              f"• *CVE*: {cve_id}\n" \
              f"• *CVSS Score*: {cvss_score}\n" \
              f"• *Affected Asset*: {asset_ip}{hostname_text}\n" \
              f"• *Description*: {description[:200]}..."
    
    return send_telegram_alert(message, severity)

def send_new_asset_alert(asset_ip, hostname, os_info, services):
    """
    Send an alert about a newly discovered asset on the network
    
    Args:
        asset_ip (str): IP address of the new asset
        hostname (str): Hostname of the new asset
        os_info (str): Operating system information
        services (list): List of open services/ports
    """
    # Format the services information
    services_text = "\n".join([f"  • {service['port']}/{service['protocol']}: {service['name']}" 
                         for service in services[:5]])
    
    if len(services) > 5:
        services_text += f"\n  • ...and {len(services) - 5} more"
    
    if not services_text:
        services_text = "  • No open services detected"
    
    # Create the alert message
    message = f"New asset discovered on network:\n" \
              f"• *IP Address*: {asset_ip}\n" \
              f"• *Hostname*: {hostname}\n" \
              f"• *Operating System*: {os_info}\n" \
              f"• *Open Services*:\n{services_text}"
    
    return send_telegram_alert(message, "info")