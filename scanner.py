import nmap
import logging
from database import Asset, Service, engine
from sqlalchemy.orm import sessionmaker

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SentinelScanner')

Session = sessionmaker(bind=engine)

def safe_scan(subnet):
    try:
        logger.info(f"🚀 Starting safe scan: {subnet}")
        nm = nmap.PortScanner()
        
        # Use passive discovery techniques
        nm.scan(hosts=subnet, arguments='-sn')
        
        if not nm.all_hosts():
            logger.warning("⚠️ No active devices found")
            return False
            
        logger.info(f"🔍 Found {len(nm.all_hosts())} active devices")
        return True
        
    except Exception as e:
        logger.error(f"🔴 Scan error: {str(e)}")
        return False

def full_scan(subnet):
    try:
        if not safe_scan(subnet):
            return
            
        logger.info("🔄 Starting detailed scan...")
        nm = nmap.PortScanner()
        scan_result = nm.scan(hosts=subnet, arguments='-F -O')
        
        session = Session()
        
        for ip, device_data in scan_result['scan'].items():
            if device_data['status']['state'] != 'up':
                continue
                
            hostname = device_data['hostnames'][0]['name'] if device_data['hostnames'] else ip
            os_info = device_data.get('osmatch', [{}])[0].get('name', 'Unknown')
            
            asset = Asset(
                ip=ip,
                hostname=hostname,
                os=os_info,
                asset_type="Server" if 'server' in os_info.lower() else "Device",
                cloud_provider="On-Prem"
            )
            session.add(asset)
            session.flush()
            
            # Record services
            for proto in device_data.get('tcp', {}):
                service_data = device_data['tcp'][proto]
                service = Service(
                    port=proto,
                    protocol='tcp',
                    name=service_data['name'],
                    version=service_data.get('version', ''),
                    asset_id=asset.id
                )
                session.add(service)
                
        session.commit()
        logger.info(f"✅ Scan complete! Saved {len(nm.all_hosts())} devices")
        
    except nmap.PortScannerError as e:
        logger.error(f"🔴 Nmap error: {str(e)}")
    except Exception as e:
        logger.error(f"🔴 Unexpected error: {str(e)}")