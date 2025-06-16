import nmap
import logging
from typing import List, Dict, Any
from .vendor_lookup import get_vendor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("data/logs/netsentry.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def scan_devices(network_range: str) -> List[Dict[str, Any]]:
    """Scan for devices using advanced Nmap scripts for camera detection."""
    try:
        nm = nmap.PortScanner()
        logger.info(f"Scanning devices in {network_range} with advanced scripts...")
        
        # Advanced scan with camera-specific ports, scripts, and stealth timing
        nm.scan(
            hosts=network_range,
            arguments=(
                "-sS -sV -O -p 80,554,8554 "
                "--script=http-enum,http-auth,rtsp-url-brute,http-vuln-cve2017-5638,http-headers "
                "-T2 --scan-delay 100ms"
            )
        )
        devices = []
        
        for host in nm.all_hosts():
            device = {
                "ip": host,
                "mac": nm[host]["addresses"].get("mac", "Unknown"),
                "vendor": "Unknown",
                "ports": [],
                "status": nm[host]["status"]["state"],
                "os": nm[host].get("osmatch", [{}])[0].get("name", "Unknown"),
                "scripts": {}
            }
            if "tcp" in nm[host]:
                device["ports"] = [
                    {
                        "port": p,
                        "service": nm[host]["tcp"][p]["name"],
                        "state": nm[host]["tcp"][p]["state"],
                        "version": nm[host]["tcp"][p].get("version", "Unknown")
                    }
                    for p in nm[host]["tcp"]
                ]
                # Capture script outputs (e.g., default credentials, vulnerabilities)
                for port in nm[host]["tcp"]:
                    if "script" in nm[host]["tcp"][port]:
                        device["scripts"][port] = nm[host]["tcp"][port]["script"]
            device["vendor"] = get_vendor(device["mac"])
            devices.append(device)
        
        logger.info(f"Found {len(devices)} devices in {network_range}")
        return devices
    
    except Exception as e:
        logger.error(f"Device scan failed: {str(e)}")
        return []