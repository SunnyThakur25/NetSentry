import json
import logging
from typing import Set, Tuple, List, Dict, Any
from .wifi_scanner import scan_wifi_networks, deauth_network, spoof_mac, inject_probe
from .device_scanner import scan_devices
from .traffic_analyzer import analyze_traffic
from .visualizer import create_network_tree
from .storage import cache_results, save_results, generate_report

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

def load_config(config_file: str = "config/config.json") -> Dict[str, Any]:
    """Load configuration from JSON."""
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        logger.info(f"Loaded configuration from {config_file}")
        return config
    except Exception as e:
        logger.error(f"Failed to load config: {str(e)}")
        return {
            "interface": "wlan0",
            "network_range": "192.168.1.0/24",
            "output_json": "output/netsentry_results.json",
            "output_tree": "output/netsentry_tree.png"
        }

def netsentry(config: Dict[str, Any]) -> tuple[Set[Tuple[str, str]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Main function to detect hidden networks, devices, and streams."""
    try:
        interface = config["interface"]
        network_range = config["network_range"]
        
        # Spoof MAC for stealth
        logger.info("Initiating MAC spoofing for stealth")
        if not spoof_mac(interface):
            logger.warning("MAC spoofing failed, proceeding without spoofing")
        
        # Scan Wi-Fi networks
        networks = scan_wifi_networks(interface)
        
        # Attempt deauth for hidden SSIDs (ethical use only)
        for _, bssid in networks:
            if "<Hidden SSID>" in networks:
                logger.info(f"Attempting deauth for {bssid}")
                deauth_network(bssid, interface)
                inject_probe(interface)
                networks.update(scan_wifi_networks(interface))
        
        # Scan devices
        devices = scan_devices(network_range)
        
        # Analyze traffic
        streams = analyze_traffic(interface)
        
        # Cache and save results
        cache_results(networks, devices, streams)
        save_results(networks, devices, streams, config["output_json"])
        
        # Generate report
        generate_report(networks, devices, streams)
        
        # Visualize results
        create_network_tree(networks, devices, streams, config["output_tree"])
        
        logger.info("NetSentry scan completed successfully")
        return networks, devices, streams
    
    except Exception as e:
        logger.error(f"NetSentry failed: {str(e)}")
        return set(), [], []

if __name__ == "__main__":
    config = load_config()
    networks, devices, streams = netsentry(config)
    print(f"Found {len(networks)} networks, {len(devices)} devices, {len(streams)} streams.")