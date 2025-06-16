import sqlite3
from Crypto.Cipher import AES
import json
import logging
from datetime import datetime
from typing import Set, Tuple, List, Dict, Any
from config.keys import ENCRYPTION_KEY

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

def encrypt_data(data: str) -> tuple[bytes, bytes, bytes]:
    """Encrypt data using AES."""
    try:
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return cipher.nonce, tag, ciphertext
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise

def cache_results(networks: Set[Tuple[str, str]], devices: List[Dict[str, Any]], streams: List[Dict[str, Any]]) -> None:
    """Cache results in encrypted SQLite database."""
    try:
        conn = sqlite3.connect("data/cache.db")
        conn.execute("CREATE TABLE IF NOT EXISTS results (timestamp TEXT, data BLOB, nonce BLOB, tag BLOB)")
        data = json.dumps({"networks": list(networks), "devices": devices, "streams": streams})
        nonce, tag, ciphertext = encrypt_data(data)
        conn.execute(
            "INSERT INTO results (timestamp, data, nonce, tag) VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(), ciphertext, nonce, tag)
        )
        conn.commit()
        logger.info("Results cached successfully")
    except Exception as e:
        logger.error(f"Failed to cache results: {str(e)}")
    finally:
        conn.close()

def save_results(
    networks: Set[Tuple[str, str]],
    devices: List[Dict[str, Any]],
    streams: List[Dict[str, Any]],
    output_file: str = "output/netsentry_results.json"
) -> None:
    """Save results to JSON."""
    try:
        results = {"networks": list(networks), "devices": devices, "streams": streams}
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save results: {str(e)}")

def generate_report(
    networks: Set[Tuple[str, str]],
    devices: List[Dict[str, Any]],
    streams: List[Dict[str, Any]],
    output_file: str = "output/report.md"
) -> None:
    """Generate a pentest report in Markdown."""
    try:
        with open(output_file, "w") as f:
            f.write("# NetSentry Pentest Report\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Executive Summary\n")
            f.write(f"NetSentry identified {len(networks)} Wi-Fi networks, {len(devices)} devices, "
                    f"and {len(streams)} potential camera streams.\n\n")
            
            f.write("## Wi-Fi Networks\n")
            if networks:
                for ssid, bssid in networks:
                    f.write(f"- **SSID**: {ssid}, **BSSID**: {bssid}\n")
            else:
                f.write("No networks detected.\n")
            
            f.write("\n## Devices\n")
            if devices:
                for device in devices:
                    ports = ", ".join([f"{p['port']} ({p['service']})" for p in device["ports"]])
                    scripts = "\n".join([f"  - Port {k}: {v}" for k, v in device.get("scripts", {}).items()])
                    f.write(f"- **IP**: {device['ip']}\n")
                    f.write(f"  - **MAC**: {device['mac']}\n")
                    f.write(f"  - **Vendor**: {device['vendor']}\n")
                    f.write(f"  - **OS**: {device['os']}\n")
                    f.write(f"  - **Ports**: {ports or 'None'}\n")
                    if scripts:
                        f.write(f"  - **Scripts**:\n{scripts}\n")
            else:
                f.write("No devices detected.\n")
            
            f.write("\n## Camera Streams\n")
            if streams:
                for stream in streams:
                    f.write(f"- **Protocol**: {stream['protocol']}\n")
                    f.write(f"  - **Source IP**: {stream['src_ip']}\n")
                    f.write(f"  - **Destination IP**: {stream['dst_ip']}\n")
                    f.write(f"  - **Timestamp**: {stream['timestamp']}\n")
            else:
                f.write("No streams detected.\n")
            
            f.write("\n## Recommendations\n")
            f.write("- Secure Wi-Fi networks with WPA3 or strong WPA2 passwords.\n")
            f.write("- Change default credentials on IP cameras and CCTV systems.\n")
            f.write("- Monitor network traffic for unauthorized streams.\n")
            f.write("- Conduct regular vulnerability scans.\n")
        
        logger.info(f"Report generated at {output_file}")
    except Exception as e:
        logger.error(f"Failed to generate report: {str(e)}")