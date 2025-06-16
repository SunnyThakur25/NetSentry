import os
import logging
from typing import Optional

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

OUI_FILE = "data/oui.txt"

def get_vendor(mac: str) -> Optional[str]:
    """Query local OUI database for vendor."""
    try:
        if not os.path.exists(OUI_FILE):
            logger.warning(f"OUI file not found at {OUI_FILE}")
            return "Unknown"
        
        with open(OUI_FILE, "r") as f:
            for line in f:
                if mac[:8].replace(":", "").upper() in line:
                    vendor = line.split("\t")[1].strip()
                    logger.debug(f"Found vendor {vendor} for MAC {mac}")
                    return vendor
        return "Unknown"
    
    except Exception as e:
        logger.error(f"Vendor lookup failed: {str(e)}")
        return "Unknown"